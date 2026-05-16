#!/usr/bin/env python3
import asyncio
import aiohttp
import psutil
import subprocess
import time
import os
import sys
import argparse
import socket
import csv
from urllib.parse import quote
from typing import List, Dict
from jinja2 import Environment, FileSystemLoader

# Parse args
parser = argparse.ArgumentParser(description="System Performance Benchmark for WAF vs AI Model")
parser.add_argument("--concurrencies", type=int, nargs="+", default=[10, 50, 100, 500], help="List of concurrencies to test")
parser.add_argument("--duration", type=int, default=60, help="Duration for each concurrency test (seconds)")
parser.add_argument("--target", choices=["ai", "waf"], default="ai", help="Test Target: ai (FastAPI) or waf (ModSecurity)")
parser.add_argument("--target-url", default="http://127.0.0.1:8000/predict", help="URL to send requests. WAF default: http://127.0.0.1/?q=")
parser.add_argument("--dataset", required=True, help="Path to CSV dataset to draw payloads from")
parser.add_argument("--start-server", action="store_true", help="Automatically start api_server.py as a subprocess (only for target=ai)")
args = parser.parse_args()

PAYLOADS = []

def load_payloads(filepath):
    """Load payloads from CSV (Payload,Label)."""
    p = []
    if not os.path.exists(filepath):
        print(f"Error: Dataset {filepath} not found.")
        sys.exit(1)
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if row:
                p.append(row[0])
    return p if p else ["<script>alert(1)</script>"]

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

async def fetch_ai(session: aiohttp.ClientSession, url: str, payload: str) -> float:
    start_time = time.perf_counter()
    try:
        async with session.post(url, json={"payload": payload}) as response:
            await response.read()
    except Exception:
        pass
    return time.perf_counter() - start_time

async def fetch_waf(session: aiohttp.ClientSession, url: str, payload: str) -> float:
    start_time = time.perf_counter()
    try:
        # Assuming URL points to base address e.g. http://127.0.0.1/?q=
        async with session.get(f"{url}{quote(payload)}") as response:
            await response.read()
    except Exception:
        pass
    return time.perf_counter() - start_time

async def worker(session: aiohttp.ClientSession, url: str, target: str, end_time: float, latencies: List[float]):
    i = 0
    total_payloads = len(PAYLOADS)
    while time.time() < end_time:
        p = PAYLOADS[i % total_payloads]
        
        if target == "ai":
            lat = await fetch_ai(session, url, p)
        else:
            lat = await fetch_waf(session, url, p)
            
        latencies.append(lat)
        i += 1

async def load_test(concurrency: int, duration: int) -> List[float]:
    latencies = []
    end_time = time.time() + duration
    
    connector = aiohttp.TCPConnector(limit=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for _ in range(concurrency):
            tasks.append(asyncio.create_task(worker(session, args.target_url, args.target, end_time, latencies)))
        await asyncio.gather(*tasks)
    
    return latencies

async def run_phase(concurrency: int, duration: int, pids: List[int]) -> Dict:
    print(f"\n--- Testing Concurrency: {concurrency} for {duration} seconds ---")
    end_time = time.time() + duration
    
    async def monitor_all():
        processes = []
        for pid in pids:
            try:
                p = psutil.Process(pid)
                processes.append(p)
                for child in p.children(recursive=True):
                    processes.append(child)
            except psutil.NoSuchProcess:
                pass
                
        cpu_hist = []
        mem_hist = []
        for p in processes:
            try: p.cpu_percent() 
            except: pass
            
        while time.time() < end_time:
            total_cpu = 0
            total_mem = 0
            for p in processes:
                try:
                    total_cpu += p.cpu_percent(interval=None)
                    total_mem += p.memory_info().rss / (1024 * 1024)
                except psutil.NoSuchProcess:
                    continue
            cpu_hist.append(total_cpu)
            mem_hist.append(total_mem)
            await asyncio.sleep(1.0)
            
        avg_cpu = sum(cpu_hist) / len(cpu_hist) if cpu_hist else 0.0
        max_mem = max(mem_hist) if mem_hist else 0.0
        return avg_cpu, max_mem

    monitor_task = asyncio.create_task(monitor_all())
    
    # Run Load
    latencies = await load_test(concurrency, duration)
    avg_cpu, max_mem = await monitor_task
    
    total_requests = len(latencies)
    rps = total_requests / duration
    
    if latencies:
        latencies.sort()
        p90 = latencies[int(len(latencies) * 0.90)] * 1000  # ms
        p95 = latencies[int(len(latencies) * 0.95)] * 1000
        p99 = latencies[int(len(latencies) * 0.99)] * 1000
        avg_lat = (sum(latencies) / len(latencies)) * 1000
    else:
        p90 = p95 = p99 = avg_lat = 0.0

    print(f"RPS: {rps:.2f} | Latency p95: {p95:.2f}ms | CPU: {avg_cpu:.1f}% | RAM: {max_mem:.1f}MB")
    return {
        "concurrency": concurrency,
        "rps": rps,
        "p90": p90,
        "p95": p95,
        "p99": p99,
        "avg_lat": avg_lat,
        "cpu": avg_cpu,
        "ram": max_mem
    }

def generate_html_report(results, engine_name, dataset_name, duration):
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "report", "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("performance_template.html")
    
    concurrencies = [r["concurrency"] for r in results]
    rps_data = [round(r["rps"], 2) for r in results]
    latency_data = [round(r["p95"], 2) for r in results]
    
    context = {
        "engine_name": "CNN-BiLSTM API" if args.target == 'ai' else "ModSecurity WAF",
        "dataset_name": dataset_name,
        "generated_at": time.strftime('%Y-%m-%d %H:%M:%S'),
        "duration_per_test": duration,
        "results": results,
        "concurrencies": concurrencies,
        "rps_data": rps_data,
        "latency_data": latency_data
    }
    
    rendered = template.render(**context)
    
    os.makedirs("benchmark/results", exist_ok=True)
    report_file = f"benchmark/results/system_performance_{args.target}_{int(time.time())}.html"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(rendered)
        
    print(f"\n✅ Professional HTML Report saved to {report_file}")

async def main():
    global PAYLOADS
    print(f"Loading dataset: {args.dataset}")
    PAYLOADS = load_payloads(args.dataset)
    print(f"Loaded {len(PAYLOADS)} payloads.")
    
    server_process = None
    pids = []
    
    if args.target == 'ai' and args.start_server:
        print("Starting API Server as a subprocess...")
        python_exe = sys.executable
        server_process = subprocess.Popen([python_exe, "benchmark/waf_vs_ai/api_server.py"])
        pids.append(server_process.pid)
        print("Waiting for server to output ready signal...")
        
        for _ in range(30):
            if is_port_open(8000):
                break
            await asyncio.sleep(1)
        else:
            print("Server failed to start in time.")
            if server_process: server_process.terminate()
            return
            
        print("API Server started successfully.")
        await asyncio.sleep(2)
    elif args.target == 'waf':
        # Try to find nginx process
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] == 'nginx':
                    pids.append(proc.info['pid'])
            except: pass
        if not pids:
            print(f"Warning: Could not find nginx running. CPU/RAM metrics for WAF will be 0.")
    else:
        # Find running ai server
        for proc in psutil.process_iter(['pid', 'cmdline']):
            try:
                if proc.info['cmdline'] and 'api_server.py' in ' '.join(proc.info['cmdline']):
                    pids.append(proc.info['pid'])
            except: pass
    
    results = []
    for c in args.concurrencies:
        res = await run_phase(c, args.duration, pids)
        results.append(res)
        
    dataset_name = os.path.basename(args.dataset)
    generate_html_report(results, args.target, dataset_name, args.duration)
    
    if server_process:
        print("Stopping API Server...")
        server_process.terminate()
        server_process.wait()

if __name__ == "__main__":
    asyncio.run(main())

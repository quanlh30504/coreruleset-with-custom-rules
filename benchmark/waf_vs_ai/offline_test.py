#!/usr/bin/env python3
import os
import sys
import time
import pickle
import numpy as np
from datetime import datetime

# Enable relative imports to benchmark module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import custom layer so the model can load it
sys.path.insert(0, os.path.abspath("AI-train/CNN-BiLSTM"))
# Suppress TF logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

from AttentionLayer import AttentionLayer
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

from core.dataset_reader import DatasetReader
from core.models import TestResult, TestSession
from core.metrics_calculator import MetricsCalculator
from report.report_generator import ReportGenerator

# Define Dummy Config for ReportGenerator
class DummyPerformance:
    max_workers = 1
    delay_ms = 0
class DummyTarget:
    url = "Offline CNN-BiLSTM-Attention"
    method = "Internal Predict"
class DummyDatasetConfig:
    name = "Mereani"
    filepath = ""
class DummyOutput:
    report_dir = "benchmark/results"
    export_csv = False
    export_false_negatives = False
    top_fn_count = 100
class DummyAIBench:
    datasets = {}
    model_name = "CNN-BiLSTM"
class DummyConfig:
    performance = DummyPerformance()
    target = DummyTarget()
    dataset = DummyDatasetConfig()
    output = DummyOutput()
    ai_benchmark = DummyAIBench()
    report = type('ReportConfig', (), {'open_browser': False, 'waf_name': 'WAF', 'ai_name': 'CNN-BiLSTM (This Run)'})()


def classify_result(label: int, is_blocked: bool) -> str:
    if label == 1 and is_blocked:
        return "TP"
    elif label == 1 and not is_blocked:
        return "FN"
    elif label == 0 and is_blocked:
        return "FP"
    elif label == 0 and not is_blocked:
        return "TN"
    return "ERR"

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Offline evaluation of CNN-BiLSTM WAF Model")
    parser.add_argument("--dataset", required=True, help="Path to CSV dataset")
    parser.add_argument("--name", default="Offline-Test", help="Dataset name")
    parser.add_argument("--batch-size", type=int, default=512, help="Prediction batch size")
    args = parser.parse_args()

    print(f"Loading dataset: {args.dataset}")
    reader = DatasetReader()
    payloads = reader.read(args.dataset, "utf-8")
    
    total = len(payloads)
    malicious = sum(1 for p in payloads if p.label == 1)
    benign = total - malicious

    print(f"Total: {total} (Malicious: {malicious}, Benign: {benign})")
    
    # Load Model Assets
    print("Loading tokenizer and model...")
    with open("AI-train/CNN-BiLSTM/waf_tokenizer.pkl", "rb") as f:
        tokenizer = pickle.load(f)
        
    model = load_model("AI-train/CNN-BiLSTM/waf_cnn_bilstm_attn.keras", custom_objects={'AttentionLayer': AttentionLayer})
    max_len = model.input_shape[1] # Should be 200
    print(f"Model loaded. Max sequence length: {max_len}")

    # Prepare data
    print("Converting texts to sequences...")
    texts = [p.payload for p in payloads]
    seqs = tokenizer.texts_to_sequences(texts)
    
    print("Padding sequences...")
    padded = pad_sequences(seqs, maxlen=max_len, padding='post', truncating='post')

    print(f"Running predictions with batch size {args.batch_size}...")
    start_time = time.time()
    start_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    preds_prob = model.predict(padded, batch_size=args.batch_size)
    
    end_time = time.time()
    end_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = end_time - start_time
    print(f"Prediction complete in {duration:.2f}s")
    
    # Evaluate
    results = []
    for i, prob in enumerate(preds_prob):
        record = payloads[i]
        score = float(prob[0])
        is_blocked = score > 0.5
        status_code = 403 if is_blocked else 200
        classification = classify_result(record.label, is_blocked)
        
        tr = TestResult(
            index=record.index,
            payload=record.payload,
            label=record.label,
            status_code=status_code,
            classification=classification
        )
        results.append(tr)

    metrics = MetricsCalculator.calculate(results)
    print("-" * 40)
    print("RESULTS:")
    print(f"  Accuracy:  {metrics.accuracy * 100:.2f}%")
    print(f"  Precision: {metrics.precision * 100:.2f}%")
    print(f"  Recall:    {metrics.recall * 100:.2f}%")
    print(f"  F1-Score:  {metrics.f1_score * 100:.2f}%")
    print(f"  FPR:       {metrics.fpr * 100:.2f}%")
    print("-" * 40)

    # Generate Report
    config = DummyConfig()
    config.dataset.name = args.name
    config.dataset.filepath = args.dataset
    
    session = TestSession(
        dataset_name=args.name,
        dataset_filepath=args.dataset,
        target_url="Offline CNN-BiLSTM WAF Model",
        http_method="Python Predict API",
        total_payloads=total,
        total_malicious=malicious,
        total_benign=benign,
        start_time=start_dt,
        end_time=end_dt,
        duration_seconds=duration,
    )
    
    report_gen = ReportGenerator(config)
    report_path = report_gen.generate(results, metrics, session)
    print(f"✅ HTML Report saved: {report_path}")

if __name__ == "__main__":
    main()

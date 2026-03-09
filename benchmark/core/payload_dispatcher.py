"""
Async payload dispatcher for the WAF Auto-Test Runner.

Sends HTTP requests concurrently using aiohttp with rate limiting,
retry logic, and timeout handling.
"""

import asyncio
import logging
import signal
import sys
from typing import List
from urllib.parse import quote

import aiohttp
from tqdm import tqdm

from .config_loader import AppConfig
from .models import PayloadRecord, TestResult
from .response_evaluator import ResponseEvaluator

logger = logging.getLogger(__name__)


class PayloadDispatcher:
    """
    Dispatches payloads to the target WAF asynchronously.

    Features:
        - Configurable concurrency via semaphore
        - Per-request timeout and connect timeout
        - Retry with exponential backoff for transient errors
        - Graceful shutdown on SIGINT (saves partial results)
        - Real-time progress bar with ETA
    """

    def __init__(self, config: AppConfig):
        self.config = config
        self._shutdown_requested = False
        self._partial_results: List[TestResult] = []

    async def dispatch_all(
        self, payloads: List[PayloadRecord]
    ) -> List[TestResult]:
        """
        Send all payloads to the target WAF concurrently.

        Args:
            payloads: List of PayloadRecord to test.

        Returns:
            List of TestResult with classifications.
        """
        perf = self.config.performance
        target = self.config.target

        semaphore = asyncio.Semaphore(perf.max_workers)
        connector = aiohttp.TCPConnector(
            limit=perf.max_connections,
            limit_per_host=perf.max_connections,
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(
            total=perf.request_timeout,
            connect=perf.connect_timeout,
        )

        # Register signal handler for graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._handle_shutdown)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass

        results: List[TestResult] = []
        total = len(payloads)

        logger.info(
            "Starting dispatch: %d payloads → %s (%s) | workers=%d",
            total, target.url, target.method, perf.max_workers,
        )

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout
        ) as session:
            pbar = tqdm(
                total=total,
                desc="Testing payloads",
                unit="req",
                ncols=100,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
            )

            # Create tasks in batches to avoid excessive memory usage
            tasks = []
            for record in payloads:
                task = asyncio.ensure_future(
                    self._send_one(session, semaphore, record)
                )
                tasks.append(task)

            for future in asyncio.as_completed(tasks):
                if self._shutdown_requested:
                    logger.warning(
                        "Shutdown requested. Saving %d/%d results...",
                        len(results), total,
                    )
                    # Cancel remaining tasks
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    break

                try:
                    result = await future
                    results.append(result)
                    self._partial_results = results
                    pbar.update(1)
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.error("Unexpected error in dispatcher: %s", e)
                    pbar.update(1)

            pbar.close()

        # Sort results by original index for consistent output
        results.sort(key=lambda r: r.index)

        logger.info(
            "Dispatch complete: %d/%d payloads processed", len(results), total
        )
        return results

    async def _send_one(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        record: PayloadRecord,
    ) -> TestResult:
        """
        Send a single payload with retry logic.

        Args:
            session: aiohttp client session.
            semaphore: Concurrency limiter.
            record: The payload to send.

        Returns:
            TestResult with classification.
        """
        perf = self.config.performance
        target = self.config.target
        max_retries = perf.max_retries
        status_code = -1

        async with semaphore:
            for attempt in range(max_retries + 1):
                try:
                    status_code = await self._do_request(
                        session, target.url, target.method,
                        target.param_name, record.payload,
                    )

                    # If rate-limited or server unavailable, backoff and retry
                    if status_code in (429, 503) and attempt < max_retries:
                        backoff = 2 ** attempt
                        logger.debug(
                            "HTTP %d for payload #%d, retrying in %ds...",
                            status_code, record.index, backoff,
                        )
                        await asyncio.sleep(backoff)
                        continue

                    break  # Success or non-retryable status

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < max_retries:
                        backoff = 2 ** attempt
                        logger.debug(
                            "Error for payload #%d (%s), retry %d/%d in %ds",
                            record.index, type(e).__name__,
                            attempt + 1, max_retries, backoff,
                        )
                        await asyncio.sleep(backoff)
                    else:
                        logger.warning(
                            "Failed payload #%d after %d retries: %s",
                            record.index, max_retries, e,
                        )
                        status_code = -1

            # Apply inter-request delay if configured
            if perf.delay_ms > 0:
                await asyncio.sleep(perf.delay_ms / 1000.0)

        classification = ResponseEvaluator.classify(record.label, status_code)
        return TestResult(
            index=record.index,
            payload=record.payload,
            label=record.label,
            status_code=status_code,
            classification=classification,
        )

    @staticmethod
    async def _do_request(
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param_name: str,
        payload: str,
    ) -> int:
        """Execute a single HTTP request and return the status code."""
        if method == "GET":
            encoded_payload = quote(payload, safe="")
            full_url = f"{url}?{param_name}={encoded_payload}"
            async with session.get(full_url) as resp:
                return resp.status
        else:
            async with session.post(
                url, data={param_name: payload}
            ) as resp:
                return resp.status

    def _handle_shutdown(self):
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        if not self._shutdown_requested:
            self._shutdown_requested = True
            logger.info("Shutdown signal received. Finishing current requests...")
            print(
                "\n⚠ Shutdown requested. Saving partial results...",
                file=sys.stderr,
            )

    @property
    def partial_results(self) -> List[TestResult]:
        """Return partial results collected before shutdown."""
        return list(self._partial_results)

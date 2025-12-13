r"""
Locust Load Testing for PCAP Analyzer Web API

Tests concurrent upload and analysis workloads to validate:
- Queue handling (max 5 concurrent)
- Timeout behavior (30 min)
- Resource limits (memory/CPU)
- Load shedding (if enabled)

Usage:
    # Web UI (interactive)
    locust -f scripts/locustfile.py --host=http://localhost:8000

    # Headless (10 users, 2 users/sec spawn, 5min)
    locust -f scripts/locustfile.py \\
        --host=http://localhost:8000 \\
        --users 10 \\
        --spawn-rate 2 \\
        --run-time 5m \\
        --headless

    # Stress test (queue saturation)
    locust -f scripts/locustfile.py \\
        --host=http://localhost:8000 \\
        --users 20 \\
        --spawn-rate 5 \\
        --run-time 10m \\
        --headless

Environment Variables:
    PCAP_FILE: Path to test PCAP file (default: tests/data/sample.pcap)
    MAX_WAIT_TIME: Max wait time for analysis (default: 600s)
"""

import os
import time
from pathlib import Path

from locust import HttpUser, between, events, task


class PCAPAnalyzerUser(HttpUser):
    """
    Simulated user for PCAP Analyzer load testing.

    Behavior:
    1. Upload PCAP file
    2. Poll status until completed
    3. Download report (HTML)
    4. Wait 5-15 seconds
    5. Repeat
    """

    wait_time = between(5, 15)  # Wait 5-15s between tasks

    def on_start(self):
        """Initialize test data on user start."""
        # PCAP file to use for testing
        self.pcap_file = os.getenv("PCAP_FILE", "tests/data/sample.pcap")

        # Validate file exists
        if not Path(self.pcap_file).exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")

        # Max wait time for analysis (default 10 minutes)
        self.max_wait_time = int(os.getenv("MAX_WAIT_TIME", "600"))

        print(f"[User {self.environment.runner.user_count}] Started with PCAP: {self.pcap_file}")

    @task(10)
    def upload_and_analyze(self):
        """
        Main task: Upload PCAP, wait for completion, download report.

        Weight: 10 (main workload)
        """
        # Upload PCAP
        with self.client.post(
            "/upload",
            files={"file": ("test.pcap", open(self.pcap_file, "rb"), "application/vnd.tcpdump.pcap")},
            catch_response=True,
        ) as response:
            if response.status_code == 503:
                # Queue full - expected behavior
                response.success()
                print("[INFO] Queue full (503) - expected under load")
                return
            elif response.status_code != 200:
                response.failure(f"Upload failed: {response.status_code}")
                return

            try:
                task_id = response.json()["task_id"]
                queue_position = response.json().get("queue_position", 0)
                print(f"[INFO] Upload successful - Task ID: {task_id}, Queue position: {queue_position}")
                response.success()
            except Exception as e:
                response.failure(f"Invalid JSON response: {e}")
                return

        # Poll status until completed
        poll_start = time.time()
        poll_interval = 2  # Poll every 2 seconds

        while time.time() - poll_start < self.max_wait_time:
            with self.client.get(f"/status/{task_id}", name="/status/[task_id]", catch_response=True) as status_resp:
                if status_resp.status_code != 200:
                    status_resp.failure(f"Status check failed: {status_resp.status_code}")
                    return

                try:
                    status_data = status_resp.json()
                    status = status_data["status"]
                except Exception as e:
                    status_resp.failure(f"Invalid status JSON: {e}")
                    return

                if status == "completed":
                    # Analysis completed successfully
                    elapsed = time.time() - poll_start
                    print(f"[INFO] Analysis completed in {elapsed:.1f}s - Task ID: {task_id}")
                    status_resp.success()

                    # Download report (HTML)
                    with self.client.get(
                        f"/report/{task_id}", name="/report/[task_id]", catch_response=True
                    ) as report_resp:
                        if report_resp.status_code == 200:
                            report_size = len(report_resp.content)
                            print(f"[INFO] Report downloaded ({report_size} bytes) - Task ID: {task_id}")
                            report_resp.success()
                        else:
                            report_resp.failure(f"Report download failed: {report_resp.status_code}")

                    return

                elif status == "failed":
                    # Analysis failed
                    error = status_data.get("error", "Unknown error")
                    print(f"[ERROR] Analysis failed: {error} - Task ID: {task_id}")
                    status_resp.failure(f"Analysis failed: {error}")
                    return

                elif status in ["pending", "processing"]:
                    # Still running
                    status_resp.success()
                    time.sleep(poll_interval)

                elif status == "timeout":
                    # Analysis timeout (30 min)
                    print(f"[ERROR] Analysis timeout - Task ID: {task_id}")
                    status_resp.failure("Analysis timeout")
                    return

                else:
                    # Unknown status
                    status_resp.failure(f"Unknown status: {status}")
                    return

        # Timeout waiting for completion
        elapsed = time.time() - poll_start
        print(f"[ERROR] Timeout waiting for analysis ({elapsed:.1f}s) - Task ID: {task_id}")

    @task(1)
    def health_check(self):
        """
        Health check endpoint.

        Weight: 1 (occasional check)
        """
        with self.client.get("/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 503:
                # Service degraded - still acceptable
                response.success()
                print("[WARN] Service degraded (503)")
            else:
                response.failure(f"Health check failed: {response.status_code}")


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Print test configuration on start."""
    print("=" * 60)
    print("LOAD TEST STARTED")
    print("=" * 60)
    print(f"Host: {environment.host}")
    print(f"Users: {environment.runner.user_count if hasattr(environment.runner, 'user_count') else 'N/A'}")
    print(f"Spawn Rate: {environment.runner.spawn_rate if hasattr(environment.runner, 'spawn_rate') else 'N/A'}")
    print(f"PCAP File: {os.getenv('PCAP_FILE', 'tests/data/sample.pcap')}")
    print(f"Max Wait Time: {os.getenv('MAX_WAIT_TIME', '600')}s")
    print("=" * 60)
    print()


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Print test results on stop."""
    print()
    print("=" * 60)
    print("LOAD TEST RESULTS")
    print("=" * 60)

    # Overall stats
    stats = environment.stats.total
    print(f"Total Requests:          {stats.num_requests:,}")
    print(f"Total Failures:          {stats.num_failures:,}")
    print(f"Failure Rate:            {stats.fail_ratio*100:.1f}%")
    print(f"Average Response Time:   {stats.avg_response_time:.0f}ms")
    print(f"Median Response Time:    {stats.median_response_time:.0f}ms")
    print(f"95th Percentile:         {stats.get_response_time_percentile(0.95):.0f}ms")
    print(f"99th Percentile:         {stats.get_response_time_percentile(0.99):.0f}ms")
    print(f"Max Response Time:       {stats.max_response_time:.0f}ms")
    print(f"Requests/sec:            {stats.current_rps:.2f}")
    print()

    # Per-endpoint stats
    print("Endpoint Breakdown:")
    print(f"{'Endpoint':<30} {'Requests':>10} {'Failures':>10} {'Avg (ms)':>10} {'95% (ms)':>10}")
    print("-" * 80)

    for endpoint, endpoint_stats in environment.stats.entries.items():
        if isinstance(endpoint, tuple):
            method, name = endpoint
            endpoint_name = f"{method} {name}"
        else:
            endpoint_name = str(endpoint)

        print(
            f"{endpoint_name:<30} "
            f"{endpoint_stats.num_requests:>10,} "
            f"{endpoint_stats.num_failures:>10,} "
            f"{endpoint_stats.avg_response_time:>10.0f} "
            f"{endpoint_stats.get_response_time_percentile(0.95):>10.0f}"
        )

    print()

    # Validation
    print("=" * 60)
    print("VALIDATION")
    print("=" * 60)

    passed = True
    issues = []

    # Check 1: Failure rate <10%
    if stats.fail_ratio > 0.10:
        passed = False
        issues.append(f"High failure rate: {stats.fail_ratio*100:.1f}% (expected <10%)")
    else:
        print(f"✅ Failure rate acceptable (<10%): {stats.fail_ratio*100:.1f}%")

    # Check 2: Average response time reasonable
    if stats.avg_response_time > 60000:  # 60 seconds
        passed = False
        issues.append(f"High average response time: {stats.avg_response_time:.0f}ms (expected <60s)")
    else:
        print(f"✅ Average response time acceptable: {stats.avg_response_time:.0f}ms")

    # Check 3: 95th percentile reasonable
    p95 = stats.get_response_time_percentile(0.95)
    if p95 > 120000:  # 120 seconds
        passed = False
        issues.append(f"High 95th percentile: {p95:.0f}ms (expected <120s)")
    else:
        print(f"✅ 95th percentile acceptable: {p95:.0f}ms")

    print()

    if passed:
        print("Status: ✅ PASS")
    else:
        print("Status: ❌ FAIL")
        print()
        print("Issues:")
        for issue in issues:
            print(f"  - {issue}")

    print("=" * 60)

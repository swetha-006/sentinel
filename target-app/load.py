from __future__ import annotations
import argparse
import concurrent.futures
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

def request(url: str) -> tuple[int, float]:
    start = time.perf_counter()
    try:
        with urlopen(Request(url, headers={"User-Agent":"sentinel-demo-load/1.0"}), timeout=5) as response:
            response.read()
            return response.status, time.perf_counter() - start
    except (HTTPError, URLError, TimeoutError):
        return 0, time.perf_counter() - start

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080/health")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    args = parser.parse_args()
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(request, [args.url] * args.requests))
    durations = sorted(d for _, d in results)
    errors = sum(status < 200 or status >= 400 for status, _ in results)
    p95 = durations[min(len(durations)-1, int(len(durations)*0.95))] if durations else 0.0
    print(json.dumps({"requests":len(results),"error_rate":errors/len(results) if results else 1.0,"p95_latency_seconds":p95,"elapsed_seconds":time.perf_counter()-start},sort_keys=True))

if __name__ == "__main__":
    main()

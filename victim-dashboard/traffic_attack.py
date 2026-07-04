import argparse
import random
import threading
import time
import urllib.error
import urllib.request


STOP_EVENT = threading.Event()


def worker_thread(base_url: str, endpoints: list[str], min_delay: float, max_delay: float, stats: dict, lock: threading.Lock) -> None:
    while not STOP_EVENT.is_set():
        endpoint = random.choice(endpoints)
        url = f"{base_url}{endpoint}"
        ok = False

        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "victim-dashboard-loadgen/1.0",
                    "Connection": "close",
                },
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                ok = 200 <= resp.status < 500
        except (urllib.error.URLError, TimeoutError, OSError):
            ok = False

        with lock:
            stats["sent"] += 1
            if ok:
                stats["ok"] += 1
            else:
                stats["err"] += 1

        sleep_for = random.uniform(min_delay, max_delay)
        if sleep_for > 0:
            time.sleep(sleep_for)


def reporter_thread(start_ts: float, stats: dict, lock: threading.Lock) -> None:
    last_sent = 0
    while not STOP_EVENT.is_set():
        time.sleep(1)
        with lock:
            sent = stats["sent"]
            ok = stats["ok"]
            err = stats["err"]

        delta = sent - last_sent
        last_sent = sent
        elapsed = time.time() - start_ts
        print(f"[ATTACK] elapsed={elapsed:.0f}s sent={sent} ok={ok} err={err} rps~{delta}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab-only traffic generator for victim-dashboard server.")
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--duration", type=int, default=60, help="Seconds to run. Use 0 for infinite.")
    parser.add_argument("--min-delay", type=float, default=0.0)
    parser.add_argument("--max-delay", type=float, default=0.02)
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    endpoints = ["/", "/api/ping", "/api/data"]

    if args.workers < 1:
        raise ValueError("--workers must be >= 1")
    if args.min_delay < 0 or args.max_delay < 0 or args.max_delay < args.min_delay:
        raise ValueError("Invalid delay bounds")

    print(f"[ATTACK] target={base_url} workers={args.workers} duration={args.duration}s")
    print(f"[ATTACK] endpoints={endpoints}")

    stats = {"sent": 0, "ok": 0, "err": 0}
    lock = threading.Lock()
    start_ts = time.time()

    reporter = threading.Thread(target=reporter_thread, args=(start_ts, stats, lock), daemon=True)
    reporter.start()

    workers = []
    for _ in range(args.workers):
        t = threading.Thread(
            target=worker_thread,
            args=(base_url, endpoints, args.min_delay, args.max_delay, stats, lock),
            daemon=True,
        )
        t.start()
        workers.append(t)

    try:
        if args.duration <= 0:
            while True:
                time.sleep(1)
        else:
            time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        STOP_EVENT.set()
        for t in workers:
            t.join(timeout=1.0)

        with lock:
            sent = stats["sent"]
            ok = stats["ok"]
            err = stats["err"]
        elapsed = max(1e-6, time.time() - start_ts)
        print(
            f"[ATTACK] done elapsed={elapsed:.1f}s sent={sent} ok={ok} err={err} avg_rps={sent/elapsed:.2f}"
        )


if __name__ == "__main__":
    main()

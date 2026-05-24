#!/usr/bin/env python3

import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description=(
            "Measure BCF discovery API latency and append the result to a CSV file."
        )
    )
    parser.add_argument(
        "--bcf-base",
        default="http://127.0.0.1:8004",
        help="BCF base URL. Default: %(default)s",
    )
    parser.add_argument(
        "--target-nf-type",
        default="AUSF",
        help="Target NF type for discovery. Default: %(default)s",
    )
    parser.add_argument(
        "--csv",
        default=str(script_dir / "amf_bcf_registration_timings.csv"),
        help="CSV output path. Default: %(default)s",
    )
    parser.add_argument(
        "--event-name",
        default="BCF_Discovery_API",
        help="CSV Event_Name value. Default: %(default)s",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds. Default: %(default)s",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of measurement runs. Default: %(default)s",
    )
    parser.add_argument(
        "--require-nonempty",
        action="store_true",
        help="Treat an empty nfInstances array as failure.",
    )
    parser.add_argument(
        "--print-response",
        action="store_true",
        help="Print the discovery JSON response body.",
    )
    return parser.parse_args()


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def append_csv(csv_path: Path, timestamp: datetime, event_name: str, duration_ms: float) -> None:
    ensure_parent_dir(csv_path)
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0

    with csv_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(["Timestamp", "Event_Name", "Duration_ms"])
        writer.writerow([timestamp.isoformat(), event_name, f"{duration_ms:.3f}"])


def build_discovery_url(base: str, target_nf_type: str) -> str:
    query = urllib.parse.urlencode({"target-nf-type": target_nf_type})
    return f"{base.rstrip('/')}/nbcf_discovery/v1/nf_instances?{query}"


def run_one_measurement(args: argparse.Namespace, run_index: int) -> Dict[str, Any]:
    url = build_discovery_url(args.bcf_base, args.target_nf_type)

    start_perf = time.perf_counter()
    request = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            response_code = response.getcode()
            response_body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        response_code = exc.code
        response_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Run {run_index}: discovery request failed with HTTP {response_code}: {response_body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Run {run_index}: discovery request failed: {exc}"
        ) from exc

    end_perf = time.perf_counter()
    end_ts = datetime.now().astimezone()
    duration_ms = (end_perf - start_perf) * 1000.0

    if response_code != 200:
        raise RuntimeError(
            f"Run {run_index}: discovery request returned HTTP {response_code}: {response_body}"
        )

    try:
        response_json = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Run {run_index}: discovery response is not valid JSON: {response_body}"
        ) from exc

    nf_instances: List[Any] = response_json.get("nfInstances", [])
    if not isinstance(nf_instances, list):
        raise RuntimeError(
            f"Run {run_index}: discovery response missing nfInstances array: {response_body}"
        )

    if args.require_nonempty and len(nf_instances) == 0:
        raise RuntimeError(
            f"Run {run_index}: discovery response is empty for target NF type {args.target_nf_type}"
        )

    return {
        "timestamp": end_ts,
        "duration_ms": duration_ms,
        "response_json": response_json,
        "count": len(nf_instances),
        "url": url,
    }


def main() -> int:
    args = parse_args()
    csv_path = Path(args.csv).resolve()

    if args.runs < 1:
        print("--runs must be >= 1", file=sys.stderr)
        return 2

    for run_index in range(1, args.runs + 1):
        if args.runs > 1:
            print(f"[Run {run_index}/{args.runs}] starting discovery measurement...")

        result = run_one_measurement(args, run_index)
        append_csv(csv_path, result["timestamp"], args.event_name, result["duration_ms"])

        print(
            f"[Run {run_index}/{args.runs}] "
            f"{args.event_name}={result['duration_ms']:.3f} ms "
            f"(target={args.target_nf_type}, count={result['count']}) "
            f"written to {csv_path}"
        )

        if args.print_response:
            print(json.dumps(result["response_json"], ensure_ascii=False, indent=2))

        if run_index != args.runs:
            time.sleep(1.0)

    return 0


if __name__ == "__main__":
    sys.exit(main())

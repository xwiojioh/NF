#!/usr/bin/env python3

import argparse
import csv
import hashlib
import json
import secrets
import select
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

REG_SUCCESS_MARKER = "[AMF][BCF-REG] Registration SUCCESS"
REG_FAILURE_MARKER = "[AMF][BCF-REG] Registration FAILED"
TOKEN_READY_MARKER = "[AMF][TOKEN] State"
TOKEN_READY_STATE = "TOKEN_READY"

EVENT_NAME = "AMF_BCF_Discovery_E2E"


Point = Optional[Tuple[int, int]]


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    amf_dir = script_dir.parent

    parser = argparse.ArgumentParser(
        description=(
            "Measure strict AMF->BCF service discovery E2E latency. "
            "The script starts the real AMF, waits for AMF BCF registration/auth, "
            "obtains a BCF-issued token using the AMF DID/private key, then sends "
            "an authenticated discovery request and requires non-empty results."
        )
    )
    parser.add_argument(
        "--amf-dir",
        default=str(amf_dir),
        help="AMF working directory. Default: %(default)s",
    )
    parser.add_argument(
        "--amf-cmd",
        default="./build-local/amf -c ./etc/config.local.yaml -o",
        help="Command used to start AMF. Default: %(default)s",
    )
    parser.add_argument(
        "--no-start-amf",
        action="store_true",
        help="Do not launch AMF; assume AMF has already registered to BCF.",
    )
    parser.add_argument(
        "--keep-amf-running",
        action="store_true",
        help="Do not stop the AMF process after the measurement.",
    )
    parser.add_argument(
        "--profile",
        default="/tmp/oai/extended_amf_profile.json",
        help="AMF extended profile containing did/nfInstanceId/privateKey. Default: %(default)s",
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
        default=EVENT_NAME,
        help="CSV Event_Name value. Default: %(default)s",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of measured discovery runs. Default: %(default)s",
    )
    parser.add_argument(
        "--warmups",
        type=int,
        default=0,
        help="Warm-up discovery runs that are not written to CSV. Default: %(default)s",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Sleep interval between discovery runs in seconds. Default: %(default)s",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="Timeout in seconds for AMF startup and BCF readiness waits. Default: %(default)s",
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds for BCF API calls. Default: %(default)s",
    )
    parser.add_argument(
        "--token-file",
        default="",
        help="Use an existing Bearer token from this file instead of performing BCF auth.",
    )
    parser.add_argument(
        "--auth-per-run",
        action="store_true",
        help="Request a fresh BCF token before every measured discovery run.",
    )
    parser.add_argument(
        "--expect-strict-auth",
        action="store_true",
        help="Require unauthenticated discovery to return HTTP 401 before running measurements.",
    )
    parser.add_argument(
        "--print-response",
        action="store_true",
        help="Print each discovery JSON response body.",
    )
    parser.add_argument(
        "--print-live-log",
        action="store_true",
        help="Print AMF output while waiting for registration/auth readiness.",
    )
    return parser.parse_args()


def now_ms() -> int:
    return int(time.time() * 1000)


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


def load_amf_profile(path: Path) -> Dict[str, str]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    did = str(data.get("did", "")).strip()
    nf_instance_id = str(data.get("nfInstanceId", data.get("nf_instance_id", ""))).strip()
    private_key = str(data.get("privateKey", data.get("private_key", ""))).strip()

    if not did:
        raise RuntimeError(f"AMF profile missing did: {path}")
    if not nf_instance_id:
        raise RuntimeError(f"AMF profile missing nfInstanceId: {path}")
    if not private_key:
        raise RuntimeError(f"AMF profile missing privateKey/private_key: {path}")

    if private_key.startswith(("0x", "0X")):
        private_key = private_key[2:]
    if len(private_key) != 64:
        raise RuntimeError(f"AMF privateKey must be 32-byte hex, got length {len(private_key)}")
    int(private_key, 16)

    return {
        "did": did,
        "nf_instance_id": nf_instance_id,
        "private_key": private_key,
    }


def http_json(
    method: str,
    url: str,
    *,
    body: Optional[Dict[str, Any]] = None,
    token: str = "",
    timeout: float = 10.0,
) -> Tuple[int, str, Any]:
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.getcode()
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc}") from exc

    parsed: Any = None
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
    return status, raw, parsed


def build_discovery_url(base: str, target_nf_type: str) -> str:
    query = urllib.parse.urlencode({"target-nf-type": target_nf_type})
    return f"{base.rstrip('/')}/nbcf_discovery/v1/nf_instances?{query}"


def build_nf_by_did_url(base: str, did: str) -> str:
    query = urllib.parse.urlencode({"did": did})
    return f"{base.rstrip('/')}/nbcf_management/v1/nf_instances?{query}"


def wait_for_bcf_ready(base: str, timeout: float, http_timeout: float) -> None:
    deadline = time.monotonic() + timeout
    account_url = f"{base.rstrip('/')}/dper/currentAccount"
    probe_url = build_discovery_url(base, "AUSF")

    last_error = ""
    while time.monotonic() < deadline:
        try:
            probe_status, _, _ = http_json("GET", probe_url, timeout=http_timeout)
            account_status, account_raw, account_json = http_json(
                "GET", account_url, timeout=http_timeout
            )
            account_text = account_raw.strip()
            if isinstance(account_json, dict):
                account_text = json.dumps(account_json, ensure_ascii=False)

            zero_account = "0000000000000000000000000000000000000000" in account_text
            if probe_status in (200, 401) and account_status == 200 and not zero_account:
                return
            last_error = (
                f"probe_status={probe_status}, account_status={account_status}, "
                f"zero_account={zero_account}"
            )
        except Exception as exc:  # noqa: BLE001 - readiness loop should keep polling.
            last_error = str(exc)
        time.sleep(0.5)

    raise RuntimeError(f"BCF did not become ready before timeout: {last_error}")


def query_nf_visible(base: str, did: str, http_timeout: float) -> bool:
    status, raw, parsed = http_json("GET", build_nf_by_did_url(base, did), timeout=http_timeout)
    if status != 200:
        return False
    if isinstance(parsed, dict):
        data = parsed.get("data")
        return data not in (None, "", {}, [])
    return bool(raw.strip())


def wait_for_nf_visible(base: str, did: str, timeout: float, http_timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if query_nf_visible(base, did, http_timeout):
            return
        time.sleep(0.5)
    raise RuntimeError(f"AMF DID is not visible in BCF before timeout: {did}")


def wait_for_target_available(
    base: str,
    target_nf_type: str,
    timeout: float,
    http_timeout: float,
    token: str = "",
) -> None:
    deadline = time.monotonic() + timeout
    url = build_discovery_url(base, target_nf_type)
    last_error = ""

    while time.monotonic() < deadline:
        try:
            status, raw, parsed = http_json("GET", url, token=token, timeout=http_timeout)
            if status == 200 and isinstance(parsed, dict):
                instances = parsed.get("nfInstances", [])
                if isinstance(instances, list) and instances:
                    return
            last_error = f"HTTP {status}: {raw[:200]}"
        except Exception as exc:  # noqa: BLE001 - readiness loop should keep polling.
            last_error = str(exc)
        time.sleep(0.5)

    raise RuntimeError(
        f"No non-empty discovery result for target NF type {target_nf_type}: {last_error}"
    )


def terminate_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return

    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=10)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        proc.terminate()
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass

    proc.kill()
    proc.wait(timeout=5)


def drain_process_output(proc: subprocess.Popen, print_lines: bool) -> None:
    if proc.stdout is None:
        return

    def drain() -> None:
        try:
            for line in proc.stdout:
                if print_lines:
                    print(line.rstrip("\n"))
        except ValueError:
            return

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()


def start_amf_and_wait_ready(args: argparse.Namespace) -> subprocess.Popen:
    amf_dir = Path(args.amf_dir).resolve()
    if not amf_dir.exists():
        raise FileNotFoundError(f"AMF directory does not exist: {amf_dir}")

    proc = subprocess.Popen(
        args.amf_cmd,
        cwd=str(amf_dir),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    if proc.stdout is None:
        raise RuntimeError("Failed to capture AMF stdout")

    deadline = time.monotonic() + args.timeout
    saw_registration = False
    saw_token_ready = False
    last_lines: List[str] = []

    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break

        remaining = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([proc.stdout], [], [], min(0.25, remaining))
        if not ready:
            continue

        line = proc.stdout.readline()
        if not line:
            continue

        clean = line.rstrip("\n")
        last_lines.append(clean)
        if len(last_lines) > 20:
            last_lines.pop(0)

        if args.print_live_log:
            print(clean)

        if REG_FAILURE_MARKER in clean:
            raise RuntimeError(f"AMF registration failed: {clean}")
        if REG_SUCCESS_MARKER in clean:
            saw_registration = True
        if TOKEN_READY_MARKER in clean and TOKEN_READY_STATE in clean:
            saw_token_ready = True

        if saw_registration and saw_token_ready:
            drain_process_output(proc, args.print_live_log)
            return proc

    tail = "\n".join(last_lines[-10:])
    terminate_process(proc)
    raise RuntimeError(
        "AMF did not reach registration + BCF token ready before timeout. "
        f"saw_registration={saw_registration}, saw_token_ready={saw_token_ready}\n{tail}"
    )


def point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None

    if p1 == p2:
        numerator = (3 * x1 * x1) % SECP256K1_P
        denominator = pow(2 * y1, -1, SECP256K1_P)
    else:
        numerator = (y2 - y1) % SECP256K1_P
        denominator = pow((x2 - x1) % SECP256K1_P, -1, SECP256K1_P)

    slope = (numerator * denominator) % SECP256K1_P
    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def scalar_mult(k: int, point: Point) -> Point:
    result: Point = None
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + len(raw).to_bytes(1, "big") + raw


def der_signature(r: int, s: int) -> bytes:
    body = der_int(r) + der_int(s)
    return b"\x30" + len(body).to_bytes(1, "big") + body


def sign_challenge(private_key_hex: str, challenge_hex: str) -> str:
    private_key_int = int(private_key_hex, 16)
    if private_key_int <= 0 or private_key_int >= SECP256K1_N:
        raise RuntimeError("AMF private key is outside the secp256k1 order")

    challenge_bytes = bytes.fromhex(challenge_hex)
    digest = hashlib.sha256(challenge_bytes).digest()
    e = int.from_bytes(digest, "big")
    generator = (SECP256K1_GX, SECP256K1_GY)

    while True:
        k = secrets.randbelow(SECP256K1_N - 1) + 1
        point = scalar_mult(k, generator)
        if point is None:
            continue
        r = point[0] % SECP256K1_N
        if r == 0:
            continue
        s = (pow(k, -1, SECP256K1_N) * (e + r * private_key_int)) % SECP256K1_N
        if s == 0:
            continue
        return der_signature(r, s).hex()


def obtain_bcf_token(args: argparse.Namespace, profile: Dict[str, str]) -> str:
    if args.token_file:
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise RuntimeError(f"Token file is empty: {args.token_file}")
        return token

    base = args.bcf_base.rstrip("/")
    init_url = f"{base}/nbcf_auth/v1/auth/init"
    verify_url = f"{base}/nbcf_auth/v1/auth/verify"

    init_body = {
        "nf_did": profile["did"],
        "nf_type": "AMF",
        "nf_instance_id": profile["nf_instance_id"],
        "timestamp_ms": now_ms(),
    }
    init_status, init_raw, init_json = http_json(
        "POST", init_url, body=init_body, timeout=args.http_timeout
    )
    if init_status != 200 or not isinstance(init_json, dict):
        raise RuntimeError(f"BCF auth/init failed with HTTP {init_status}: {init_raw}")

    session_id = str(init_json.get("session_id", "")).strip()
    challenge = str(init_json.get("challenge", "")).strip()
    if not session_id or not challenge:
        raise RuntimeError(f"BCF auth/init response missing session_id/challenge: {init_raw}")

    signature = sign_challenge(profile["private_key"], challenge)
    verify_body = {
        "session_id": session_id,
        "nf_did": profile["did"],
        "nf_type": "AMF",
        "nf_instance_id": profile["nf_instance_id"],
        "challenge_signature": signature,
        "timestamp_ms": now_ms(),
    }
    verify_status, verify_raw, verify_json = http_json(
        "POST", verify_url, body=verify_body, timeout=args.http_timeout
    )
    if verify_status != 200 or not isinstance(verify_json, dict):
        raise RuntimeError(f"BCF auth/verify failed with HTTP {verify_status}: {verify_raw}")

    token = str(verify_json.get("access_token", verify_json.get("auth_token", ""))).strip()
    if not token:
        raise RuntimeError(f"BCF auth/verify response missing token: {verify_raw}")
    return token


def assert_strict_auth_enabled(args: argparse.Namespace) -> None:
    url = build_discovery_url(args.bcf_base, args.target_nf_type)
    status, raw, _ = http_json("GET", url, timeout=args.http_timeout)
    if status != 401:
        raise RuntimeError(
            "--expect-strict-auth was set, but unauthenticated discovery did not return "
            f"HTTP 401. Got HTTP {status}: {raw[:200]}"
        )


def select_nf_instance(instances: List[Any], target_nf_type: str) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    for item in instances:
        if not isinstance(item, dict):
            continue
        profile = item.get("nfProfile", item)
        if not isinstance(profile, dict):
            continue
        profile = dict(profile)
        if "did" not in profile and "did" in item:
            profile["did"] = item["did"]
        nf_type = str(profile.get("nfType", profile.get("nf_type", ""))).upper()
        nf_status = str(profile.get("nfStatus", profile.get("nf_status", "REGISTERED"))).upper()
        if nf_type == target_nf_type.upper() and nf_status == "REGISTERED":
            candidates.append(profile)

    if not candidates:
        raise RuntimeError(
            f"Discovery response has no REGISTERED {target_nf_type} instance"
        )

    def candidate_key(item: Dict[str, Any]) -> Tuple[int, int, str]:
        priority = int(item.get("priority", 9999) or 9999)
        load = int(item.get("load", 100) or 100)
        nf_instance_id = str(item.get("nfInstanceId", item.get("nf_instance_id", "")))
        return priority, load, nf_instance_id

    return sorted(candidates, key=candidate_key)[0]


def run_discovery_once(
    args: argparse.Namespace,
    token: str,
    run_label: str,
) -> Dict[str, Any]:
    url = build_discovery_url(args.bcf_base, args.target_nf_type)

    start_perf = time.perf_counter()
    status, raw, parsed = http_json("GET", url, token=token, timeout=args.http_timeout)
    end_perf = time.perf_counter()
    end_ts = datetime.now().astimezone()

    duration_ms = (end_perf - start_perf) * 1000.0
    if status != 200 or not isinstance(parsed, dict):
        raise RuntimeError(f"{run_label}: discovery failed with HTTP {status}: {raw}")

    instances = parsed.get("nfInstances", [])
    if not isinstance(instances, list):
        raise RuntimeError(f"{run_label}: discovery response missing nfInstances array: {raw}")
    if not instances:
        raise RuntimeError(
            f"{run_label}: discovery response is empty for target NF type {args.target_nf_type}"
        )

    selected = select_nf_instance(instances, args.target_nf_type)
    selected_id = str(selected.get("nfInstanceId", selected.get("nf_instance_id", "")))

    return {
        "timestamp": end_ts,
        "duration_ms": duration_ms,
        "response_json": parsed,
        "count": len(instances),
        "selected_id": selected_id,
        "url": url,
    }


def main() -> int:
    args = parse_args()
    csv_path = Path(args.csv).resolve()

    if args.runs < 1:
        print("--runs must be >= 1", file=sys.stderr)
        return 2
    if args.warmups < 0:
        print("--warmups must be >= 0", file=sys.stderr)
        return 2
    if args.keep_amf_running and args.no_start_amf:
        print("--keep-amf-running has no effect with --no-start-amf", file=sys.stderr)

    profile = load_amf_profile(Path(args.profile).resolve())
    proc: Optional[subprocess.Popen] = None

    try:
        print("[Precheck] waiting for BCF ready...")
        wait_for_bcf_ready(args.bcf_base, args.timeout, args.http_timeout)

        if args.expect_strict_auth:
            print("[Precheck] checking strict token enforcement...")
            assert_strict_auth_enabled(args)

        if not args.no_start_amf:
            print("[AMF] starting AMF and waiting for BCF registration/auth readiness...")
            proc = start_amf_and_wait_ready(args)

        print("[Precheck] waiting for AMF DID visibility in BCF...")
        wait_for_nf_visible(args.bcf_base, profile["did"], args.timeout, args.http_timeout)

        print("[Auth] obtaining BCF Bearer token for AMF DID...")
        token = obtain_bcf_token(args, profile)

        print(f"[Precheck] waiting for non-empty {args.target_nf_type} discovery result...")
        wait_for_target_available(
            args.bcf_base,
            args.target_nf_type,
            args.timeout,
            args.http_timeout,
            token=token,
        )

        total_runs = args.warmups + args.runs
        measured_index = 0

        for overall_index in range(1, total_runs + 1):
            is_warmup = overall_index <= args.warmups
            run_label = (
                f"Warmup {overall_index}/{args.warmups}"
                if is_warmup
                else f"Run {measured_index + 1}/{args.runs}"
            )

            if args.auth_per_run and not is_warmup:
                token = obtain_bcf_token(args, profile)

            result = run_discovery_once(args, token, run_label)

            if is_warmup:
                print(
                    f"[{run_label}] {args.event_name}={result['duration_ms']:.3f} ms "
                    f"(target={args.target_nf_type}, count={result['count']}, "
                    f"selected={result['selected_id']}, not written)"
                )
            else:
                measured_index += 1
                append_csv(csv_path, result["timestamp"], args.event_name, result["duration_ms"])
                print(
                    f"[{run_label}] {args.event_name}={result['duration_ms']:.3f} ms "
                    f"(target={args.target_nf_type}, count={result['count']}, "
                    f"selected={result['selected_id']}) written to {csv_path}"
                )

            if args.print_response:
                print(json.dumps(result["response_json"], ensure_ascii=False, indent=2))

            if overall_index != total_runs:
                time.sleep(args.interval)

        return 0
    finally:
        if proc is not None and not args.keep_amf_running:
            terminate_process(proc)


if __name__ == "__main__":
    sys.exit(main())

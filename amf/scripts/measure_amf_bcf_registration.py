#!/usr/bin/env python3

import argparse
import csv
import json
import re
import select
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
TS_RE = re.compile(r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\]")
LOCAL_TZ = datetime.now().astimezone().tzinfo

START_MARKER = "Send HTTP message to "
START_PATH_MARKER = "/nbcf_management/"
START_RESOURCE_MARKER = "/nf_instances/"
SUCCESS_MARKER = "[AMF][BCF-REG] Registration SUCCESS"
FAILURE_MARKER = "[AMF][BCF-REG] Registration FAILED"

AUTH_INIT_START_MARKER = "[BCF Auth] HTTP POST "
AUTH_INIT_PATH_MARKER = "/nbcf_auth/v1/auth/init"
AUTH_INIT_END_MARKER = "[BCF Auth] HTTP 200 from "

AUTH_VERIFY_START_MARKER = "[BCF Auth] HTTP POST "
AUTH_VERIFY_PATH_MARKER = "/nbcf_auth/v1/auth/verify"
AUTH_VERIFY_END_MARKER = "[BCF Auth] HTTP 200 from "

TOKEN_READY_MARKER = "[AMF][TOKEN] State → TOKEN_READY"

REGISTER_EVENT_NAME = "AMF_BCF_Register_E2E"
AUTH_INIT_EVENT_NAME = "AMF_BCF_Auth_Init"
AUTH_VERIFY_EVENT_NAME = "AMF_BCF_Auth_Verify"
AUTH_E2E_EVENT_NAME = "AMF_BCF_Auth_E2E"


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    amf_dir = script_dir.parent

    parser = argparse.ArgumentParser(
        description=(
            "Launch the real AMF process, measure AMF->BCF registration time, "
            "and append the result to a CSV file."
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
        "--csv",
        default=str(script_dir / "amf_bcf_registration_timings.csv"),
        help="CSV output path. Default: %(default)s",
    )
    parser.add_argument(
        "--bcf-base",
        default="http://127.0.0.1:8004",
        help="BCF base URL used for cleanup checks. Default: %(default)s",
    )
    parser.add_argument(
        "--event-name",
        default=REGISTER_EVENT_NAME,
        help="CSV Event_Name value for registration. Default: %(default)s",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="Timeout in seconds for one measurement run. Default: %(default)s",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of successful measurement runs to collect. Default: %(default)s",
    )
    parser.add_argument(
        "--attempts-per-run",
        type=int,
        default=3,
        help="Maximum attempts for each successful run slot. Default: %(default)s",
    )
    parser.add_argument(
        "--inter-run-delay",
        type=float,
        default=3.0,
        help="Sleep interval between runs in seconds. Default: %(default)s",
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=5.0,
        help="HTTP timeout in seconds for BCF readiness and cleanup checks. Default: %(default)s",
    )
    parser.add_argument(
        "--bcf-ready-timeout",
        type=float,
        default=30.0,
        help="How long to wait for BCF HTTP/account readiness before each attempt. Default: %(default)s",
    )
    parser.add_argument(
        "--keep-amf-running",
        action="store_true",
        help="Do not stop the AMF process after a successful run.",
    )
    parser.add_argument(
        "--print-live-log",
        action="store_true",
        help="Print AMF output live while parsing it.",
    )
    parser.add_argument(
        "--cleanup-timeout",
        type=float,
        default=30.0,
        help="How long to wait for AMF deregistration to disappear from BCF between runs. Default: %(default)s",
    )
    return parser.parse_args()


def strip_ansi(line: str) -> str:
    return ANSI_RE.sub("", line)


def parse_log_timestamp(line: str) -> Optional[datetime]:
    match = TS_RE.match(line)
    if not match:
        return None

    raw = match.group("ts")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=LOCAL_TZ)
        except ValueError:
            continue
    return None


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


def load_local_amf_profile(amf_dir: Path) -> Tuple[str, str]:
    profile_path = Path("/tmp/oai/extended_amf_profile.json")
    if not profile_path.exists():
        raise FileNotFoundError(f"AMF extended profile not found: {profile_path}")

    with profile_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    did = data.get("did", "").strip()
    if not did:
        raise RuntimeError(f"AMF extended profile does not contain DID: {profile_path}")
    nf_instance_id = data.get("nfInstanceId", "").strip()
    return did, nf_instance_id


def http_get_json(url: str, timeout_seconds: float) -> Tuple[int, str, object]:
    request = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            code = response.getcode()
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        code = exc.code
        body = exc.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GET {url} failed: {exc}") from exc

    try:
        payload: object = json.loads(body) if body else None
    except json.JSONDecodeError:
        payload = None
    return code, body, payload


def build_discovery_url(bcf_base: str, target_nf_type: str) -> str:
    query = urllib.parse.urlencode({"target-nf-type": target_nf_type})
    return f"{bcf_base.rstrip('/')}/nbcf_discovery/v1/nf_instances?{query}"


def wait_for_bcf_ready(bcf_base: str, timeout_seconds: float, http_timeout: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    account_url = f"{bcf_base.rstrip('/')}/dper/currentAccount"
    probe_url = build_discovery_url(bcf_base, "AUSF")
    last_error = ""

    while time.monotonic() < deadline:
        try:
            probe_status, _, _ = http_get_json(probe_url, http_timeout)
            account_status, account_body, account_payload = http_get_json(account_url, http_timeout)
            account_text = account_body.strip()
            if isinstance(account_payload, dict):
                account_text = json.dumps(account_payload, ensure_ascii=False)

            zero_account = "0000000000000000000000000000000000000000" in account_text
            if probe_status in (200, 401) and account_status == 200 and not zero_account:
                return

            last_error = (
                f"probe_status={probe_status}, account_status={account_status}, "
                f"zero_account={zero_account}"
            )
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.5)

    raise RuntimeError(f"BCF did not become ready before timeout: {last_error}")


def extract_nf_profile(payload: object) -> Optional[Dict[str, object]]:
    if not isinstance(payload, dict):
        return None

    data = payload.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return None

    if isinstance(data, dict):
        nf_profile = data.get("nfProfile")
        if isinstance(nf_profile, dict):
            return nf_profile
        return data
    return None


def query_nf_registered(bcf_base: str, did: str, timeout_seconds: float) -> bool:
    query = urllib.parse.urlencode({"did": did})
    url = f"{bcf_base.rstrip('/')}/nbcf_management/v1/nf_instances?{query}"

    try:
        status, _, payload = http_get_json(url, timeout_seconds)
    except RuntimeError:
        return False
    if status != 200:
        return False

    profile = extract_nf_profile(payload)
    if not profile:
        return False

    nf_status = str(profile.get("nfStatus", profile.get("nf_status", ""))).upper()
    return nf_status == "REGISTERED"


def wait_for_nf_not_registered(bcf_base: str, did: str, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not query_nf_registered(bcf_base, did, timeout_seconds=3.0):
            return True
        time.sleep(0.5)
    return False


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


def detect_registration_window(line: str) -> Tuple[bool, bool]:
    is_start = (
        START_MARKER in line
        and START_PATH_MARKER in line
        and START_RESOURCE_MARKER in line
    )
    is_success = SUCCESS_MARKER in line
    return is_start, is_success


def detect_auth_init_window(line: str) -> Tuple[bool, bool]:
    is_start = AUTH_INIT_START_MARKER in line and AUTH_INIT_PATH_MARKER in line
    is_end = AUTH_INIT_END_MARKER in line and AUTH_INIT_PATH_MARKER in line
    return is_start, is_end


def detect_auth_verify_window(line: str) -> Tuple[bool, bool]:
    is_start = AUTH_VERIFY_START_MARKER in line and AUTH_VERIFY_PATH_MARKER in line
    is_end = AUTH_VERIFY_END_MARKER in line and AUTH_VERIFY_PATH_MARKER in line
    return is_start, is_end


def build_run_results(
    args: argparse.Namespace,
    registration_end: datetime,
    registration_start_perf: float,
    registration_end_perf: float,
    auth_init_end: datetime,
    auth_init_start_perf: float,
    auth_init_end_perf: float,
    auth_verify_end: datetime,
    auth_verify_start_perf: float,
    auth_verify_end_perf: float,
    auth_e2e_end: datetime,
    auth_e2e_end_perf: float,
) -> List[Tuple[datetime, str, float]]:
    return [
        (
            registration_end,
            args.event_name,
            (registration_end_perf - registration_start_perf) * 1000.0,
        ),
        (
            auth_init_end,
            AUTH_INIT_EVENT_NAME,
            (auth_init_end_perf - auth_init_start_perf) * 1000.0,
        ),
        (
            auth_verify_end,
            AUTH_VERIFY_EVENT_NAME,
            (auth_verify_end_perf - auth_verify_start_perf) * 1000.0,
        ),
        (
            auth_e2e_end,
            AUTH_E2E_EVENT_NAME,
            (auth_e2e_end_perf - auth_init_start_perf) * 1000.0,
        ),
    ]


def run_one_measurement(args: argparse.Namespace, run_index: int) -> List[Tuple[datetime, str, float]]:
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

    registration_start_ts: Optional[datetime] = None
    registration_success_ts: Optional[datetime] = None
    auth_init_start_ts: Optional[datetime] = None
    auth_init_end_ts: Optional[datetime] = None
    auth_verify_start_ts: Optional[datetime] = None
    auth_verify_end_ts: Optional[datetime] = None
    auth_e2e_end_ts: Optional[datetime] = None
    registration_start_perf: Optional[float] = None
    registration_success_perf: Optional[float] = None
    auth_init_start_perf: Optional[float] = None
    auth_init_end_perf: Optional[float] = None
    auth_verify_start_perf: Optional[float] = None
    auth_verify_end_perf: Optional[float] = None
    auth_e2e_end_perf: Optional[float] = None
    failure_line: Optional[str] = None
    recent_lines: List[str] = []
    deadline = time.monotonic() + args.timeout

    try:
        while time.monotonic() < deadline:
            if proc.stdout is None:
                raise RuntimeError("Failed to capture AMF stdout")

            timeout_left = max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select([proc.stdout], [], [], min(0.25, timeout_left))
            if not ready:
                if proc.poll() is not None:
                    break
                continue

            line = proc.stdout.readline()
            if not line:
                continue

            line_perf = time.perf_counter()
            line_ts = datetime.now().astimezone()
            clean = strip_ansi(line.rstrip("\n"))
            recent_lines.append(clean)
            if len(recent_lines) > 20:
                recent_lines.pop(0)

            if args.print_live_log:
                print(clean)

            ts = parse_log_timestamp(clean)
            if ts is None:
                continue

            reg_is_start, reg_is_success = detect_registration_window(clean)
            auth_init_is_start, auth_init_is_end = detect_auth_init_window(clean)
            auth_verify_is_start, auth_verify_is_end = detect_auth_verify_window(clean)

            if reg_is_start and registration_start_ts is None:
                registration_start_ts = line_ts
                registration_start_perf = line_perf
            elif reg_is_success and registration_success_ts is None:
                registration_success_ts = line_ts
                registration_success_perf = line_perf
            elif auth_init_is_start and auth_init_start_ts is None:
                auth_init_start_ts = line_ts
                auth_init_start_perf = line_perf
            elif auth_init_is_end and auth_init_end_ts is None:
                auth_init_end_ts = line_ts
                auth_init_end_perf = line_perf
            elif auth_verify_is_start and auth_verify_start_ts is None:
                auth_verify_start_ts = line_ts
                auth_verify_start_perf = line_perf
            elif auth_verify_is_end and auth_verify_end_ts is None:
                auth_verify_end_ts = line_ts
                auth_verify_end_perf = line_perf
            elif TOKEN_READY_MARKER in clean and auth_e2e_end_ts is None:
                auth_e2e_end_ts = line_ts
                auth_e2e_end_perf = line_perf
                break
            elif FAILURE_MARKER in clean:
                failure_line = clean
                break

        if registration_start_ts is None:
            raise RuntimeError(
                f"Run {run_index}: did not detect AMF registration start log before timeout\n"
                + "\n".join(recent_lines[-10:])
            )
        if failure_line is not None:
            raise RuntimeError(f"Run {run_index}: AMF registration failed: {failure_line}")
        if registration_success_ts is None:
            raise RuntimeError(
                f"Run {run_index}: did not detect AMF registration success log before timeout\n"
                + "\n".join(recent_lines[-10:])
            )
        if auth_init_start_ts is None or auth_init_end_ts is None:
            raise RuntimeError(
                f"Run {run_index}: did not detect auth/init request-response logs before timeout\n"
                + "\n".join(recent_lines[-10:])
            )
        if auth_verify_start_ts is None or auth_verify_end_ts is None:
            raise RuntimeError(
                f"Run {run_index}: did not detect auth/verify request-response logs before timeout\n"
                + "\n".join(recent_lines[-10:])
            )
        if auth_e2e_end_ts is None:
            auth_e2e_end_ts = auth_verify_end_ts
            auth_e2e_end_perf = auth_verify_end_perf

        return build_run_results(
            args,
            registration_end=registration_success_ts,
            registration_start_perf=registration_start_perf,
            registration_end_perf=registration_success_perf,
            auth_init_end=auth_init_end_ts,
            auth_init_start_perf=auth_init_start_perf,
            auth_init_end_perf=auth_init_end_perf,
            auth_verify_end=auth_verify_end_ts,
            auth_verify_start_perf=auth_verify_start_perf,
            auth_verify_end_perf=auth_verify_end_perf,
            auth_e2e_end=auth_e2e_end_ts,
            auth_e2e_end_perf=auth_e2e_end_perf,
        )
    finally:
        if not args.keep_amf_running:
            terminate_process(proc)


def main() -> int:
    args = parse_args()
    csv_path = Path(args.csv).resolve()
    amf_dir = Path(args.amf_dir).resolve()

    if args.runs < 1:
        print("--runs must be >= 1", file=sys.stderr)
        return 2
    if args.attempts_per_run < 1:
        print("--attempts-per-run must be >= 1", file=sys.stderr)
        return 2
    if args.keep_amf_running and args.runs > 1:
        print("--keep-amf-running cannot be used together with --runs > 1", file=sys.stderr)
        return 2

    local_amf_did, local_nf_instance_id = load_local_amf_profile(amf_dir)
    if local_nf_instance_id:
        print(f"[Profile] AMF nfInstanceId={local_nf_instance_id}")
    print(f"[Profile] AMF DID={local_amf_did}")

    for run_index in range(1, args.runs + 1):
        last_error: Optional[Exception] = None

        for attempt_index in range(1, args.attempts_per_run + 1):
            print(
                f"[Run {run_index}/{args.runs} Attempt {attempt_index}/{args.attempts_per_run}] "
                "waiting for BCF ready..."
            )
            wait_for_bcf_ready(args.bcf_base, args.bcf_ready_timeout, args.http_timeout)

            try:
                print(
                    f"[Run {run_index}/{args.runs} Attempt {attempt_index}/{args.attempts_per_run}] "
                    "starting measurement..."
                )
                run_results = run_one_measurement(args, run_index)
                result_texts = []
                for end_ts, event_name, duration_ms in run_results:
                    append_csv(csv_path, end_ts, event_name, duration_ms)
                    result_texts.append(f"{event_name}={duration_ms:.3f} ms")

                print(
                    f"[Run {run_index}/{args.runs}] {'; '.join(result_texts)} "
                    f"written to {csv_path}"
                )
                break
            except Exception as exc:
                last_error = exc
                print(
                    f"[Run {run_index}/{args.runs} Attempt {attempt_index}/{args.attempts_per_run}] "
                    f"FAILED: {exc}",
                    file=sys.stderr,
                )
                if attempt_index >= args.attempts_per_run:
                    raise RuntimeError(
                        f"Run {run_index}/{args.runs} failed after "
                        f"{args.attempts_per_run} attempts"
                    ) from last_error
                time.sleep(args.inter_run_delay)

        if run_index != args.runs and not args.keep_amf_running:
            cleaned = wait_for_nf_not_registered(
                args.bcf_base, local_amf_did, args.cleanup_timeout
            )
            if cleaned:
                print(
                    f"[Run {run_index}/{args.runs}] AMF is no longer REGISTERED in BCF; "
                    "continuing..."
                )
            else:
                print(
                    f"[Run {run_index}/{args.runs}] WARNING: AMF still appears REGISTERED "
                    f"after {args.cleanup_timeout:.1f}s; continuing after delay.",
                    file=sys.stderr,
                )
            time.sleep(args.inter_run_delay)

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import socket
import struct
import time
from typing import Optional

# ================= 配置区域 =================
AMF_IP = "10.29.124.26"
AMF_PORT = 38412

PPID_NGAP = 60          # NGAP PPID = 60
SCTP_STREAM = 0

# ================= 关键：请填入“真实 APER 编码”的 NGAP 报文 =================
# 强烈建议：从 Wireshark 抓包中复制 NGAP payload（不是整个 SCTP 包）
# Wireshark: SCTP DATA -> Payload Protocol: NGAP -> "Data" 字段/或 Follow Stream 导出 payload
#
# 如果这里填的是你现在那种“手搓TLV”，AMF 必定 Decode fail，不会返回 NGSetupResponse。
NG_SETUP_REQ_HEX = ""  # <<< 必填：正确的 NGSetupRequest(APer) 十六进制
# 如果你也想完全复用抓到的 InitialUEMessage，也可填这里（同样是 NGAP APER payload）
INITIAL_UE_MSG_HEX = ""  # <<< 可选：正确的 InitialUEMessage(APer) 十六进制

# ================= 如果你只想拼 NAS + InitialUEMessage（不推荐手搓 NGAP） =================
# 你的 NAS Registration Request（这个可以保留）
nas_pdu_hex = "7e004109000d0102f8590000000000000000132e08e060000000000000"


def hexdump_prefix(b: bytes, n=80) -> str:
    h = b.hex()
    return h[:n] + ("..." if len(h) > n else "")


# 你原来的拼装（仅作为“实验用”保留）
def build_initial_ue_message_like_before(nas_hex: str) -> bytes:
    nas_bytes = binascii.unhexlify(nas_hex)
    nas_len = len(nas_bytes)
    len_byte = f"{nas_len:02x}"

    head = "000f40000005005500020001002600" + len_byte
    tail = (
        "007900114002f8590000e014e00002f85900007b"
        "005a00010003"
        "007000010000"
    )
    payload_content = binascii.unhexlify(head) + nas_bytes + binascii.unhexlify(tail)
    total_len = len(payload_content)
    final_pkt = bytes.fromhex(f"000f40{total_len:02x}") + payload_content
    return final_pkt


# ================= SCTP 发送实现（优先 pysctp；没有则退化 socket） =================
def sctp_connect() -> object:
    """
    返回一个“socket-like”的对象，提供 send_ngap(payload_bytes) 和 recv(timeout)。
    优先使用 pysctp，这样能稳定设置 PPID/stream。
    """
    try:
        import sctp  # pysctp
    except Exception:
        sctp = None

    if sctp is not None:
        # pysctp: one-to-one style TCP-like SCTP socket
        sock = sctp.sctpsocket_tcp(socket.AF_INET)
        sock.connect((AMF_IP, AMF_PORT))
        return _PySctpWrapper(sock)

    # fallback: 原生 socket（很多环境下无法在 send 时精确指定 PPID/stream）
    # 仅用于“你已经在系统层设好默认 PPID”的情况；不推荐
    IPPROTO_SCTP = 132
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
    sock.connect((AMF_IP, AMF_PORT))
    return _RawSctpWrapper(sock)


class _PySctpWrapper:
    def __init__(self, sock):
        self.sock = sock

    def close(self):
        self.sock.close()

    def send_ngap(self, payload: bytes, ppid: int = PPID_NGAP, stream: int = SCTP_STREAM):
        # pysctp 会走 sctp_sendmsg，ppid 要网络字节序（很多实现要求 htonl） :contentReference[oaicite:1]{index=1}
        ppid_net = socket.htonl(ppid)
        self.sock.sctp_send(payload, to=(AMF_IP, AMF_PORT), ppid=ppid_net, stream=stream)

    def recv(self, n: int = 4096, timeout: Optional[float] = None) -> bytes:
        if timeout is not None:
            self.sock.settimeout(timeout)
        return self.sock.recv(n)


class _RawSctpWrapper:
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def close(self):
        self.sock.close()

    def send_ngap(self, payload: bytes, ppid: int = PPID_NGAP, stream: int = SCTP_STREAM):
        # 警告：原生 socket.send 无法逐包指定 PPID/stream
        # 这里仅尽力发送 payload；若 AMF 显示 PPID 不对，必须换 pysctp
        self.sock.send(payload)

    def recv(self, n: int = 4096, timeout: Optional[float] = None) -> bytes:
        if timeout is not None:
            self.sock.settimeout(timeout)
        return self.sock.recv(n)


# ================= 主流程 =================
def run_fake_gnb():
    print(f"[*] Connecting SCTP to {AMF_IP}:{AMF_PORT} ...")
    try:
        s = sctp_connect()
    except Exception as e:
        print(f"[!] SCTP connect failed: {e}")
        return
    print("[+] Connected.")

    # -------- Step 1: NG Setup --------
    if not NG_SETUP_REQ_HEX.strip():
        print("[!] NG_SETUP_REQ_HEX is empty.")
        print("    你必须填入『真实 NGAP APER 编码』的 NGSetupRequest payload（从抓包/现成gNB导出）。")
        s.close()
        return

    ng_setup = binascii.unhexlify(NG_SETUP_REQ_HEX.replace(" ", "").replace("\n", ""))
    print(f"[*] Sending NGSetupRequest ({len(ng_setup)} bytes), PPID={PPID_NGAP}, stream={SCTP_STREAM} ...")
    try:
        s.send_ngap(ng_setup, ppid=PPID_NGAP, stream=SCTP_STREAM)
    except Exception as e:
        print(f"[!] Send NGSetupRequest failed: {e}")
        s.close()
        return

    # AMF 若立即断开，recv 会返回 b''（长度0）或直接超时
    try:
        data = s.recv(4096, timeout=3)
    except socket.timeout:
        data = b""

    if data == b"":
        print("[!] No response / association closed (recv 0 bytes).")
        print("    如果 AMF 端日志仍然显示 Decode fail：说明你的 NG_SETUP_REQ_HEX 仍不是合法 APER。")
        s.close()
        return

    print(f"[+] Got response ({len(data)} bytes): {hexdump_prefix(data)}")

    time.sleep(0.5)

    # -------- Step 2: Initial UE Message --------
    if INITIAL_UE_MSG_HEX.strip():
        ue_msg = binascii.unhexlify(INITIAL_UE_MSG_HEX.replace(" ", "").replace("\n", ""))
        print(f"[*] Sending InitialUEMessage (replay) ({len(ue_msg)} bytes) ...")
    else:
        # 退化到你原来的手拼（不保证 NGAP 合法，仅用于实验）
        ue_msg = build_initial_ue_message_like_before(nas_pdu_hex)
        print(f"[*] Sending InitialUEMessage (hand-built, risky) ({len(ue_msg)} bytes) ...")

    try:
        s.send_ngap(ue_msg, ppid=PPID_NGAP, stream=SCTP_STREAM)
    except BrokenPipeError:
        print("[!] Broken pipe: AMF closed SCTP association (通常因为你前面发的 NGAP 仍然无法解码/被拒).")
        s.close()
        return
    except Exception as e:
        print(f"[!] Send InitialUEMessage failed: {e}")
        s.close()
        return

    # -------- Step 3: Wait for Authentication Request --------
    print("[*] Waiting for AMF response ...")
    try:
        data2 = s.recv(8192, timeout=5)
    except socket.timeout:
        print("[!] Timeout. AMF didn't reply.")
        s.close()
        return

    if data2 == b"":
        print("[!] Connection closed by AMF (recv 0 bytes).")
        s.close()
        return

    hex_data = data2.hex()
    print(f"[+] Received ({len(data2)} bytes): {hex_data[:120]}...")

    # 你之前用的 NAS 标识符（仅供参考）
    if "7e0056" in hex_data:
        print("\n" + "=" * 50)
        print("[SUCCESS] AMF returned Authentication Request (found '7e0056').")
        print("=" * 50)
    else:
        print("[?] Received data, but '7e0056' not found (可能是 NGAP 层拒绝/返回错误消息).")

    s.close()


if __name__ == "__main__":
    run_fake_gnb()

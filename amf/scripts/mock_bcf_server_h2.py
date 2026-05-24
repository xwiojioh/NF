#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mock BCF Server for OAI 5GC DID Self-Authentication Testing
支持 HTTP/2 协议

专门为 OAI 5G 核心网设计的 BCF 模拟服务器，支持：
1. NF 注册（PUT /nbcf_management/v1/nf_instances/{nfInstanceId}）
2. NF 发现与查询（GET /nbcf_nfm/v1/nf_instances?target_nf_type=...）
3. 公钥查询接口（GET /nbcf_nfm/v1/did/{did}/publickey）
4. 存储 DID 文档和公钥
5. NF 向 BCF 自身认证（POST /nbcf_auth/v1/auth/init, POST /nbcf_auth/v1/auth/verify）

使用 Quart + Hypercorn 实现 HTTP/2 支持

API 版本:
  - /nbcf_management/v1/... - NF 管理（注册/注销/心跳）
  - /nbcf_nfm/v1/...        - NF 发现（通用 BCF 框架使用）
  - /nbcf_did/v1/...        - DID 操作（兼容旧接口）
  - /nbcf_auth/v1/...       - NF 自身认证（challenge-response）
"""
# =============================================================================
# Imports
import argparse
import asyncio
import base64
import copy
import contextvars
import json
import logging
import secrets
import time
import hashlib
import socket
import uuid
import http.client
from datetime import datetime
from typing import Dict, Optional, Any, List, Tuple
from urllib.parse import unquote, urlparse
import ssl
import os
import threading
import h2.connection
import h2.events
import h2.config
import h2.exceptions

try:
    from coincurve import PrivateKey, PublicKey
    from coincurve.ecdsa import (
        cdata_to_der,
        der_to_cdata,
        deserialize_compact,
    )
    try:
        from coincurve.ecdsa import serialize_compact
    except ImportError:
        from coincurve.ecdsa import cdata_to_bytes as serialize_compact
except ImportError as exc:
    raise ImportError(
        "coincurve is required for ES256K JWS signing in mock_bcf_server_h2.py"
    ) from exc

LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'
THIRD_PARTY_QUIET_LOGGERS = (
    "asyncio",
    "h2",
    "h2.config",
    "h2.connection",
    "hpack",
    "hpack.hpack",
    "hpack.table",
    "hypercorn",
    "hypercorn.access",
    "hypercorn.error",
)


def configure_logging() -> logging.Logger:
    """Keep BCF business logs readable while silencing third-party debug noise."""
    # Root logger only keeps warnings/errors from third-party libraries.
    logging.basicConfig(
        level=logging.WARNING,
        format=LOG_FORMAT,
        datefmt=LOG_DATEFMT,
    )

    bcf_logger = logging.getLogger("mock_bcf")
    bcf_logger.setLevel(logging.DEBUG)
    bcf_logger.propagate = False
    bcf_logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT))
    bcf_logger.addHandler(handler)

    for logger_name in THIRD_PARTY_QUIET_LOGGERS:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    return bcf_logger


logger = configure_logging()

SUPPORTED_NOTIFICATION_TRANSPORTS = ("auto", "h2c-prior", "http1-json")
DEFAULT_NOTIFICATION_TRANSPORT = "auto"

# Create Quart app
from quart import Quart, request, jsonify, Response
from hypercorn.config import Config
from hypercorn.asyncio import serve

app = Quart(__name__)

REQUEST_ID_CTX = contextvars.ContextVar("bcf_request_id", default="")
REQUEST_STAGE_CTX = contextvars.ContextVar("bcf_request_stage", default="SYS")
REQUEST_START_MS_CTX = contextvars.ContextVar("bcf_request_start_ms", default=0)

# 预配置 NF 实例 - 设为空，完全依赖 NF 动态注册
PRECONFIGURED_NF_INSTANCES: Dict[str, dict] = {}


def now_ms() -> int:
    return int(time.time() * 1000)


def compact_json(data: Any) -> str:
    return json.dumps(
        data, ensure_ascii=False, separators=(',', ':'), sort_keys=True, default=str
    )


def current_request_id() -> str:
    return REQUEST_ID_CTX.get("")


def current_request_stage() -> str:
    return REQUEST_STAGE_CTX.get("SYS")


def shorten(value: Any, limit: int = 64) -> str:
    text = "" if value is None else str(value)
    text = text.replace('\n', '\\n')
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def normalize_hex_string(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    return "".join(text.split())


def format_hex_for_log(value: Any, head: int = 96, tail: int = 32) -> str:
    text = normalize_hex_string(value)
    if not text:
        return ""
    if len(text) <= head + tail:
        return text
    return f"{text[:head]}...{text[-tail:]}"


def decode_hex_field(field_name: str, value: Any) -> Tuple[str, bytes]:
    normalized = normalize_hex_string(value)
    if not normalized:
        raise ValueError(f"{field_name} is empty")
    if len(normalized) % 2 != 0:
        raise ValueError(f"{field_name} hex length must be even")
    try:
        return normalized, bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not valid hex: {exc}") from exc


def normalize_notification_transport(
    value: Any, fallback: str = "auto"
) -> str:
    raw = "" if value is None else str(value).strip().lower()
    aliases = {
        "": fallback,
        "auto": "auto",
        "h2c": "h2c-prior",
        "h2-prior": "h2c-prior",
        "h2c-prior": "h2c-prior",
        "http1": "http1-json",
        "http11": "http1-json",
        "http/1.1": "http1-json",
        "http1-json": "http1-json",
    }
    return aliases.get(raw, raw)


def resolve_notification_transport(
    requested: Any, fallback: str = "auto"
) -> str:
    normalized = normalize_notification_transport(requested, fallback=fallback)
    if normalized not in SUPPORTED_NOTIFICATION_TRANSPORTS:
        logger.warning(
            "Invalid notification transport '%s', fallback to '%s'",
            requested,
            fallback,
        )
        return fallback
    return normalized


def classify_transport_exception(exc: Exception) -> str:
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "dns_error"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, ConnectionResetError):
        return "connection_reset"
    if isinstance(exc, BrokenPipeError):
        return "broken_pipe"
    if isinstance(exc, ssl.SSLError):
        return "ssl_error"
    if isinstance(exc, h2.exceptions.ProtocolError):
        return "http2_protocol_error"
    if isinstance(exc, http.client.HTTPException):
        return "http_client_error"
    if isinstance(exc, OSError):
        return f"os_error_{exc.errno if exc.errno is not None else 'unknown'}"
    return exc.__class__.__name__


def build_notification_transport_plan(
    notification_uri: str,
    requested_transport: str,
) -> List[str]:
    parsed = urlparse(notification_uri)
    scheme = (parsed.scheme or "http").lower()
    if requested_transport != "auto":
        return [requested_transport]
    if scheme == "https":
        return ["http1-json"]
    return ["h2c-prior", "http1-json"]


def _format_log_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple, set)):
        if all(isinstance(item, (str, int, float, bool)) or item is None for item in value):
            return ",".join(_format_log_value(item) for item in value)
        return compact_json(list(value))
    if isinstance(value, dict):
        return compact_json(value)

    text = str(value).replace('\n', '\\n')
    if not text:
        return '""'
    if any(ch.isspace() for ch in text):
        return json.dumps(text, ensure_ascii=False)
    return text


def _build_log_prefix(module: str, stage: str, req: Optional[str] = None) -> str:
    prefix = f"[{module}][{stage}]"
    request_id = req if req is not None else current_request_id()
    if request_id:
        prefix += f"[req={request_id}]"
    return prefix


def log_event(
    module: str,
    stage: str,
    msg: str,
    *,
    level: int = logging.INFO,
    req: Optional[str] = None,
    **kwargs: Any,
) -> None:
    prefix = _build_log_prefix(module, stage, req=req)
    kv_parts = []
    for key, value in kwargs.items():
        if value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        kv_parts.append(f"{key}={_format_log_value(value)}")

    suffix = f" {' '.join(kv_parts)}" if kv_parts else ""
    logger.log(level, f"{prefix} {msg}{suffix}")


def log_exception(
    module: str,
    stage: str,
    msg: str,
    *,
    req: Optional[str] = None,
    **kwargs: Any,
) -> None:
    prefix = _build_log_prefix(module, stage, req=req)
    kv_parts = []
    for key, value in kwargs.items():
        if value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        kv_parts.append(f"{key}={_format_log_value(value)}")

    suffix = f" {' '.join(kv_parts)}" if kv_parts else ""
    logger.exception(f"{prefix} {msg}{suffix}")


def log_debug_json(stage: str, label: str, data: Any, *, req: Optional[str] = None) -> None:
    log_event(
        "BCF", stage, "Debug payload",
        level=logging.DEBUG, req=req, **{label: compact_json(data)}
    )


def detect_request_stage(path: str, method: str) -> str:
    normalized_path = path.lower()
    normalized_method = method.upper()

    if "/nbcf_auth/" in normalized_path or "/nbcf-auth/" in normalized_path:
        return "AUTH"
    if "/subscriptions" in normalized_path or "/subscription" in normalized_path:
        return "SUB"
    if "/nbcf_nfm/" in normalized_path or "/nbcf-nfm/" in normalized_path:
        return "DISC"
    if "/nbcf_management/" in normalized_path:
        if normalized_method == "PUT":
            return "REG"
        if normalized_method in ("PATCH", "DELETE"):
            return "STATE"
    return "SYS"


def extract_request_id() -> str:
    for header_name in ("X-Request-ID", "X-Correlation-ID", "Request-Id"):
        header_value = request.headers.get(header_name)
        if header_value:
            return header_value
    return uuid.uuid4().hex[:8]


def nf_profile_plmn(profile: Dict[str, Any]) -> str:
    plmn_list = profile.get("plmnList") or profile.get("plmn_list") or []
    values = []
    for plmn in plmn_list:
        if not isinstance(plmn, dict):
            continue
        mcc = plmn.get("mcc", "")
        mnc = plmn.get("mnc", "")
        if mcc or mnc:
            values.append(f"{mcc}/{mnc}")
    return ",".join(values[:3]) if values else "N/A"


def nf_profile_service_count(profile: Dict[str, Any]) -> int:
    services = profile.get("nfServices") or profile.get("nf_services") or []
    return len(services) if isinstance(services, list) else 0


def nf_profile_ip(profile: Dict[str, Any]) -> str:
    services = profile.get("nfServices") or profile.get("nf_services") or []
    for service in services:
        if not isinstance(service, dict):
            continue
        endpoints = service.get("ipEndPoints") or service.get("ip_end_points") or []
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                continue
            ipv4 = endpoint.get("ipv4Address") or endpoint.get("ipv4_address")
            port = endpoint.get("port")
            if ipv4:
                return f"{ipv4}:{port}" if port else str(ipv4)
        fqdn = service.get("fqdn")
        if fqdn:
            return fqdn

    ipv4_addresses = profile.get("ipv4Addresses") or profile.get("ipv4_addresses") or []
    if ipv4_addresses:
        return str(ipv4_addresses[0])
    fqdn = profile.get("fqdn")
    if fqdn:
        return str(fqdn)
    return "N/A"


def summarize_nf_profile(profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(profile, dict):
        return {}

    return {
        "nfInstanceId": profile.get("nfInstanceId") or profile.get("nf_instance_id") or "N/A",
        "nfType": profile.get("nfType") or profile.get("nf_type") or "UNKNOWN",
        "plmn": nf_profile_plmn(profile),
        "services": nf_profile_service_count(profile),
        "ip": nf_profile_ip(profile),
        "capacity": profile.get("capacity"),
        "priority": profile.get("priority"),
        "load": profile.get("load"),
    }


def summarize_subscription(sub: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "sub_id": sub.get("subscription_id") or "N/A",
        "subscriber": sub.get("subscriber_nf_type") or shorten(sub.get("subscriber_nf_did", ""), 24) or "UNKNOWN",
        "target_nf_type": sub.get("target_nf_type") or "ANY",
        "notification_uri": sub.get("notification_uri") or "N/A",
    }


def normalize_state_event(event_type: str) -> str:
    if event_type == "TARGET_NF_REGISTERED":
        return "REGISTERED"
    if event_type == "NF_UPDATED":
        return "UPDATED"
    if event_type == "NF_DEREGISTERED":
        return "DEREGISTERED"
    return event_type


def multibase_to_hex(multibase_str: str) -> str:
    """
    Convert a multibase-encoded public key to hex format.
    
    Multibase format: <prefix><encoded_data>
    - 'z' prefix = base58btc encoding
    - 'f' prefix = base16 (hex) encoding
    
    Args:
        multibase_str: Multibase encoded string (e.g., "zbWJz3rapGe...")
        
    Returns:
        Hex-encoded public key string
    """
    if not multibase_str:
        return ""

    # Delegate to a more general decoder that returns bytes + hex
    try:
        decoded_bytes, decoded_hex = decode_public_key_multibase(multibase_str)
        return decoded_hex
    except Exception as e:
        log_event(
            "BCF", "REG", "Failed to decode multibase public key",
            level=logging.ERROR,
            error=str(e),
        )
        return multibase_str  # Return as-is if decoding fails


# =============================================================================
# JWT-style Access Token Utilities (stdlib only: hmac, hashlib, base64, json)
# =============================================================================

# Base58 (btc) alphabet for multibase base58btc decoding
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58_decode(s: str) -> bytes:
    """
    Decode a base58btc-encoded string (no multibase prefix) into bytes.

    Args:
        s: base58 string (no 'z' prefix)

    Returns:
        Decoded bytes
    """
    if not s:
        return b''

    # Convert base58 string to integer
    num = 0
    try:
        for char in s:
            num = num * 58 + BASE58_ALPHABET.index(char)
    except ValueError as e:
        raise ValueError(f"Invalid base58 character: {e}")

    # Convert integer to bytes
    combined = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big') if num != 0 else b''

    # Handle leading zeros (base58 '1' == 0x00)
    n_pad = 0
    for c in s:
        if c == '1':
            n_pad += 1
        else:
            break

    return b'\x00' * n_pad + combined


def decode_public_key_multibase(pubkey_multibase: str) -> Tuple[bytes, str]:
    """
    Decode a public key given in multibase formats used in DID documents.

    Supports:
      - base58btc multibase with 'z' prefix
      - hex multibase with 'f' prefix
      - plain hex starting with '0x' or raw hex

    Returns tuple (decoded_bytes, decoded_hex_string)
    """
    if not pubkey_multibase:
        return b'', ''

    # multibase base58btc
    if pubkey_multibase.startswith('z'):
        payload = pubkey_multibase[1:]
        decoded = base58_decode(payload)
        # Note: decoded may include multicodec prefix; caller may need to strip it
        return decoded, decoded.hex()

    # multibase hex (base16) 'f' prefix
    if pubkey_multibase.startswith('f'):
        hexpart = pubkey_multibase[1:]
        try:
            decoded = bytes.fromhex(hexpart)
            return decoded, hexpart
        except Exception as e:
            raise ValueError(f"Invalid multibase hex payload: {e}")

    # common hex formats
    if pubkey_multibase.startswith('0x'):
        hexpart = pubkey_multibase[2:]
        try:
            decoded = bytes.fromhex(hexpart)
            return decoded, hexpart
        except Exception as e:
            raise ValueError(f"Invalid 0x hex payload: {e}")

    # If seems like plain hex
    try:
        decoded = bytes.fromhex(pubkey_multibase)
        return decoded, pubkey_multibase
    except Exception:
        # Unknown format, return raw bytes (utf-8) as fallback
        return pubkey_multibase.encode('utf-8'), pubkey_multibase

# Token/JWS 默认配置
BCF_TOKEN_EXPIRES_IN = 3600  # 1 小时
BCF_JWT_ISSUER = os.environ.get("BCF_JWT_ISSUER", "BCF")
BCF_JWT_KID = os.environ.get("BCF_JWT_KID", "bcf-key-001")
BCF_JWT_ALG = "ES256K"
BCF_DEFAULT_TARGET_NF_TYPES = ["AUSF", "UDM", "SMF"]
BCF_ES256K_PRIVATE_KEY_PATH = os.environ.get(
    "BCF_ES256K_PRIVATE_KEY_PATH",
    os.path.join(os.path.dirname(__file__), "bcf_secp256k1.key"),
)
BCF_SCOPE_BY_TARGET_NF = {
    "AUSF": ["nausf-auth:ue-authentications"],
    "UDM": ["nudm-ueau:generate-auth-data"],
    "SMF": ["nsmf-pdusession:create-sm-context"],
}

_ES256K_KEY_MANAGER = None
_ES256K_KEY_MANAGER_ERROR = None


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def _base64url_decode(s: str) -> bytes:
    """Base64url 解码（自动补齐填充）"""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


def _json_dumps_compact(data: Any) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, separators=(',', ':'), sort_keys=True
    ).encode('utf-8')


def normalize_target_nf_types(raw_value: Any) -> List[str]:
    if raw_value is None:
        values = []
    elif isinstance(raw_value, list):
        values = raw_value
    else:
        values = [raw_value]

    normalized = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip().upper()
        if not text or text in normalized:
            continue
        normalized.append(text)

    if normalized:
        return normalized
    return list(BCF_DEFAULT_TARGET_NF_TYPES)


def generate_scope_for_targets(target_nf_types: List[str]) -> List[str]:
    scopes = []
    for nf_type in normalize_target_nf_types(target_nf_types):
        mapped_scopes = BCF_SCOPE_BY_TARGET_NF.get(
            nf_type, [f"nf-access:{nf_type.lower()}"]
        )
        for scope in mapped_scopes:
            if scope not in scopes:
                scopes.append(scope)
    return scopes


def generate_scope_for_nf(nf_type: str) -> str:
    """
    根据 NF 类型生成 scope 字符串（空格分隔）

    所有 NF 获得基础 scope: bcf:auth bcf:registry bcf:discovery
    """
    return " ".join(generate_scope_for_targets([nf_type]))


def resolve_target_nf_types_for_request(
    nf_type: str, raw_target_nf_types: Any
) -> List[str]:
    normalized_nf_type = str(nf_type or "").strip().upper()
    if normalized_nf_type == "AUSF":
        return ["UDM"]
    return normalize_target_nf_types(raw_target_nf_types)


class ES256KKeyManager:
    def __init__(self, private_key_path: str, kid: str):
        self.private_key_path = private_key_path
        self.kid = kid
        self.private_key_bytes = b""
        self.public_key: Optional[PublicKey] = None
        self._load_or_create_private_key()

    def _load_or_create_private_key(self) -> None:
        private_key_bytes = b""
        if os.path.exists(self.private_key_path):
            with open(self.private_key_path, "rb") as f:
                private_key_bytes = f.read().strip()
            if len(private_key_bytes) != 32:
                raise ValueError(
                    f"Invalid secp256k1 private key length: {len(private_key_bytes)}"
                )
            log_event(
                "BCF", "Token", "Loaded ES256K signing key",
                kid=self.kid,
                path=self.private_key_path,
            )
        else:
            private_key_dir = os.path.dirname(self.private_key_path)
            if private_key_dir:
                os.makedirs(private_key_dir, exist_ok=True)
            private_key_bytes = PrivateKey().secret
            with open(self.private_key_path, "wb") as f:
                f.write(private_key_bytes)
            try:
                os.chmod(self.private_key_path, 0o600)
            except OSError:
                pass
            log_event(
                "BCF", "Token", "Generated ES256K signing key",
                kid=self.kid,
                path=self.private_key_path,
            )

        self.private_key_bytes = private_key_bytes
        self.public_key = PrivateKey(self.private_key_bytes).public_key

    def get_public_jwk(self) -> dict:
        public_key_bytes = self.public_key.format(compressed=False)
        if len(public_key_bytes) != 65 or public_key_bytes[0] != 0x04:
            raise ValueError("Invalid uncompressed secp256k1 public key format")
        x_bytes = public_key_bytes[1:33]
        y_bytes = public_key_bytes[33:65]
        return {
            "kid": self.kid,
            "kty": "EC",
            "crv": "secp256k1",
            "alg": BCF_JWT_ALG,
            "use": "sig",
            "x": b64url(x_bytes).decode("ascii"),
            "y": b64url(y_bytes).decode("ascii"),
        }


def get_es256k_key_manager() -> ES256KKeyManager:
    global _ES256K_KEY_MANAGER, _ES256K_KEY_MANAGER_ERROR
    if _ES256K_KEY_MANAGER is not None:
        return _ES256K_KEY_MANAGER
    if _ES256K_KEY_MANAGER_ERROR is not None:
        raise _ES256K_KEY_MANAGER_ERROR

    try:
        _ES256K_KEY_MANAGER = ES256KKeyManager(
            BCF_ES256K_PRIVATE_KEY_PATH, BCF_JWT_KID
        )
        return _ES256K_KEY_MANAGER
    except Exception as e:
        _ES256K_KEY_MANAGER_ERROR = e
        raise


def sign_es256k(
    header_dict: dict, payload_dict: dict, private_key_bytes: bytes
) -> str:
    header_json = _json_dumps_compact(header_dict)
    payload_json = _json_dumps_compact(payload_dict)
    header_b64 = b64url(header_json).decode("ascii")
    payload_b64 = b64url(payload_json).decode("ascii")
    signing_input = f"{header_b64}.{payload_b64}"
    digest = hashlib.sha256(signing_input.encode("ascii")).digest()

    private_key = PrivateKey(private_key_bytes)
    der_sig = private_key.sign(digest, hasher=None)
    cdata = der_to_cdata(der_sig)
    raw_sig = serialize_compact(cdata)
    if len(raw_sig) != 64:
        raise ValueError("Invalid ES256K compact signature length")

    signature_b64 = b64url(raw_sig).decode("ascii")
    return f"{signing_input}.{signature_b64}"


def verify_es256k_signature(
    signing_input: str, signature_raw: bytes, public_key: PublicKey
) -> bool:
    if len(signature_raw) != 64:
        return False

    try:
        digest = hashlib.sha256(signing_input.encode("ascii")).digest()
        cdata = deserialize_compact(signature_raw)
        der_signature = cdata_to_der(cdata)
        return public_key.verify(der_signature, digest, hasher=None)
    except Exception:
        return False


def decode_access_token_parts_without_verify(token: str) -> Optional[dict]:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        signature = _base64url_decode(parts[2])
        return {
            "header": header,
            "payload": payload,
            "signature": signature,
            "signing_input": f"{parts[0]}.{parts[1]}",
        }
    except Exception:
        return None


def decode_access_token_without_verify(token: str) -> Optional[dict]:
    """
    解码 JWT payload（不验证签名），用于日志/调试

    Args:
        token: JWT 格式字符串

    Returns:
        payload dict, 或 None（格式错误时）
    """
    try:
        decoded = decode_access_token_parts_without_verify(token)
        return decoded.get("payload") if decoded else None
    except Exception:
        return None


def verify_access_token(token: str) -> Optional[dict]:
    """
    验证 ES256K JWS 签名并检查过期时间
    """
    try:
        decoded = decode_access_token_parts_without_verify(token)
        if not decoded:
            return None

        header = decoded["header"]
        payload = decoded["payload"]
        signature = decoded["signature"]
        signing_input = decoded["signing_input"]
        alg = str(header.get("alg", "")).upper()

        if alg != BCF_JWT_ALG:
            log_event(
                "BCF", "AUTH", "Unsupported token algorithm",
                level=logging.WARNING,
                alg=alg or "N/A",
            )
            return None

        key_manager = get_es256k_key_manager()
        if header.get("kid") != key_manager.kid:
            log_event(
                "BCF", "AUTH", "Unknown ES256K token kid",
                level=logging.WARNING,
                kid=header.get("kid", ""),
            )
            return None

        if not verify_es256k_signature(
            signing_input, signature, key_manager.public_key
        ):
            log_event(
                "BCF", "AUTH", "ES256K signature verification failed",
                level=logging.WARNING,
                kid=header.get("kid", ""),
            )
            return None

        # 检查过期
        now = int(time.time())
        exp = payload.get("exp")
        if exp is None:
            log_event("BCF", "AUTH", "JWT token missing exp", level=logging.WARNING)
            return None
        if int(exp) < now:
            log_event("BCF", "AUTH", "JWT token expired", level=logging.DEBUG)
            return None

        # 检查 nbf
        if int(payload.get("nbf", 0) or 0) > now:
            log_event("BCF", "AUTH", "JWT token not yet valid", level=logging.DEBUG)
            return None

        return payload
    except Exception as e:
        log_event("BCF", "AUTH", "JWT verification error", level=logging.ERROR, error=str(e))
        return None


# =============================================================================
# BCF Storage - 存储 NF 注册信息和 DID 文档
# =============================================================================

class BCFStorage:
    """
    BCF 存储模拟
    
    存储结构：
    - nf_profiles: nfInstanceId -> 完整 NF Profile（包含 DID 和 DID Document）
    - did_to_nf: DID -> nfInstanceId 映射
    - did_documents: DID -> DID Document
    - did_public_keys: DID -> public key hex string (从 DID Document 中提取)
    """
    
    def __init__(self):
        import threading
        self._lock = threading.RLock()

        # 核心存储
        self.nf_profiles: Dict[str, dict] = {}
        self.did_to_nf: Dict[str, str] = {}
        self.did_documents: Dict[str, dict] = {}
        # DID -> 解码后的公钥 hex (用于验签)
        self.did_public_keys: Dict[str, str] = {}
        # 更详细的公钥信息：存储 multibase 原始字符串、解码 bytes、解码 hex
        # 格式: did -> { 'multibase': str, 'bytes': bytes, 'hex': str }
        self.did_public_keys_info: Dict[str, Dict[str, Any]] = {}

        # BCF 认证会话存储: session_id -> session_info
        self.auth_sessions: Dict[str, dict] = {}
        # BCF 已签发的 token: token_str -> token_info
        self.auth_tokens: Dict[str, dict] = {}
        # 订阅存储: subscription_id -> subscription_info
        # subscription_info: {
        #   "subscriber_nf_did": ..., "notification_uri": ..., "target_nf_type": ..., "created_at_ms": ...
        # }
        self.subscriptions: Dict[str, dict] = {}
        
        # 统计
        self.stats = {
            "registrations": 0,
            "public_key_queries": 0,
            "nf_discovery_queries": 0,
            "auth_triggers": 0,
            "auth_init_requests": 0,
            "auth_verify_requests": 0,
            "auth_successes": 0,
            "auth_failures": 0,
            "start_time": datetime.utcnow().isoformat() + "Z"
        }
        
        # 加载预配置的 NF 实例
        self._load_preconfigured_nfs()
    
    def _load_preconfigured_nfs(self):
        """加载预配置的 NF 实例"""
        if not PRECONFIGURED_NF_INSTANCES:
            log_event(
                "BCF", "STATE", "Registry initialized without preconfigured NF instances",
                registered_nfs=0,
            )
            return
            
        for nf_id, nf_profile in PRECONFIGURED_NF_INSTANCES.items():
            self.nf_profiles[nf_id] = {
                **nf_profile,
                'registrationTime': datetime.utcnow().isoformat() + "Z",
                'lastUpdateTime': datetime.utcnow().isoformat() + "Z"
            }
            
            did = nf_profile.get('did', '')
            if did:
                self.did_to_nf[did] = nf_id
                # 为预配置的 NF 创建简单的 DID 文档
                self.did_documents[did] = {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": did,
                    "verificationMethod": [],
                    "authentication": []
                }
        
        log_event(
            "BCF", "STATE", "Loaded preconfigured NF instances",
            count=len(PRECONFIGURED_NF_INSTANCES),
        )
        for nf_id, nf in PRECONFIGURED_NF_INSTANCES.items():
            summary = summarize_nf_profile({**nf, "nfInstanceId": nf_id})
            log_event("BCF", "STATE", "Preconfigured NF", **summary)
    
    def discover_nf_instances(
        self,
        target_nf_type: Optional[str] = None,
        requester_nf_type: Optional[str] = None,
        target_plmn_mcc: Optional[str] = None,
        target_plmn_mnc: Optional[str] = None,
        target_snssai_sst: Optional[int] = None,
        target_snssai_sd: Optional[str] = None,
        service_name: Optional[str] = None,
        locality: Optional[str] = None,
        max_results: int = 10
    ) -> List[dict]:
        """
        NF 发现 - 根据条件查询 NF 实例
        
        Args:
            target_nf_type: 目标 NF 类型 (AMF, SMF, AUSF, UDM 等)
            requester_nf_type: 请求方 NF 类型
            target_plmn_mcc: 目标 PLMN MCC
            target_plmn_mnc: 目标 PLMN MNC
            target_snssai_sst: 目标 S-NSSAI SST
            target_snssai_sd: 目标 S-NSSAI SD
            service_name: 所需服务名称
            locality: 地理位置
            max_results: 最大返回数量
        
        Returns:
            符合条件的 NF Profile 列表
        """
        with self._lock:
            self.stats["nf_discovery_queries"] += 1
            
            results = []
            
            for nf_id, nf_profile in self.nf_profiles.items():
                # 筛选 NF 类型
                if target_nf_type:
                    if nf_profile.get('nfType', '').upper() != target_nf_type.upper():
                        continue
                
                # 筛选 NF 状态（只返回 REGISTERED 的）
                if nf_profile.get('nfStatus', '').upper() != 'REGISTERED':
                    continue
                
                # 筛选 PLMN
                if target_plmn_mcc and target_plmn_mnc:
                    plmn_list = nf_profile.get('plmnList', [])
                    plmn_match = False
                    for plmn in plmn_list:
                        if plmn.get('mcc') == target_plmn_mcc and plmn.get('mnc') == target_plmn_mnc:
                            plmn_match = True
                            break
                    if not plmn_match:
                        continue
                
                # 筛选 S-NSSAI
                if target_snssai_sst is not None:
                    snssai_list = nf_profile.get('sNssaiList', [])
                    snssai_match = False
                    for snssai in snssai_list:
                        if snssai.get('sst') == target_snssai_sst:
                            if target_snssai_sd:
                                if snssai.get('sd') == target_snssai_sd:
                                    snssai_match = True
                                    break
                            else:
                                snssai_match = True
                                break
                    if not snssai_match:
                        continue
                
                # 筛选服务名称
                if service_name:
                    services = nf_profile.get('nfServices', [])
                    service_match = False
                    for svc in services:
                        if svc.get('serviceName') == service_name:
                            service_match = True
                            break
                    if not service_match:
                        continue
                
                # 筛选地理位置
                if locality:
                    if nf_profile.get('locality', '') != locality:
                        continue
                
                results.append(nf_profile)
                
                if len(results) >= max_results:
                    break
            
            # 按优先级排序（priority 越小越优先）
            results.sort(key=lambda x: x.get('priority', 65535))
            
            log_event(
                "BCF", "DISC", "Found candidates",
                count=len(results),
                target_nf_type=target_nf_type or "ALL",
                requester=requester_nf_type or "N/A",
                service_name=service_name or "N/A",
                plmn=f"{target_plmn_mcc}/{target_plmn_mnc}"
                if target_plmn_mcc and target_plmn_mnc else "N/A",
            )
            for nf_profile in results:
                summary = summarize_nf_profile(nf_profile)
                log_event("BCF", "DISC", "Candidate", **summary)
            
            return results
    
    def register_nf(self, nf_instance_id: str, nf_profile: dict) -> dict:
        """
        注册 NF（处理 AMF 的注册请求）
        """
        with self._lock:
            did = nf_profile.get('did', '')
            did_document = nf_profile.get('didDocument', {})
            nf_type = nf_profile.get('nfType', 'UNKNOWN')
            
            log_debug_json("REG", "raw_profile", nf_profile)
            if 'nfServices' not in nf_profile:
                log_event(
                    "BCF", "REG", "NF profile missing services",
                    level=logging.WARNING,
                    nfInstanceId=nf_instance_id,
                    nfType=nf_type,
                )
            
            # 存储 NF Profile
            stored_profile = {
                **nf_profile,
                'nfInstanceId': nf_instance_id,
                'registrationTime': datetime.utcnow().isoformat() + "Z",
                'lastUpdateTime': datetime.utcnow().isoformat() + "Z",
                'nfStatus': 'REGISTERED'
            }
            self.nf_profiles[nf_instance_id] = stored_profile
            
            # 存储 DID 映射
            if did:
                self.did_to_nf[did] = nf_instance_id
                self.did_documents[did] = did_document
            
            # 从 DID Document 中提取并保存公钥（用于后续验签）
            public_key_hex = ""
            public_key_raw = ""
            public_key_bytes = b''
            if did and did_document:
                verification_methods = did_document.get('verificationMethod', [])
                for vm in verification_methods:
                    if 'publicKeyMultibase' in vm:
                        public_key_raw = vm['publicKeyMultibase']
                        try:
                            public_key_bytes, public_key_hex = decode_public_key_multibase(public_key_raw)
                        except Exception as e:
                            log_event(
                                "BCF", "REG", "Failed to decode public key",
                                level=logging.ERROR,
                                nfInstanceId=nf_instance_id,
                                nfType=nf_type,
                                error=str(e),
                            )
                            public_key_hex = multibase_to_hex(public_key_raw)  # best-effort
                        break
                    elif 'publicKeyHex' in vm:
                        public_key_raw = vm['publicKeyHex']
                        public_key_hex = public_key_raw
                        break
                
                if public_key_hex:
                    self.did_public_keys[did] = public_key_hex
                    # Save detailed info if we have decoded bytes
                    info: Dict[str, Any] = {'multibase': public_key_raw, 'hex': public_key_hex}
                    if 'public_key_bytes' in locals() and isinstance(public_key_bytes, (bytes, bytearray)):
                        info['bytes'] = public_key_bytes
                    elif 'public_key_bytes' in locals():
                        # if decode_public_key_multibase returned str in fallback
                        info['bytes'] = (public_key_bytes.encode('utf-8') if isinstance(public_key_bytes, str) else b'')
                    self.did_public_keys_info[did] = info

                    log_event(
                        "BCF", "REG", "Stored public key",
                        nfInstanceId=nf_instance_id,
                        nfType=nf_type,
                        did=shorten(did, 48),
                        key_len=len(info.get('bytes', b'')),
                        key_prefix=shorten(public_key_hex, 24),
                    )
                    log_event(
                        "BCF", "REG", "Public key payload",
                        level=logging.DEBUG,
                        nfInstanceId=nf_instance_id,
                        public_key_multibase=shorten(public_key_raw, 80),
                        public_key_hex=shorten(public_key_hex, 80),
                    )
                else:
                    log_event(
                        "BCF", "REG", "No public key found in DID document",
                        level=logging.WARNING,
                        nfInstanceId=nf_instance_id,
                        nfType=nf_type,
                        did=shorten(did, 48),
                    )
            
            self.stats["registrations"] += 1

            summary = summarize_nf_profile(stored_profile)
            log_event("BCF", "REG", "Stored NF profile", **summary)
            log_event(
                "BCF", "REG", "State -> REGISTERED",
                nfInstanceId=nf_instance_id,
                nfType=nf_type,
                did=shorten(did, 48),
            )
            log_event(
                "BCF", "STATE", "NF REGISTERED",
                nfInstanceId=nf_instance_id,
                nfType=nf_type,
                plmn=summary.get("plmn"),
                services=summary.get("services"),
            )
            
            return stored_profile
    
    def get_public_key_by_did(self, did: str) -> Optional[dict]:
        """
        根据 DID 查询公钥
        
        响应格式需要与 AMF 的 public_key_response_t 结构对应:
        - found: bool
        - did: string
        - public_key: string (十六进制格式)
        - nf_type: string
        - nf_instance_id: string
        - error_message: string
        """
        with self._lock:
            self.stats["public_key_queries"] += 1
            
            # 首先检查是否在已注册的 DID 中
            if did in self.did_documents:
                did_doc = self.did_documents[did]
                verification_methods = did_doc.get('verificationMethod', [])
                
                if verification_methods:
                    vm = verification_methods[0]
                    public_key = None
                    
                    # 支持多种公钥格式
                    if 'publicKeyMultibase' in vm:
                        public_key = vm['publicKeyMultibase']
                        # 如果是 multibase 格式，移除前缀 'z' (base58btc)
                        if public_key.startswith('z'):
                            # 保持原样，AMF 会处理
                            pass
                    elif 'publicKeyHex' in vm:
                        public_key = vm['publicKeyHex']
                    elif 'publicKeyBase58' in vm:
                        public_key = vm['publicKeyBase58']
                    
                    if public_key:
                        # 获取关联的 NF 信息
                        nf_type = ""
                        nf_instance_id = ""
                        if did in self.did_to_nf:
                            nf_instance_id = self.did_to_nf[did]
                            if nf_instance_id in self.nf_profiles:
                                nf = self.nf_profiles[nf_instance_id]
                                nf_type = nf.get("nfType", "")
                        
                        log_event(
                            "BCF", "AUTH", "Public key query success",
                            did=shorten(did, 48),
                            nfType=nf_type or "N/A",
                            nfInstanceId=nf_instance_id or "N/A",
                        )
                        
                        # 返回与 public_key_response_t 对应的格式
                        return {
                            "found": True,
                            "did": did,
                            "public_key": public_key,
                            "nf_type": nf_type,
                            "nf_instance_id": nf_instance_id,
                            "error_message": ""
                        }
            
            # 如果 DID 是新格式 did:oai5gc:<binding_hash>:<public_key_hex>，从 DID 提取公钥
            # 新格式: did:oai5gc:<32字符binding_hash>:<公钥十六进制>
            # 旧格式: did:oai5gc:<public_key_hex> (用于向后兼容)
            if did.startswith("did:oai5gc:") and len(did) > 11:
                did_suffix = did[11:]  # 跳过 "did:oai5gc:"
                
                # 检查是否是新格式（包含冒号分隔符）
                if ':' in did_suffix:
                    parts = did_suffix.split(':', 1)
                    if len(parts) == 2:
                        binding_hash = parts[0]
                        public_key_hex = parts[1]
                        
                        # 验证 binding_hash 是 32 字符的十六进制
                        if len(binding_hash) == 32 and all(c in '0123456789abcdefABCDEF' for c in binding_hash):
                            # 验证公钥格式（压缩格式 33 字节或非压缩格式 65 字节）
                            if len(public_key_hex) >= 66 and all(c in '0123456789abcdefABCDEF' for c in public_key_hex):
                                log_event(
                                    "BCF", "AUTH", "Public key extracted from DID",
                                    did=shorten(did, 56),
                                    format="NEW",
                                    binding_hash=binding_hash,
                                    public_key=shorten(public_key_hex, 32),
                                )
                                return {
                                    "found": True,
                                    "did": did,
                                    "public_key": public_key_hex,
                                    "nf_type": "",
                                    "nf_instance_id": "",
                                    "error_message": ""
                                }
                
                # 旧格式: did:oai5gc:<public_key_hex> (向后兼容)
                public_key_hex = did_suffix
                
                # 验证是否看起来像有效的十六进制公钥
                if len(public_key_hex) >= 64 and all(c in '0123456789abcdefABCDEF' for c in public_key_hex):
                    log_event(
                        "BCF", "AUTH", "Public key extracted from DID",
                        did=shorten(did, 48),
                        format="LEGACY",
                        public_key=shorten(public_key_hex, 32),
                    )
                    return {
                        "found": True,
                        "did": did,
                        "public_key": public_key_hex,
                        "nf_type": "",
                        "nf_instance_id": "",
                        "error_message": ""
                    }
            
            log_event(
                "BCF", "AUTH", "Public key query not found",
                level=logging.WARNING,
                did=shorten(did, 48),
            )
            return {
                "found": False,
                "did": did,
                "public_key": "",
                "nf_type": "",
                "nf_instance_id": "",
                "error_message": f"DID not registered: {did}"
            }
    
    def get_did_document(self, did: str) -> Optional[dict]:
        """获取完整的 DID 文档"""
        with self._lock:
            return self.did_documents.get(did)
    
    def get_nf_instance(self, nf_instance_id: str) -> Optional[dict]:
        """获取 NF 实例"""
        with self._lock:
            return self.nf_profiles.get(nf_instance_id)
    
    def get_all_nf_instances(self, nf_type: Optional[str] = None) -> List[dict]:
        """获取所有 NF 实例"""
        with self._lock:
            if nf_type:
                return [nf for nf in self.nf_profiles.values() 
                        if nf.get('nfType') == nf_type]
            return list(self.nf_profiles.values())
    
    def update_nf_status(self, nf_instance_id: str, patch_data: dict) -> Optional[dict]:
        """更新 NF 状态（心跳）"""
        with self._lock:
            if nf_instance_id not in self.nf_profiles:
                return None
            
            nf = self.nf_profiles[nf_instance_id]
            nf['lastUpdateTime'] = datetime.utcnow().isoformat() + "Z"
            
            for key, value in patch_data.items():
                if key in ['nfStatus', 'load']:
                    nf[key] = value

            summary = summarize_nf_profile(nf)
            log_event(
                "BCF", "STATE", "NF UPDATED",
                nfInstanceId=nf_instance_id,
                nfType=summary.get("nfType"),
                nfStatus=nf.get("nfStatus", "UNKNOWN"),
                load=nf.get("load"),
            )
            
            return nf
    
    def deregister_nf(self, nf_instance_id: str) -> bool:
        """注销 NF"""
        with self._lock:
            if nf_instance_id not in self.nf_profiles:
                return False
            
            nf = self.nf_profiles[nf_instance_id]
            did = nf.get('did')
            
            del self.nf_profiles[nf_instance_id]
            
            if did:
                self.did_to_nf.pop(did, None)
                self.did_documents.pop(did, None)
                self.did_public_keys.pop(did, None)
                self.did_public_keys_info.pop(did, None)

            # 清理与该 NF 相关的认证会话与 token
            sessions_to_delete = [
                session_id for session_id, session in self.auth_sessions.items()
                if session.get('nf_instance_id') == nf_instance_id or
                (did and session.get('nf_did') == did)
            ]
            for session_id in sessions_to_delete:
                del self.auth_sessions[session_id]

            tokens_to_delete = [
                token for token, token_info in self.auth_tokens.items()
                if token_info.get('nf_instance_id') == nf_instance_id or
                (did and token_info.get('nf_did') == did)
            ]
            for token in tokens_to_delete:
                del self.auth_tokens[token]
            
            log_event(
                "BCF", "STATE", "NF DEREGISTERED",
                nfInstanceId=nf_instance_id,
                nfType=nf.get("nfType", "UNKNOWN"),
            )
            return True

    # =============================================================================
    # Subscription helpers
    # =============================================================================

    def list_subscriptions_for_target(self, target_nf_type: Optional[str] = None) -> List[dict]:
        """Return subscriptions that are interested in a given target_nf_type (or all)."""
        with self._lock:
            out = []
            for sub in self.subscriptions.values():
                t = sub.get('target_nf_type') or ''
                if not t or not target_nf_type:
                    out.append(sub)
                else:
                    if t.upper() == target_nf_type.upper():
                        out.append(sub)
            return out

    def is_nf_authenticated(self, nf_instance_id: str) -> bool:
        """检查 NF 当前是否已完成认证且 token 仍有效。"""
        with self._lock:
            now_ms = int(time.time() * 1000)
            expired_tokens = []

            for token, token_info in self.auth_tokens.items():
                if token_info.get('expires_at_ms', 0) <= now_ms:
                    expired_tokens.append(token)
                    continue

                token_nf_instance_id = token_info.get('nf_instance_id') or \
                    token_info.get('claims', {}).get('sub', '')
                if token_nf_instance_id == nf_instance_id:
                    return True

            for token in expired_tokens:
                del self.auth_tokens[token]

            return False

    # =========================================================================
    # BCF 认证方法
    # =========================================================================

    def create_auth_session(self, nf_did: str, nf_type: str,
                            nf_instance_id: str,
                            target_nf_types: Optional[List[str]] = None) -> dict:
        """
        创建 BCF 自身认证会话，生成 challenge

        NF 向 BCF 发起自身认证，BCF 生成 challenge 供 NF 签名。

        Returns:
            challenge 响应 dict，包含 session_id, challenge 等
        """
        with self._lock:
            self.stats["auth_init_requests"] += 1

            session_id = secrets.token_hex(16)
            challenge = secrets.token_hex(32)  # 256-bit nonce
            now_ms = int(time.time() * 1000)
            # challenge 有效期 60 秒
            expires_ms = now_ms + 60000

            session = {
                "session_id": session_id,
                "nf_did": nf_did,
                "nf_type": nf_type,
                "nf_instance_id": nf_instance_id,
                "target_nf_types": resolve_target_nf_types_for_request(
                    nf_type, target_nf_types
                ),
                "challenge": challenge,
                "challenge_expires_ms": expires_ms,
                "created_at_ms": now_ms,
                "state": "CHALLENGE_ISSUED"
            }
            self.auth_sessions[session_id] = session

            log_event(
                "BCF", "AUTH", "Challenge issued",
                session_id=session_id,
                nfType=nf_type,
                nfInstanceId=nf_instance_id,
                aud=session["target_nf_types"],
                did=shorten(nf_did, 48),
                expires_ms=expires_ms,
                challenge=shorten(challenge, 24),
            )

            return {
                "session_id": session_id,
                "challenge": challenge,
                "challenge_expires_ms": expires_ms,
                "timestamp_ms": now_ms
            }

    def verify_auth_challenge(self, session_id: str, nf_did: str,
                               challenge_signature: str) -> dict:
        """
        验证 NF 对 challenge 的签名，签发 auth token (self-auth 模型)

        严格验签：
        1. 检查 session 存在且未过期
        2. 检查 nf_did 与 session 中一致
        3. 从 did_public_keys 中查找注册时保存的公钥
        4. 使用 secp256k1 真实验签（coincurve 或 ecdsa 库）
        5. 验签失败必须返回失败，不允许 mock 放行

        Returns:
            认证结果 dict
        """
        with self._lock:
            self.stats["auth_verify_requests"] += 1
            now_ms = int(time.time() * 1000)

            # 查找 session
            session = self.auth_sessions.get(session_id)
            if not session:
                log_event(
                    "BCF", "AUTH", "Verify failed",
                    level=logging.ERROR,
                    session_id=session_id,
                    error_code="SESSION_NOT_FOUND",
                )
                self.stats["auth_failures"] += 1
                return {
                    "success": False,
                    "session_id": session_id,
                    "error_code": "SESSION_NOT_FOUND",
                    "error_message": "Authentication session not found",
                    "timestamp_ms": now_ms
                }

            # 检查 session 是否过期
            if now_ms > session["challenge_expires_ms"]:
                log_event(
                    "BCF", "AUTH", "Verify failed",
                    level=logging.ERROR,
                    session_id=session_id,
                    error_code="CHALLENGE_EXPIRED",
                )
                del self.auth_sessions[session_id]
                self.stats["auth_failures"] += 1
                return {
                    "success": False,
                    "session_id": session_id,
                    "error_code": "CHALLENGE_EXPIRED",
                    "error_message": "Challenge has expired",
                    "timestamp_ms": now_ms
                }

            # 检查 nf_did 一致性
            if nf_did != session["nf_did"]:
                log_event(
                    "BCF", "AUTH", "Verify failed",
                    level=logging.ERROR,
                    session_id=session_id,
                    error_code="DID_MISMATCH",
                    request_did=shorten(nf_did, 40),
                    session_did=shorten(session["nf_did"], 40),
                )
                self.stats["auth_failures"] += 1
                return {
                    "success": False,
                    "session_id": session_id,
                    "error_code": "DID_MISMATCH",
                    "error_message": "NF DID does not match session",
                    "timestamp_ms": now_ms
                }

            nf_instance_id = session.get("nf_instance_id", "")
            if not nf_instance_id:
                nf_instance_id = self.did_to_nf.get(nf_did, "")
            was_authenticated = bool(
                nf_instance_id and self.is_nf_authenticated(nf_instance_id)
            )

            # 检查签名非空
            if not challenge_signature:
                log_event(
                    "BCF", "AUTH", "Verify failed",
                    level=logging.ERROR,
                    session_id=session_id,
                    error_code="INVALID_SIGNATURE",
                )
                self.stats["auth_failures"] += 1
                return {
                    "success": False,
                    "session_id": session_id,
                    "error_code": "INVALID_SIGNATURE",
                    "error_message": "Challenge signature is empty",
                    "timestamp_ms": now_ms
                }

            # 真实签名验证（不再有 mock 放行）
            verify_result = self._verify_signature(
                nf_did, session.get("challenge", ""), challenge_signature)

            if not verify_result.get("verified", False):
                log_event(
                    "BCF", "AUTH", "Verify failed",
                    level=logging.ERROR,
                    session_id=session_id,
                    nfInstanceId=nf_instance_id or "N/A",
                    error_code="SIGNATURE_INVALID",
                    failure_reason=verify_result.get("reason", "signature verify returned false"),
                )
                self.stats["auth_failures"] += 1
                return {
                    "success": False,
                    "session_id": session_id,
                    "error_code": "SIGNATURE_INVALID",
                    "error_message": "Challenge signature verification failed",
                    "timestamp_ms": now_ms
                }

            # 签名验证通过，签发 JWT-style access token
            expires_in = BCF_TOKEN_EXPIRES_IN  # 1 小时
            now_s = int(now_ms / 1000)
            expires_at_ms = now_ms + (expires_in * 1000)
            token_jti = str(uuid.uuid4())

            # sub 使用 NF Instance ID（3GPP AccessTokenClaims 语义）
            # nf_did 作为扩展 claim 保留
            # 如果 session 中没有 nf_instance_id，尝试从 did_to_nf 映射获取
            if not nf_instance_id:
                nf_instance_id = self.did_to_nf.get(nf_did, nf_did)

            target_nf_types = resolve_target_nf_types_for_request(
                session.get("nf_type"), session.get("target_nf_types")
            )
            token_claims = {
                "iss": BCF_JWT_ISSUER,
                "sub": nf_instance_id,
                "aud": target_nf_types,
                "scope": generate_scope_for_targets(target_nf_types),
                "exp": now_s + expires_in,
                "iat": now_s,
                "nbf": now_s,
                "jti": token_jti,
                "nf_type": session["nf_type"],
                "nf_did": nf_did,
                "session_id": session_id
            }

            key_manager = get_es256k_key_manager()
            token_header = {
                "alg": BCF_JWT_ALG,
                "typ": "JWT",
                "kid": key_manager.kid,
            }
            log_event("BCF", "Token", "Signing ES256K token")
            log_event(
                "BCF", "Token", "Token header",
                alg=BCF_JWT_ALG,
                kid=key_manager.kid,
            )
            log_event(
                "BCF", "Token", "Token claims",
                iss=token_claims.get("iss"),
                sub=token_claims.get("sub"),
                aud=token_claims.get("aud"),
                scope=token_claims.get("scope"),
            )
            auth_token = sign_es256k(
                token_header, token_claims, key_manager.private_key_bytes
            )

            # 存储 token（以 jti 为内部索引，token 字符串为查找键）
            self.auth_tokens[auth_token] = {
                "token": auth_token,
                "jti": token_jti,
                "session_id": session_id,
                "nf_did": nf_did,
                "nf_instance_id": nf_instance_id,
                "nf_type": session["nf_type"],
                "target_nf_types": target_nf_types,
                "issued_at_ms": now_ms,
                "expires_at_ms": expires_at_ms,
                "claims": token_claims
            }

            # 清理已完成的 session
            session["state"] = "COMPLETED"
            del self.auth_sessions[session_id]

            self.stats["auth_successes"] += 1

            log_event(
                "BCF", "AUTH", "Verify success",
                session_id=session_id,
                nfInstanceId=nf_instance_id,
                nfType=session["nf_type"],
                token_jti=token_jti,
                aud=token_claims["aud"],
                scope=token_claims["scope"],
                expires_in=expires_in,
            )

            return {
                "success": True,
                "session_id": session_id,
                "access_token": auth_token,
                "auth_token": auth_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "expires_at_ms": expires_at_ms,
                "newly_authenticated": not was_authenticated,
                "nf_instance_id": nf_instance_id,
                "nf_did": nf_did,
                "timestamp_ms": now_ms
            }

    def _verify_signature(self, nf_did: str, challenge_hex: str,
                          signature_hex: str) -> Dict[str, Any]:
        """
        验证 NF 对 challenge 的 secp256k1 签名（真实验签，无 mock 模式）

        验签规则（与客户端 sign_nonce_with_logging 完全一致）：
        1. challenge_hex -> bytes.fromhex() -> challenge_bytes
        2. SHA256(challenge_bytes) -> hash (32 bytes)
        3. 使用 DID 对应公钥对 hash 进行 ECDSA secp256k1 验签
        4. 签名格式为 DER

        公钥来源：注册时从 DID Document 提取并保存到 self.did_public_keys
        公钥格式：压缩 secp256k1 (33 bytes hex) 或非压缩 (65 bytes hex)
        """
        verify_result: Dict[str, Any] = {
            "verified": False,
            "reason": "signature verify returned false",
            "verify_mode": "sha256(challenge_bytes)",
        }

        def fail(reason: str, msg: str, *, level: int = logging.ERROR,
                 possible_cause: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
            verify_result["reason"] = reason
            log_event("BCF", "AUTH", msg, level=level, **kwargs)
            if possible_cause:
                log_event(
                    "BCF", "AUTH",
                    "Verify failed: possible cause = signed payload mismatch (raw bytes / hex string / double-hash)",
                    level=logging.ERROR,
                    failure_reason=reason,
                    possible_cause=possible_cause,
                )
            return verify_result

        # 1. 查找注册时保存的公钥
        public_key_hex = self.did_public_keys.get(nf_did, "")
        if not public_key_hex:
            return fail(
                "public key invalid",
                "Public key lookup failed",
                did=shorten(nf_did, 48),
            )
        log_event(
            "BCF", "AUTH", "Public key lookup success",
            did=shorten(nf_did, 48),
            public_key_hex=format_hex_for_log(public_key_hex),
        )

        # 2. 解码 challenge 和 signature
        try:
            challenge_hex_normalized, challenge_bytes = decode_hex_field(
                "session challenge", challenge_hex
            )
        except ValueError as exc:
            reason = "session challenge missing" if "empty" in str(exc).lower() else "challenge encoding mismatch suspected"
            return fail(
                reason,
                "Session challenge missing or invalid",
                error=str(exc),
                possible_cause="challenge raw bytes vs hex-string mismatch",
            )

        try:
            signature_hex_normalized, sig_bytes = decode_hex_field(
                "challenge_signature", signature_hex
            )
        except ValueError as exc:
            return fail(
                "signature format invalid",
                "Signature payload invalid",
                error=str(exc),
            )

        log_event(
            "BCF", "AUTH", "Verify input prepared",
            level=logging.DEBUG,
            challenge_bytes_len=len(challenge_bytes),
            challenge_bytes_hex=format_hex_for_log(challenge_hex_normalized, head=128, tail=32),
        )
        log_event(
            "BCF", "AUTH", "Signature payload",
            level=logging.DEBUG,
            signature_der_hex=format_hex_for_log(signature_hex_normalized, head=160, tail=32),
            signature_der_bytes_len=len(sig_bytes),
        )

        # Prefer previously decoded bytes saved at registration time
        pk_bytes = None
        info = self.did_public_keys_info.get(nf_did)
        if info and 'bytes' in info and isinstance(info['bytes'], (bytes, bytearray)):
            pk_bytes = bytes(info['bytes'])
            log_event(
                "BCF", "AUTH", "Using stored public key bytes",
                level=logging.DEBUG,
                bytes_len=len(pk_bytes),
            )
        else:
            try:
                _, pk_bytes = decode_hex_field("public key", public_key_hex)
            except ValueError as exc:
                return fail(
                    "public key invalid",
                    "Invalid public key encoding",
                    error=str(exc),
                )

        public_key_log_hex = pk_bytes.hex()
        log_event(
            "BCF", "AUTH", "Public key prepared",
            level=logging.DEBUG,
            public_key_hex=format_hex_for_log(public_key_log_hex, head=160, tail=32),
            public_key_bytes_len=len(pk_bytes),
        )

        # 3. SHA256(challenge_bytes)
        challenge_hash = hashlib.sha256(challenge_bytes).digest()
        log_event(
            "BCF", "AUTH", "Computed challenge hash",
            level=logging.DEBUG,
            challenge_hash=challenge_hash.hex(),
        )
        log_event(
            "BCF", "AUTH", "Verify mode",
            level=logging.DEBUG,
            verify_input="sha256(challenge_bytes)",
            hasher="None",
        )

        # 4. 尝试使用 coincurve 进行真实验签
        try:
            pubkey = PublicKey(pk_bytes)
        except Exception as exc:
            return fail(
                "public key invalid",
                "Invalid public key object",
                error=str(exc),
            )

        try:
            verified = pubkey.verify(sig_bytes, challenge_hash, hasher=None)
            log_event(
                "BCF", "AUTH", "Signature verification via coincurve",
                result="SUCCESS" if verified else "FAILED",
            )
        except Exception as exc:
            reason = "signature format invalid"
            error_text = str(exc)
            lowered = error_text.lower()
            if "pub" in lowered or "key" in lowered or "point" in lowered:
                reason = "public key invalid"
            return fail(
                reason,
                "coincurve verification error",
                error=error_text,
                possible_cause="prehash/double-hash mismatch",
            )

        if verified:
            verify_result["verified"] = True
            verify_result["reason"] = ""
            return verify_result

        diagnostic_hex_string = "N/A"
        diagnostic_double_hash = "N/A"
        try:
            hex_ascii_bytes = challenge_hex_normalized.encode("ascii")
            diagnostic_hex_string = (
                "SUCCESS" if pubkey.verify(sig_bytes, hex_ascii_bytes) else "FAILED"
            )
        except Exception as exc:
            diagnostic_hex_string = f"ERROR:{shorten(exc, 48)}"

        try:
            diagnostic_double_hash = (
                "SUCCESS" if pubkey.verify(sig_bytes, challenge_hash) else "FAILED"
            )
        except Exception as exc:
            diagnostic_double_hash = f"ERROR:{shorten(exc, 48)}"

        log_event(
            "BCF", "AUTH", "Verify diagnostics",
            level=logging.ERROR,
            diagnostic_hex_string=diagnostic_hex_string,
            diagnostic_double_hash=diagnostic_double_hash,
        )

        try:
            import ecdsa
        except ImportError:
            pass
        else:
            try:
                if len(pk_bytes) == 33:
                    vk = ecdsa.VerifyingKey.from_string(
                        pk_bytes, curve=ecdsa.SECP256k1
                    )
                elif len(pk_bytes) == 65 and pk_bytes[0] == 0x04:
                    vk = ecdsa.VerifyingKey.from_string(
                        pk_bytes[1:], curve=ecdsa.SECP256k1
                    )
                elif len(pk_bytes) == 64:
                    vk = ecdsa.VerifyingKey.from_string(
                        pk_bytes, curve=ecdsa.SECP256k1
                    )
                else:
                    vk = None

                if vk is not None:
                    fallback_verified = vk.verify_digest(
                        sig_bytes,
                        challenge_hash,
                        sigdecode=ecdsa.util.sigdecode_der,
                    )
                    log_event(
                        "BCF", "AUTH", "Signature verification via ecdsa",
                        result="SUCCESS" if fallback_verified else "FAILED",
                    )
                    if fallback_verified:
                        verify_result["verified"] = True
                        verify_result["reason"] = ""
                        return verify_result
            except ecdsa.BadSignatureError:
                log_event(
                    "BCF", "AUTH", "Signature verification via ecdsa failed",
                    level=logging.ERROR,
                    error="bad_signature",
                )
            except Exception as exc:
                log_event(
                    "BCF", "AUTH", "Signature verification via ecdsa error",
                    level=logging.ERROR,
                    error=str(exc),
                )

        if diagnostic_hex_string == "SUCCESS" or diagnostic_double_hash == "SUCCESS":
            return fail(
                "challenge encoding mismatch suspected",
                "Signature verification via coincurve returned false",
                possible_cause="challenge raw bytes vs hex-string mismatch or prehash/double-hash mismatch",
            )

        return fail(
            "signature verify returned false",
            "Signature verification via coincurve returned false",
            possible_cause="AMF/BCF signed payload mismatch or prehash/double-hash mismatch",
        )

    def validate_token(self, token: str) -> Optional[dict]:
        """
        验证 BCF 签发的 JWT access token 是否有效

        优先使用 JWT 签名验证；同时检查内存存储（防止已撤销的 token 通过）
        """
        with self._lock:
            # 1. 检查内存存储中是否存在（防止已撤销的 token）
            entry = self.auth_tokens.get(token)
            if not entry:
                # token 不在存储中（可能已被清理或撤销）
                # 仍尝试 JWT 解码，提供信息性错误
                claims = decode_access_token_without_verify(token)
                if claims:
                    log_event(
                        "BCF", "AUTH", "Token has valid JWT format but is not active",
                        level=logging.DEBUG,
                        sub=claims.get("sub", "N/A"),
                    )
                return None

            # 2. JWT 签名验证
            claims = verify_access_token(token)
            if not claims:
                log_event(
                    "BCF", "AUTH", "Stored token failed verification and was removed",
                    level=logging.WARNING,
                )
                del self.auth_tokens[token]
                return None

            # 3. 过期检查（双重保险：JWT exp + 存储 expires_at_ms）
            now_ms = int(time.time() * 1000)
            if now_ms > entry["expires_at_ms"]:
                del self.auth_tokens[token]
                return None

            return entry
    
    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._lock:
            return {
                **self.stats,
                "registered_nfs": len(self.nf_profiles),
                "registered_dids": len(self.did_documents),
                "active_auth_sessions": len(self.auth_sessions),
                "issued_tokens": len(self.auth_tokens),
                "nf_types": list(set(nf.get('nfType', 'UNKNOWN') 
                                    for nf in self.nf_profiles.values()))
            }


# Global storage
storage = BCFStorage()


# =============================================================================
# 模拟请求方 NF
# =============================================================================

class MockRequesterNF:
    """模拟请求方 NF（如 SMF）"""
    
    def __init__(self):
        self.did = "did:oai5gc:mock:smf:test001"
        self.nf_type = "SMF"
        self.nf_instance_id = "mock-smf-001"
        self.private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        self.public_key_hex = "04" + "a" * 64 + "b" * 64
        
    def generate_auth_request(self, target_did: str = "") -> dict:
        """生成认证请求"""
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        sign_data = f"{self.did}|{target_did}|{nonce}|{timestamp}"
        signature = hashlib.sha256(
            (sign_data + self.private_key_hex).encode()
        ).hexdigest()
        
        return {
            "initiator_did": self.did,
            "nonce": nonce,
            "timestamp": timestamp,
            "nf_type": self.nf_type,
            "signature": signature
        }
    
    def get_registration_profile(self) -> dict:
        """获取注册 profile"""
        return {
            "nfType": self.nf_type,
            "nfInstanceId": self.nf_instance_id,
            "did": self.did,
            "didDocument": {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/secp256k1-2019/v1"
                ],
                "id": self.did,
                "controller": self.did,
                "verificationMethod": [{
                    "id": f"{self.did}#key-1",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": self.did,
                    "publicKeyHex": self.public_key_hex
                }],
                "authentication": [f"{self.did}#key-1"],
                "assertionMethod": [f"{self.did}#key-1"]
            },
            "nfStatus": "REGISTERED",
            "ipv4Addresses": ["192.168.70.133"],
            "heartBeatTimer": 50
        }


mock_requester = MockRequesterNF()


# =============================================================================
# URL 路径兼容 - 主路径使用下划线风格 nf_instances
# 
# 主路径（下划线风格）:
#   /nbcf_management/v1/nf_instances/
#   /nbcf_nfm/v1/nf_instances/
# 
# 兼容路径（连字符风格，向后兼容）:
#   /nbcf_management/v1/nf-instances/
#   /nbcf_management/v1/nf-instances/
#   /nbcf-nfm/v1/nf-instances/
# 
# 通过双重路由装饰器同时支持两种格式。
# =============================================================================


# =============================================================================
# HTTP/2 Routes
# =============================================================================

@app.before_request
async def log_request():
    """Initialize request trace context and log compact request metadata."""
    request_id = extract_request_id()
    stage = detect_request_stage(request.path, request.method)
    REQUEST_ID_CTX.set(request_id)
    REQUEST_STAGE_CTX.set(stage)
    REQUEST_START_MS_CTX.set(now_ms())

    log_event(
        "BCF", stage, "Request received",
        method=request.method,
        path=request.path,
        remote=request.headers.get("X-Forwarded-For") or request.remote_addr or "N/A",
    )
    try:
        data = await request.get_data(as_text=True)
        if data:
            payload = data[:1000] if len(data) > 1000 else data
            log_event(
                "BCF", stage, "Request body",
                level=logging.DEBUG,
                body=payload,
            )
    except Exception:
        pass


@app.after_request
async def add_cors_headers(response):
    """Add CORS headers"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
    request_id = current_request_id()
    if request_id:
        response.headers['X-Request-ID'] = request_id
    start_ms = REQUEST_START_MS_CTX.get(0)
    if start_ms:
        log_event(
            "BCF", current_request_stage(), "Request completed",
            level=logging.DEBUG,
            status=response.status_code,
            duration_ms=max(0, now_ms() - start_ms),
        )
    return response


# =============================================================================
# NF Management Endpoints
# =============================================================================

@app.route('/nbcf_management/v1/nf_instances/<nf_instance_id>', methods=['PUT'])
@app.route('/nbcf_management/v1/nf-instances/<nf_instance_id>', methods=['PUT'])
@app.route('/nbcf_management/v1/nf-instances/<nf_instance_id>', methods=['PUT'])
@app.route('/nbcf_management/v1/nf_instances/<nf_instance_id>', methods=['PUT'])
async def register_nf(nf_instance_id: str):
    """
    NF 注册 - AMF 发送的注册请求
    PUT /nbcf_management/v1/nf_instances/{nfInstanceId}
    """
    try:
        data = await request.get_json(force=True)
    except Exception as e:
        log_event("BCF", "REG", "Invalid registration JSON", level=logging.ERROR, error=str(e))
        return jsonify({"error": "invalid_json", "message": str(e)}), 400
    log_event(
        "BCF", "REG", "Received NF registration",
        nfType=data.get('nfType', 'N/A'),
        nfInstanceId=nf_instance_id,
        did=shorten(data.get('did', 'N/A'), 48),
    )
    log_debug_json("REG", "raw_profile", data)
    
    result = storage.register_nf(nf_instance_id, data)
    
    response = Response(
        json.dumps(result, indent=2),
        status=201,
        mimetype='application/json'
    )
    response.headers['Location'] = f'/nbcf_management/v1/nf_instances/{nf_instance_id}'

    log_event(
        "BCF", "REG", "Registration response sent",
        status=201,
        nfInstanceId=nf_instance_id,
        location=response.headers['Location'],
    )
    log_event(
        "BCF", "SUB", "Notification deferred until verify succeeds",
        level=logging.DEBUG,
        event="TARGET_NF_REGISTERED",
        nfInstanceId=nf_instance_id,
    )

    return response


@app.route('/nbcf_management/v1/nf_instances', methods=['GET'])
@app.route('/nbcf_management/v1/nf-instances', methods=['GET'])
@app.route('/nbcf_management/v1/nf-instances', methods=['GET'])
@app.route('/nbcf_management/v1/nf_instances', methods=['GET'])
async def get_nf_instances():
    """获取所有 NF 实例"""
    nf_type = request.args.get('nf_type')
    instances = storage.get_all_nf_instances(nf_type)
    return jsonify(instances)


@app.route('/nbcf_management/v1/subscriptions', methods=['POST'])
@app.route('/nbcf_management/v1/subscriptions', methods=['POST'])
@app.route('/nbcf_management/v1/subscription', methods=['POST'])
async def create_subscription():
    """
    Create subscription endpoint - minimal mock implementation
    POST /nbcf_management/v1/subscriptions
    Body: see bcf_subscription_request_t
    Returns: {"success": true, "subscription_id": "...", "target_nf_list": [...]}
    """
    try:
        data = await request.get_json(force=True)
    except Exception as e:
        log_event("BCF", "SUB", "Invalid subscription JSON", level=logging.ERROR, error=str(e))
        return jsonify({"success": False, "error_message": "invalid_json"}), 400

    # Validate Authorization header (optional) - accept Bearer tokens
    auth = request.headers.get('Authorization', '')
    token = None
    if auth.startswith('Bearer '):
        token = auth[len('Bearer '):].strip()

    # Very small validation: token must be known and valid
    payload = None
    if token:
        entry = storage.validate_token(token)
        payload = entry.get("claims") if entry else None

    notification_uri = data.get('notification_uri', '')
    if notification_uri and \
            not notification_uri.lower().startswith('http://') and \
            not notification_uri.lower().startswith('https://'):
        notification_uri = 'http://' + notification_uri
    notification_transport = resolve_notification_transport(
        data.get('notification_transport'),
        fallback=DEFAULT_NOTIFICATION_TRANSPORT,
    )

    log_event(
        "BCF", "SUB", "Create subscription",
        subscriber=data.get('subscriber_nf_type', '') or shorten(data.get('subscriber_nf_did', ''), 24) or "UNKNOWN",
        target=data.get('target_nf_type', '') or "ANY",
        notification_uri=notification_uri or "N/A",
        notification_transport=notification_transport,
        authorized=bool(payload),
    )

    # Build subscription record
    sub_id = uuid.uuid4().hex
    sub = {
        'subscription_id': sub_id,
        'subscriber_nf_did': data.get('subscriber_nf_did', ''),
        'subscriber_nf_type': data.get('subscriber_nf_type', ''),
        'subscriber_nf_instance_id': data.get('subscriber_nf_instance_id', ''),
        'notification_uri': notification_uri,
        'notification_transport': notification_transport,
        'target_nf_type': data.get('target_nf_type', ''),
        'created_at_ms': int(time.time() * 1000),
        'token_payload': payload
    }

    with storage._lock:
        storage.subscriptions[sub_id] = sub

    # Build target_nf_list by querying storage for matching, REGISTERED and authenticated NFs
    try:
        # Determine requested target type
        target_type = sub.get('target_nf_type') or None
        # Use discovery API to get full profiles (discover_nf_instances returns full profiles)
        candidates = storage.discover_nf_instances(target_nf_type=target_type, max_results=100)
        log_event(
            "BCF", "SUB", "Found discovery candidates for subscription",
            count=len(candidates),
            target_nf_type=target_type or "ANY",
        )

        # Filter candidates: require REGISTERED status and successful BCF authentication
        target_nf_list = []
        for nf in candidates:
            nf_id = nf.get('nfInstanceId') or nf.get('nf_instance_id') or ''
            if not nf_id:
                continue
            if str(nf.get('nfStatus', '')).upper() != 'REGISTERED':
                continue
            if storage.is_nf_authenticated(nf_id):
                target_nf_list.append(nf)

        resp = {
            'success': True,
            'subscription_id': sub_id,
            'notification_transport': notification_transport,
            'target_nf_list': target_nf_list
        }
    except Exception as e:
        log_exception("BCF", "SUB", "Failed to build target NF list", error=str(e))
        resp = {
            'success': True,
            'subscription_id': sub_id,
            'notification_transport': notification_transport,
            'target_nf_list': []
        }

    log_event(
        "BCF", "SUB", "Subscription created",
        sub_id=sub_id,
        target_nf_type=sub.get('target_nf_type') or "ANY",
        notification_transport=notification_transport,
        candidates=len(resp.get('target_nf_list', [])),
    )
    log_event(
        "BCF", "SUB", "Subscription created without immediate notify",
        level=logging.DEBUG,
        sub_id=sub_id,
    )

    return jsonify(resp), 201


@app.route('/mock/trigger_subscription_notify', methods=['POST'])
async def mock_trigger_subscription_notify():
    """
    Debug endpoint to trigger notifications for a subscription.
    Body: { "subscription_id": "...", "event_type": "TARGET_NF_REGISTERED", "target": { ... } }
    This will POST the notification JSON to the subscription.notification_uri
    using the configured transport mode.
    """
    try:
        data = await request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "message": str(e)}), 400

    sub_id = data.get('subscription_id')
    if not sub_id or sub_id not in storage.subscriptions:
        return jsonify({"error": "not_found", "message": "subscription not found"}), 404

    sub = storage.subscriptions[sub_id]
    event_type = data.get('event_type', 'TARGET_NF_REGISTERED')
    target = data.get('target', {})

    notif = {
        'subscription_id': sub_id,
        'event_type': event_type,
        'target': target,
        'timestamp_ms': int(time.time() * 1000)
    }

    # Try to POST notification to subscriber notification_uri
    notif_url = sub.get('notification_uri')
    log_event(
        "BCF", "SUB", "Manual notify trigger",
        sub_id=sub_id,
        event=event_type,
        notification_uri=notif_url or "N/A",
        notification_transport=sub.get('notification_transport') or DEFAULT_NOTIFICATION_TRANSPORT,
    )

    if notif_url:
        try:
            fixed = (
                notif_url
                if notif_url.lower().startswith(('http://', 'https://'))
                else 'http://' + notif_url
            )
            if not send_notification(
                fixed,
                notif,
                request_id=current_request_id(),
                transport_mode=sub.get('notification_transport'),
            ):
                return jsonify({"status": "failed", "error": "notification_send_failed"}), 502
        except Exception as e:
            log_event(
                "BCF", "SUB", "Manual notify trigger failed",
                level=logging.WARNING,
                sub_id=sub_id,
                notification_uri=notif_url,
                error=str(e),
            )
            return jsonify({"status": "failed", "error": str(e)}), 502

    return jsonify({"status": "sent", "notification": notif}), 200


def notify_subscribers(
    event_type: str,
    target: Optional[dict] = None,
    request_id: str = "",
    *_unused_args: Any,
):
    """
    Notify all matching subscriptions about an event (best-effort).
    event_type: one of 'NF_REGISTERED', 'NF_UPDATED', 'NF_DEREGISTERED', etc.
    target: full target nf profile (dict)

    Note:
      Keep accepting extra positional arguments for backward compatibility with
      older thread scheduling call sites. They are intentionally ignored.
    """
    try:
        if event_type == 'NF_SUBSCRIPTION_CREATED':
            log_event(
                "BCF", "SUB", "Skip subscription-created self notification",
                level=logging.DEBUG,
                req=request_id,
                event=event_type,
            )
            return

        # Normalize target information. The real notification path must always
        # carry the full profile snapshot that exists in registry/storage.
        if not isinstance(target, dict):
            full_target_profile = {}
        else:
            full_target_profile = copy.deepcopy(target)

        if event_type == 'NF_DEREGISTERED' and isinstance(full_target_profile, dict):
            dereg_time = datetime.utcnow().isoformat(timespec='milliseconds') + "Z"
            full_target_profile['nfStatus'] = 'DEREGISTERED'
            full_target_profile['lastUpdateTime'] = dereg_time
            full_target_profile['deregistrationTime'] = dereg_time

        if event_type == 'TARGET_NF_REGISTERED':
            target_nf_id = (
                full_target_profile.get('nfInstanceId') or
                full_target_profile.get('nf_instance_id') or ''
            )
            if not target_nf_id:
                log_event(
                    "BCF", "SUB", "Skip notify: empty nfInstanceId",
                    level=logging.WARNING,
                    req=request_id,
                    event=event_type,
                )
                return
            nf_profile = storage.get_nf_instance(target_nf_id)
            if not nf_profile or str(nf_profile.get('nfStatus', '')).upper() != 'REGISTERED':
                log_event(
                    "BCF", "SUB", "Skip notify: target NF not registered",
                    req=request_id,
                    event=event_type,
                    nfInstanceId=target_nf_id,
                )
                return
            if not storage.is_nf_authenticated(target_nf_id):
                log_event(
                    "BCF", "SUB", "Skip notify: target NF not authenticated",
                    req=request_id,
                    event=event_type,
                    nfInstanceId=target_nf_id,
                )
                return
            # Use the full profile persisted in registry as notification payload.
            full_target_profile = copy.deepcopy(nf_profile)

        target_nf_type = (
            full_target_profile.get('nfType') or
            full_target_profile.get('nf_type') or ''
        )
        target_nf_id = (
            full_target_profile.get('nfInstanceId') or
            full_target_profile.get('nf_instance_id') or ''
        )

        log_event(
            "BCF", "STATE", f"NF {normalize_state_event(event_type)}",
            req=request_id,
            nfType=target_nf_type or "UNKNOWN",
            nfInstanceId=target_nf_id or "N/A",
        )

        # Gather matching subscriptions snapshot
        subs = []
        with storage._lock:
            for s in storage.subscriptions.values():
                t = (s.get('target_nf_type') or '').strip()
                if t and target_nf_type and t.upper() == target_nf_type.upper():
                    subs.append(s.copy())

        log_event(
            "BCF", "SUB", "Found matched subscriptions",
            req=request_id,
            count=len(subs),
            target_nf_type=target_nf_type or "UNKNOWN",
            event=event_type,
        )

        if not subs:
            return

        for sub in subs:
            try:
                notif_url = sub.get('notification_uri') or ''
                subscription_id = sub.get('subscription_id') or ''
                if not notif_url:
                    continue

                if not notif_url.lower().startswith(('http://', 'https://')):
                    fixed_url = 'http://' + notif_url
                else:
                    fixed_url = notif_url

                payload = {
                    'event': event_type,
                    'subscription_id': subscription_id,
                    'target_nf_type': target_nf_type,
                    'target_nf_instance_id': target_nf_id,
                    'target_nf_profile': copy.deepcopy(full_target_profile),
                }
                log_event(
                    "BCF", "SUB", "Notify subscriber",
                    req=request_id,
                    sub_id=subscription_id,
                    event=normalize_state_event(event_type),
                    nfInstanceId=target_nf_id or "N/A",
                    nfType=target_nf_type or "UNKNOWN",
                    notification_uri=fixed_url,
                    notification_transport=sub.get('notification_transport') or DEFAULT_NOTIFICATION_TRANSPORT,
                )
                log_debug_json("SUB", "notification_payload", payload, req=request_id)

                send_notification(
                    fixed_url,
                    payload,
                    request_id=request_id,
                    transport_mode=sub.get('notification_transport'),
                )
            except Exception as e:
                log_exception(
                    "BCF", "SUB", "notify_subscriber failed",
                    req=request_id,
                    error=str(e),
                )
    except Exception as e:
        log_exception("BCF", "SUB", "notify_subscribers failed", req=request_id, error=str(e))


def schedule_subscription_notification(event_type: str, target: Optional[dict] = None):
    """
    Schedule subscription notification in a background thread.

    Keep a single scheduling path so all callers invoke notify_subscribers
    consistently with keyword arguments. This avoids mismatched positional
    argument calls during deregistration or future call-site additions.
    """
    try:
        request_id = current_request_id()
        threading.Thread(
            target=notify_subscribers,
            kwargs={
                'event_type': event_type,
                'target': target or {},
                'request_id': request_id,
            },
            daemon=True
        ).start()
    except Exception:
        log_event(
            "BCF", "SUB", "Failed to schedule notification",
            level=logging.DEBUG,
            event=event_type,
        )


def send_notification_h2c_prior(
    notification_uri: str, payload: dict, request_id: str = ""
) -> dict:
    """
    Send subscription notification using HTTP/2 cleartext prior knowledge only.

    Requirements:
      - scheme must be http
      - no HTTP/1.1 fallback
      - no Upgrade
    """
    parsed = urlparse(notification_uri)
    if not parsed.scheme:
        raise ValueError("notification_uri missing scheme")
    if parsed.scheme.lower() != 'http':
        raise ValueError(
            f"unsupported scheme for h2c prior knowledge: {parsed.scheme}"
        )
    if not parsed.hostname:
        raise ValueError("notification_uri missing host")

    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or '/'
    if parsed.query:
        path = f"{path}?{parsed.query}"

    body_bytes = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    config = h2.config.H2Configuration(client_side=True, header_encoding='utf-8')
    conn = h2.connection.H2Connection(config=config)

    response_status = None
    response_headers = []
    response_body = bytearray()
    stream_ended = False

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)

        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(
            stream_id,
            [
                (':method', 'POST'),
                (':scheme', 'http'),
                (':authority', f'{host}:{port}'),
                (':path', path),
                ('content-type', 'application/json'),
                ('content-length', str(len(body_bytes))),
            ],
            end_stream=False
        )
        conn.send_data(stream_id, body_bytes, end_stream=True)
        sock.sendall(conn.data_to_send())

        while not stream_ended:
            received = sock.recv(65535)
            if not received:
                break

            events = conn.receive_data(received)
            outbound = conn.data_to_send()
            if outbound:
                sock.sendall(outbound)

            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    response_headers.extend(event.headers)
                    for name, value in event.headers:
                        if name == ':status':
                            response_status = int(value)
                elif isinstance(event, h2.events.DataReceived):
                    response_body.extend(event.data)
                    conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    outbound = conn.data_to_send()
                    if outbound:
                        sock.sendall(outbound)
                elif isinstance(event, h2.events.StreamEnded):
                    if event.stream_id == stream_id:
                        stream_ended = True
                elif isinstance(event, h2.events.StreamReset):
                    raise RuntimeError(
                        f"HTTP/2 stream reset by peer: error_code={event.error_code}"
                    )
                elif isinstance(event, h2.events.ConnectionTerminated):
                    raise RuntimeError(
                        f"HTTP/2 connection terminated: error_code={event.error_code}"
                    )

    return {
        "success": response_status in (200, 204),
        "status": response_status,
        "reason": "http2-response",
        "headers": {name: value for name, value in response_headers},
        "body": response_body.decode('utf-8', errors='replace'),
    }


def send_notification_http1_json(
    notification_uri: str, payload: dict, request_id: str = ""
) -> dict:
    parsed = urlparse(notification_uri)
    if not parsed.scheme:
        raise ValueError("notification_uri missing scheme")
    if parsed.scheme.lower() not in ('http', 'https'):
        raise ValueError(
            f"unsupported scheme for HTTP/1 notification delivery: {parsed.scheme}"
        )
    if not parsed.hostname:
        raise ValueError("notification_uri missing host")

    is_https = parsed.scheme.lower() == 'https'
    host = parsed.hostname
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or '/'
    if parsed.query:
        path = f"{path}?{parsed.query}"

    body_bytes = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'Content-Length': str(len(body_bytes)),
        'Host': parsed.netloc or f"{host}:{port}",
    }

    conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    conn_kwargs: Dict[str, Any] = {'timeout': 5}
    if is_https:
        conn_kwargs['context'] = ssl._create_unverified_context()

    conn = conn_cls(host, port, **conn_kwargs)
    try:
        conn.request('POST', path, body=body_bytes, headers=headers)
        response = conn.getresponse()
        response_body = response.read().decode('utf-8', errors='replace')
        return {
            "success": response.status in (200, 204),
            "status": response.status,
            "reason": response.reason or "",
            "headers": dict(response.getheaders()),
            "body": response_body,
        }
    finally:
        conn.close()


def send_notification(
    notification_uri: str,
    payload: dict,
    request_id: str = "",
    transport_mode: Optional[str] = None,
) -> bool:
    requested_transport = resolve_notification_transport(
        transport_mode, fallback=DEFAULT_NOTIFICATION_TRANSPORT
    )
    transport_plan = build_notification_transport_plan(
        notification_uri, requested_transport
    )

    last_result: Dict[str, Any] = {}
    last_failure_kind = ""

    for index, transport in enumerate(transport_plan, start=1):
        attempt = f"{index}/{len(transport_plan)}"
        log_event(
            "BCF", "SUB", "Sending notification",
            req=request_id,
            notification_uri=notification_uri,
            transport=transport,
            requested_transport=requested_transport,
            attempt=attempt,
            event=payload.get("event") or payload.get("event_type") or "N/A",
            sub_id=payload.get("subscription_id", "N/A"),
        )

        try:
            if transport == "h2c-prior":
                result = send_notification_h2c_prior(
                    notification_uri, payload, request_id=request_id
                )
            else:
                result = send_notification_http1_json(
                    notification_uri, payload, request_id=request_id
                )
        except Exception as e:
            failure_kind = classify_transport_exception(e)
            last_failure_kind = failure_kind
            last_result = {"error": str(e)}
            log_event(
                "BCF", "SUB", "Notification transport error",
                level=logging.WARNING,
                req=request_id,
                notification_uri=notification_uri,
                transport=transport,
                requested_transport=requested_transport,
                attempt=attempt,
                failure_kind=failure_kind,
                error=str(e),
            )
            continue

        if result.get("success"):
            log_event(
                "BCF", "SUB", "Notification delivered",
                req=request_id,
                notification_uri=notification_uri,
                transport=transport,
                requested_transport=requested_transport,
                attempt=attempt,
                status=result.get("status", "N/A"),
                reason=result.get("reason", "N/A"),
            )
            return True

        last_result = result
        log_event(
            "BCF", "SUB", "Notification delivery failed",
            level=logging.WARNING,
            req=request_id,
            notification_uri=notification_uri,
            transport=transport,
            requested_transport=requested_transport,
            attempt=attempt,
            status=result.get("status", "N/A"),
            reason=result.get("reason", "unexpected_status"),
            response_headers=shorten(
                compact_json(result.get("headers", {})), 192
            ) if result.get("headers") else "N/A",
            body=shorten(result.get("body", ""), 160),
        )

    log_event(
        "BCF", "SUB", "All notification delivery attempts failed",
        level=logging.WARNING,
        req=request_id,
        notification_uri=notification_uri,
        requested_transport=requested_transport,
        attempts=",".join(transport_plan),
        last_status=last_result.get("status", "N/A"),
        last_reason=last_result.get("reason", "N/A"),
        last_error=last_result.get("error", "N/A"),
        last_failure_kind=last_failure_kind or "response_error",
    )
    return False


@app.route('/nbcf_management/v1/nf_instances/<nf_instance_id>', methods=['GET'])
@app.route('/nbcf_management/v1/nf-instances/<nf_instance_id>', methods=['GET'])
@app.route('/nbcf_management/v1/nf-instances/<nf_instance_id>', methods=['GET'])
@app.route('/nbcf_management/v1/nf_instances/<nf_instance_id>', methods=['GET'])
async def get_nf_instance(nf_instance_id: str):
    """获取单个 NF 实例"""
    nf = storage.get_nf_instance(nf_instance_id)
    if nf is None:
        return jsonify({"error": "not_found", "message": f"NF {nf_instance_id} not found"}), 404
    return jsonify(nf)


@app.route('/nbcf_management/v1/nf_instances/<nf_instance_id>', methods=['PATCH'])
@app.route('/nbcf_management/v1/nf-instances/<nf_instance_id>', methods=['PATCH'])
@app.route('/nbcf_management/v1/nf-instances/<nf_instance_id>', methods=['PATCH'])
@app.route('/nbcf_management/v1/nf_instances/<nf_instance_id>', methods=['PATCH'])
async def heartbeat(nf_instance_id: str):
    """NF 心跳"""
    try:
        data = await request.get_json(force=True)
    except:
        data = {}

    log_event(
        "BCF", "STATE", "Heartbeat received",
        level=logging.DEBUG,
        nfInstanceId=nf_instance_id,
        patch=compact_json(data) if data else "{}",
    )
    result = storage.update_nf_status(nf_instance_id, data)
    
    if result is None:
        return jsonify({"error": "not_found", "message": f"NF {nf_instance_id} not found"}), 404
    # Notify subscribers about profile change (best-effort)
    target = copy.deepcopy(result)
    schedule_subscription_notification('NF_UPDATED', target)

    return jsonify(result)


@app.route('/nbcf_management/v1/nf_instances/<nf_instance_id>', methods=['DELETE'])
@app.route('/nbcf_management/v1/nf-instances/<nf_instance_id>', methods=['DELETE'])
@app.route('/nbcf_management/v1/nf-instances/<nf_instance_id>', methods=['DELETE'])
@app.route('/nbcf_management/v1/nf_instances/<nf_instance_id>', methods=['DELETE'])
async def deregister_nf(nf_instance_id: str):
    """NF 注销"""
    # Try to fetch profile before deletion so we can notify subscribers
    nf = storage.get_nf_instance(nf_instance_id)
    nf_snapshot = copy.deepcopy(nf) if isinstance(nf, dict) else {}
    log_event("BCF", "STATE", "Received NF deregistration", nfInstanceId=nf_instance_id)
    if storage.deregister_nf(nf_instance_id):
        if nf_snapshot:
            nf_snapshot['nfInstanceId'] = nf_snapshot.get('nfInstanceId', nf_instance_id)
            schedule_subscription_notification('NF_DEREGISTERED', nf_snapshot)
        else:
            log_event(
                "BCF", "SUB", "Skip deregistration notify: missing NF snapshot",
                level=logging.WARNING,
                nfInstanceId=nf_instance_id,
            )

        return '', 204
    return jsonify({"error": "not_found", "message": f"NF {nf_instance_id} not found"}), 404


# =============================================================================
# NF Discovery Endpoints - 通用 BCF NF 发现接口
# =============================================================================

@app.route('/nbcf_nfm/v1/nf_instances', methods=['GET'])
@app.route('/nbcf-nfm/v1/nf-instances', methods=['GET'])
@app.route('/nbcf_nfm/v1/nf-instances', methods=['GET'])
@app.route('/nbcf-nfm/v1/nf_instances', methods=['GET'])
async def discover_nf_instances():
    """
    NF 发现 - 通用 BCF 框架使用
    GET /nbcf_nfm/v1/nf_instances?target_nf_type=AUSF&requester_nf_type=AMF&...
    
    查询参数 (支持连字符和下划线两种格式):
      - target_nf_type / target-nf-type: 目标 NF 类型 (必选)
      - requester_nf_type / requester-nf-type: 请求方 NF 类型
      - requester_nf_instance_id / requester-nf-instance-id: 请求方 NF Instance ID
      - target_plmn_mcc / target-plmn-mcc: 目标 PLMN MCC
      - target_plmn_mnc / target-plmn-mnc: 目标 PLMN MNC
      - target_snssai_sst / target-snssai-sst: 目标 S-NSSAI SST
      - target-snssai-sd: 目标 S-NSSAI SD
      - service-names / service-name: 所需服务名称
      - locality: 地理位置
      - max-results: 最大返回数量 (默认 10)
    
    响应格式:
    {
        "nfInstances": [...],
        "validityPeriod": 3600
    }
    """
    # 解析查询参数 (支持连字符和下划线两种格式)
    target_nf_type = request.args.get('target-nf-type') or request.args.get('target_nf_type')
    requester_nf_type = request.args.get('requester-nf-type') or request.args.get('requester_nf_type') or request.args.get('requester-nf_type')
    requester_nf_id = request.args.get('requester-nf-instance-id') or request.args.get('requester_nf_instance_id')
    target_plmn_mcc = request.args.get('target-plmn-mcc') or request.args.get('target_plmn_mcc')
    target_plmn_mnc = request.args.get('target-plmn-mnc') or request.args.get('target_plmn_mnc')
    target_snssai_sst = request.args.get('target-snssai-sst') or request.args.get('target_snssai_sst')
    target_snssai_sd = request.args.get('target-snssai-sd') or request.args.get('target_snssai_sd')
    service_name = request.args.get('service-names') or request.args.get('service-name') or request.args.get('service_names') or request.args.get('service_name')
    locality = request.args.get('locality')
    max_results = int(request.args.get('max-results', request.args.get('max_results', '10')))
    
    log_event(
        "BCF", "DISC", "Query",
        target_nf_type=target_nf_type or "ALL",
        requester=requester_nf_type or "N/A",
        requester_nf_instance_id=requester_nf_id or "N/A",
        service_name=service_name or "N/A",
        locality=locality or "N/A",
        max_results=max_results,
    )
    
    # 执行发现
    nf_instances = storage.discover_nf_instances(
        target_nf_type=target_nf_type,
        requester_nf_type=requester_nf_type,
        target_plmn_mcc=target_plmn_mcc,
        target_plmn_mnc=target_plmn_mnc,
        target_snssai_sst=int(target_snssai_sst) if target_snssai_sst else None,
        target_snssai_sd=target_snssai_sd,
        service_name=service_name,
        locality=locality,
        max_results=max_results
    )
    
    log_event(
        "BCF", "DISC", "Discovery response ready",
        count=len(nf_instances),
        target_nf_type=target_nf_type or "ALL",
    )
    
    response_data = {
        "nfInstances": nf_instances,
        "validityPeriod": 3600,
        "searchId": secrets.token_hex(8)
    }
    
    return jsonify(response_data)


@app.route('/nbcf_nfm/v1/nf_instances/<nf_instance_id>', methods=['GET'])
@app.route('/nbcf-nfm/v1/nf-instances/<nf_instance_id>', methods=['GET'])
@app.route('/nbcf_nfm/v1/nf-instances/<nf_instance_id>', methods=['GET'])
@app.route('/nbcf-nfm/v1/nf_instances/<nf_instance_id>', methods=['GET'])
async def get_nf_instance_nfm(nf_instance_id: str):
    """
    获取单个 NF 实例信息 - 通用 BCF 框架使用
    GET /nbcf_nfm/v1/nf_instances/{nfInstanceId}
    """
    nf = storage.get_nf_instance(nf_instance_id)
    if nf is None:
        return jsonify({
            "error": "not_found",
            "message": f"NF Instance {nf_instance_id} not found"
        }), 404
    
    log_event(
        "BCF", "DISC", "NF instance query",
        nfInstanceId=nf_instance_id,
        nfType=nf.get('nfType', 'N/A'),
    )
    return jsonify(nf)


@app.route('/nbcf_nfm/v1/did/<path:did>/publickey', methods=['GET'])
@app.route('/nbcf-nfm/v1/did/<path:did>/publickey', methods=['GET'])
async def get_public_key_nfm(did: str):
    """
    公钥查询 - 通用 BCF 框架使用
    GET /nbcf_nfm/v1/did/{did}/publickey
    
    响应格式:
    {
        "found": true/false,
        "did": "did:oai5gc:...",
        "publicKey": "hex_string",
        "nfType": "AMF",
        "nfInstanceId": "uuid",
        "errorMessage": ""
    }
    """
    did = unquote(did)
    
    log_event("BCF", "DISC", "Public key query", did=shorten(did, 56), api="nfm")
    
    result = storage.get_public_key_by_did(did)
    
    # 转换为通用 BCF 框架期望的响应格式
    response = {
        "found": result.get("found", False),
        "did": result.get("did", did),
        "publicKey": result.get("public_key", ""),
        "nfType": result.get("nf_type", ""),
        "nfInstanceId": result.get("nf_instance_id", ""),
        "errorMessage": result.get("error_message", "")
    }
    
    if not response["found"]:
        log_event(
            "BCF", "DISC", "Public key query result",
            level=logging.WARNING,
            result="NOT_FOUND",
            did=shorten(did, 56),
        )
        return jsonify(response), 404
    
    log_event(
        "BCF", "DISC", "Public key query result",
        result="FOUND",
        did=shorten(did, 56),
        public_key=shorten(response['publicKey'], 32) if response['publicKey'] else "N/A",
        nfType=response['nfType'] or "N/A",
        nfInstanceId=response['nfInstanceId'] or "N/A",
    )
    
    return jsonify(response)


# =============================================================================
# DID Endpoints - 双向认证核心接口（兼容旧接口）
# =============================================================================

@app.route('/nbcf_did/v1/public_key/<path:did>', methods=['GET'])
@app.route('/nbcf-did/v1/public-key/<path:did>', methods=['GET'])
@app.route('/nbcf-did/v1/public_key/<path:did>', methods=['GET'])
async def get_public_key(did: str):
    """
    公钥查询 - 双向认证核心接口
    GET /nbcf_did/v1/public_key/{did}
    
    响应格式与 AMF 的 public_key_response_t 结构对应:
    {
        "found": true/false,
        "did": "did:oai5gc:...",
        "public_key": "hex_string",
        "nf_type": "AMF",
        "nf_instance_id": "uuid",
        "error_message": ""
    }
    """
    did = unquote(did)
    
    log_event("BCF", "AUTH", "Public key query", did=shorten(did, 56), api="did")
    
    result = storage.get_public_key_by_did(did)
    
    # result 现在总是返回一个 dict，检查 found 字段
    if not result.get("found", False):
        log_event(
            "BCF", "AUTH", "Public key query result",
            level=logging.WARNING,
            result="NOT_FOUND",
            did=shorten(did, 56),
        )
        # 返回完整的响应格式，即使是 404
        return jsonify(result), 404
    
    log_event(
        "BCF", "AUTH", "Public key query result",
        result="FOUND",
        did=shorten(did, 56),
        public_key=shorten(result.get('public_key', ''), 32),
        nfType=result.get('nf_type', 'N/A'),
        nfInstanceId=result.get('nf_instance_id', 'N/A'),
    )
    
    return jsonify(result)


@app.route('/nbcf_did/v1/did_document/<path:did>', methods=['GET'])
@app.route('/nbcf_did/v1/did_documents/<path:did>', methods=['GET'])
@app.route('/nbcf-did/v1/did-document/<path:did>', methods=['GET'])
@app.route('/nbcf-did/v1/did-documents/<path:did>', methods=['GET'])
async def get_did_document(did: str):
    """
    获取 DID 文档
    
    返回格式（与 AMF/AUSF 期望的 public_key_response_t 兼容）:
    {
        "found": true,
        "did": "did:oai5gc:...",
        "did_document": { ... },
        "public_key": "04...",  // HEX format (not multibase)
        "nf_type": "AMF",
        "nf_instance_id": "..."
    }
    """
    did = unquote(did)
    
    log_event("BCF", "AUTH", "DID document query", did=shorten(did, 48))
    
    # 获取 DID 文档
    did_doc = storage.get_did_document(did)
    
    if did_doc is None:
        log_event(
            "BCF", "AUTH", "DID document not found",
            level=logging.WARNING,
            did=shorten(did, 48),
        )
        return jsonify({
            "found": False,
            "did": did,
            "error_message": f"DID Document not found: {did[:50]}..."
        }), 404
    
    # 提取公钥（从 verificationMethod）并转换为 HEX 格式
    public_key_raw = None
    public_key_hex = None
    verification_methods = did_doc.get('verificationMethod', [])
    for vm in verification_methods:
        if 'publicKeyHex' in vm:
            # Already in hex format
            public_key_hex = vm['publicKeyHex']
            public_key_raw = public_key_hex
            break
        elif 'publicKeyMultibase' in vm:
            # Multibase format - need to convert to hex
            public_key_raw = vm['publicKeyMultibase']
            public_key_hex = multibase_to_hex(public_key_raw)
            log_event(
                "BCF", "AUTH", "Converted multibase public key",
                level=logging.DEBUG,
                source=shorten(public_key_raw, 20),
                converted=shorten(public_key_hex, 40),
            )
            break
    
    # 查找对应的 NF Profile 以获取 nf_type 和 nf_instance_id
    nf_type = ""
    nf_instance_id = ""
    with storage._lock:
        if did in storage.did_to_nf:
            nf_instance_id = storage.did_to_nf[did]
            if nf_instance_id in storage.nf_profiles:
                nf_profile = storage.nf_profiles[nf_instance_id]
                nf_type = nf_profile.get('nfType', '')
    
    response = {
        "found": True,
        "did": did,
        "did_document": did_doc,
        "public_key": public_key_hex or "",
        "nf_type": nf_type,
        "nf_instance_id": nf_instance_id
    }
    
    log_event(
        "BCF", "AUTH", "DID document found",
        did=shorten(did, 48),
        nfType=nf_type or "N/A",
        nfInstanceId=nf_instance_id or "N/A",
        public_key=shorten(public_key_hex, 32) if public_key_hex else "N/A",
    )
    
    return jsonify(response)


@app.route('/nbcf_did/v1/register', methods=['POST'])
@app.route('/nbcf-did/v1/register', methods=['POST'])
async def simple_did_register():
    """简化的 DID 注册"""
    try:
        data = await request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "message": str(e)}), 400
    
    nf_instance_id = data.get('nfInstanceId', f"simple-{secrets.token_hex(8)}")
    result = storage.register_nf(nf_instance_id, data)
    return jsonify(result), 201


# =============================================================================
# BCF 认证端点 - NF 自身认证 (challenge-response, self-auth)
# =============================================================================

@app.route('/nbcf_auth/v1/auth/init', methods=['POST'])
@app.route('/nbcf-auth/v1/auth/init', methods=['POST'])
async def bcf_auth_init():
    """
    BCF 认证初始化 - NF 发起自身认证，BCF 返回 challenge

    请求 Body:
    {
        "nf_did": "did:oai5gc:...",
        "nf_type": "AMF",
        "nf_instance_id": "amf-001",
        "timestamp_ms": 1234567890123
    }

    响应 Body:
    {
        "session_id": "hex_string",
        "challenge": "hex_string (256-bit nonce)",
        "challenge_expires_ms": 1234567890123,
        "timestamp_ms": 1234567890123
    }
    """
    try:
        data = await request.get_json(force=True)
    except Exception as e:
        log_event("BCF", "AUTH", "Invalid auth init JSON", level=logging.ERROR, error=str(e))
        return jsonify({
            "success": False,
            "error_code": "INVALID_REQUEST",
            "error_message": "Failed to parse JSON body",
            "timestamp_ms": int(time.time() * 1000)
        }), 400

    nf_did = data.get("nf_did", "")
    nf_type = data.get("nf_type", "")
    nf_instance_id = data.get("nf_instance_id", "")
    target_nf_types = resolve_target_nf_types_for_request(
        nf_type,
        data.get("target_nf_types", data.get("target_nf_type"))
    )
    timestamp_ms = data.get("timestamp_ms", 0)

    log_event(
        "BCF", "AUTH", "Init request",
        nfType=nf_type or "N/A",
        nfInstanceId=nf_instance_id or "N/A",
        aud=target_nf_types,
        did=shorten(nf_did, 48),
        timestamp_ms=timestamp_ms,
    )
    log_debug_json("AUTH", "auth_init_body", data)

    # 基本参数校验
    if not nf_did:
        log_event("BCF", "AUTH", "Missing required field", level=logging.ERROR, field="nf_did")
        return jsonify({
            "success": False,
            "error_code": "MISSING_FIELD",
            "error_message": "nf_did is required",
            "timestamp_ms": int(time.time() * 1000)
        }), 400

    if not nf_type:
        log_event("BCF", "AUTH", "Missing required field", level=logging.ERROR, field="nf_type")
        return jsonify({
            "success": False,
            "error_code": "MISSING_FIELD",
            "error_message": "nf_type is required",
            "timestamp_ms": int(time.time() * 1000)
        }), 400

    # 创建自身认证会话，生成 challenge
    challenge_resp = storage.create_auth_session(
        nf_did=nf_did,
        nf_type=nf_type,
        nf_instance_id=nf_instance_id,
        target_nf_types=target_nf_types,
    )

    log_event(
        "BCF", "AUTH", "Init response",
        session_id=challenge_resp['session_id'],
        expires_ms=challenge_resp['challenge_expires_ms'],
        aud=target_nf_types,
    )

    return jsonify(challenge_resp), 200


@app.route('/nbcf_auth/v1/auth/verify', methods=['POST'])
@app.route('/nbcf-auth/v1/auth/verify', methods=['POST'])
async def bcf_auth_verify():
    """
    BCF 认证验证 - NF 提交签名后的 challenge，BCF 验签并签发 token

    请求 Body:
    {
        "session_id": "hex_string",
        "nf_did": "did:oai5gc:...",
        "challenge_signature": "hex_string",
        "timestamp_ms": 1234567890123
    }

    成功响应 Body:
    {
        "success": true,
        "session_id": "hex_string",
        "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJiY2YiLC...}.sig",
        "expires_in": 3600,
        "expires_at_ms": 1234567890123,
        "nf_did": "did:oai5gc:...",
        "timestamp_ms": 1234567890123
    }

    失败响应 Body:
    {
        "success": false,
        "session_id": "hex_string",
        "error_code": "SIGNATURE_INVALID",
        "error_message": "...",
        "timestamp_ms": 1234567890123
    }
    """
    try:
        data = await request.get_json(force=True)
    except Exception as e:
        log_event("BCF", "AUTH", "Invalid auth verify JSON", level=logging.ERROR, error=str(e))
        return jsonify({
            "success": False,
            "error_code": "INVALID_REQUEST",
            "error_message": "Failed to parse JSON body",
            "timestamp_ms": int(time.time() * 1000)
        }), 400

    session_id = data.get("session_id", "")
    nf_did = data.get("nf_did", "")
    challenge_signature = data.get("challenge_signature", "")
    timestamp_ms = data.get("timestamp_ms", 0)

    log_event(
        "BCF", "AUTH", "Verify request",
        session_id=session_id or "N/A",
        did=shorten(nf_did, 48),
        signature=shorten(challenge_signature, 24),
        timestamp_ms=timestamp_ms,
    )
    log_debug_json("AUTH", "auth_verify_body", data)

    # 基本参数校验
    if not session_id:
        log_event("BCF", "AUTH", "Missing required field", level=logging.ERROR, field="session_id")
        return jsonify({
            "success": False,
            "error_code": "MISSING_FIELD",
            "error_message": "session_id is required",
            "timestamp_ms": int(time.time() * 1000)
        }), 400

    if not nf_did:
        log_event("BCF", "AUTH", "Missing required field", level=logging.ERROR, field="nf_did")
        return jsonify({
            "success": False,
            "error_code": "MISSING_FIELD",
            "error_message": "nf_did is required",
            "timestamp_ms": int(time.time() * 1000)
        }), 400

    # 验证签名并签发 token
    result = storage.verify_auth_challenge(
        session_id=session_id,
        nf_did=nf_did,
        challenge_signature=challenge_signature
    )

    # 根据结果返回不同 HTTP 状态码
    if result.get("success"):
        issued_token = result.get('access_token') or result.get('auth_token', '')
        jwt_claims = decode_access_token_without_verify(issued_token)
        log_event(
            "BCF", "AUTH", "Verify success",
            session_id=session_id,
            nfInstanceId=result.get("nf_instance_id", "N/A"),
            nfType=jwt_claims.get('nf_type', '?') if jwt_claims else "N/A",
            expires_in=result.get("expires_in"),
        )
        # 解码 JWT 显示摘要
        if jwt_claims:
            log_event(
                "BCF", "AUTH", "Issued token",
                sub=jwt_claims.get('sub', '?'),
                jti=shorten(jwt_claims.get('jti', '?'), 12),
                aud=jwt_claims.get('aud', []),
                scope=jwt_claims.get('scope', '?'),
            )
        else:
            log_event(
                "BCF", "AUTH", "Issued token",
                token=shorten(issued_token, 32),
            )

        if result.get("newly_authenticated"):
            nf_instance_id = storage.did_to_nf.get(nf_did, '')
            nf_profile = storage.get_nf_instance(nf_instance_id) if nf_instance_id else None
            if nf_profile and str(nf_profile.get('nfStatus', '')).upper() == 'REGISTERED':
                target = copy.deepcopy(nf_profile)
                schedule_subscription_notification('TARGET_NF_REGISTERED', target)
            else:
                log_event(
                    "BCF", "SUB", "Skip registered notify after verify",
                    level=logging.DEBUG,
                    nfInstanceId=nf_instance_id or "N/A",
                )
        return jsonify(result), 200
    else:
        error_code = result.get("error_code", "UNKNOWN")
        log_event(
            "BCF", "AUTH", "Verify failed",
            level=logging.ERROR,
            session_id=session_id or "N/A",
            error_code=error_code,
        )

        # 根据不同错误码返回不同 HTTP 状态码
        if error_code == "SESSION_NOT_FOUND":
            return jsonify(result), 404
        elif error_code == "CHALLENGE_EXPIRED":
            return jsonify(result), 410
        elif error_code in ("SIGNATURE_INVALID", "DID_MISMATCH", "INVALID_SIGNATURE"):
            return jsonify(result), 401
        else:
            return jsonify(result), 400


@app.route('/nbcf_auth/v1/token/validate', methods=['POST'])
@app.route('/nbcf-auth/v1/token/validate', methods=['POST'])
async def bcf_token_validate():
    """
    BCF Token 验证 - 可选端点，用于 NF 间验证 token 有效性

    请求 Body:
    {
        "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOi..."
    }

    成功响应包含 JWT claims 摘要。
    """
    try:
        data = await request.get_json(force=True)
    except Exception:
        return jsonify({"valid": False, "error": "Invalid request body"}), 400

    token = data.get("access_token", "") or data.get("auth_token", "")
    if not token:
        return jsonify({"valid": False, "error": "access_token is required"}), 400

    entry = storage.validate_token(token)
    if entry:
        claims = entry.get("claims", {})
        log_event(
            "BCF", "AUTH", "Token validate success",
            sub=claims.get('sub', '?'),
            nfType=entry['nf_type'],
            scope=claims.get('scope', '?'),
        )
        return jsonify({
            "valid": True,
            "nf_instance_id": entry.get("nf_instance_id", claims.get("sub", "")),
            "nf_did": entry["nf_did"],
            "nf_type": entry["nf_type"],
            "expires_at_ms": entry["expires_at_ms"],
            "token_claims": {
                "iss": claims.get("iss"),
                "sub": claims.get("sub"),
                "aud": claims.get("aud"),
                "scope": claims.get("scope"),
                "jti": claims.get("jti"),
                "nf_did": claims.get("nf_did"),
                "exp": claims.get("exp"),
                "iat": claims.get("iat"),
                "nbf": claims.get("nbf"),
            }
        }), 200
    else:
        log_event("BCF", "AUTH", "Token validate failed", level=logging.WARNING)
        return jsonify({"valid": False, "error": "Token invalid or expired"}), 401


@app.route('/nbcf_auth/v1/jwks', methods=['GET'])
@app.route('/nbcf-auth/v1/jwks', methods=['GET'])
async def bcf_jwks():
    try:
        key_manager = get_es256k_key_manager()
        return jsonify({"keys": [key_manager.get_public_jwk()]}), 200
    except Exception as e:
        log_event(
            "BCF", "Token", "Failed to build JWKS response",
            level=logging.ERROR,
            error=str(e),
        )
        return jsonify({"keys": [], "error": "jwks_unavailable"}), 500


# =============================================================================
# 测试工具端点
# =============================================================================

@app.route('/test/trigger-auth', methods=['GET', 'POST'])
async def trigger_auth():
    """
    触发双向认证测试
    向 AMF 发送认证请求
    """
    if request.method == 'POST':
        try:
            data = await request.get_json(force=True)
            target = data.get('target', 'localhost:8080')
        except:
            target = 'localhost:8080'
    else:
        target = request.args.get('target', 'localhost:8080')
    
    storage.stats["auth_triggers"] += 1
    
    log_event("BCF", "AUTH", "Trigger authentication test", target=target)
    
    # 首先注册模拟 NF
    mock_profile = mock_requester.get_registration_profile()
    storage.register_nf(mock_requester.nf_instance_id, mock_profile)
    
    # 生成认证请求
    auth_request = mock_requester.generate_auth_request()
    
    # 发送到 AMF - 使用正确的 DID Auth API 路径
    amf_url = f"http://{target}/nf_auth/v1/mutual_auth/init"
    log_event("BCF", "AUTH", "Sending test auth request", target_uri=amf_url)
    log_debug_json("AUTH", "test_auth_request", auth_request)
    
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(amf_url, json=auth_request, timeout=10) as resp:
                resp_text = await resp.text()
                log_event(
                    "BCF", "AUTH", "Received test auth response",
                    status=resp.status,
                    body=shorten(resp_text, 500),
                )
                
                return jsonify({
                    "status": "sent",
                    "target": target,
                    "auth_request": auth_request,
                    "amf_response": {
                        "status_code": resp.status,
                        "body": resp_text[:1000]
                    }
                })
    except ImportError:
        # Fallback without aiohttp
        import urllib.request
        import urllib.error
        
        req = urllib.request.Request(
            amf_url,
            data=json.dumps(auth_request).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_body = resp.read().decode('utf-8')
                log_event(
                    "BCF", "AUTH", "Received test auth response",
                    status=resp.status,
                    body=shorten(resp_body, 500),
                )
                
                return jsonify({
                    "status": "sent",
                    "target": target,
                    "auth_request": auth_request,
                    "amf_response": {
                        "status_code": resp.status,
                        "body": resp_body[:1000]
                    }
                })
        except urllib.error.HTTPError as e:
            log_event(
                "BCF", "AUTH", "Test auth HTTP error",
                level=logging.ERROR,
                status=e.code,
                reason=e.reason,
            )
            return jsonify({
                "status": "error",
                "target": target,
                "auth_request": auth_request,
                "error": f"HTTP {e.code}: {e.reason}"
            }), 502
        except Exception as e:
            log_event("BCF", "AUTH", "Test auth connection error", level=logging.ERROR, error=str(e))
            return jsonify({
                "status": "connection_error",
                "target": target,
                "auth_request": auth_request,
                "error": str(e)
            }), 502
    except Exception as e:
        log_event("BCF", "AUTH", "Test auth unexpected error", level=logging.ERROR, error=str(e))
        return jsonify({
            "status": "error",
            "target": target,
            "auth_request": auth_request,
            "error": str(e)
        }), 500


# =============================================================================
# 系统端点
# =============================================================================

@app.route('/health', methods=['GET'])
async def health():
    """健康检查"""
    return jsonify({
        "status": "healthy",
        "service": "Mock BCF Server (HTTP/2)",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


@app.route('/status', methods=['GET'])
async def status():
    """服务器状态"""
    stats = storage.get_stats()
    
    nf_summary = []
    nf_by_type = {}
    
    for nf in storage.nf_profiles.values():
        nf_type = nf.get('nfType', 'UNKNOWN')
        if nf_type not in nf_by_type:
            nf_by_type[nf_type] = []
        
        ip_addr = nf.get('ipv4Addresses', ['N/A'])[0] if nf.get('ipv4Addresses') else 'N/A'
        services = nf.get('nfServices', [])
        svc_port = services[0].get('ipEndPoints', [{}])[0].get('port', 'N/A') if services and services[0].get('ipEndPoints') else 'N/A'
        
        nf_info = {
            "nfInstanceId": nf.get('nfInstanceId'),
            "nfType": nf_type,
            "nfStatus": nf.get('nfStatus', 'UNKNOWN'),
            "ipAddress": ip_addr,
            "port": svc_port,
            "priority": nf.get('priority', 65535),
            "load": nf.get('load', 0),
            "did": nf.get('did', '')[:50] + "..." if len(nf.get('did', '')) > 50 else nf.get('did', '')
        }
        nf_summary.append(nf_info)
        nf_by_type[nf_type].append(nf_info)
    
    return jsonify({
        **stats,
        "protocol": "HTTP/2",
        "version": "3.3.0",
        "nf_counts_by_type": {k: len(v) for k, v in nf_by_type.items()},
        "registered_nf_summary": nf_summary
    })


@app.route('/', methods=['GET'])
async def api_info():
    """API 信息"""
    return jsonify({
        "name": "Mock BCF Server for OAI 5GC (HTTP/2)",
        "version": "3.3.0",
        "protocol": "HTTP/2 supported",
        "description": "模拟 BCF 服务器，用于 NF 发现和 NF 自身认证测试（真实 secp256k1 验签）。支持通用 BCF NF 发现框架。",
        "endpoints": {
            "NF 管理（NF 注册用）": {
                "PUT /nbcf_management/v1/nf_instances/{id}": "NF 注册",
                "GET /nbcf_management/v1/nf_instances": "列出所有 NF",
                "GET /nbcf_management/v1/nf_instances/{id}": "获取 NF 详情",
                "PATCH /nbcf_management/v1/nf_instances/{id}": "NF 心跳",
                "DELETE /nbcf_management/v1/nf_instances/{id}": "NF 注销"
            },
            "NF 发现（通用 BCF 框架）": {
                "GET /nbcf_nfm/v1/nf_instances?target_nf_type=AUSF": "NF 发现（支持多种查询条件）",
                "GET /nbcf_nfm/v1/nf_instances/{id}": "获取单个 NF 详情",
                "GET /nbcf_nfm/v1/did/{did}/publickey": "公钥查询（通用格式）"
            },
            "BCF 认证（NF 自身认证）": {
                "POST /nbcf_auth/v1/auth/init": "认证初始化（NF 发起自身认证，BCF 返回 challenge）",
                "POST /nbcf_auth/v1/auth/verify": "签名验证（NF 提交签名，BCF 真实验签后返回 token）",
                "POST /nbcf_auth/v1/token/validate": "Token 验证（可选，验证 token 有效性）"
            },
            "DID 操作（兼容旧接口）": {
                "GET /nbcf_did/v1/public_key/{did}": "查询公钥（返回 public_key_response_t 格式）",
                "GET /nbcf_did/v1/did_documents/{did}": "获取 DID 文档"
            },
            "测试工具": {
                "GET /test/trigger-auth?target=host:port": "触发双向认证测试",
                "POST /test/trigger-auth": "触发双向认证（body: {target: 'host:port'}）"
            },
            "系统": {
                "GET /health": "健康检查",
                "GET /status": "服务状态（含已注册 NF 列表）"
            }
        },
        "nf_discovery_query_params": {
            "target_nf_type": "目标 NF 类型 (AMF, SMF, AUSF, UDM, PCF 等)",
            "requester_nf_type": "请求方 NF 类型",
            "requester_nf_instance_id": "请求方 NF Instance ID",
            "target_plmn_mcc": "目标 PLMN MCC",
            "target_plmn_mnc": "目标 PLMN MNC",
            "target_snssai_sst": "目标 S-NSSAI SST",
            "target_snssai_sd": "目标 S-NSSAI SD",
            "service_name": "所需服务名称 (nausf-auth, nudm-ueau 等)",
            "locality": "地理位置",
            "max_results": "最大返回数量 (默认 10)"
        },
        "nf_discovery_response_format": {
            "nfInstances": "NF Profile 数组",
            "validityPeriod": "结果有效期（秒）",
            "searchId": "搜索标识"
        },
        "public_key_response_format": {
            "found": "bool - 是否找到",
            "did": "string - DID 标识",
            "publicKey": "string - 十六进制格式公钥",
            "nfType": "string - NF 类型 (AMF, SMF 等)",
            "nfInstanceId": "string - NF 实例 ID",
            "errorMessage": "string - 错误信息"
        },
        "preconfigured_nf_instances": list(PRECONFIGURED_NF_INSTANCES.keys()),
        "supported_nf_types": ["AMF", "SMF", "AUSF", "UDM", "PCF", "NSSF", "NEF", "UPF"]
    })


@app.route('/', methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
async def options_handler(path=''):
    """CORS 预检"""
    return '', 204


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Mock BCF Server for OAI 5GC DID Mutual Authentication (HTTP/2)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 启动服务器（默认端口 8089）
  python3 mock_bcf_server_h2.py

  # 指定端口和地址
  python3 mock_bcf_server_h2.py --port 8089 --host 10.29.124.26

  # 启用 HTTPS (HTTP/2 over TLS)
  python3 mock_bcf_server_h2.py --port 8089 --ssl

测试流程:
  1. 启动此服务器
  2. 配置 AMF 的 bcf 指向此服务器 (config.yaml 中的 bcf 节)
  3. 启动 AMF，查看日志确认注册成功
  4. 访问 http://server:8089/status 查看已注册的 NF
  5. 访问 http://server:8089/test/trigger-auth?target=amf_ip:8080 触发认证

NF 发现示例:
  curl "http://server:8089/nbcf_nfm/v1/nf_instances?target_nf_type=AUSF"
  curl "http://server:8089/nbcf_nfm/v1/nf_instances?target_nf_type=UDM&service-name=nudm-ueau"

预配置的 NF 实例:
  - AUSF: ausf-001 @ 192.168.70.138:8090, ausf-002 @ 192.168.70.139:8090
  - UDM:  udm-001 @ 192.168.70.137:8091
  - SMF:  smf-001 @ 192.168.70.133:8080

公钥查询响应格式:
  {
    "found": true,
    "did": "did:oai5gc:...",
    "publicKey": "hex_string",
    "nfType": "AUSF",
    "nfInstanceId": "ausf-001",
    "errorMessage": ""
  }
        """
    )
    
    parser.add_argument('--port', '-p', type=int, default=8089,
                       help='监听端口 (默认: 8089)')
    parser.add_argument('--host', '-H', type=str, default='0.0.0.0',
                       help='监听地址 (默认: 0.0.0.0)')
    parser.add_argument('--ssl', action='store_true',
                       help='启用 SSL/TLS (HTTP/2 over HTTPS)')
    parser.add_argument('--cert', type=str, default='cert.pem',
                       help='SSL 证书文件 (默认: cert.pem)')
    parser.add_argument('--key', type=str, default='key.pem',
                       help='SSL 私钥文件 (默认: key.pem)')
    parser.add_argument('--ausf-ip', type=str, default='192.168.70.138',
                       help='AUSF IP 地址 (默认: 192.168.70.138)')
    parser.add_argument('--ausf-port', type=int, default=8090,
                       help='AUSF 端口 (默认: 8090)')
    parser.add_argument(
        '--notification-transport',
        type=str,
        default=os.environ.get('BCF_NOTIFICATION_TRANSPORT', 'auto'),
        help='订阅通知投递模式: auto / h2c-prior / http1-json (默认: auto)',
    )
    
    args = parser.parse_args()
    DEFAULT_NOTIFICATION_TRANSPORT = resolve_notification_transport(
        args.notification_transport, fallback='auto'
    )
    
    # 更新预配置的 AUSF IP 地址
    if args.ausf_ip != '192.168.70.138' or args.ausf_port != 8090:
        PRECONFIGURED_NF_INSTANCES['ausf-001']['ipv4Addresses'] = [args.ausf_ip]
        PRECONFIGURED_NF_INSTANCES['ausf-001']['nfServices'][0]['ipEndPoints'][0]['ipv4Address'] = args.ausf_ip
        PRECONFIGURED_NF_INSTANCES['ausf-001']['nfServices'][0]['ipEndPoints'][0]['port'] = args.ausf_port
        log_event(
            "BCF", "STATE", "Updated preconfigured AUSF address",
            nfInstanceId="ausf-001",
            ip=f"{args.ausf_ip}:{args.ausf_port}",
        )
    
    # Configure Hypercorn
    config = Config()
    config.bind = [f"{args.host}:{args.port}"]
    config.accesslog = None
    config.loglevel = "warning"
    
    # HTTP/2 support - h2 is enabled by default for HTTPS, use h2c for HTTP
    # For HTTP/2 over cleartext (h2c), we need to enable it explicitly
    config.h2_max_concurrent_streams = 100
    config.h2_max_header_list_size = 65536
    
    if args.ssl:
        if not os.path.exists(args.cert) or not os.path.exists(args.key):
            log_event(
                "BCF", "STATE", "SSL certificate missing, generating self-signed cert",
                level=logging.WARNING,
                cert=args.cert,
                key=args.key,
            )
            generate_self_signed_cert(args.cert, args.key)
        config.certfile = args.cert
        config.keyfile = args.key
        protocol = "https"
    else:
        protocol = "http"
    
    print()
    log_event(
        "BCF", "STATE", "Server starting",
        version="3.3.0",
        protocol=protocol,
        listen=f"{args.host}:{args.port}",
        transport="hypercorn+h2",
        notification_transport=DEFAULT_NOTIFICATION_TRANSPORT,
    )
    log_event(
        "BCF", "STATE", "Key endpoints ready",
        reg="PUT:/nbcf_management/v1/nf_instances/{id}",
        disc="GET:/nbcf_nfm/v1/nf_instances",
        auth_init="POST:/nbcf_auth/v1/auth/init",
        auth_verify="POST:/nbcf_auth/v1/auth/verify",
        status="GET:/status",
    )
    for nf_id, nf in PRECONFIGURED_NF_INSTANCES.items():
        ip = nf.get('ipv4Addresses', ['N/A'])[0] if nf.get('ipv4Addresses') else 'N/A'
        svc = nf.get('nfServices', [{}])[0] if nf.get('nfServices') else {}
        port = svc.get('ipEndPoints', [{}])[0].get('port', 'N/A') if svc.get('ipEndPoints') else 'N/A'
        log_event(
            "BCF", "STATE", "Preconfigured NF instance",
            nfType=nf.get('nfType', 'N/A'),
            nfInstanceId=nf_id,
            ip=f"{ip}:{port}",
        )
    log_event("BCF", "STATE", "Waiting for NF connections")
    print()
    
    # Run with asyncio
    asyncio.run(serve(app, config))


def generate_self_signed_cert(cert_file: str, key_file: str):
    """生成自签名证书（用于测试）"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import timedelta
        
        # Generate key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OAI 5GC Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Mock BCF Server"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        
        # Write key
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        # Write cert
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        log_event("BCF", "STATE", "Generated self-signed certificate", cert=cert_file, key=key_file)
    except ImportError:
        log_event(
            "BCF", "STATE", "cryptography dependency missing for certificate generation",
            level=logging.ERROR,
            error="pip install cryptography",
        )
        raise


if __name__ == '__main__':
    main()

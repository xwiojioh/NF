#!/usr/bin/env python3
"""
JWT Token 生成工具（用于测试 NF Discovery / Subscription 鉴权）

用法:
    python3 gen_token.py [DID] [有效期秒数]

示例:
    python3 gen_token.py                                  # 默认 did:oai:gc:amf001，24小时有效
    python3 gen_token.py did:oai:gc:smf001 3600           # SMF，1小时有效
    python3 gen_token.py did:oai:gc:expired001 -1         # 已过期 token（用于测试 401）

环境变量:
    JWT_SECRET   覆盖默认密钥（需与服务端一致）

服务端默认密钥: p3chain-dev-secret-2026
开启强制鉴权:  export ENABLE_JWT_AUTH=true
"""

import hmac
import hashlib
import base64
import json
import time
import sys
import os

# 所有可用权限
ALL_PERMISSIONS = [
    "service_discovery",
    "subscription_create",
    "subscription_manage",
    "subscription_delete",
]

SECRET = os.environ.get("JWT_SECRET", "p3chain-dev-secret-2026").encode()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(did: str, permissions: list, ttl_seconds: int = 86400) -> str:
    now = int(time.time())
    exp = now + ttl_seconds if ttl_seconds > 0 else now - 10  # 负数 = 过期

    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url_encode(
        json.dumps(
            {
                "did": did,
                "permissions": permissions,
                "iat": now,
                "exp": exp,
                "iss": "p3chain",
                "sub": did,
            }
        ).encode()
    )

    message = f"{header}.{payload}"
    sig = b64url_encode(
        hmac.new(SECRET, message.encode(), hashlib.sha256).digest()
    )
    return f"{message}.{sig}"


if __name__ == "__main__":
    did = sys.argv[1] if len(sys.argv) > 1 else "did:oai:gc:amf001"
    ttl = int(sys.argv[2]) if len(sys.argv) > 2 else 86400

    token = make_token(did, ALL_PERMISSIONS, ttl)

    print("=" * 60)
    print(f"DID        : {did}")
    print(f"Permissions: {ALL_PERMISSIONS}")
    print(f"TTL        : {ttl}s ({'已过期' if ttl < 0 else '有效'})")
    print(f"Secret     : {SECRET.decode()}")
    print("=" * 60)
    print(token)
    print()
    print("# 使用示例（Discovery）:")
    print(f'curl -H "Authorization: Bearer {token}" \\')
    print(f'     "http://127.0.0.1:8004/nbcf_discovery/v1/nf-instances?target-nf-type=AUSF"')
    print()
    print("# 使用示例（创建订阅，subscriberDid 自动从 token 提取）:")
    print(f'curl -X POST -H "Authorization: Bearer {token}" \\')
    print(f'     -H "Content-Type: application/json" \\')
    print(f'     -d \'{{"targetNfType":"AUSF","callbackUrl":"http://127.0.0.1:9000/notifications","eventTypes":["NF_REGISTERED","NF_DEREGISTERED"]}}\' \\')
    print(f'     "http://127.0.0.1:8004/nbcf_subscription/v1/subscriptions"')

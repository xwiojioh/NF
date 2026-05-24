#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mock BCF Server for OAI 5GC DID Mutual Authentication Testing

专门为 OAI AMF 设计的 BCF 模拟服务器，支持：
1. 接收 AMF 注册请求（/nbcf_management/v1/nf_instances/{nfInstanceId}）
2. 存储 DID 文档和公钥
3. 提供公钥查询接口（双向认证时使用）
4. 模拟请求方 NF 触发 AMF 的双向认证流程

根据 AMF 日志分析，AMF 发送的注册请求格式：
- URL: PUT http://oai-bcf:8080/nbcf_management/v1/nf_instances/{nfInstanceId}
- Body: 包含 did, didDocument, nfType, nfInstanceId 等字段

Usage:
    python3 mock_bcf_server.py [--port 8080]

Author: OAI 5GC Team
Date: 2026-01-19
"""

import argparse
import json
import logging
import secrets
import threading
import time
import hashlib
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional, Any, List
from urllib.parse import urlparse, parse_qs, unquote
import base64
import socket
import ssl

# Try to import requests, fall back to urllib if not available
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


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
    """
    
    def __init__(self):
        self._lock = threading.RLock()
        
        # 核心存储
        self.nf_profiles: Dict[str, dict] = {}
        self.did_to_nf: Dict[str, str] = {}
        self.did_documents: Dict[str, dict] = {}
        
        # 统计
        self.stats = {
            "registrations": 0,
            "public_key_queries": 0,
            "auth_triggers": 0,
            "start_time": datetime.utcnow().isoformat() + "Z"
        }
    
    def register_nf(self, nf_instance_id: str, nf_profile: dict) -> dict:
        """
        注册 NF（处理 AMF 的注册请求）
        
        AMF 发送的 profile 包含:
        - nfInstanceId
        - nfType
        - did
        - didDocument (包含 verificationMethod 和公钥)
        - 其他 NF 信息
        """
        with self._lock:
            did = nf_profile.get('did', '')
            did_document = nf_profile.get('didDocument', {})
            nf_type = nf_profile.get('nfType', 'UNKNOWN')
            
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
            
            self.stats["registrations"] += 1
            
            logger.info(f"=" * 60)
            logger.info(f"NF REGISTERED:")
            logger.info(f"  NF Instance ID: {nf_instance_id}")
            logger.info(f"  NF Type: {nf_type}")
            logger.info(f"  DID: {did[:50]}..." if len(did) > 50 else f"  DID: {did}")
            logger.info(f"=" * 60)
            
            return stored_profile
    
    def get_public_key_by_did(self, did: str) -> Optional[dict]:
        """
        根据 DID 查询公钥
        
        这是双向认证的关键接口：
        当 AMF 收到认证请求时，会调用此接口获取对方的公钥
        """
        with self._lock:
            self.stats["public_key_queries"] += 1
            
            if did not in self.did_documents:
                logger.warning(f"Public key query: DID not found - {did[:50]}...")
                return None
            
            did_doc = self.did_documents[did]
            
            # 从 DID Document 中提取公钥
            # 根据 AMF 日志，公钥在 verificationMethod 数组中
            verification_methods = did_doc.get('verificationMethod', [])
            
            if not verification_methods:
                logger.warning(f"No verificationMethod in DID Document for {did[:50]}...")
                return None
            
            # 获取第一个验证方法
            vm = verification_methods[0]
            public_key = None
            public_key_type = vm.get('type', 'EcdsaSecp256k1VerificationKey2019')
            
            # 尝试不同的公钥格式
            if 'publicKeyMultibase' in vm:
                public_key = vm['publicKeyMultibase']
            elif 'publicKeyHex' in vm:
                public_key = vm['publicKeyHex']
            elif 'publicKeyBase58' in vm:
                public_key = vm['publicKeyBase58']
            
            if not public_key:
                logger.warning(f"No public key found in verificationMethod")
                return None
            
            # 获取关联的 NF 信息
            nf_info = None
            if did in self.did_to_nf:
                nf_instance_id = self.did_to_nf[did]
                if nf_instance_id in self.nf_profiles:
                    nf = self.nf_profiles[nf_instance_id]
                    nf_info = {
                        "nfType": nf.get("nfType"),
                        "nfInstanceId": nf_instance_id,
                        "nfStatus": nf.get("nfStatus", "REGISTERED")
                    }
            
            logger.info(f"Public key query SUCCESS: {did[:50]}...")
            
            return {
                "did": did,
                "publicKey": public_key,
                "publicKeyType": public_key_type,
                "nfInfo": nf_info,
                "didDocument": did_doc,
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            
            logger.info(f"NF Deregistered: {nf_instance_id}")
            return True
    
    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._lock:
            return {
                **self.stats,
                "registered_nfs": len(self.nf_profiles),
                "registered_dids": len(self.did_documents),
                "nf_types": list(set(nf.get('nfType', 'UNKNOWN') 
                                    for nf in self.nf_profiles.values()))
            }


# Global storage
storage = BCFStorage()


# =============================================================================
# 模拟请求方 NF - 用于触发 AMF 的双向认证
# =============================================================================

class MockRequesterNF:
    """
    模拟请求方 NF（如 SMF）
    
    用于向 AMF 发起双向认证请求，触发 AMF 的认证流程
    """
    
    def __init__(self):
        # 模拟 SMF 的 DID 和密钥（测试用）
        self.did = "did:oai5gc:mock:smf:test001"
        self.nf_type = "SMF"
        self.nf_instance_id = "mock-smf-001"
        
        # 生成测试用的密钥对（实际使用时应该用真正的密钥）
        self.private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        self.public_key_hex = "04" + "a" * 64 + "b" * 64  # 模拟的公钥
        
    def generate_auth_request(self, target_did: str = "") -> dict:
        """
        生成认证请求
        
        这是发送给 AMF 的 /namf-did-auth/v1/init 请求
        """
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        
        # 构造要签名的数据
        sign_data = f"{self.did}|{target_did}|{nonce}|{timestamp}"
        
        # 模拟签名（实际应该用私钥签名）
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
        """获取注册 profile（用于在 BCF 注册）"""
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


# Global mock requester
mock_requester = MockRequesterNF()


# =============================================================================
# HTTP Request Handler
# =============================================================================

class BCFRequestHandler(BaseHTTPRequestHandler):
    """BCF HTTP 请求处理器"""
    
    protocol_version = 'HTTP/1.1'
    
    def log_message(self, format, *args):
        logger.debug(f"{self.address_string()} - {format % args}")
    
    def send_json_response(self, status_code: int, data: Any):
        """发送 JSON 响应"""
        body = json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8')
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)
    
    def send_error_response(self, status_code: int, error: str, message: str):
        """发送错误响应"""
        self.send_json_response(status_code, {
            "error": error,
            "message": message,
            "status": status_code,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    
    def read_json_body(self) -> Optional[dict]:
        """读取 JSON 请求体"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        
        try:
            body = self.rfile.read(content_length).decode('utf-8')
            logger.debug(f"Request body: {body[:500]}..." if len(body) > 500 else f"Request body: {body}")
            return json.loads(body)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return None
    
    def do_OPTIONS(self):
        """CORS 预检"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept')
        self.send_header('Content-Length', '0')
        self.end_headers()
    
    def do_GET(self):
        """处理 GET 请求"""
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query)
        
        logger.info(f"GET {path}")
        
        # =================================================================
        # 公钥查询 - 双向认证核心接口
        # GET /nbcf_did/v1/public_key/{did}
        # =================================================================
        if path.startswith('/nbcf_did/v1/public_key/'):
            did = path[len('/nbcf_did/v1/public_key/'):]
            did = unquote(did)
            self.handle_get_public_key(did)
        
        # =================================================================
        # DID 文档查询
        # GET /nbcf_did/v1/did_documents/{did}
        # =================================================================
        elif path.startswith('/nbcf_did/v1/did_documents/'):
            did = path[len('/nbcf_did/v1/did_documents/'):]
            did = unquote(did)
            self.handle_get_did_document(did)
        
        # =================================================================
        # NF 实例查询
        # GET /nbcf_management/v1/nf_instances
        # GET /nbcf_management/v1/nf_instances/{nfInstanceId}
        # =================================================================
        elif path == '/nbcf_management/v1/nf_instances':
            nf_type = query.get('nf-type', [None])[0]
            self.handle_get_nf_instances(nf_type)
        
        elif path.startswith('/nbcf_management/v1/nf_instances/'):
            nf_instance_id = path[len('/nbcf_management/v1/nf_instances/'):]
            self.handle_get_nf_instance(nf_instance_id)
        
        # =================================================================
        # 触发认证测试
        # GET /test/trigger-auth?target={amf_host}:{port}
        # =================================================================
        elif path == '/test/trigger-auth':
            target = query.get('target', ['localhost:8080'])[0]
            self.handle_trigger_auth(target)
        
        # =================================================================
        # 系统端点
        # =================================================================
        elif path == '/health':
            self.handle_health()
        
        elif path == '/status':
            self.handle_status()
        
        elif path == '/':
            self.handle_api_info()
        
        else:
            self.send_error_response(404, "not_found", f"Unknown endpoint: {path}")
    
    def do_PUT(self):
        """
        处理 PUT 请求
        
        AMF 注册使用 PUT 方法：
        PUT /nbcf_management/v1/nf_instances/{nfInstanceId}
        """
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        
        logger.info(f"PUT {path}")
        
        data = self.read_json_body()
        if data is None:
            self.send_error_response(400, "invalid_json", "Invalid JSON body")
            return
        
        # =================================================================
        # NF 注册 - AMF 发送的注册请求
        # PUT /nbcf_management/v1/nf_instances/{nfInstanceId}
        # =================================================================
        if path.startswith('/nbcf_management/v1/nf_instances/'):
            nf_instance_id = path[len('/nbcf_management/v1/nf_instances/'):]
            self.handle_register_nf(nf_instance_id, data)
        
        else:
            self.send_error_response(404, "not_found", f"Unknown endpoint: {path}")
    
    def do_POST(self):
        """处理 POST 请求"""
        parsed = urlparse(self.path)
        path = parsed.path
        
        logger.info(f"POST {path}")
        
        data = self.read_json_body()
        if data is None:
            self.send_error_response(400, "invalid_json", "Invalid JSON body")
            return
        
        # =================================================================
        # 简化的 DID 注册（可选）
        # POST /nbcf_did/v1/register
        # =================================================================
        if path == '/nbcf_did/v1/register':
            self.handle_simple_did_register(data)
        
        # =================================================================
        # 手动触发认证
        # POST /test/trigger-auth
        # =================================================================
        elif path == '/test/trigger-auth':
            target = data.get('target', 'localhost:8080')
            self.handle_trigger_auth(target)
        
        else:
            self.send_error_response(404, "not_found", f"Unknown endpoint: {path}")
    
    def do_PATCH(self):
        """处理 PATCH 请求（心跳）"""
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        
        logger.info(f"PATCH {path}")
        
        data = self.read_json_body()
        if data is None:
            self.send_error_response(400, "invalid_json", "Invalid JSON body")
            return
        
        if path.startswith('/nbcf_management/v1/nf_instances/'):
            nf_instance_id = path[len('/nbcf_management/v1/nf_instances/'):]
            self.handle_heartbeat(nf_instance_id, data)
        else:
            self.send_error_response(404, "not_found", f"Unknown endpoint: {path}")
    
    def do_DELETE(self):
        """处理 DELETE 请求"""
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        
        logger.info(f"DELETE {path}")
        
        if path.startswith('/nbcf_management/v1/nf_instances/'):
            nf_instance_id = path[len('/nbcf_management/v1/nf_instances/'):]
            self.handle_deregister_nf(nf_instance_id)
        else:
            self.send_error_response(404, "not_found", f"Unknown endpoint: {path}")
    
    # =========================================================================
    # Handler Implementations
    # =========================================================================
    
    def handle_register_nf(self, nf_instance_id: str, data: dict):
        """
        处理 NF 注册
        
        这是 AMF 启动时发送的请求，包含:
        - NF Profile
        - DID
        - DID Document (包含公钥)
        """
        logger.info("=" * 70)
        logger.info("  RECEIVED NF REGISTRATION REQUEST")
        logger.info("=" * 70)
        logger.info(f"  NF Instance ID: {nf_instance_id}")
        logger.info(f"  NF Type: {data.get('nfType', 'N/A')}")
        logger.info(f"  DID: {data.get('did', 'N/A')[:60]}...")
        
        did_doc = data.get('didDocument', {})
        if did_doc:
            logger.info(f"  DID Document ID: {did_doc.get('id', 'N/A')[:60]}...")
            vm = did_doc.get('verificationMethod', [{}])[0] if did_doc.get('verificationMethod') else {}
            logger.info(f"  Public Key Type: {vm.get('type', 'N/A')}")
            pk = vm.get('publicKeyMultibase') or vm.get('publicKeyHex') or 'N/A'
            logger.info(f"  Public Key: {pk[:40]}..." if len(pk) > 40 else f"  Public Key: {pk}")
        
        logger.info("=" * 70)
        
        # 注册 NF
        result = storage.register_nf(nf_instance_id, data)
        
        # 返回 201 Created
        self.send_response(201)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Location', f'/nbcf_management/v1/nf_instances/{nf_instance_id}')
        self.send_header('Access-Control-Allow-Origin', '*')
        
        body = json.dumps(result, indent=2).encode('utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)
        
        logger.info(f"NF Registration successful, returned 201 Created")
    
    def handle_get_public_key(self, did: str):
        """
        处理公钥查询
        
        这是双向认证的核心接口：
        当 AMF 收到认证请求时，会调用此接口获取发起方的公钥
        """
        logger.info("=" * 70)
        logger.info("  PUBLIC KEY QUERY REQUEST")
        logger.info("=" * 70)
        logger.info(f"  DID: {did[:60]}..." if len(did) > 60 else f"  DID: {did}")
        
        result = storage.get_public_key_by_did(did)
        
        if result:
            logger.info(f"  Result: FOUND")
            logger.info(f"  NF Type: {result.get('nfInfo', {}).get('nfType', 'N/A')}")
            logger.info("=" * 70)
            self.send_json_response(200, result)
        else:
            logger.warning(f"  Result: NOT FOUND")
            logger.info("=" * 70)
            self.send_error_response(404, "did_not_found",
                f"DID not found in BCF registry: {did[:50]}...")
    
    def handle_get_did_document(self, did: str):
        """获取 DID 文档"""
        doc = storage.get_did_document(did)
        
        if doc:
            self.send_json_response(200, doc)
        else:
            self.send_error_response(404, "did_not_found",
                f"DID document not found: {did[:50]}...")
    
    def handle_get_nf_instances(self, nf_type: Optional[str]):
        """获取 NF 实例列表"""
        nfs = storage.get_all_nf_instances(nf_type)
        
        self.send_json_response(200, {
            "nfInstances": nfs,
            "count": len(nfs)
        })
    
    def handle_get_nf_instance(self, nf_instance_id: str):
        """获取单个 NF 实例"""
        nf = storage.get_nf_instance(nf_instance_id)
        
        if nf:
            self.send_json_response(200, nf)
        else:
            self.send_error_response(404, "nf_not_found",
                f"NF instance not found: {nf_instance_id}")
    
    def handle_simple_did_register(self, data: dict):
        """简化的 DID 注册"""
        required = ['did', 'publicKey']
        for field in required:
            if field not in data:
                self.send_error_response(400, "missing_field",
                    f"Missing required field: {field}")
                return
        
        nf_instance_id = data.get('nfInstanceId', secrets.token_hex(16))
        
        # 构造 NF profile
        nf_profile = {
            'nfType': data.get('nfType', 'UNKNOWN'),
            'nfInstanceId': nf_instance_id,
            'did': data['did'],
            'didDocument': {
                'id': data['did'],
                'verificationMethod': [{
                    'id': f"{data['did']}#key-1",
                    'type': 'EcdsaSecp256k1VerificationKey2019',
                    'publicKeyHex': data['publicKey']
                }]
            },
            'nfStatus': 'REGISTERED'
        }
        
        result = storage.register_nf(nf_instance_id, nf_profile)
        
        self.send_json_response(201, {
            "status": "registered",
            "nfInstanceId": nf_instance_id,
            "did": data['did']
        })
    
    def handle_heartbeat(self, nf_instance_id: str, data: dict):
        """处理心跳"""
        result = storage.update_nf_status(nf_instance_id, data)
        
        if result:
            self.send_json_response(200, {
                "nfInstanceId": nf_instance_id,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        else:
            self.send_error_response(404, "nf_not_found",
                f"NF not found: {nf_instance_id}")
    
    def handle_deregister_nf(self, nf_instance_id: str):
        """处理注销"""
        if storage.deregister_nf(nf_instance_id):
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.end_headers()
        else:
            self.send_error_response(404, "nf_not_found",
                f"NF not found: {nf_instance_id}")
    
    def handle_trigger_auth(self, target: str):
        """
        触发双向认证测试
        
        向目标 AMF 发送认证请求，触发 AMF 的双向认证流程
        AMF 会：
        1. 收到请求
        2. 向 BCF 查询发起方的公钥
        3. 验证签名
        4. 返回挑战
        """
        logger.info("=" * 70)
        logger.info("  TRIGGERING MUTUAL AUTHENTICATION")
        logger.info("=" * 70)
        logger.info(f"  Target AMF: {target}")
        logger.info(f"  Requester DID: {mock_requester.did}")
        logger.info(f"  Requester Type: {mock_requester.nf_type}")
        
        # 首先在 BCF 中注册模拟请求方
        mock_profile = mock_requester.get_registration_profile()
        storage.register_nf(mock_requester.nf_instance_id, mock_profile)
        logger.info(f"  Mock requester registered in BCF")
        
        # 生成认证请求
        auth_request = mock_requester.generate_auth_request()
        logger.info(f"  Auth request generated:")
        logger.info(f"    - nonce: {auth_request['nonce']}")
        logger.info(f"    - timestamp: {auth_request['timestamp']}")
        
        # 发送请求到 AMF
        url = f"http://{target}/namf-did-auth/v1/init"
        logger.info(f"  Sending to: {url}")
        logger.info("=" * 70)
        
        storage.stats["auth_triggers"] += 1
        
        try:
            # 发送 HTTP 请求
            if HAS_REQUESTS:
                response = requests.post(
                    url,
                    json=auth_request,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                status_code = response.status_code
                response_text = response.text
                try:
                    response_json = response.json()
                except:
                    response_json = response_text
            else:
                # 使用 urllib 作为后备
                req_data = json.dumps(auth_request).encode('utf-8')
                req = urllib.request.Request(
                    url,
                    data=req_data,
                    headers={"Content-Type": "application/json"},
                    method='POST'
                )
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        status_code = resp.status
                        response_text = resp.read().decode('utf-8')
                        try:
                            response_json = json.loads(response_text)
                        except:
                            response_json = response_text
                except urllib.error.HTTPError as e:
                    status_code = e.code
                    response_text = e.read().decode('utf-8')
                    response_json = response_text
            
            logger.info(f"  Response status: {status_code}")
            logger.info(f"  Response body: {response_text[:500]}")
            
            self.send_json_response(200, {
                "status": "triggered",
                "target": target,
                "request": auth_request,
                "response": {
                    "status_code": status_code,
                    "body": response_json
                }
            })
            
        except Exception as e:
            logger.error(f"  Connection/Error: {e}")
            self.send_json_response(200, {
                "status": "connection_failed",
                "target": target,
                "request": auth_request,
                "error": str(e),
                "hint": "Make sure AMF is running and accessible"
            })
    
    def handle_health(self):
        """健康检查"""
        self.send_json_response(200, {
            "status": "healthy",
            "service": "Mock BCF Server",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    
    def handle_status(self):
        """服务器状态"""
        stats = storage.get_stats()
        
        # 添加已注册的 NF 摘要
        nf_summary = []
        for nf in storage.nf_profiles.values():
            nf_summary.append({
                "nfInstanceId": nf.get('nfInstanceId'),
                "nfType": nf.get('nfType'),
                "did": nf.get('did', '')[:50] + "..." if len(nf.get('did', '')) > 50 else nf.get('did', '')
            })
        
        self.send_json_response(200, {
            **stats,
            "registered_nf_summary": nf_summary
        })
    
    def handle_api_info(self):
        """API 信息"""
        self.send_json_response(200, {
            "name": "Mock BCF Server for OAI 5GC",
            "version": "2.0.0",
            "description": "模拟 BCF 服务器，用于 DID 双向认证测试",
            "endpoints": {
                "NF 管理（AMF 注册用）": {
                    "PUT /nbcf_management/v1/nf_instances/{id}": "NF 注册（AMF 使用此接口）",
                    "GET /nbcf_management/v1/nf_instances": "列出所有 NF",
                    "GET /nbcf_management/v1/nf_instances/{id}": "获取 NF 详情",
                    "PATCH /nbcf_management/v1/nf_instances/{id}": "NF 心跳",
                    "DELETE /nbcf_management/v1/nf_instances/{id}": "NF 注销"
                },
                "DID 操作（双向认证用）": {
                    "GET /nbcf_did/v1/public_key/{did}": "查询公钥（AMF 认证时使用）",
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
            "usage": {
                "step1": "启动此服务器: python3 mock_bcf_server.py --port 8080",
                "step2": "配置 AMF 的 bcf_addr 指向此服务器",
                "step3": "启动 AMF，AMF 会自动注册到此服务器",
                "step4": "访问 /status 查看 AMF 是否注册成功",
                "step5": "访问 /test/trigger-auth?target=amf_ip:8080 触发双向认证"
            }
        })


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Mock BCF Server for OAI 5GC DID Mutual Authentication',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 启动服务器（默认端口 8080，与 AMF 配置的 oai-bcf:8080 匹配）
  python3 mock_bcf_server.py

  # 指定端口
  python3 mock_bcf_server.py --port 9090

测试流程:
  1. 启动此服务器
  2. 配置 AMF 的 bcf_addr 指向此服务器
  3. 启动 AMF，查看日志确认注册成功
  4. 访问 http://localhost:8080/status 查看已注册的 NF
  5. 访问 http://localhost:8080/test/trigger-auth?target=amf_ip:8080 触发认证
        """
    )
    
    parser.add_argument('--port', '-p', type=int, default=8080,
                       help='监听端口 (默认: 8080)')
    parser.add_argument('--host', '-H', type=str, default='0.0.0.0',
                       help='监听地址 (默认: 0.0.0.0)')
    
    args = parser.parse_args()
    
    # 启动服务器
    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, BCFRequestHandler)
    
    print()
    logger.info("=" * 70)
    logger.info("  Mock BCF Server for OAI 5GC DID Mutual Authentication")
    logger.info("=" * 70)
    logger.info(f"  Listening on: http://{args.host}:{args.port}")
    logger.info("-" * 70)
    logger.info("  Key Endpoints:")
    logger.info(f"    PUT  /nbcf_management/v1/nf_instances/{{id}}  - NF 注册")
    logger.info(f"    GET  /nbcf_did/v1/public_key/{{did}}          - 公钥查询")
    logger.info(f"    GET  /test/trigger-auth?target=host:port     - 触发认证测试")
    logger.info(f"    GET  /status                                 - 查看状态")
    logger.info("-" * 70)
    logger.info("  Waiting for AMF registration...")
    logger.info("=" * 70)
    print()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        logger.info("Shutting down...")
        httpd.shutdown()


if __name__ == '__main__':
    main()

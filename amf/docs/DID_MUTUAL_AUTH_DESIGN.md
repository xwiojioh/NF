# DID 双向认证机制设计文档

本文档描述了在 OAI 5GC AMF 中实现的基于 DID 的双向认证（Mutual Authentication）机制，用于在网元间交换业务信息之前完成身份可信校验。

**版本**: v2.1  
**更新日期**: 2026-01-20  
**分支**: `authentication`

---

## 目录

1. [概述](#1-概述)
2. [架构设计](#2-架构设计)
3. [认证协议流程](#3-认证协议流程)
4. [数据结构定义](#4-数据结构定义)
5. [HTTP API 接口](#5-http-api-接口)
6. [代码结构与实现](#6-代码结构与实现)
7. [核心模块详解](#7-核心模块详解)
8. [集成与配置](#8-集成与配置)
9. [安全性分析](#9-安全性分析)
10. [部署与测试](#10-部署与测试)
11. [Mock BCF 服务器](#11-mock-bcf-服务器)
12. [故障排除](#12-故障排除)

---

## 1. 概述

### 1.1 背景与动机

在传统 5GC 架构中，网元间通信依赖 TLS 证书进行身份认证。然而，这种方式存在以下局限性：

- **中心化依赖**：依赖 CA（证书颁发机构）作为信任锚点
- **证书管理复杂**：大规模部署时证书的分发、更新、撤销管理复杂
- **跨域信任困难**：不同运营商或域之间的证书互信配置复杂

基于 DID（Decentralized Identifier）的认证机制提供了一种**去中心化、自主可控**的身份验证方案。

### 1.2 设计目标

| 目标 | 描述 |
|------|------|
| **去中心化认证** | 通过区块链存储公钥，消除对中心化 CA 的依赖 |
| **双向认证** | NF-A 和 NF-B 互相验证对方身份，防止中间人攻击 |
| **挑战-响应机制** | 使用随机 nonce 防止重放攻击 |
| **最小侵入** | 以模块化方式集成到现有 C++ 代码，不破坏原有架构 |
| **可扩展性** | 支持所有网元类型（AMF、SMF、UPF 等）的认证 |

### 1.3 密码学规范

| 项目 | 规范 |
|------|------|
| 椭圆曲线 | **secp256k1** (Bitcoin/Ethereum 兼容) |
| 签名算法 | ECDSA |
| 哈希算法 | SHA256 (签名前置哈希) |
| Nonce 格式 | 32 字节随机数 + 8 字节时间戳 (共 40 字节) |
| 编码格式 | Hex 编码（小写） |
| DID 格式 | \`did:oai5gc:<hex_signature>\` |

---

## 2. 架构设计

### 2.1 整体架构图

\`\`\`
┌────────────────────────────────────────────────────────────────────────────────┐
│                        DID 双向认证架构                                         │
│                                                                                │
│  ┌──────────────────┐                              ┌──────────────────┐        │
│  │                  │                              │                  │        │
│  │     NF-A         │◄───── 双向认证 ─────────────►│     NF-B         │        │
│  │   (如 AMF)       │                              │   (如 SMF)       │        │
│  │                  │                              │                  │        │
│  │ ┌──────────────┐ │                              │ ┌──────────────┐ │        │
│  │ │ DID Auth    │ │                              │ │ DID Auth    │ │        │
│  │ │ Module      │ │                              │ │ Module      │ │        │
│  │ └──────────────┘ │                              │ └──────────────┘ │        │
│  │                  │                              │                  │        │
│  └────────┬─────────┘                              └────────┬─────────┘        │
│           │                                                 │                  │
│           │  查询公钥                                        │  查询公钥        │
│           ▼                                                 ▼                  │
│  ┌──────────────────────────────────────────────────────────────────────┐     │
│  │                                                                      │     │
│  │                        BCF (Blockchain Function)                     │     │
│  │                           DID Proxy 服务                             │     │
│  │                                                                      │     │
│  │  ┌─────────────────────────────────────────────────────────────┐    │     │
│  │  │                     DID Registry                             │    │     │
│  │  │                                                              │    │     │
│  │  │  did:oai5gc:xxx  →  { publicKey, nfType, nfInstanceId }     │    │     │
│  │  │  did:oai5gc:yyy  →  { publicKey, nfType, nfInstanceId }     │    │     │
│  │  │                                                              │    │     │
│  │  └─────────────────────────────────────────────────────────────┘    │     │
│  │                                                                      │     │
│  └──────────────────────────────────────────────────────────────────────┘     │
│                                                                                │
└────────────────────────────────────────────────────────────────────────────────┘
\`\`\`

### 2.2 认证模块组件架构

\`\`\`
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DID Auth Module 组件图                              │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        DIDAuth (高级包装类)                           │  │
│  │                        src/amf-app/did_auth/did_auth.hpp              │  │
│  │                                                                       │  │
│  │   - init_auth_as_initiator()  主动发起认证                            │  │
│  │   - generate_challenge()      生成挑战（响应方）                       │  │
│  │   - process_auth_response()   验证签名（响应方）                       │  │
│  │   - is_peer_authenticated()   检查认证状态                            │  │
│  │                                                                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     did_auth_module (核心实现)                         │  │
│  │                                                                       │  │
│  │   发起方接口:                        响应方接口:                        │  │
│  │   - create_auth_init_request()      - handle_auth_init()              │  │
│  │   - process_auth_challenge()        - handle_auth_complete()          │  │
│  │   - process_auth_result()                                             │  │
│  │                                                                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│           │                    │                    │                       │
│           ▼                    ▼                    ▼                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │   did_crypto    │  │ did_nonce_mgr   │  │ did_session_mgr │            │
│  │                 │  │                 │  │                 │            │
│  │ - secp256k1签名 │  │ - Nonce生成     │  │ - 会话状态机    │            │
│  │ - ECDSA验签     │  │ - Nonce验证     │  │ - Token管理     │            │
│  │ - SHA256哈希    │  │ - 防重放检测    │  │ - 超时清理      │            │
│  │ - Hex编解码     │  │ - 过期清理      │  │                 │            │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘            │
│           │                                         │                       │
│           │                    ┌────────────────────┘                       │
│           ▼                    ▼                                            │
│  ┌─────────────────────────────────────────┐                               │
│  │       bcf_interface (回调接口)          │                               │
│  │                                         │                               │
│  │  - NF 发现回调 (nf_discovery_callback)  │                               │
│  │  - 公钥查询回调 (public_key_query)      │                               │
│  │  - 公钥本地缓存 (内存缓存)              │                               │
│  │  - NF 选择器 (nf_selector)              │                               │
│  └─────────────────────────────────────────┘                               │
│                       │                                                     │
│                       │ (回调由外部 BCF 客户端实现)                         │
│                       ▼                                                     │
│             ┌─────────────────────┐                                        │
│             │   外部 BCF 服务      │                                        │
│             │  (独立工程实现)      │                                        │
│             └─────────────────────┘                                        │
└─────────────────────────────────────────────────────────────────────────────┘
\`\`\`

### 2.3 与 AMF 架构的集成

\`\`\`
┌─────────────────────────────────────────────────────────────────────────────┐
│                          AMF 架构集成视图                                    │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                    HTTP Server (双协议支持)                            │ │
│  │   ┌─────────────────────────┐  ┌─────────────────────────────────┐   │ │
│  │   │ amf_http1_server.cpp    │  │    amf_http2_server.cpp         │   │ │
│  │   │ (Pistache, HTTP/1.1)    │  │    (nghttp2, HTTP/2)            │   │ │
│  │   │ DIDAuthApiImpl          │  │    DID Auth handlers 内置       │   │ │
│  │   └─────────────────────────┘  └─────────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│           │                    │                    │                      │
│           ▼                    ▼                    ▼                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │  DIDAuthApiImpl │  │ 其他 API Impl   │  │ 其他 API Impl   │            │
│  │   (新增)        │  │  (现有)         │  │  (现有)         │            │
│  └────────┬────────┘  └─────────────────┘  └─────────────────┘            │
│           │                                                                │
│           ▼                                                                │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                            amf_app                                    │ │
│  │                                                                       │ │
│  │  新增成员:                          新增方法:                          │ │
│  │  - m_did_auth (DIDAuth*)           - init_did_auth_module()          │ │
│  │  - m_did_auth_enabled              - handle_did_auth_init()          │ │
│  │                                    - handle_did_auth_complete()       │ │
│  │                                    - handle_did_auth_status()         │ │
│  │                                                                       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│           │                                                                │
│           ▼                                                                │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                        DID Auth Module                                │ │
│  │                      src/amf-app/did_auth/                            │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
\`\`\`

**HTTP/2 支持说明:**

AMF 默认使用 HTTP/2 协议（通过配置 `http_version: 2`）。DID Auth API 路由同时在 HTTP/1.1 和 HTTP/2 服务器中注册：

- **HTTP/1.1 服务器** (`amf_http1_server.cpp`): 使用 Pistache 路由 + `DIDAuthApiImpl`
- **HTTP/2 服务器** (`amf_http2_server.cpp`): 使用 nghttp2 + 内置 handler 函数

---

## 3. 认证协议流程

### 3.1 优化后的三步握手流程

本实现采用优化后的三步握手协议，减少往返次数：

\`\`\`
┌────────────┐                                           ┌────────────┐
│  发起方     │                                           │  响应方     │
│ (Initiator)│                                           │ (Responder)│
│   NF-A     │                                           │   NF-B     │
└─────┬──────┘                                           └─────┬──────┘
      │                                                        │
      │  Step 1: POST /nf_auth/v1/mutual_auth/init            │
      │  ┌──────────────────────────────────────────────┐     │
      │  │ {                                            │     │
      │  │   "initiator_did": "did:oai5gc:abc123...",  │     │
      │  │   "nonce": "a1b2c3...(80 hex chars)",       │     │
      │  │   "timestamp": 1705632000000,               │     │
      │  │   "nf_type": "AMF"                          │     │
      │  │ }                                            │     │
      │  └──────────────────────────────────────────────┘     │
      │─────────────────────────────────────────────────────▶│
      │                                                        │
      │                        ┌─────────────────────────────┐│
      │                        │ 1. 从 BCF 查询发起方公钥     ││
      │                        │ 2. 验证 DID 格式            ││
      │                        │ 3. 生成响应方 nonce          ││
      │                        │ 4. 对发起方 nonce 签名       ││
      │                        │ 5. 创建会话                 ││
      │                        └─────────────────────────────┘│
      │                                                        │
      │  Step 2: Challenge Response (HTTP 200)                │
      │  ┌──────────────────────────────────────────────┐     │
      │  │ {                                            │     │
      │  │   "session_id": "sess-uuid-xxx",            │     │
      │  │   "responder_did": "did:oai5gc:def456...",  │     │
      │  │   "challenge_nonce": "d4e5f6...",           │     │
      │  │   "challenge_timestamp": 1705632001000,     │     │
      │  │   "responder_signature": "3045022100..."    │     │
      │  │ }                                            │     │
      │  └──────────────────────────────────────────────┘     │
      │◀─────────────────────────────────────────────────────│
      │                                                        │
      │ ┌─────────────────────────────────────┐               │
      │ │ 1. 从 BCF 查询响应方公钥            │               │
      │ │ 2. 验证响应方签名 (对发起方nonce)    │               │
      │ │ 3. 对响应方 nonce 签名              │               │
      │ └─────────────────────────────────────┘               │
      │                                                        │
      │  Step 3: POST /nf_auth/v1/mutual_auth/complete        │
      │  ┌──────────────────────────────────────────────┐     │
      │  │ {                                            │     │
      │  │   "session_id": "sess-uuid-xxx",            │     │
      │  │   "initiator_signature": "304402..."        │     │
      │  │ }                                            │     │
      │  └──────────────────────────────────────────────┘     │
      │─────────────────────────────────────────────────────▶│
      │                                                        │
      │                        ┌─────────────────────────────┐│
      │                        │ 1. 验证发起方签名            ││
      │                        │ 2. 生成认证 Token           ││
      │                        │ 3. 更新会话状态为 COMPLETE   ││
      │                        └─────────────────────────────┘│
      │                                                        │
      │  Step 4: Auth Result (HTTP 200)                       │
      │  ┌──────────────────────────────────────────────┐     │
      │  │ {                                            │     │
      │  │   "success": true,                          │     │
      │  │   "auth_token": "eyJhbGciOiJIUzI1NiIs...",  │     │
      │  │   "expires_in": 3600,                       │     │
      │  │   "peer_did": "did:oai5gc:abc123..."        │     │
      │  │ }                                            │     │
      │  └──────────────────────────────────────────────┘     │
      │◀─────────────────────────────────────────────────────│
      │                                                        │
      ▼                                                        ▼
 ══════════════════════ 双向认证完成 ══════════════════════════
\`\`\`

### 3.2 会话状态机

\`\`\`
                                 ┌─────────┐
                    ┌────────────│  IDLE   │◄────────────────┐
                    │            └────┬────┘                 │
                    │                 │                      │
                    │     收到/发起 AuthInit                 │
                    │                 │                      │
                    ▼                 ▼                      │
           ┌─────────────┐    ┌──────────────┐              │
           │ AUTH_FAILED │    │ AUTH_PENDING │              │
           │             │    │ (等待认证)    │              │
           └─────────────┘    └──────┬───────┘              │
                  ▲                  │                      │
                  │                  │ 发送/收到 Challenge   │
                  │                  ▼                      │
                  │          ┌───────────────────┐          │
          验签失败 │          │ CHALLENGE_SENT    │          │ 会话超时
                  │◀─────────│ (响应方发送挑战)   │          │ 或关闭
                  │          └────────┬──────────┘          │
                  │                   │                     │
                  │          ┌────────▼──────────┐          │
                  │          │ CHALLENGE_RECEIVED│          │
                  │◀─────────│ (发起方收到挑战)   │          │
                  │          └────────┬──────────┘          │
                  │                   │                     │
                  │                   │ 发送响应             │
                  │                   ▼                     │
                  │          ┌─────────────────┐            │
                  │          │  RESPONSE_SENT  │            │
                  │◀─────────│  (已发送响应)   │            │
                  │          └────────┬────────┘            │
                  │                   │                     │
                  │                   │ 验签成功             │
                  │                   ▼                     │
                  │          ┌─────────────────┐            │
                  │          │  PEER_VERIFIED  │            │
                  │◀─────────│ (对端已验证)    │            │
                  │          └────────┬────────┘            │
                  │                   │                     │
                  │                   │ 双向验证完成         │
                  │                   ▼                     │
                  │          ┌───────────────────────┐      │
                  └──────────│ MUTUAL_AUTH_COMPLETE  │──────┘
                             │    (双向认证完成)     │
                             └───────────────────────┘
\`\`\`

### 3.3 签名数据格式

#### 发起方发送的 Nonce 签名数据格式
\`\`\`
被签名数据 = SHA256(initiator_nonce_hex)
签名 = ECDSA_Sign(私钥, 被签名数据)
\`\`\`

#### 响应方验证签名
\`\`\`
被验证数据 = SHA256(initiator_nonce_hex)
验证结果 = ECDSA_Verify(发起方公钥, 被验证数据, 签名)
\`\`\`

---

## 4. 数据结构定义

### 4.1 枚举类型

\`\`\`cpp
// 文件: src/amf-app/did_auth/did_auth_types.hpp

/**
 * @brief 认证会话状态
 */
enum class AuthState {
  IDLE,                   // 空闲状态
  AUTH_PENDING,           // 等待认证
  CHALLENGE_SENT,         // 已发送挑战（作为响应方）
  CHALLENGE_RECEIVED,     // 已收到挑战（作为发起方）
  RESPONSE_SENT,          // 已发送响应
  PEER_VERIFIED,          // 对端已验证（单向完成）
  MUTUAL_AUTH_COMPLETE,   // 双向认证完成
  AUTH_FAILED             // 认证失败
};

/**
 * @brief 认证结果
 */
enum class AuthResult {
  SUCCESS,                  // 认证成功
  MUTUAL_SUCCESS,           // 双向认证成功
  FAILURE_INVALID_DID,      // DID 无效
  FAILURE_KEY_NOT_FOUND,    // 公钥未找到
  FAILURE_SIGNATURE_INVALID,// 签名验证失败
  FAILURE_NONCE_EXPIRED,    // Nonce 过期
  FAILURE_NONCE_REUSED,     // Nonce 重复使用（重放攻击）
  FAILURE_TIMEOUT,          // 认证超时
  FAILURE_BCF_UNAVAILABLE,  // BCF 不可用
  FAILURE_SESSION_NOT_FOUND,// 会话不存在
  FAILURE_INTERNAL_ERROR    // 内部错误
};
\`\`\`

### 4.2 核心数据结构

\`\`\`cpp
/**
 * @brief Nonce 结构 (32字节随机数 + 8字节时间戳)
 */
struct nonce_t {
  std::vector<uint8_t> random_bytes;  // 32 字节随机数
  uint64_t timestamp_ms;              // 毫秒级时间戳
  
  std::string to_hex() const;           // 转为 80 字符 Hex
  static nonce_t from_hex(const std::string& hex_str);
  bool is_expired(uint64_t timeout_ms = 300000) const;
  static uint64_t current_timestamp_ms();
};

/**
 * @brief 认证会话上下文
 */
struct auth_session_t {
  std::string session_id;
  std::string local_did;
  std::string remote_did;
  std::string peer_did;              // 对端 DID (alias)
  AuthState state;
  
  nonce_t local_nonce;               // 本地生成的 nonce
  nonce_t remote_nonce;              // 对端发来的 nonce
  std::string remote_public_key;     // 对端公钥
  
  bool is_initiator;                 // 是否为发起方
  bool authenticated;                // 是否已认证
  
  std::string auth_token;            // 认证令牌
  uint64_t token_expires_at;         // 令牌过期时间
  uint64_t created_at;               // 会话创建时间
};

/**
 * @brief BCF 公钥查询响应
 */
struct bcf_public_key_response_t {
  std::string did;
  std::string public_key;     // Hex 编码的压缩公钥 (66 字符)
  std::string nf_type;
  std::string nf_instance_id;
  bool found;
  std::string error_message;
};
\`\`\`

### 4.3 HTTP API 请求/响应结构

\`\`\`cpp
/**
 * @brief 简化的认证请求 (HTTP API 输入)
 */
struct auth_request_t {
  std::string initiator_did;
  std::string nonce;
  uint64_t timestamp;
  std::string nf_type;
};

/**
 * @brief 简化的挑战响应 (HTTP API 输出)
 */
struct auth_challenge_t {
  std::string responder_did;
  std::string challenge_nonce;
  uint64_t challenge_timestamp;
  std::string responder_signature;
};

/**
 * @brief 简化的认证响应 (HTTP API 输入)
 */
struct auth_response_t {
  std::string session_id;
  std::string initiator_signature;
};

/**
 * @brief 简化的认证结果 (HTTP API 输出)
 */
struct auth_result_t {
  std::string peer_did;
  std::string auth_token;
  int expires_in;
  std::string error_message;
};
\`\`\`

---

## 5. HTTP API 接口

### 5.1 API 端点概览

| 方法 | 端点 | 描述 |
|------|------|------|
| POST | \`/nf_auth/v1/mutual_auth/init\` | 发起认证，接收挑战 |
| POST | \`/nf_auth/v1/mutual_auth/complete\` | 完成认证，提交签名 |
| GET | \`/nf_auth/v1/status/{sessionId}\` | 查询会话状态 |

### 5.2 认证初始化 API

**POST /nf_auth/v1/mutual_auth/init**

请求体:
\`\`\`json
{
  "initiator_did": "did:oai5gc:abc123def456...",
  "nonce": "a1b2c3d4e5f6...(80 hex characters)",
  "timestamp": 1705632000000,
  "nf_type": "AMF",
  "session_id": "optional-client-session-id"
}
\`\`\`

成功响应 (200 OK):
\`\`\`json
{
  "session_id": "sess-550e8400-e29b-41d4-a716-446655440000",
  "responder_did": "did:oai5gc:789xyz...",
  "challenge_nonce": "f6e5d4c3b2a1...(80 hex characters)",
  "challenge_timestamp": 1705632001000,
  "responder_signature": "3045022100abc...def"
}
\`\`\`

错误响应 (4xx/5xx):
\`\`\`json
{
  "error": "invalid_request",
  "message": "Missing required field: initiator_did"
}
\`\`\`

### 5.3 认证完成 API

**POST /nf_auth/v1/mutual_auth/complete**

请求体:
\`\`\`json
{
  "session_id": "sess-550e8400-e29b-41d4-a716-446655440000",
  "initiator_signature": "304402...signature_hex"
}
\`\`\`

成功响应 (200 OK):
\`\`\`json
{
  "success": true,
  "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "peer_did": "did:oai5gc:abc123..."
}
\`\`\`

失败响应 (401 Unauthorized):
\`\`\`json
{
  "success": false,
  "error": "authentication_failed",
  "message": "Signature verification failed"
}
\`\`\`

### 5.4 状态查询 API

**GET /nf_auth/v1/status/{sessionId}**

成功响应 (200 OK):
\`\`\`json
{
  "session_id": "sess-550e8400-e29b-41d4-a716-446655440000",
  "peer_did": "did:oai5gc:abc123...",
  "authenticated": true,
  "state": "COMPLETE",
  "created_at": 1705632000000
}
\`\`\`

---

## 6. 代码结构与实现

### 6.1 新增文件列表

\`\`\`
src/amf-app/did_auth/
├── CMakeLists.txt              # 构建配置
├── did_auth.hpp                # 主模块头文件 (did_auth_module + DIDAuth)
├── did_auth.cpp                # 主模块实现
├── did_auth_types.hpp          # 数据结构定义
├── did_auth_types.cpp          # 数据结构实现
├── did_crypto.hpp              # 加密模块头文件
├── did_crypto.cpp              # 加密模块实现 (secp256k1, ECDSA, SHA256)
├── did_nonce_manager.hpp       # Nonce 管理器头文件
├── did_nonce_manager.cpp       # Nonce 管理器实现
├── did_session_manager.hpp     # 会话管理器头文件
├── did_session_manager.cpp     # 会话管理器实现
├── bcf_interface.hpp           # BCF 回调接口定义 (NF发现、公钥查询、NF选择)
├── bcf_interface.cpp           # NF 选择器实现
├── did_auth_http_handler.hpp   # HTTP 处理器头文件
├── did_auth_http_handler.cpp   # HTTP 处理器实现
└── itti_msg_did_auth.hpp       # ITTI 消息定义

src/sbi/api/
├── DIDAuthApi.h                # API 基类定义
└── DIDAuthApi.cpp              # API 路由注册

src/sbi/impl/
├── DIDAuthApiImpl.h            # API 实现头文件
└── DIDAuthApiImpl.cpp          # API 实现
\`\`\`

### 6.2 修改的现有文件

| 文件路径 | 修改内容 |
|---------|---------|
| \`src/amf-app/amf_app.hpp\` | 添加 \`m_did_auth\` 成员和认证处理方法声明 |
| \`src/amf-app/amf_app.cpp\` | 实现 \`init_did_auth_module()\` 和 \`handle_did_auth_*\` 方法 |
| \`src/sbi/amf_http1_server.hpp\` | 添加 \`DIDAuthApiImpl\` 成员 |
| \`src/sbi/amf_http1_server.cpp\` | 初始化 DID Auth API (HTTP/1.1) |
| \`src/sbi/amf_http2_server.hpp\` | 添加 DID Auth handler 声明 |
| \`src/sbi/amf_http2_server.cpp\` | 添加 `/nf_auth/v1/` 路由和 handler 实现 (HTTP/2) |
| \`src/amf-app/CMakeLists.txt\` | 添加 DID_AUTH 子目录和链接库 |

### 6.3 amf_app.hpp 新增内容

\`\`\`cpp
// 文件: src/amf-app/amf_app.hpp

#include "did_auth/did_auth.hpp"

class amf_app {
 private:
  // DID Authentication
  std::unique_ptr<oai::amf::did_auth::DIDAuth> m_did_auth;
  bool m_did_auth_enabled;

 public:
  // DID Auth initialization
  bool init_did_auth_module();

  // DID Auth HTTP handlers
  bool handle_did_auth_init(
      const std::string& initiator_did,
      const std::string& nonce,
      uint64_t timestamp,
      const std::string& nf_type,
      const std::string& source_address,
      nlohmann::json& response_json,
      int& http_code);

  bool handle_did_auth_complete(
      const std::string& session_id,
      const std::string& initiator_signature,
      const std::string& source_address,
      nlohmann::json& response_json,
      int& http_code);

  bool handle_did_auth_status(
      const std::string& session_id,
      nlohmann::json& response_json,
      int& http_code);
};
\`\`\`

### 6.4 CMakeLists.txt 配置

\`\`\`cmake
# 文件: src/amf-app/did_auth/CMakeLists.txt

add_library(DID_AUTH STATIC
  did_auth.cpp
  did_auth_types.cpp
  did_crypto.cpp
  did_nonce_manager.cpp
  did_session_manager.cpp
  bcf_interface.cpp
)

target_include_directories(DID_AUTH PUBLIC 
  \${CMAKE_CURRENT_SOURCE_DIR}
  \${SRC_TOP_DIR}/common
  \${SRC_TOP_DIR}/\${MOUNTED_COMMON}/common
  \${SRC_TOP_DIR}/\${MOUNTED_COMMON}/http
  \${SRC_TOP_DIR}/\${MOUNTED_COMMON}/logger
  \${SRC_TOP_DIR}/\${MOUNTED_COMMON}/utils
)

# OpenSSL for cryptographic operations
find_package(OpenSSL REQUIRED)
target_link_libraries(DID_AUTH PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# nlohmann_json
find_package(nlohmann_json QUIET)
if(nlohmann_json_FOUND)
  target_link_libraries(DID_AUTH PUBLIC nlohmann_json::nlohmann_json)
endif()

target_compile_features(DID_AUTH PUBLIC cxx_std_17)
\`\`\`

---

## 7. 核心模块详解

### 7.1 加密模块 (did_crypto)

\`\`\`cpp
// 文件: src/amf-app/did_auth/did_crypto.hpp

class did_crypto {
 public:
  did_crypto();                                    // 生成新密钥对
  did_crypto(const std::string& private_key_hex); // 从私钥恢复
  ~did_crypto();

  // 签名操作
  std::string sign(const std::string& message_hex);
  std::string sign_raw(const std::vector<uint8_t>& data);

  // 验签操作 (静态方法)
  static bool verify(
      const std::string& message_hex,
      const std::string& signature_hex,
      const std::string& public_key_hex);

  // 公钥操作
  std::string get_public_key_hex() const;
  static std::string derive_public_key(const std::string& private_key_hex);

  // 哈希操作
  static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
  static std::string sha256_hex(const std::string& data);

  // Hex 编解码
  static std::string to_hex(const std::vector<uint8_t>& data);
  static std::vector<uint8_t> from_hex(const std::string& hex);

  // 随机数生成
  static std::vector<uint8_t> generate_random_bytes(size_t count);

 private:
  std::vector<uint8_t> m_private_key;  // 32 字节私钥
  std::string m_public_key_hex;        // 66 字符压缩公钥
};
\`\`\`

**关键实现细节:**

1. **secp256k1 曲线**: 使用 OpenSSL 的 EC_KEY 和 NID_secp256k1
2. **ECDSA 签名**: 返回 DER 编码的签名 (可变长度, 约 70-72 字节)
3. **公钥压缩**: 使用 POINT_CONVERSION_COMPRESSED (33 字节 = 66 Hex)
4. **安全清理**: 析构时使用 OPENSSL_cleanse 清除私钥

### 7.2 Nonce 管理器 (did_nonce_manager)

\`\`\`cpp
// 文件: src/amf-app/did_auth/did_nonce_manager.hpp

class did_nonce_manager {
 public:
  did_nonce_manager(uint64_t validity_sec = 300);  // 默认 5 分钟有效期
  ~did_nonce_manager();

  // 生成新 Nonce
  nonce_t generate_nonce();
  std::string generate_nonce_hex();

  // 验证 Nonce
  bool validate_nonce(const std::string& nonce_hex);
  bool validate_and_consume(const std::string& nonce_hex);

  // 标记已使用 (防重放)
  void mark_used(const std::string& nonce_hex);

  // 检查是否已使用
  bool is_used(const std::string& nonce_hex) const;

  // 清理过期 Nonce
  void cleanup_expired();

 private:
  uint64_t m_validity_ms;
  std::unordered_set<std::string> m_used_nonces;
  std::map<uint64_t, std::string> m_nonce_expiry;  // 过期时间 -> nonce
  mutable std::shared_mutex m_mutex;
};
\`\`\`

**防重放攻击机制:**
- 每个 Nonce 包含时间戳，超过 validity_sec 后自动过期
- 已使用的 Nonce 记录在 \`m_used_nonces\` 中
- 定期调用 \`cleanup_expired()\` 清理过期记录

### 7.3 会话管理器 (did_session_manager)

\`\`\`cpp
// 文件: src/amf-app/did_auth/did_session_manager.hpp

class did_session_manager {
 public:
  did_session_manager(
      uint64_t session_timeout_sec = 300,   // 会话超时 5 分钟
      uint64_t token_validity_sec = 3600);  // Token 有效期 1 小时

  // 创建会话
  std::string create_session(
      const std::string& local_did,
      const std::string& remote_did,
      bool is_initiator);

  // 获取/更新会话
  std::shared_ptr<auth_session_t> get_session(const std::string& session_id);
  bool update_session_state(const std::string& session_id, AuthState new_state);

  // 完成认证
  std::string complete_authentication(const std::string& session_id);

  // 查询
  std::string find_session_by_peer_did(const std::string& peer_did) const;
  bool is_session_authenticated(const std::string& session_id) const;

  // 维护
  void cleanup_expired_sessions();
  void close_session(const std::string& session_id);

 private:
  std::map<std::string, std::shared_ptr<auth_session_t>> m_sessions;
  std::map<std::string, std::string> m_peer_did_to_session;
  mutable std::shared_mutex m_mutex;
  
  uint64_t m_session_timeout_ms;
  uint64_t m_token_validity_sec;
  
  std::string generate_auth_token(const auth_session_t& session);
};
\`\`\`

### 7.4 BCF 接口与回调（bcf_interface）

注意：BCF（Binding/Discovery/Capability Function）实现为独立工程，不再在本仓库内包含其 HTTP 客户端实现。仓库内提供与 BCF 交互的接口与回调定义（见 `src/amf-app/did_auth/bcf_interface.hpp`），上层 NF（如 AMF）需要在运行时将具体的查询实现通过回调注入到 DIDAuth 模块。

主要元素：
- nf_profile_t：描述一个 NF 的 profile，需要包含用于互相认证的可达 URI（get_uri() / get_service_uri()）。
- nf_discovery_criteria_t：发起方用于向 BCF 请求候选 NF 的筛选条件（NF 类型、PLMN、S-NSSAI、服务名等）。
- nf_discovery_response_t：BCF 返回的候选 NF 列表（vector<nf_profile_t>）。
- public_key_response_t：查询 DID 对应公钥的响应（found + public_key 字段）。

回调类型（在代码中定义）：
- nf_discovery_callback_t: std::function<nf_discovery_response_t(const nf_discovery_criteria_t&)>，用于执行 NF 发现。
- public_key_query_callback_t: std::function<public_key_response_t(const std::string& did)>，用于按 DID 查询公钥。

NF 选择器：仓库提供 `nf_selector` 工具，支持多种策略（按优先级 priority、按负载 load、按容量 capacity、轮询 round-robin、随机 random、按地域 locality 等）。发起方在拿到 `nf_discovery_response_t` 后可调用 `nf_selector::select(...)` 选择最终的目标 NF，并从 `nf_profile_t` 获取 URI，随后开始双向认证流程。

示例（伪代码，说明交互流程）：

1) 发起方（Initiator）准备 discovery criteria 并调用 discovery 回调：

```cpp
nf_discovery_criteria_t crit;
// 填充 crit（nf_type, plmn, snssai, service_name 等）
nf_discovery_response_t resp = nf_discovery_callback(crit);
// resp.nf_profiles 中包含若干 nf_profile_t，每个都应包含 get_uri()
```

2) 使用 nf_selector 选出一个 NF：

```cpp
nf_profile_t selected = nf_selector::select(resp.nf_profiles, NfSelectionStrategy::ROUND_ROBIN, local_locality);
std::string remote_uri = selected.get_uri();
```

3) 获取公钥（若需要）：

```cpp
public_key_response_t pk_resp = public_key_query_callback(remote_did);
if (pk_resp.found) {
  // 使用 pk_resp.public_key 进行签名验证等
}
```

保留的 BCF HTTP API 示例（仅作兼容参考，实际部署中可能由外部 BCF 实现提供）：
- `GET /nbcf_did/v1/public-key/{did}` - 查询 DID 对应的公钥（返回 JSON 中包含 publicKeyHex 字段）


### 7.5 高级包装类 (DIDAuth)

```cpp
// 文件: src/amf-app/did_auth/did_auth.hpp

/**
 * @brief BCF 交互相关的回调类型（由上层注入）
 * - nf_discovery_callback_t: 用于 NF 发现
 * - public_key_query_callback_t: 用于按 DID 查询公钥
 */

class DIDAuth {
 public:
  // 构造器不再包含内嵌 BCF 的 URI，BCF 操作通过回调注入
  DIDAuth(
    const std::string& local_did,
    const std::string& private_key_path);
  ~DIDAuth();

  bool initialize();

  // 注入回调：NF 发现与按 DID 查询公钥
  void set_nf_discovery_callback(nf_discovery_callback_t cb);
  void set_public_key_query_callback(public_key_query_callback_t cb);

  // 响应方接口
  bool generate_challenge(
    const auth_request_t& request,
    auth_challenge_t& challenge,
    std::string& session_id);

  bool process_auth_response(
      const auth_response_t& response,
      auth_result_t& result);

  // 发起方接口（需要先设置 HTTP 回调）
  bool init_auth_as_initiator(
      const std::string& remote_endpoint,
      std::string& auth_token);

  // 状态查询
  bool get_session(const std::string& session_id, auth_session_t& session);
  bool is_peer_authenticated(const std::string& peer_did);
  std::string get_peer_auth_token(const std::string& peer_did);

  // 维护
  void cleanup_expired_sessions();

  // 获取底层模块（用于高级操作）
  did_auth_module* get_module() { return m_module.get(); }

 private:
  std::string m_local_did;
  std::string m_private_key_path;
  std::string m_bcf_api_uri;

  std::unique_ptr<did_auth_module> m_module;
  bool m_initialized;

  // HTTP request callback for initiator mode
  http_request_callback_t m_http_callback;

  std::map<std::string, std::string> m_peer_did_to_session;
  mutable std::mutex m_peer_map_mutex;
};
\`\`\`

---

## 8. 集成与配置

### 8.1 初始化流程

\`\`\`cpp
// 在 amf_app 构造函数中调用
bool amf_app::init_did_auth_module() {
  // 1. 检查是否启用 NF 注册且配置了 BCF
  if (!amf_cfg->support_features.enable_nf_registration ||
      amf_cfg->bcf_addr.uri_root.empty()) {
    m_did_auth_enabled = false;
    return true;
  }

  // 2. 读取扩展 Profile (包含 DID)
  nlohmann::json extended_profile = read_extended_profile_from_file();
  std::string local_did = extended_profile["did"];

  // 3. 获取 BCF API URI
  std::string bcf_api_uri = amf_cfg->bcf_addr.uri_root;

  // 4. 私钥路径
  std::string private_key_path = "/usr/local/etc/oai/keys/private_key.pem";

  // 5. 创建并初始化 DIDAuth 实例
  m_did_auth = std::make_unique<oai::amf::did_auth::DIDAuth>(
      local_did, private_key_path, bcf_api_uri);

  if (!m_did_auth->initialize()) {
    m_did_auth_enabled = false;
    return false;
  }

  // 6. 设置 HTTP 回调（通过 amf_sbi 发送请求）
  m_did_auth->set_http_request_callback(
      [](const std::string& uri, const std::string& method,
         const std::string& body, std::string& response_body,
         uint32_t& response_code) -> bool {
        return amf_sbi_inst->send_did_auth_request(
            uri, method, body, response_body, response_code);
      });

  m_did_auth_enabled = true;
  return true;
}
\`\`\`

### 8.2 HTTP 回调架构

DID 认证模块采用回调机制与 HTTP 通信解耦，由 `amf_sbi` 负责实际的 HTTP 通信：

\`\`\`
┌─────────────────────────────────────────────────────────────────┐
│                         amf_app                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  init_did_auth_module()                                     ││
│  │    └── set_http_request_callback(lambda -> amf_sbi)         ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌──────────────────────┐           ┌───────────────────────┐
│      DIDAuth         │           │       amf_sbi         │
│ (did_auth module)    │ callback  │                       │
│                      │◄──────────│ send_did_auth_request │
│ init_auth_as_initiator           │                       │
│   └── m_http_callback()          │ send_http_request()   │
└──────────────────────┘           └───────────────────────┘
                                            │
                                            ▼
                                   ┌───────────────────┐
                                   │   http_client     │
                                   │  (common-src)     │
                                   └───────────────────┘
\`\`\`

**amf_sbi 新增方法:**
\`\`\`cpp
// 文件: src/amf-app/amf_sbi.hpp

// DID 认证 HTTP 请求（作为回调被 DID auth 模块调用）
bool send_did_auth_request(
    const std::string& uri, const std::string& method, const std::string& body,
    std::string& response_body, uint32_t& response_code);

// 发起 DID 双向认证
bool initiate_did_mutual_auth(
    const std::string& remote_endpoint, std::string& auth_token);
\`\`\`

### 8.3 配置要求

| 配置项 | 说明 | 示例值 |
|--------|------|--------|
| \`enable_nf_registration\` | 启用 NF 注册 | \`true\` |
| \`bcf_addr.uri_root\` | BCF API 基础 URI（非空时启用 DID Auth） | \`http://did-proxy:8080\` |
| 私钥文件路径 | secp256k1 私钥 (PEM 格式) | \`/usr/local/etc/oai/keys/private_key.pem\` |
| 扩展 Profile 路径 | DID Proxy 生成的 Profile（AMF） | \`/usr/local/etc/oai/extended_amf_profile.json\` |

> **注意**：扩展 Profile 文件名格式为 \`extended_{nf_type}_profile.json\`，如 \`extended_amf_profile.json\`、\`extended_smf_profile.json\`。

### 8.4 依赖库

| 库 | 用途 | 版本要求 |
|----|------|----------|
| OpenSSL | secp256k1, ECDSA, SHA256 | >= 1.1.0 |
| nlohmann/json | JSON 解析 | >= 3.0 |
| Pistache | HTTP 服务器 | (已集成) |

> **注意**：BCF HTTP 客户端已移出本模块，BCF 交互通过回调接口实现。上层应用（如 AMF）需负责注入具体的 HTTP 查询实现。

---

## 9. 安全性分析

### 9.1 威胁模型与防护

| 威胁 | 防护措施 |
|------|----------|
| **重放攻击** | Nonce 包含时间戳，5分钟有效期；已使用 Nonce 记录防止重复使用 |
| **中间人攻击** | 双向签名验证，必须持有私钥才能生成有效签名 |
| **伪造身份** | DID 绑定公钥，公钥存储在区块链，无法伪造 |
| **会话劫持** | Session ID 使用 UUID，Token 有时效性 |
| **公钥窃取** | 公钥本身是公开的，窃取无意义；私钥安全存储 |
| **BCF 不可用** | 公钥本地缓存，降级为缓存模式 |

### 9.2 密钥管理建议

1. **私钥存储**: 使用文件系统权限保护 (chmod 600)
2. **私钥轮换**: 定期生成新密钥对并更新 BCF 注册
3. **内存清理**: 使用 \`OPENSSL_cleanse\` 清除敏感数据
4. **审计日志**: 记录所有认证事件

### 9.3 Nonce 安全性

\`\`\`
Nonce 结构: [32字节随机数][8字节时间戳] = 40字节 = 80 Hex字符

- 随机数: 使用 OpenSSL RAND_bytes 生成，256位熵
- 时间戳: 毫秒级精度，用于过期检测
- 有效期: 默认 300秒 (5分钟)
- 使用追踪: 防止同一 Nonce 被多次使用
\`\`\`

---

## 10. 部署与测试

### 10.1 部署步骤

1. **生成密钥对**
\`\`\`bash
# 使用 DID Proxy 生成密钥和 DID
./did-proxy generate-keys --output /usr/local/etc/oai/keys/

# 输出文件:
# - private_key.pem  (secp256k1 私钥)
# - public_key.pem   (对应公钥)
\`\`\`

2. **注册到 BCF**
\`\`\`bash
# DID Proxy 自动完成 DID 注册
./did-proxy register --bcf-endpoint http://bcf:8080
\`\`\`

3. **配置 AMF**
\`\`\`yaml
# config.yaml
support_features:
  enable_bcf_nf_registration: true

bcf:
  host: did-proxy
  port: 8080
\`\`\`

4. **启动 AMF**
\`\`\`bash
./oai-amf -c /etc/oai/config.yaml
\`\`\`

### 10.2 测试场景

#### 场景 1: 正常双向认证

\`\`\`bash
# 模拟 NF-B 向 NF-A (AMF) 发起认证

# Step 1: 发送 init 请求
curl -X POST http://amf:8080/nf_auth/v1/mutual_auth/init \\
  -H "Content-Type: application/json" \\
  -d '{
    "initiator_did": "did:oai5gc:test123...",
    "nonce": "a1b2c3d4...(80 chars)",
    "timestamp": 1705632000000,
    "nf_type": "SMF"
  }'

# 预期响应: 200 OK + challenge

# Step 2: 发送 complete 请求
curl -X POST http://amf:8080/nf_auth/v1/mutual_auth/complete \\
  -H "Content-Type: application/json" \\
  -d '{
    "session_id": "sess-xxx",
    "initiator_signature": "3045..."
  }'

# 预期响应: 200 OK + auth_token
\`\`\`

#### 场景 2: 签名验证失败

\`\`\`bash
# 使用错误的签名
curl -X POST http://amf:8080/nf_auth/v1/mutual_auth/complete \\
  -H "Content-Type: application/json" \\
  -d '{
    "session_id": "sess-xxx",
    "initiator_signature": "invalid_signature"
  }'

# 预期响应: 401 Unauthorized
\`\`\`

#### 场景 3: Nonce 过期

\`\`\`bash
# 等待 5 分钟后发送 complete
# 预期响应: 401 (Nonce expired)
\`\`\`

### 10.3 日志输出示例

\`\`\`
[2026-01-19 10:00:00.123] [amf_app] [info] Initializing DID Authentication module
[2026-01-19 10:00:00.456] [amf_app] [info] DID Auth module initialized, local DID: did:oai5gc:abc123...
[2026-01-19 10:00:05.789] [amf_server] [info] DID Auth Init from 192.168.1.100
[2026-01-19 10:00:05.790] [amf_app] [debug] Querying BCF for public key: did:oai5gc:xyz789...
[2026-01-19 10:00:05.850] [amf_app] [info] Auth challenge generated for session sess-550e8400...
[2026-01-19 10:00:06.123] [amf_server] [info] DID Auth Complete from 192.168.1.100
[2026-01-19 10:00:06.124] [amf_app] [debug] Verifying signature for session sess-550e8400...
[2026-01-19 10:00:06.125] [amf_app] [info] Auth completed successfully, peer DID: did:oai5gc:xyz789...
\`\`\`

### 10.4 集成测试脚本

参见 \`scripts/test_did_mutual_auth.sh\`:

\`\`\`bash
#!/bin/bash
# DID 双向认证测试脚本

# 启动 Mock BCF 服务器
./scripts/test_did_mutual_auth.sh start-bcf

# 测试 BCF 公钥查询
./scripts/test_did_mutual_auth.sh test-bcf-query

# 测试认证初始化
./scripts/test_did_mutual_auth.sh --amf-host 192.168.70.132 test-auth-init

# 运行所有测试
./scripts/test_did_mutual_auth.sh all

# 停止服务器
./scripts/test_did_mutual_auth.sh stop-bcf
\`\`\`

---

## 附录

### A. 文件清单

**DID Auth 模块文件 (src/amf-app/did_auth/):**

| 文件 | 行数 | 描述 |
|------|------|------|
| \`did_auth.hpp\` | ~400 | 核心模块头文件 (含 http_request_callback_t) |
| \`did_auth.cpp\` | ~750 | 核心模块实现 (含 HTTP 回调机制) |
| \`did_auth_types.hpp\` | ~336 | 数据类型定义 |
| \`did_auth_types.cpp\` | ~200 | 数据类型实现 |
| \`did_crypto.hpp\` | ~120 | 加密模块头文件 |
| \`did_crypto.cpp\` | ~509 | 加密模块实现 |
| \`did_nonce_manager.hpp\` | ~80 | Nonce 管理头文件 |
| \`did_nonce_manager.cpp\` | ~200 | Nonce 管理实现 |
| \`did_session_manager.hpp\` | ~100 | 会话管理头文件 |
| \`did_session_manager.cpp\` | ~360 | 会话管理实现 |
| \`bcf_interface.hpp\` | ~200 | BCF 回调接口与 NF Profile 定义 |
| \`bcf_interface.cpp\` | ~150 | NF 选择器实现 |

**SBI API 文件:**

| 文件 | 行数 | 描述 |
|------|------|------|
| \`DIDAuthApi.h\` | ~121 | SBI API 定义 |
| \`DIDAuthApi.cpp\` | ~160 | SBI API 路由 |
| \`DIDAuthApiImpl.h\` | ~60 | API 实现头文件 |
| \`DIDAuthApiImpl.cpp\` | ~232 | API 实现 |

**修改的现有文件:**

| 文件 | 修改内容 |
|------|----------|
| \`src/amf-app/amf_app.hpp\` | 添加 \`m_did_auth\` 成员和认证处理方法 |
| \`src/amf-app/amf_app.cpp\` | 实现 DID auth 初始化和 HTTP 回调设置 |
| \`src/amf-app/amf_sbi.hpp\` | 添加 \`send_did_auth_request\` 和 \`initiate_did_mutual_auth\` |
| \`src/amf-app/amf_sbi.cpp\` | 实现 DID 认证 HTTP 请求方法 |
| \`src/sbi/amf_http2_server.hpp\` | 添加 DID Auth handler 方法声明 |
| \`src/sbi/amf_http2_server.cpp\` | 添加 \`/nf_auth/v1/\` 路由和 handler 实现 |

**测试相关文件 (scripts/):**

| 文件 | 描述 |
|------|------|
| \`mock_bcf_server_h2.py\` | Mock BCF 服务器 (支持 HTTP/2, Quart + Hypercorn) |
| \`mock_bcf_server.py\` | Mock BCF 服务器 (HTTP/1.1, 备用) |
| \`mock_bcf_config.json\` | 预定义 NF 配置 |
| \`test_did_mutual_auth.sh\` | 自动化测试脚本 |
| \`test_did_auth.sh\` | curl 测试脚本 |

### B. 参考资料

1. [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
2. [secp256k1 Curve Parameters](https://en.bitcoin.it/wiki/Secp256k1)
3. [ECDSA Digital Signature Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
4. [3GPP TS 29.510 - NRF Services](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3345)

---

## 11. Mock BCF 服务器

### 11.1 概述

为了测试 DID 双向认证功能，我们提供了一个 Mock BCF 服务器，模拟 BCF（Blockchain Function）的功能。

**支持两个版本：**
- \`mock_bcf_server_h2.py\` - **推荐**，支持 HTTP/2（AMF 默认使用 HTTP/2）
- \`mock_bcf_server.py\` - HTTP/1.1 版本（备用）

### 11.2 功能特性

| 功能 | 说明 |
|------|------|
| NF 注册 | 接收 AMF 的 DID 文档注册请求 |
| 公钥查询 | 提供 DID → 公钥 的查询接口 |
| 认证触发 | 模拟请求方 NF 向 AMF 发起认证请求 |
| 状态查看 | 查看已注册的 NF 列表 |

### 11.3 API 端点

| 方法 | 端点 | 描述 |
|------|------|------|
| PUT | \`/nbcf_management/v1/nf_instances/{id}\` | NF 注册（AMF 启动时调用） |
| GET | \`/nbcf_did/v1/public-key/{did}\` | 公钥查询（认证时调用） |
| GET | \`/nbcf_did/v1/did_documents/{did}\` | 获取完整 DID 文档 |
| GET | \`/test/trigger-auth?target=host:port\` | 触发认证测试 |
| GET | \`/status\` | 查看服务状态和已注册 NF |
| GET | \`/health\` | 健康检查 |

### 11.4 公钥查询响应格式

AMF 期望的 BCF 公钥查询响应格式：

\`\`\`json
{
  "did": "did:oai5gc:abc123...",
  "publicKey": {
    "publicKeyHex": "04abcd1234...",
    "type": "EcdsaSecp256k1VerificationKey2019"
  },
  "nfInfo": {
    "nfType": "SMF",
    "nfInstanceId": "uuid-xxx",
    "nfStatus": "REGISTERED"
  },
  "didDocument": { ... },
  "timestamp": "2026-01-20T12:00:00.000Z"
}
\`\`\`

**注意**：\`publicKey\` 必须是一个对象（包含 \`publicKeyHex\` 字段），而不是直接的字符串。

### 11.5 启动 Mock BCF 服务器

\`\`\`bash
# 安装依赖
pip3 install quart hypercorn h2

# 启动 HTTP/2 版本（推荐）
cd scripts/
python3 mock_bcf_server_h2.py --port 8089 --host 10.29.124.26

# 或者使用 HTTP/1.1 版本
python3 mock_bcf_server.py --port 8089 --host 10.29.124.26
\`\`\`

### 11.6 配置 AMF 连接 BCF

在 AMF 配置文件中配置 BCF 地址：

\`\`\`yaml
# config.yaml
bcf:
  host: 10.29.124.26      # BCF 服务器地址
  sbi:
    port: 8089            # BCF 端口
    api_version: v1
    interface_name: eth0  # 网络接口名
\`\`\`

### 11.7 测试流程

\`\`\`bash
# 1. 启动 Mock BCF 服务器
python3 mock_bcf_server_h2.py --port 8089 --host 10.29.124.26

# 2. 启动 AMF（AMF 会自动注册到 BCF）
./oai-amf -c config.yaml

# 3. 查看 AMF 是否注册成功
curl http://10.29.124.26:8089/status

# 4. 注册一个模拟的请求方 NF（如 SMF）
curl -X PUT http://10.29.124.26:8089/nbcf_management/v1/nf_instances/mock-smf-001 \\
  -H "Content-Type: application/json" \\
  -d '{
    "nfType": "SMF",
    "nfInstanceId": "mock-smf-001",
    "did": "did:oai5gc:mock:smf:test001",
    "didDocument": {
      "@context": ["https://www.w3.org/ns/did/v1"],
      "id": "did:oai5gc:mock:smf:test001",
      "verificationMethod": [{
        "id": "did:oai5gc:mock:smf:test001#key-1",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": "did:oai5gc:mock:smf:test001",
        "publicKeyHex": "04aaaa...bbbb"
      }]
    }
  }'

# 5. 测试认证接口
curl --http2-prior-knowledge -X POST http://10.29.124.26:8080/nf_auth/v1/mutual_auth/init \\
  -H "Content-Type: application/json" \\
  -d '{
    "initiator_did": "did:oai5gc:mock:smf:test001",
    "nonce": "a1b2c3d4e5f6...",
    "timestamp": 1705632000000,
    "nf_type": "SMF"
  }'
\`\`\`

---

## 12. 故障排除

### 12.1 常见问题

#### 问题 1: HTTP 505 - Invalid HTTP version

**症状**：Mock BCF 服务器日志显示：
\`\`\`
code 505, message Invalid HTTP version (2.0)
"PRI * HTTP/2.0" 505
\`\`\`

**原因**：AMF 使用 HTTP/2 协议，但 Mock BCF 服务器只支持 HTTP/1.1。

**解决方案**：使用支持 HTTP/2 的 \`mock_bcf_server_h2.py\`：
\`\`\`bash
pip3 install quart hypercorn h2
python3 mock_bcf_server_h2.py --port 8089 --host 10.29.124.26
\`\`\`

#### 问题 2: 404 Not Found - DID Auth API

**症状**：curl 测试认证接口返回 404。

**原因**：DID Auth 路由未注册到 HTTP/2 服务器。

**解决方案**：确保 \`amf_http2_server.cpp\` 中添加了 \`/nf_auth/v1/\` 路由处理，然后重新编译 AMF。

#### 问题 3: Failed to generate auth challenge

**症状**：AMF 日志显示：
\`\`\`
[amf_app] [error] Failed to generate auth challenge
\`\`\`

**原因**：
1. 请求方的 DID 未在 BCF 中注册
2. BCF 返回的公钥格式不正确

**解决方案**：
1. 确保请求方 NF 已在 BCF 注册
2. 检查 BCF 公钥响应格式（\`publicKey\` 应为对象，包含 \`publicKeyHex\`）

#### 问题 4: 连接 BCF 失败

**症状**：AMF 日志显示无法连接 BCF。

**可能原因**：
1. BCF 地址配置错误
2. 网络接口绑定问题
3. 防火墙阻止

**排查步骤**：
\`\`\`bash
# 1. 检查 BCF 是否可访问
curl http://bcf_host:bcf_port/health

# 2. 检查 AMF 配置中的 interface_name 是否正确
ip addr show

# 3. 如果 AMF 的 HTTP 客户端绑定到特定接口，确保 BCF 地址可通过该接口访问
# 配置中使用实际 IP 而非 localhost
\`\`\`

### 12.2 调试建议

1. **启用详细日志**：在 AMF 配置中设置 \`log_level: debug\`

2. **检查 BCF 日志**：Mock BCF 服务器会打印所有收到的请求

3. **使用 curl 测试**：
\`\`\`bash
# 测试 HTTP/2
curl --http2-prior-knowledge -v http://host:port/endpoint

# 测试 HTTP/1.1
curl -v http://host:port/endpoint
\`\`\`

4. **检查网络连通性**：
\`\`\`bash
# 检查端口是否在监听
ss -tlnp | grep port_number

# 检查防火墙
iptables -L -n
\`\`\`

### 12.3 日志分析

**成功的认证流程日志**：
\`\`\`
[amf_app] [info] Initializing DID Authentication module
[amf_app] [info] DID Auth module initialized, local DID: did:oai5gc:abc123...
[amf_server] [debug] DID Auth request: POST /nf_auth/v1/mutual_auth/init
[amf_server] [info] Received DID Auth Init request (HTTP/2)
[amf_app] [info] Processing DID Auth Init from 192.168.1.100 (DID: did:oai5gc:xyz789...)
[amf_app] [debug] Querying BCF for public key: did:oai5gc:xyz789...
[amf_app] [info] Auth challenge generated for session sess-550e8400...
\`\`\`

**失败的认证流程日志**：
\`\`\`
[amf_app] [info] Processing DID Auth Init from (DID: did:oai5gc:mock:smf:test001)
[amf_app] [error] Failed to generate auth challenge
# 原因：BCF 查询公钥失败或返回格式错误
\`\`\`

---

## 13. UE 认证流程中的 DID 双向认证

### 13.1 概述

当 UE 发起注册请求时，AMF 需要向 AUSF 发送 UE 认证请求。在启用 DID/BCF 认证的场景下，AMF 必须首先与 AUSF 完成 DID 双向认证，然后才能发送 UE 认证请求。

### 13.2 完整流程图

\`\`\`
┌────────┐       ┌────────┐       ┌────────┐       ┌────────┐
│   UE   │       │   AMF  │       │  AUSF  │       │   BCF  │
└───┬────┘       └───┬────┘       └───┬────┘       └───┬────┘
    │                │                │                │
    │ 1. Registration│                │                │
    │    Request     │                │                │
    │───────────────>│                │                │
    │                │                │                │
    │                │ 2. DID Auth Init (POST)          │
    │                │    /nf_auth/v1/mutual_auth/init │
    │                │───────────────>│                │
    │                │                │                │
    │                │                │ 3. Query AMF   │
    │                │                │    Public Key  │
    │                │                │───────────────>│
    │                │                │<───────────────│
    │                │                │                │
    │                │ 4. Challenge Response           │
    │                │    (session_id, nonce, sig)     │
    │                │<───────────────│                │
    │                │                │                │
    │                │ 5. Query AUSF Public Key        │
    │                │───────────────────────────────>│
    │                │<───────────────────────────────│
    │                │                │                │
    │                │ 6. DID Auth Complete (POST)     │
    │                │    /nf_auth/v1/mutual_auth/complete
    │                │───────────────>│                │
    │                │                │                │
    │                │ 7. Auth Result + Token          │
    │                │<───────────────│                │
    │                │                │                │
    │                │ 8. UE Auth Request (POST)       │
    │                │    /nausf-auth/v1/ue-authentications
    │                │    Header: X-DID-Auth-Token     │
    │                │───────────────>│                │
    │                │                │                │
    │                │                │ 9. Verify Token│
    │                │                │    (internal)  │
    │                │                │                │
    │                │ 10. Auth Response               │
    │                │<───────────────│                │
    │                │                │                │
    │ 11. Auth Req/  │                │                │
    │     Response   │                │                │
    │<───────────────│                │                │
\`\`\`

### 13.3 实现细节

#### 13.3.1 AMF 侧（发起方）

**文件**: `src/amf-app/amf_sbi.cpp`

\`\`\`cpp
void amf_sbi::handle_itti_message(
    itti_sbi_ue_authentication_request& itti_msg) {
  
  // DID auth token (populated if BCF/DID auth is enabled)
  std::string auth_token;
  
  // Step 1: DID Mutual Authentication with AUSF
  if (amf_cfg->register_bcf) {
    std::string ausf_did_auth_endpoint = amf_cfg->ausf_addr.uri_root;
    
    bool auth_success = amf_app_inst->initiate_did_auth(
        ausf_did_auth_endpoint, "", auth_token);
    
    if (!auth_success) {
      // Return 403 Forbidden
      return;
    }
  }
  
  // Step 2: Prepare HTTP request with DID auth token
  oai::http::request http_request = 
      http_client_inst->prepare_json_request(uri, body);
  
  // Add DID auth header
  if (amf_cfg->register_bcf && !auth_token.empty()) {
    http_request.headers.insert({"X-DID-Auth-Token", auth_token});
  }
  
  // Step 3: Send request to AUSF
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);
}
\`\`\`

#### 13.3.2 AUSF 侧（验证方）

**文件**: `src/api_server/ausf_http2-server.cpp`

\`\`\`cpp
void ausf_http2_server::ue_authentications_post_handler(
    const AuthenticationInfo& authenticationInfo,
    const header_map& request_headers,
    const response& response) {
  
  // Verify DID mutual authentication
  if (ausf_cfg.register_bcf && m_ausf_app->is_did_auth_enabled()) {
    
    // Check for auth token header
    auto token_it = request_headers.find("x-did-auth-token");
    if (token_it == request_headers.end()) {
      // Return 401 Unauthorized
      return;
    }
    
    std::string auth_token = token_it->second.value;
    
    // Verify token
    if (!m_ausf_app->verify_did_auth_token(auth_token)) {
      // Return 403 Forbidden
      return;
    }
  }
  
  // Proceed with UE authentication
  m_ausf_app->handle_ue_authentications(...);
}
\`\`\`

### 13.4 HTTP 头部规范

| Header Name | Description | Example |
|-------------|-------------|---------|
| X-DID-Auth-Token | DID 认证令牌 | `token-550e8400-e29b-41d4-a716...` |

### 13.5 错误响应

| HTTP Code | Error | Description |
|-----------|-------|-------------|
| 401 | did_auth_required | 请求缺少 DID 认证令牌 |
| 403 | did_auth_invalid | DID 认证令牌无效或已过期 |
| 403 | did_auth_failed | DID 双向认证失败 |

### 13.6 安全考虑

1. **令牌有效期**：认证令牌默认有效期为 1 小时，可通过配置调整
2. **会话重用**：如果 AMF 已与 AUSF 完成认证，可复用已有会话
3. **令牌刷新**：令牌过期前应重新进行 DID 认证

---

**文档结束**

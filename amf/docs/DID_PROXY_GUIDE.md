# DID Proxy 与 BCF 集成完整指南

本文档描述了 OAI 5GC 的 DID Proxy 服务实现，用于为网元 (NF) 自动生成 DID/DID Document，并通过 SBI/HTTP 完成向 BCF（Blockchain Function）的身份注册。

---

## 目录

1. [架构概述](#1-架构概述)
2. [DID 生成原理](#2-did-生成原理)
3. [代码修改汇总](#3-代码修改汇总)
4. [DID Proxy 服务 (Go)](#4-did-proxy-服务-go)
5. [网元侧修改 (C++)](#5-网元侧修改-c)
6. [配置文件](#6-配置文件)
7. [部署与运行](#7-部署与运行)
8. [其他网元适配清单](#8-其他网元适配清单)
9. [调试与排错](#9-调试与排错)

---

## 1. 架构概述

### 1.1 整体架构

\`\`\`
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OAI 5GC 架构                                    │
│                                                                             │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐       │
│  │                 │     │                 │     │                 │       │
│  │   NF (AMF等)    │◄───►│   DID Proxy     │     │      BCF        │       │
│  │                 │     │   (Go 服务)      │     │  (区块链网元)   │       │
│  └────────┬────────┘     └────────┬────────┘     └────────▲────────┘       │
│           │                       │                       │                │
│           │ 1. 读取配置           │ 2. 生成 UUID v4        │                │
│           │                       │    生成密钥对          │                │
│           │                       │    生成 DID            │                │
│           │ 3. 读取 nfInstanceId  │    保存扩展 Profile    │                │
│           │    和扩展 Profile     ▼                       │                │
│           │              ┌─────────────────┐              │                │
│           │              │  Extended NF    │              │                │
│           │              │  Profile File   │              │                │
│           │              │  (JSON)         │              │                │
│           │              └─────────────────┘              │                │
│           │                                               │                │
│           └───────────────────────────────────────────────┘                │
│                      4. HTTP PUT 注册到 BCF                                │
│                                                                             │
│  ┌─────────────┐                                                           │
│  │    NRF      │  ◄── AMF 标准注册流程（保持不变）                          │
│  └─────────────┘                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
\`\`\`

### 1.2 工作流程

1. **DID Proxy** 读取 OAI 配置文件，生成 **UUID v4 格式的 nfInstanceId**
2. **DID Proxy** 使用 **secp256k1** 曲线生成 ECDSA 密钥对
3. **DID Proxy** 基于 \`SHA256(nfInstanceId) + 私钥签名\` 生成 DID
4. **DID Proxy** 将扩展后的 NF Profile (含 DID 和 nfInstanceId) 写入文件
5. **网元 (AMF/SMF/UPF)** 启动时从扩展 Profile 文件读取 **nfInstanceId**
6. **网元** 使用相同的 nfInstanceId 确保与 DID 的一致性
7. **网元** 通过 HTTP PUT 将扩展 Profile 注册到 BCF

### 1.3 nfInstanceId 共享与持久化机制

为确保 AMF 和 DID Proxy 使用相同的 nfInstanceId（DID 的生成依赖于此 ID），采用以下**优先级机制**：

**DID Proxy 端（生成时）：**
1. 首先检查配置文件中是否设置了 \`nf_instance_id\`
2. 如果未设置，检查 \`extended_{nf_type}_profile.json\` 是否已存在并包含 nfInstanceId
3. 如果都不存在，生成新的 UUID v4 格式 nfInstanceId

**AMF 端（读取时）：**
1. 首先尝试从 \`extended_amf_profile.json\` 读取 nfInstanceId
2. 如果文件不存在或读取失败，才自行生成新的 UUID

这样保证了：
- **DID 一致性**：DID 基于 nfInstanceId + 私钥签名生成，每次重启使用相同的 nfInstanceId
- **密钥复用**：密钥文件名基于 nfInstanceId，相同的 ID 复用相同的密钥对
- **向 BCF 注册一致性**：Profile 中的 nfInstanceId 与生成的 DID 匹配

### 1.4 关键路径配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| \`extended_profile_path\` | \`/usr/local/etc/oai/extended_amf_profile.json\` | 扩展 NF Profile 文件路径（AMF） |
| \`key_store_path\` | \`/usr/local/etc/oai/keys\` | 密钥存储目录 |

**文件命名约定**（支持多 NF 部署）：
- AMF: \`extended_amf_profile.json\`
- SMF: \`extended_smf_profile.json\`
- UDM: \`extended_udm_profile.json\`
- 其他 NF: \`extended_{nf_type}_profile.json\`

### 1.5 密钥与签名规范

| 项目 | 规范 |
|------|------|
| 曲线 | **secp256k1** (Bitcoin/Ethereum 兼容) |
| 私钥格式 | Hex 编码 (64 字符 = 32 字节) |
| 公钥格式 | 压缩格式 33 字节 (0x02/0x03 前缀 + X 坐标) |
| 公钥编码 | base58btc (multibase 'z' 前缀) |
| 哈希算法 | SHA256 (用于 DID 生成), Keccak256 (用于地址生成) |
| 验证方法类型 | \`EcdsaSecp256k1VerificationKey2019\` |

---

## 2. DID 生成原理

### 2.1 DID 生成流程

\`\`\`
┌─────────────────────────────────────────────────────────────────┐
│                      DID 生成流程                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  nfInstanceId (UUID v4)                                         │
│  例: "b8b62d24-573a-420b-a0ca-d58767193ca0"                     │
│                    │                                            │
│                    ▼                                            │
│  ┌─────────────────────────────┐                               │
│  │  Step 1: SHA256 哈希        │                               │
│  │  hash = SHA256(nfInstanceId)│                               │
│  └─────────────────────────────┘                               │
│                    │                                            │
│                    ▼ (32 bytes)                                 │
│  ┌─────────────────────────────┐                               │
│  │  Step 2: 私钥签名           │                               │
│  │  signature = Sign(hash,     │                               │
│  │              privateKey)    │                               │
│  └─────────────────────────────┘                               │
│                    │                                            │
│                    ▼ (65 bytes: R + S + V)                      │
│  ┌─────────────────────────────┐                               │
│  │  Step 3: Hex 编码           │                               │
│  │  signatureHex = Hex(sig)    │                               │
│  └─────────────────────────────┘                               │
│                    │                                            │
│                    ▼ (130 characters)                           │
│  ┌─────────────────────────────┐                               │
│  │  Step 4: 拼接 DID           │                               │
│  │  DID = "did:oai5gc:" +      │                               │
│  │        signatureHex         │                               │
│  └─────────────────────────────┘                               │
│                    │                                            │
│                    ▼                                            │
│  did:oai5gc:a1b2c3d4e5f6...   (完整 DID，约 140 字符)          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
\`\`\`

### 2.2 核心代码 (did/did.go)

\`\`\`go
// generateDIDIdentifier generates the DID identifier
// Process: nfInstanceId -> SHA256 hash -> Sign with private key -> Hex encode
func (g *DIDGenerator) generateDIDIdentifier() string {
    // Step 1: SHA256 hash of nfInstanceId
    hash := sha256.Sum256([]byte(g.nfInstanceID))

    // Step 2: Sign the hash with private key
    signature, err := crypto.Sign(hash[:], g.privateKey)
    if err != nil {
        // Fallback to just hash if signing fails
        hashHex := hex.EncodeToString(hash[:])
        return fmt.Sprintf("%s:%s", DIDMethod, hashHex)
    }

    // Step 3: Hex encode the signature
    signatureHex := hex.EncodeToString(signature)

    // DID format: did:oai5gc:<signature>
    return fmt.Sprintf("%s:%s", DIDMethod, signatureHex)
}
\`\`\`

### 2.3 DID Document 结构

\`\`\`json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/secp256k1-2019/v1"
  ],
  "id": "did:oai5gc:a1b2c3d4e5f6...",
  "controller": "did:oai5gc:a1b2c3d4e5f6...",
  "verificationMethod": [{
    "id": "did:oai5gc:a1b2c3d4e5f6...#key-1",
    "type": "EcdsaSecp256k1VerificationKey2019",
    "controller": "did:oai5gc:a1b2c3d4e5f6...",
    "publicKeyMultibase": "zQ3shunN..."
  }],
  "authentication": ["did:oai5gc:a1b2c3d4e5f6...#key-1"],
  "assertionMethod": ["did:oai5gc:a1b2c3d4e5f6...#key-1"],
  "created": "2026-01-14T12:00:00Z",
  "updated": "2026-01-14T12:00:00Z"
}
\`\`\`

**公钥格式说明：**
- 使用 \`publicKeyMultibase\` 字段（**不再使用** \`publicKeyJwk\`）
- 公钥为压缩格式 33 字节（0x02/0x03 前缀 + X 坐标）
- 使用 base58btc 编码，'z' 前缀表示 base58btc

---

## 3. 代码修改汇总

### 3.1 修改概览

| 类型 | 文件数量 |
|------|---------|
| 新增文件 (DID Proxy Go) | 17+ 个 |
| 修改文件 (AMF C++) | 10 个 |

### 3.2 新增文件

#### DID Proxy 服务 (Golang)

\`\`\`
src/did-proxy/
├── main.go                 # 主入口程序
├── go.mod                  # Go 模块定义
├── go.sum                  # 依赖校验
├── build.sh                # 构建脚本
├── test.sh                 # 测试脚本
├── Dockerfile              # Docker 镜像构建
├── docker-compose.yaml     # Docker Compose 编排
├── README.md               # 使用说明
│
├── config/
│   └── config.go           # OAI 配置文件解析 + UUID v4 生成 + nfInstanceId 持久化
│
├── crypto/                 # secp256k1 密码学库 (移植自以太坊 go-ethereum)
│   ├── crypto.go           # 核心密码学函数
│   ├── secp256k1/          # secp256k1 曲线实现
│   ├── sha3/               # Keccak256 哈希
│   └── ecies/              # ECIES 加密
│
├── common/                 # 通用类型定义
│   └── types.go            # Address, Hash, NodeID 等
│
├── did/
│   ├── did.go              # DID 生成器 (SHA256 + 私钥签名)
│   └── keystore.go         # 密钥存储管理 (Hex 格式)
│
├── profile/
│   └── profile.go          # NF Profile 生成，扩展 Profile 创建
│
├── logger/
│   └── logger.go           # OAI 风格日志组件
│
├── registration/
│   └── bcf_client.go       # BCF 客户端，HTTP 请求处理
│
└── etc/
    └── config_with_bcf.yaml # 示例配置文件
\`\`\`

#### AMF C++ 新增文件

| 文件 | 说明 |
|------|------|
| \`src/amf-app/did_proxy_client.hpp\` | DID Proxy 客户端接口定义 |
| \`src/amf-app/did_proxy_client.cpp\` | DID Proxy 客户端实现 |
| \`src/common/amf_bcf_helper.hpp\` | BCF URI 构造辅助类 |

### 3.3 修改文件

| 文件 | 修改内容 |
|------|----------|
| \`etc/config.yaml\` | 添加 \`register_bcf\`、BCF 网元配置、\`extended_profile_path\` |
| \`src/amf-app/amf_config.hpp\` | 添加 BCF 配置常量和成员变量 |
| \`src/amf-app/amf_config.cpp\` | 添加 BCF 配置解析逻辑 |
| \`src/amf-app/amf_app.hpp\` | 添加 BCF 注册函数声明 |
| \`src/amf-app/amf_app.cpp\` | 实现 BCF 注册/更新/注销逻辑 + nfInstanceId 读取 |
| \`src/amf-app/amf_sbi.hpp\` | 添加 BCF 请求处理函数声明 |
| \`src/amf-app/amf_sbi.cpp\` | 添加 BCF HTTP 请求处理 |
| \`src/itti/itti_msg.hpp\` | 添加 BCF 消息类型枚举 |
| \`src/itti/msgs/itti_msg_sbi.hpp\` | 添加 BCF ITTI 消息类 |
| \`src/amf-app/CMakeLists.txt\` | 添加新源文件到编译列表 |

### 3.4 新增常量、变量和函数详细说明

#### 3.4.1 \`amf_config.hpp\` - 新增常量和成员变量

| 类型 | 名称 | 说明 |
|------|------|------|
| 常量 | \`AMF_CONFIG_REGISTER_BCF\` | BCF 注册配置项名称 ("register_bcf") |
| 常量 | \`AMF_CONFIG_REGISTER_BCF_LABEL\` | BCF 注册配置项显示标签 ("Register BCF") |
| 常量 | \`AMF_BCF_CONFIG_NAME\` | BCF 网元名称 ("bcf")，用于在 nfs 配置中查找 |
| 成员变量 | \`nf_addr_t bcf_addr\` | BCF 地址结构体，包含 IP、端口、API 版本、URI |
| 成员变量 | \`bool register_bcf\` | BCF 注册开关，true 表示启用向 BCF 注册 |
| 成员变量 | \`std::string extended_profile_path\` | 扩展 NF Profile 文件路径 (DID Proxy 生成) |
| 成员变量 | \`std::string m_amf_config_path\` | 配置文件路径，用于读取 register_bcf |

#### 3.4.2 \`amf_config.cpp\` - 新增配置解析逻辑

在 \`pre_process()\` 函数中添加：

| 功能 | 说明 |
|------|------|
| 添加 BCF NF 定义 | 在构造函数中添加 BCF 网元到 m_used_sbi_values 和 nf 列表 |
| 解析 register_bcf | 从 YAML 配置读取 register_bcf.general 值 (yes/true) |
| 解析 BCF 地址 | 如果启用 BCF，从 nfs.bcf 读取 BCF 服务地址 |
| 解析 extended_profile_path | 读取扩展 Profile 文件路径，默认 /usr/local/etc/oai/extended_amf_profile.json |
| 显示 BCF 配置 | 在 display() 中输出 BCF 相关配置信息 |

#### 3.4.3 \`amf_app.hpp\` - 新增函数声明

| 函数 | 说明 |
|------|------|
| \`void register_to_bcf()\` | 触发向 BCF 注册 NF 实例。读取扩展 Profile (含 DID)，构建 BCF URI，发送 ITTI 请求消息到 SBI 层 |
| \`void update_bcf_registration()\` | 触发更新 BCF 注册信息。用于 NF 状态变更时通知 BCF |
| \`void deregister_from_bcf()\` | 触发从 BCF 注销 NF 实例。AMF 关闭时调用 |
| \`nlohmann::json read_extended_profile_from_file()\` | 从文件读取扩展 NF Profile (由 DID Proxy 生成)。返回 JSON 对象，失败返回空 JSON |
| \`void handle_itti_message(itti_sbi_bcf_register_nf_instance_response&)\` | 处理 BCF 注册响应消息。记录注册结果 |
| \`void handle_itti_message(itti_sbi_bcf_update_nf_instance_response&)\` | 处理 BCF 更新响应消息。记录更新结果 |
| \`void handle_itti_message(itti_sbi_bcf_deregister_nf_instance_response&)\` | 处理 BCF 注销响应消息。记录注销结果 |

#### 3.4.4 \`amf_app.cpp\` - 函数实现说明

| 函数 | 实现逻辑 |
|------|----------|
| \`register_to_bcf()\` | 1. 检查 register_bcf 开关<br>2. 调用 read_extended_profile_from_file() 读取扩展 Profile<br>3. 构建 BCF URI: {bcf_addr.uri_root}/nbcf_management/{api_version}/nf_instances/{amf_instance_id}<br>4. 创建 itti_sbi_bcf_register_nf_instance_request 消息<br>5. 发送 ITTI 消息到 TASK_AMF_SBI |
| \`read_extended_profile_from_file()\` | 1. 打开 extended_profile_path 文件<br>2. 解析 JSON 内容<br>3. 返回 nlohmann::json 对象 |
| \`generate_uuid()\` (修改) | 新增逻辑：优先从 extended_profile_path 读取 nfInstanceId，确保与 DID 一致 |

#### 3.4.5 \`amf_sbi.hpp\` - 新增函数声明

| 函数 | 说明 |
|------|------|
| \`void handle_itti_message(itti_sbi_bcf_register_nf_instance_request&)\` | 处理 BCF 注册请求。发送 HTTP PUT 到 BCF |
| \`void handle_itti_message(itti_sbi_bcf_update_nf_instance_request&)\` | 处理 BCF 更新请求。发送 HTTP PATCH 到 BCF |
| \`void handle_itti_message(itti_sbi_bcf_deregister_nf_instance_request&)\` | 处理 BCF 注销请求。发送 HTTP DELETE 到 BCF |

#### 3.4.6 \`amf_sbi.cpp\` - 函数实现说明

| 函数 | 实现逻辑 |
|------|----------|
| \`handle_itti_message(itti_sbi_bcf_register_nf_instance_request&)\` | 1. 从消息获取 BCF URI 和扩展 Profile<br>2. 序列化 Profile 为 JSON<br>3. 发送 HTTP PUT 请求到 BCF<br>4. 创建响应消息发回 APP 层 |
| \`handle_itti_message(itti_sbi_bcf_update_nf_instance_request&)\` | 1. 从消息获取 patch_items<br>2. 发送 HTTP PATCH 请求到 BCF<br>3. 创建响应消息发回 APP 层 |
| \`handle_itti_message(itti_sbi_bcf_deregister_nf_instance_request&)\` | 1. 发送 HTTP DELETE 请求到 BCF<br>2. 创建响应消息发回 APP 层 |

#### 3.4.7 \`itti_msg.hpp\` - 新增消息类型枚举

\`\`\`cpp
// BCF (Blockchain Function) registration messages for DID-based identity
SBI_BCF_REGISTER_NF_INSTANCE_REQUEST,   // APP -> SBI: 请求向 BCF 注册
SBI_BCF_REGISTER_NF_INSTANCE_RESPONSE,  // SBI -> APP: BCF 注册响应
SBI_BCF_UPDATE_NF_INSTANCE_REQUEST,     // APP -> SBI: 请求更新 BCF 注册
SBI_BCF_UPDATE_NF_INSTANCE_RESPONSE,    // SBI -> APP: BCF 更新响应
SBI_BCF_DEREGISTER_NF_INSTANCE_REQUEST, // APP -> SBI: 请求从 BCF 注销
SBI_BCF_DEREGISTER_NF_INSTANCE_RESPONSE // SBI -> APP: BCF 注销响应
\`\`\`

#### 3.4.8 \`itti_msg_sbi.hpp\` - 新增 ITTI 消息类

| 类名 | 成员变量 | 说明 |
|------|----------|------|
| \`itti_sbi_bcf_register_nf_instance_request\` | \`nlohmann::json extended_profile\`<br>\`std::string amf_instance_id\`<br>\`std::string bcf_uri\` | BCF 注册请求消息。携带扩展 Profile (含 DID)、NF Instance ID、BCF URI |
| \`itti_sbi_bcf_register_nf_instance_response\` | \`std::string amf_instance_id\`<br>\`uint16_t http_response_code\`<br>\`std::string bcf_uri\` | BCF 注册响应消息。携带 HTTP 响应码 |
| \`itti_sbi_bcf_update_nf_instance_request\` | \`std::vector<PatchItem> patch_items\`<br>\`std::string amf_instance_id\`<br>\`std::string bcf_uri\` | BCF 更新请求消息。携带 PATCH 操作项 |
| \`itti_sbi_bcf_update_nf_instance_response\` | \`std::string amf_instance_id\`<br>\`uint32_t http_response_code\`<br>\`std::string bcf_uri\` | BCF 更新响应消息 |
| \`itti_sbi_bcf_deregister_nf_instance_request\` | \`std::string amf_instance_id\`<br>\`std::string bcf_uri\` | BCF 注销请求消息 |
| \`itti_sbi_bcf_deregister_nf_instance_response\` | \`std::string amf_instance_id\`<br>\`uint32_t http_response_code\`<br>\`std::string bcf_uri\` | BCF 注销响应消息 |

### 3.5 调用流程

\`\`\`
AMF 启动
    │
    ▼
amf_config::pre_process()
    │── 解析 register_bcf 配置
    │── 解析 BCF 地址 (nfs.bcf)
    │── 解析 extended_profile_path
    │
    ▼
amf_app::generate_uuid()
    │── 尝试从 extended_profile_path 读取 nfInstanceId
    │── 如果文件存在，使用 DID Proxy 生成的 ID
    │── 否则，生成新的 UUID v4
    │
    ▼
amf_app::register_to_bcf()  (如果 register_bcf = true)
    │
    ▼
amf_app::read_extended_profile_from_file()
    │── 读取扩展 Profile JSON (含 DID 和 DID Document)
    │
    ▼
创建 itti_sbi_bcf_register_nf_instance_request
    │── 填充 extended_profile, amf_instance_id, bcf_uri
    │
    ▼
发送 ITTI 消息到 TASK_AMF_SBI
    │
    ▼
amf_sbi::handle_itti_message(bcf_register_request)
    │── 构建 HTTP PUT 请求
    │── 发送到 BCF: PUT {bcf_uri} 
    │── Body: extended_profile (含 DID)
    │
    ▼
创建 itti_sbi_bcf_register_nf_instance_response
    │── 填充 http_response_code
    │
    ▼
发送回 TASK_AMF_APP
    │
    ▼
amf_app::handle_itti_message(bcf_register_response)
    │── 记录注册结果
\`\`\`

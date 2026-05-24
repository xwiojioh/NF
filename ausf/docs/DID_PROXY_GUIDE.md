# AUSF DID Proxy 与 BCF 集成指南

本文档描述了 OAI 5GC AUSF 的 DID Proxy 服务集成实现，用于为 AUSF 网元自动生成 DID/DID Document，并通过 SBI/HTTP 完成向 BCF（Blockchain Function）的身份注册。

---

## 目录

1. [架构概述](#1-架构概述)
2. [代码修改汇总](#2-代码修改汇总)
3. [新增常量、变量和函数详细说明](#3-新增常量变量和函数详细说明)
4. [配置文件](#4-配置文件)
5. [调用流程](#5-调用流程)
6. [部署与运行](#6-部署与运行)

---

## 1. 架构概述

### 1.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OAI 5GC 架构 - AUSF                             │
│                                                                             │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐       │
│  │                 │     │                 │     │                 │       │
│  │      AUSF       │◄───►│   DID Proxy     │     │      BCF        │       │
│  │                 │     │   (Go 服务)      │     │  (区块链网元)   │       │
│  └────────┬────────┘     └────────┬────────┘     └────────▲────────┘       │
│           │                       │                       │                │
│           │ 1. 读取配置           │ 2. 生成 UUID v4        │                │
│           │                       │    生成密钥对          │                │
│           │                       │    生成 DID            │                │
│           │ 3. 读取 nfInstanceId  │    保存扩展 Profile    │                │
│           │    和扩展 Profile     ▼                       │                │
│           │              ┌─────────────────┐              │                │
│           │              │  Extended AUSF  │              │                │
│           │              │  Profile File   │              │                │
│           │              │  (JSON)         │              │                │
│           │              └─────────────────┘              │                │
│           │                                               │                │
│           └───────────────────────────────────────────────┘                │
│                      4. HTTP PUT 注册到 BCF                                │
│                                                                             │
│  ┌─────────────┐                                                           │
│  │    NRF      │  ◄── AUSF 标准注册流程（保持不变）                         │
│  └─────────────┘                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 工作流程

1. **DID Proxy** 读取 OAI 配置文件，生成 **UUID v4 格式的 nfInstanceId**
2. **DID Proxy** 使用 **secp256k1** 曲线生成 ECDSA 密钥对
3. **DID Proxy** 基于 `SHA256(nfInstanceId) + 私钥签名` 生成 DID
4. **DID Proxy** 将扩展后的 NF Profile (含 DID 和 nfInstanceId) 写入文件 `extended_ausf_profile.json`
5. **AUSF** 启动时从扩展 Profile 文件读取 **nfInstanceId**
6. **AUSF** 使用相同的 nfInstanceId 确保与 DID 的一致性
7. **AUSF** 通过 HTTP PUT 将扩展 Profile 注册到 BCF

### 1.3 nfInstanceId 共享与持久化机制

**DID Proxy 端（生成时）：**
1. 首先检查配置文件中是否设置了 `nf_instance_id`
2. 如果未设置，检查 `extended_ausf_profile.json` 是否已存在并包含 nfInstanceId
3. 如果都不存在，生成新的 UUID v4 格式 nfInstanceId

**AUSF 端（读取时）：**
1. 首先尝试从 `extended_ausf_profile.json` 读取 nfInstanceId
2. 如果文件不存在或读取失败，才自行生成新的 UUID

### 1.4 关键路径配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `extended_profile_path` | `/usr/local/etc/oai/extended_ausf_profile.json` | 扩展 NF Profile 文件路径 |
| `key_store_path` | `/usr/local/etc/oai/keys` | 密钥存储目录 |

**文件命名约定**（支持多 NF 部署）：
- AMF: `extended_amf_profile.json`
- **AUSF: `extended_ausf_profile.json`**
- SMF: `extended_smf_profile.json`
- UDM: `extended_udm_profile.json`

---

## 2. 代码修改汇总

### 2.1 修改概览

| 类型 | 文件数量 |
|------|---------|
| 新增文件 | 3 个 |
| 修改文件 | 7 个 |

### 2.2 新增文件

| 文件 | 说明 |
|------|------|
| `src/common/ausf_bcf_helper.hpp` | BCF URI 构造辅助类 |
| `src/ausf_app/ausf_bcf.hpp` | BCF 客户端接口定义 |
| `src/ausf_app/ausf_bcf.cpp` | BCF 客户端实现（注册/更新/注销） |

### 2.3 修改文件

| 文件 | 修改内容 |
|------|----------|
| `etc/config.yaml` | 添加 `register_bcf`、BCF 网元配置、`extended_profile_path` |
| `src/ausf_app/ausf_config.hpp` | 添加 BCF 配置常量和成员变量 |
| `src/ausf_app/ausf_config.cpp` | 添加 BCF 配置初始化逻辑 |
| `src/ausf_app/ausf_config_yaml.hpp` | 添加 `register_bcf()` 和 `get_extended_profile_path()` 函数声明 |
| `src/ausf_app/ausf_config_yaml.cpp` | 添加 BCF NF 定义和配置解析逻辑 |
| `src/ausf_app/ausf_nrf.hpp` | 添加 `read_nf_instance_id_from_extended_profile()` 函数声明 |
| `src/ausf_app/ausf_nrf.cpp` | 实现从扩展 Profile 读取 nfInstanceId 的逻辑 |
| `src/ausf_app/ausf_app.cpp` | 添加 BCF 注册/注销调用 |
| `src/ausf_app/CMakeLists.txt` | 添加 `ausf_bcf.cpp` 到编译列表 |

---

## 3. 新增常量、变量和函数详细说明

### 3.1 `ausf_config.hpp` - 新增常量和成员变量

| 类型 | 名称 | 说明 |
|------|------|------|
| 常量 | `AUSF_CONFIG_REGISTER_BCF` | BCF 注册配置项名称 ("register_bcf") |
| 常量 | `AUSF_CONFIG_REGISTER_BCF_LABEL` | BCF 注册配置项显示标签 ("Register BCF") |
| 常量 | `AUSF_BCF_CONFIG_NAME` | BCF 网元名称 ("bcf")，用于在 nfs 配置中查找 |
| 常量 | `AUSF_CONFIG_EXTENDED_PROFILE_PATH` | 扩展 Profile 路径配置项名称 |
| 常量 | `AUSF_DEFAULT_EXTENDED_PROFILE_PATH` | 默认扩展 Profile 路径 |
| 成员变量 | `nf_addr_t bcf_addr` | BCF 地址结构体，包含 IP、端口、API 版本、URI |
| 成员变量 | `bool register_bcf` | BCF 注册开关，true 表示启用向 BCF 注册 |
| 成员变量 | `std::string extended_profile_path` | 扩展 NF Profile 文件路径 (DID Proxy 生成) |

### 3.2 `ausf_bcf.hpp` - 新增类和函数

| 类/函数 | 说明 |
|---------|------|
| `class ausf_bcf` | BCF 客户端类，处理与 BCF 的通信 |
| `ausf_bcf(ausf_event& ev, const std::string& instance_id)` | 构造函数，初始化 BCF 客户端 |
| `bool read_extended_profile_from_file(nlohmann::json& profile)` | 从文件读取扩展 NF Profile |
| `static bool read_nf_instance_id_from_file(std::string& nf_instance_id)` | 从扩展 Profile 读取 nfInstanceId |
| `void register_to_bcf()` | 向 BCF 注册 NF 实例 |
| `void update_bcf_registration()` | 更新 BCF 注册信息 |
| `void deregister_from_bcf()` | 从 BCF 注销 NF 实例 |

### 3.3 `ausf_bcf_helper.hpp` - BCF URI 辅助类

| 函数 | 说明 |
|------|------|
| `static void get_bcf_nf_instance_uri(...)` | 构建 BCF NF 实例 URI |

### 3.4 `ausf_nrf.hpp/cpp` - 新增函数

| 函数 | 说明 |
|------|------|
| `static bool read_nf_instance_id_from_extended_profile(std::string& nf_instance_id)` | 从扩展 Profile 文件读取 nfInstanceId，确保与 DID 一致 |

### 3.5 `ausf_config_yaml.hpp/cpp` - 新增函数

| 函数 | 说明 |
|------|------|
| `bool register_bcf() const` | 检查 BCF 注册是否启用 |
| `std::string get_extended_profile_path() const` | 获取扩展 Profile 文件路径 |

---

## 4. 配置文件

### 4.1 `etc/config.yaml` 新增配置项

```yaml
############# Common configuration

# Log level for all the NFs
log_level:
  general: debug

# If you enable registration, the other NFs will use the NRF discovery mechanism
register_nf:
  general: yes

# If you enable BCF registration, the NF will register to BCF for DID-based identity
# DID Proxy service should generate extended_ausf_profile.json before starting the NF
register_bcf:
  general: no

# Path to extended NF Profile file (generated by DID Proxy, contains DID and DID Document)
# Naming convention: extended_{nf_type}_profile.json (e.g., extended_ausf_profile.json)
extended_profile_path: /usr/local/etc/oai/extended_ausf_profile.json

http_version: 2

############## SBI Interfaces
nfs:
  # ... 其他 NF 配置 ...
  
  bcf:
    host: oai-bcf
    sbi:
      port: 8080
      api_version: v1
      interface_name: eth0
```

---

## 5. 调用流程

```
AUSF 启动
    │
    ▼
ausf_config_yaml 构造函数
    │── 添加 BCF NF 到 m_used_sbi_values
    │── 添加 BCF 配置项到 m_used_config_values
    │
    ▼
ausf_config_yaml::to_ausf_config()
    │── 解析 register_bcf 配置
    │── 解析 BCF 地址 (nfs.bcf)
    │── 解析 extended_profile_path
    │
    ▼
ausf_app::start()
    │
    ├──► ausf_nrf::read_nf_instance_id_from_extended_profile()
    │       │── 尝试从 extended_ausf_profile.json 读取 nfInstanceId
    │       │── 如果文件存在，使用 DID Proxy 生成的 ID
    │       │── 否则，生成新的 UUID v4
    │
    ├──► ausf_nrf 构造函数 (如果 register_nrf = true)
    │       │── 使用上述获取的 nfInstanceId
    │       │── 生成 AUSF Profile
    │       │── 向 NRF 注册
    │
    └──► ausf_bcf 构造函数 (如果 register_bcf = true)
            │── 使用相同的 nfInstanceId (DID 一致性)
            │
            ▼
        ausf_bcf::register_to_bcf()
            │
            ▼
        ausf_bcf::read_extended_profile_from_file()
            │── 读取扩展 Profile JSON (含 DID 和 DID Document)
            │
            ▼
        构建 HTTP PUT 请求
            │── URI: {bcf_addr.uri_root}/nbcf_management/{api_version}/nf_instances/{ausf_instance_id}
            │── Body: extended_profile (含 DID)
            │
            ▼
        发送到 BCF
            │
            ▼
        处理响应
            │── 记录注册结果

AUSF 停止
    │
    ▼
ausf_app::stop()
    │
    ├──► ausf_bcf::deregister_from_bcf() (如果 register_bcf = true)
    │       │── 发送 HTTP DELETE 到 BCF
    │
    └──► ausf_nrf::deregister_to_nrf() (如果 register_nrf = true)
            │── 发送 HTTP DELETE 到 NRF
```

---

## 6. 部署与运行

### 6.1 前置条件

1. **DID Proxy 服务**已运行并生成 `extended_ausf_profile.json`
2. **BCF 服务**已运行并可访问
3. 配置文件中已正确配置 BCF 地址

### 6.2 启用 BCF 注册

修改 `etc/config.yaml`:

```yaml
register_bcf:
  general: yes

extended_profile_path: /usr/local/etc/oai/extended_ausf_profile.json

nfs:
  bcf:
    host: oai-bcf  # BCF 服务主机名
    sbi:
      port: 8080
      api_version: v1
      interface_name: eth0
```

### 6.3 运行顺序

1. 启动 DID Proxy 生成 `extended_ausf_profile.json`
2. 启动 BCF 服务
3. 启动 AUSF

### 6.4 验证

检查 AUSF 日志中的以下信息：

```
[ausf_app] [info] Using AUSF instance ID from extended profile: <uuid>
[ausf_app] [info] Create BCF TASK for DID registration
[ausf_app] [info] BCF TASK created
[ausf_app] [info] Registering AUSF to BCF...
[ausf_app] [info] BCF registration URI: http://oai-bcf:8080/nbcf_management/v1/nf_instances/<uuid>
[ausf_app] [info] AUSF successfully registered to BCF, status code: 201
```

---

## 附录：DID Document 结构示例

```json
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
  "created": "2026-01-21T12:00:00Z",
  "updated": "2026-01-21T12:00:00Z"
}
```

## 附录：Extended AUSF Profile 结构示例

```json
{
  "nfInstanceId": "b8b62d24-573a-420b-a0ca-d58767193ca0",
  "nfType": "AUSF",
  "nfStatus": "REGISTERED",
  "heartBeatTimer": 50,
  "ipv4Addresses": ["192.168.70.6"],
  "priority": 1,
  "capacity": 100,
  "ausfInfo": {
    "groupId": "oai-ausf-testgroupid",
    "routingIndicators": ["0210", "9876"]
  },
  "did": "did:oai5gc:a1b2c3d4e5f6...",
  "didDocument": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:oai5gc:a1b2c3d4e5f6...",
    "verificationMethod": [...]
  }
}
```

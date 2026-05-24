# BCF-AMF-AUSF 审计功能实现说明与验证记录

更新时间：2026-05-24  
适用范围：当前本机 `/home/zhang/BCF` 代码与 p3-chain 八节点环境  
汇报目标：说明我在 BCF、AMF、AUSF 三方实现了什么审计能力、审计字段是什么、审计证据如何产生和验证、以及目前真实网元的实测结果。

## 1. 总体结论

当前系统已经形成一套“BCF 链上审计索引 + AMF/AUSF 本地安全审计 + 会话摘要上链验证”的三层审计架构。

核心完成内容：

- BCF 侧实现链上审计索引，对 NF 注册、认证、发现、订阅、注销等关键操作生成可查询审计记录。
- AMF 和 AUSF 侧实现本地 `security_audit`，记录本地安全事件 JSONL，并通过 rolling hash 生成会话级摘要。
- AMF 和 AUSF 完成 DID 身份注册、BCF challenge-response 认证、Token 获取后，将本地审计摘要提交到 BCF。
- BCF 将 NF 侧提交的 `session_digest` 锚定到 p3-chain，并提供摘要查询和验证接口。
- 今天已经用真实 AMF、真实 AUSF 完成实测：注册审计、认证审计、摘要锚定、摘要验证均通过。

一句话概括：

> BCF 负责把关键控制面事实和摘要锚定到链上；AMF/AUSF 负责采集本地细粒度安全事件并提交摘要；审计方可以通过 BCF 链上记录验证操作发生过、谁发起、结果如何，以及 NF 本地日志是否被篡改。

## 2. 当前审计架构

```text
真实网元 AMF / AUSF
  |
  | 1. DID Profile 注册
  |    PUT /nbcf_management/v1/nf_instances/{nfInstanceId}
  |
  | 2. BCF 单向认证
  |    POST /nbcf_auth/v1/auth/init
  |    POST /nbcf_auth/v1/auth/verify
  |
  | 3. 业务操作
  |    NF discovery / subscription / later AMF-AUSF service call
  |
  | 4. 本地安全审计
  |    security_audit 记录 JSONL 事件并计算 rolling hash
  |
  | 5. 会话摘要上链
  |    POST /nbcf_audit/v1/session-digests
  v
BCF / p3-chain
  |
  | A. AuditService 生成链上审计索引
  | B. AnchorSessionDigest 锚定 NF 侧摘要
  | C. Query / Verify 接口供审计方查询和校验
  v
链上可信状态
  audit:log:{audit_id}
  audit:operator:{did}
  audit:operation:{operation_type}
  audit:session:{session_id}
  audit:did-sessions:{did}
```

## 3. 三方分别做什么

| 组件 | 审计职责 | 主要证据 | 当前已验证 |
|---|---|---|---|
| BCF / p3-chain | 审计链上业务事实，维护审计索引，锚定会话摘要，提供查询与验证接口 | `AuditLog`、`SessionDigest`、交易哈希、链上索引 | 已验证 |
| AMF | 生成 DID 身份，向 BCF 注册，完成 BCF 认证，订阅 AUSF 事件，记录本地安全事件，提交 AMF 会话摘要 | 本地 JSONL、AMF `session_digest`、BCF `NF_REGISTER/AUTH_VERIFY/SUBSCRIPTION_CREATE` 审计 | 已验证 |
| AUSF | 生成 DID 身份，向 BCF 注册，完成 BCF 认证，记录本地安全事件，提交 AUSF 会话摘要；作为被调用方时可校验 BCF Token | 本地 JSONL、AUSF `session_digest`、BCF `NF_REGISTER/AUTH_VERIFY` 审计 | 已验证 |

## 4. 三层审计证据模型

### Tier 0：链上业务事实和审计索引

BCF 对关键业务接口进行审计，并将结构化索引写入链上。例如：

- `NF_REGISTER`：NF 注册或更新。
- `NF_DEREGISTER`：NF 注销。
- `AUTH_VERIFY`：NF 通过 BCF challenge-response 认证。
- `DISCOVERY`：服务发现。
- `SUBSCRIPTION_CREATE`：订阅创建。
- `SUBSCRIPTION_QUERY`：订阅查询。

这些记录用于回答：

- 谁做了操作：`operator_did`
- 做了什么：`operation_type`
- 操作对象是谁：`target_object_id`
- 结果如何：`result`、`result_code`
- 哪个接口触发：`method`、`resource_path`
- 对应请求摘要是什么：`request_hash`
- 何时发生：`timestamp`
- 链上记录哈希是什么：`tx_hash`

### Tier 1：NF 会话审计摘要

AMF/AUSF 不把完整本地日志全部上链，而是把会话级摘要提交到 BCF：

```text
digest_hash = SHA256(rolling_hash + summary_metadata)
```

BCF 锚定摘要后，链上保存：

- `session_id`
- `subject_did`
- `subject_nf_type`
- `digest_hash`
- `event_count`
- `summary_seq`
- `stage`
- `summary_type`
- `anchor_tx_hash`

这用于证明 NF 本地日志是否被篡改。如果本地事件被删除、插入、改字段，重新计算出的摘要就无法和链上 `digest_hash` 匹配。

### Tier 2：NF 本地结构化审计日志

AMF/AUSF 本地 `security_audit` 将每条安全事件写入 JSONL 文件，默认路径类似：

```text
/tmp/oai-amf-audit-events.jsonl
/tmp/oai-ausf-audit-events.jsonl
```

本地事件保留更细粒度的信息，包括事件序号、阶段、结果、对端 DID、interaction ID、metadata、rolling hash 等。链上只保存摘要，避免把本地细节和敏感上下文全部暴露。

## 5. BCF 侧实现

### 5.1 相关代码位置

| 功能 | 代码位置 |
|---|---|
| HTTP 路由 | `Lee-P3chainforOai-main/ginHttp/router/api/router.go` |
| 审计上下文 | `ginHttp/router/api/audit_context.go`、`audit_middleware.go` |
| 审计查询接口 | `ginHttp/router/api/audit_api.go` |
| 摘要锚定与验证接口 | `ginHttp/router/api/audit_digest_api.go` |
| 审计服务 | `Lee-P3chainforOai-main/api/auditApi.go` |
| 摘要服务 | `Lee-P3chainforOai-main/api/auditDigestApi.go` |
| 链码合约 | `Lee-P3chainforOai-main/chain_code_example/example_didSpectrumTrade/audit_contract.go` |

### 5.2 BCF 审计流程

1. HTTP 请求进入 BCF。
2. `AuditContextMiddleware` 生成 `trace_id`，缓存原始请求体，用于后续计算 `request_hash`。
3. 业务 handler 判断业务语义，例如注册就是 `NF_REGISTER`，认证就是 `AUTH_VERIFY`。
4. handler 构造 `AuditEvent`，调用 `SubmitAudit`。
5. `SubmitAudit` 补齐公共字段：`audit_id`、`method`、`resource_path`、`timestamp`、`request_hash` 等。
6. `AuditService` 将事件放入异步队列。
7. 后台 worker 调用合约 `CreateAuditLog` 写链。
8. 写链后回填审计记录自身的 `tx_hash`。

这样做的原因是：业务请求先返回，审计写链异步完成，不把 5GC 控制面接口强行阻塞在审计上。

### 5.3 BCF 审计记录字段

| 字段 | 含义 | 示例 |
|---|---|---|
| `audit_id` | 审计记录 ID | `NF_REGISTER-...` |
| `operator_did` | 操作主体 DID | AMF DID 或 AUSF DID |
| `operation_type` | 操作类型 | `NF_REGISTER`、`AUTH_VERIFY` |
| `target_object_id` | 操作对象 | NF Instance ID、challenge session ID、subscription ID |
| `request_hash` | 请求体或请求摘要 SHA-256 | `ff49...` |
| `result` | 操作结果 | `SUCCESS` |
| `result_code` | HTTP 结果码 | `200`、`201`、`204` |
| `timestamp` | UTC 时间 | `2026-05-24T10:35:12Z` |
| `tx_hash` | 审计索引记录写链交易哈希 | `54c7...` |
| `related_tx_hash` | 关联业务交易哈希 | NF 注册交易、订阅交易等 |
| `resource_path` | 触发审计的 API 路径 | `/nbcf_auth/v1/auth/verify` |
| `method` | HTTP 方法 | `PUT`、`POST`、`GET` |
| `trace_id` | 请求链路追踪 ID | UUID |
| `session_id` | 会话 ID | `lifecycle:AMF:...` |
| `interaction_id` | 跨 NF 交互 ID | `interaction:...` |
| `subject_did` | 主体 DID | 通常等于 `operator_did` |
| `peer_did` | 对端 DID | `BCF` 或对端 NF |
| `subject_nf_type` | 主体 NF 类型 | `AMF`、`AUSF` |
| `peer_nf_type` | 对端 NF 类型 | `BCF`、`AUSF` |
| `evidence_level` | 证据层级 | `index`、`tier1` |
| `token_fingerprint` | Token 摘要指纹 | SHA-256 前 16 位 |
| `metadata` | 业务扩展字段 | `nf_type`、`verify_mode` |

### 5.4 BCF 摘要字段

`SessionDigest` 是 BCF 保存 NF 本地日志摘要的结构。

| 字段 | 含义 |
|---|---|
| `session_id` | NF 生命周期或业务会话 ID |
| `interaction_id` | 跨 NF 请求响应交互 ID |
| `subject_did` | 生成摘要的 NF DID |
| `peer_did` | 对端 DID，当前 BCF 认证阶段为 `BCF` |
| `subject_nf_type` | `AMF` 或 `AUSF` |
| `peer_nf_type` | 当前常见为 `BCF` |
| `digest_hash` | NF 本地事件 rolling hash 汇总后的摘要 |
| `prev_digest_hash` | 上一个摘要哈希，用于摘要链 |
| `event_count` | 摘要覆盖的本地事件数量 |
| `summary_seq` | 第几次摘要 |
| `stage` | 摘要阶段，如 `bcf_auth_completed` |
| `summary_type` | `checkpoint` 或 `final` |
| `related_tx_hashes` | 关联链上交易列表 |
| `timestamp` | NF 生成摘要的时间戳，毫秒 |
| `anchored_at` | BCF 锚定时间 |
| `anchor_tx_hash` | 摘要上链交易哈希 |
| `evidence_level` | 当前为 `tier1` |
| `token_fingerprint` | Token 指纹，避免记录完整 token |

### 5.5 BCF 提供的审计接口

| 接口 | 用途 |
|---|---|
| `GET /nbcf_management/v1/audit-logs` | 按 DID、操作类型、对象、时间、分页查询审计记录 |
| `GET /nbcf_management/v1/audit-logs/{auditId}` | 查询单条审计详情 |
| `POST /nbcf_audit/v1/session-digests` | NF 提交会话摘要，BCF 锚定上链 |
| `GET /nbcf_audit/v1/session-digests?did=...` | 按 DID 查询摘要 |
| `GET /nbcf_audit/v1/session-digests/{sessionId}` | 按 session ID 查询摘要 |
| `POST /nbcf_audit/v1/verify` | 校验摘要哈希是否和链上一致 |
| `POST /nbcf_audit/v1/verify-events` | 用原始事件重新计算摘要并和链上比对 |

## 6. AMF 侧实现

### 6.1 AMF 身份与注册

AMF 启动前通过 DID Proxy 生成扩展 profile：

```text
/tmp/oai/extended_amf_profile.json
```

该文件包含：

- `did`
- `nfInstanceId`
- `nfType = AMF`
- `didDocument`
- `verificationMethod`
- `publicKeyMultibase`
- AMF profile 信息

AMF 启动后读取该 profile，并向 BCF 注册：

```text
PUT /nbcf_management/v1/nf_instances/{nfInstanceId}
```

BCF 生成 `NF_REGISTER` 审计记录。

### 6.2 AMF 认证

AMF 注册成功后，调用 BCF 单向认证接口：

```text
POST /nbcf_auth/v1/auth/init
POST /nbcf_auth/v1/auth/verify
```

认证流程：

1. AMF 请求 BCF 创建 challenge。
2. BCF 返回随机 challenge 和 session ID。
3. AMF 使用 DID 对应私钥签名 challenge。
4. BCF 根据 AMF DID Document 中的公钥验证签名。
5. 验签成功后，BCF 签发 Bearer token。
6. BCF 生成 `AUTH_VERIFY` 审计记录。

今天 AMF 实测记录中，`AUTH_VERIFY` 的 `metadata` 为：

```json
{
  "nf_instance_id": "e855b760-ba4a-49ae-8ffb-9caf8b016cfe",
  "nf_type": "AMF",
  "verify_mode": "bcf_auth"
}
```

### 6.3 AMF 本地安全审计

AMF 使用 `security_audit` 记录本地安全事件。

本地事件关键字段：

| 字段 | 含义 |
|---|---|
| `event_seq` | 事件序号 |
| `session_id` | AMF 生命周期会话 |
| `interaction_id` | 跨 NF 交互 ID |
| `timestamp` | 毫秒时间戳 |
| `event_type` | 事件类型 |
| `phase` | 事件阶段 |
| `result` | 事件结果 |
| `local_DID` | AMF DID |
| `peer_DID` | 对端 DID |
| `local_type` | `AMF` |
| `peer_type` | 对端类型 |
| `request_scope_id` | 请求范围 ID |
| `token_fingerprint` | Token 指纹 |
| `metadata` | 扩展信息 |
| `canonical_json` | 参与哈希的规范 JSON |
| `rolling_hash` | 当前事件后的滚动哈希 |

每记录一条事件，AMF 更新：

```text
rolling_hash = SHA256(previous_rolling_hash + canonical_json)
```

认证完成后 AMF 生成 checkpoint 摘要，并提交给 BCF：

```text
POST /nbcf_audit/v1/session-digests
```

## 7. AUSF 侧实现

### 7.1 AUSF 身份与注册

AUSF 启动前通过 DID Proxy 生成：

```text
/tmp/oai/extended_ausf_profile.json
```

字段包括：

- `did`
- `nfInstanceId`
- `nfType = AUSF`
- `didDocument`
- `verificationMethod`
- `publicKeyMultibase`
- AUSF service 信息，如 `nausf-auth`

AUSF 启动后向 BCF 注册：

```text
PUT /nbcf_management/v1/nf_instances/{nfInstanceId}
```

BCF 生成 `NF_REGISTER` 审计记录。

### 7.2 AUSF 认证

AUSF 同样通过 BCF 单向认证接口完成认证：

```text
POST /nbcf_auth/v1/auth/init
POST /nbcf_auth/v1/auth/verify
```

认证成功后，BCF 生成 `AUTH_VERIFY` 审计记录，真实 AUSF 实测中 `metadata` 为：

```json
{
  "nf_instance_id": "9b051fd3-94d3-477e-a5b8-c9c6e828c904",
  "nf_type": "AUSF",
  "verify_mode": "bcf_auth"
}
```

### 7.3 AUSF 本地安全审计

AUSF 和 AMF 使用同一套 `security_audit` 逻辑：

- 本地记录 JSONL 事件。
- 每条事件更新 rolling hash。
- 认证完成后生成 checkpoint 摘要。
- 将摘要提交到 BCF。
- BCF 锚定摘要并可验证。

此外，AUSF 作为被调用方时，代码中已经接入了请求上下文提取能力，可从 HTTP Header 中读取：

```text
X-Session-ID
X-Interaction-ID
X-Subject-DID
X-Peer-DID
X-Subject-NF-Type
X-Peer-NF-Type
```

这为后续 AMF 调用 AUSF 的跨 NF 对账提供基础。

## 8. 谁来审计

当前不是单点“某个模块审计所有东西”，而是分层协同审计：

| 审计者 | 审计对象 | 审计方式 |
|---|---|---|
| BCF | 经过 BCF 的关键控制面操作 | 在 BCF handler 中生成 `AuditEvent`，写入链上审计索引 |
| AMF | AMF 自己的安全过程 | 本地 `security_audit` 记录事件，生成摘要提交 BCF |
| AUSF | AUSF 自己的安全过程 | 本地 `security_audit` 记录事件，生成摘要提交 BCF |
| 审计方/管理员 | 链上审计记录和 NF 摘要 | 通过 BCF 查询和验证接口检查 |

这种设计的好处：

- BCF 不需要保存所有 NF 原始日志，降低链上隐私和存储压力。
- NF 不能随意篡改本地日志而不被发现，因为摘要已上链。
- BCF 链上索引可以追溯“谁、什么时候、做了什么、结果如何”。
- 真实业务细节仍保留在 AMF/AUSF 本地，便于故障排查和争议仲裁。

## 9. 安全性保证

### 9.1 DID 身份绑定

AMF/AUSF 都有 DID 和 DID Document。DID Document 中包含 `verificationMethod` 和 `publicKeyMultibase`。BCF 在认证时根据 DID 取公钥，验证 NF 对 challenge 的签名。

安全效果：

- 防止未注册 NF 冒充合法网元。
- NF 身份和链上 profile 绑定。
- 后续审计记录可以用 DID 作为追责主体。

### 9.2 Challenge-response 认证

认证不是简单传一个静态密钥，而是：

```text
BCF 生成 challenge -> NF 私钥签名 -> BCF 公钥验签 -> 签发 token
```

安全效果：

- 私钥不出 NF。
- challenge 具有时效性，避免重放。
- 认证成功被记录为 `AUTH_VERIFY` 审计。

### 9.3 Token 权限与指纹

BCF 签发 Bearer token，token 中包含 NF DID、NF 类型、session 等身份信息和权限。审计记录不保存完整 token，只保存：

```text
token_fingerprint = SHA256(token) 的前 16 位
```

安全效果：

- 可以关联一次 token 使用轨迹。
- 不泄露完整 token。

### 9.4 请求摘要而非敏感原文

BCF 记录 `request_hash`，用于证明请求内容对应关系，但不把敏感原文直接上链。

实测已经验证：

- 认证审计记录不包含 `signature` 原文。
- 认证审计记录不包含 `nonce` 原文。
- 审计记录中只保留必要的业务元数据。

### 9.5 Rolling hash 防篡改

AMF/AUSF 本地日志不是孤立事件，而是哈希链：

```text
event_1 -> rolling_hash_1
event_2 -> rolling_hash_2 = SHA256(rolling_hash_1 + event_2)
...
summary_digest = SHA256(final_rolling_hash + summary_metadata)
```

安全效果：

- 删除任意事件会导致最终摘要不一致。
- 修改任意字段会导致最终摘要不一致。
- 调整事件顺序也会导致最终摘要不一致。

### 9.6 链上共识保证不可篡改

BCF 通过 p3-chain 写入审计索引和摘要。记录一旦经共识写入链上，就可以跨节点查询。今天已验证 AMF/AUSF 审计记录和摘要都能从 BCF 查询接口读到。

### 9.7 查询保护

BCF 审计查询接口要求至少一个过滤条件，例如 DID、operationType、auditId、sessionId 等。无过滤条件查询会返回：

```text
audit query requires at least one filter
```

这避免无条件全量扫描审计日志。

## 10. 当前实测结果

### 10.1 实验环境

| 项目 | 值 |
|---|---|
| p3-chain 节点数 | 8 个节点 |
| 本次主要提交节点 | `127.0.0.1:8001` |
| 说明 | `8004` 当前读接口可用，但作为提交入口出现 `Blockchain storage not visible`，因此真实 AMF/AUSF 验证使用 `8001` |
| AMF profile | `/tmp/oai/extended_amf_profile.json` |
| AUSF profile | `/tmp/oai/extended_ausf_profile.json` |
| 日期 | 2026-05-24 |

### 10.2 真实 AMF 验证

AMF 身份：

```text
AMF_NF_ID = e855b760-ba4a-49ae-8ffb-9caf8b016cfe
AMF_DID   = did:oai5gc:fddbed2c35266ab01e7aca05ccdf4e68:0429723f...
```

已验证记录：

| 操作 | 审计结果 | 关键字段 |
|---|---|---|
| AMF 注册 | 通过 | `operation_type=NF_REGISTER`、`nf_type=AMF`、`result_code=201` |
| AMF BCF 认证 | 通过 | `operation_type=AUTH_VERIFY`、`verify_mode=bcf_auth`、`result_code=200` |
| AMF 订阅 AUSF 事件 | 通过 | `operation_type=SUBSCRIPTION_CREATE`、`target_nf_type=AUSF` |
| AMF 摘要锚定 | 通过 | `session_id=lifecycle:AMF:e855...`、`event_count=4` |
| AMF 摘要验证 | 通过 | `/nbcf_audit/v1/verify` 返回 `verified=true` |

AMF 摘要验证结果：

```json
{
  "session_id": "lifecycle:AMF:e855b760-ba4a-49ae-8ffb-9caf8b016cfe",
  "summary_seq": 1,
  "verified": true,
  "on_chain_event_count": 4,
  "on_chain_summary_type": "checkpoint"
}
```

### 10.3 真实 AUSF 验证

AUSF 身份：

```text
AUSF_NF_ID = 9b051fd3-94d3-477e-a5b8-c9c6e828c904
AUSF_DID   = did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7...
```

已验证记录：

| 操作 | 审计结果 | 关键字段 |
|---|---|---|
| AUSF 注册 | 通过 | `operation_type=NF_REGISTER`、`nf_type=AUSF` |
| AUSF BCF 认证 | 通过 | `operation_type=AUTH_VERIFY`、`verify_mode=bcf_auth`、`result_code=200` |
| AUSF 摘要锚定 | 通过 | `session_id=lifecycle:AUSF:9b05...`、`event_count=4` |
| AUSF 摘要验证 | 通过 | `/nbcf_audit/v1/verify` 返回 `verified=true` |

AUSF 摘要验证结果：

```json
{
  "session_id": "lifecycle:AUSF:9b051fd3-94d3-477e-a5b8-c9c6e828c904",
  "summary_seq": 1,
  "verified": true,
  "on_chain_event_count": 4,
  "on_chain_summary_type": "checkpoint"
}
```

## 11. 当前能支撑的汇报点

可以向导师说明：

1. 我不是只做了普通日志，而是把 5GC NF 的关键操作映射成可查询的链上审计索引。
2. BCF 侧已经审计 NF 注册、认证、发现、订阅等操作，并支持按 DID、操作类型、目标对象、时间、分页、audit ID 查询。
3. AMF/AUSF 不是只被动接受 BCF 审计，它们自己也采集本地安全事件，生成 rolling hash，并把会话摘要锚定到 BCF 链上。
4. 链上不保存原始敏感字段，而保存请求摘要、token 指纹和会话摘要，兼顾可验证性和隐私。
5. 已经用真实 AMF 和真实 AUSF 完成实机验证，不是单纯 mock 测试。
6. 摘要验证接口已经返回 `verified=true`，说明链上摘要和声明摘要一致。

## 12. 后续可继续完善的方向

| 方向 | 说明 |
|---|---|
| 稳定 follower 提交路径 | 当前 `8004` 作为提交入口存在 `Blockchain storage not visible`，建议后续排查 follower 转发或同步机制 |
| 完整 AMF-AUSF 业务交互对账 | 当前已完成 AMF/AUSF 到 BCF 的注册和认证审计，下一步可验证 AMF 调 AUSF 的 `interaction_id` 双边对账 |
| 更细粒度权限模型 | 当前已有 `audit_read`、`audit_anchor` 等权限，可进一步区分 NF 自查、管理员审计、跨域仲裁 |
| 认证业务交易关联 | `AUTH_VERIFY` 当前主要是审计索引和 JWT 签发，可进一步把 token 签发状态作为链上业务事实关联 |
| 本地日志回放验证 | 后续可用 `/nbcf_audit/v1/verify-events` 将 NF 本地 JSONL 事件重新计算，与链上摘要做完整回放验证 |

## 13. 汇报时可用的一句话

> 当前工作实现了 BCF、AMF、AUSF 三方协同的链上可信审计机制：BCF 对控制面关键操作生成链上审计索引，AMF/AUSF 在本地记录细粒度安全事件并计算会话摘要，摘要经 BCF 共识锚定到 p3-chain。真实 AMF 和 AUSF 已完成注册、认证和摘要验证，能够证明操作主体、操作结果和本地日志完整性。

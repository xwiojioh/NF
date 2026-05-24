# BCF 审计最终统一方案

> 本文档为 p3-chain（BCF 侧）审计系统的最终设计，同时定义 AMF/AUSF 的对齐要求。


> 现状说明：BCF 最新代码已提供 `/nbcf_audit/v1/session-digests`、`/nbcf_audit/v1/verify`、`/nbcf_audit/v1/verify-events` 端点；AMF 最新代码也已经实现 `summary_submit_callback` 和本地 `security_audit`，但当前外发路径仍是旧的 `/nbcf_audit/v1/summaries` contract。本文以下内容以统一后的 `session-digests` contract 为准。

---

## 一、设计原则（三条铁律）

1. **链上业务事实是第一审计证据** — BCF 通过共识产生的业务交易（DID 注册、认证确认、授权状态、服务发现）本身就是不可篡改的审计事实，不需要额外的"审计交易"来证明它们存在。

2. **审计摘要上链，原始日志留本地** — NF 侧的详细过程日志（每个 HTTP 请求的细节）保留在 NF 本地；只有会话级摘要哈希锚定到链上，用于事后完整性验证。这与专利权利要求完全一致。

3. **AuditService 是索引兼容层，不是真理层** — BCF 现有的 AuditService 负责将链上业务事实结构化为可查询、可关联的审计索引，而非独立产生新的审计真理。

---

## 二、与专利权利要求的映射

| 专利描述 | 本方案对应实现 |
|---------|---------------|
| "网络功能对关键安全事件进行采集并生成结构化审计日志" | NF（AMF/AUSF）本地 `security_audit` 模块采集事件，写入 JSONL 文件 |
| "按照会话号进行关联" | `session_id` 贯穿 NF 本地日志和 BCF 链上索引 |
| "对同一会话号关联的审计日志进行汇总并计算审计摘要" | NF 在 checkpoint/finalize 时计算 `rolling_hash` 累积摘要 |
| "将审计摘要以状态提交请求的方式提交至分布式可信控制装置" | NF 通过 `POST /nbcf_audit/v1/session-digests` 将摘要提交到 BCF（AMF 现有实现仍需从 `/summaries` 迁移到该统一接口） |
| "经多个可信控制节点共识确认后写入分布式可信状态记录" | BCF 通过 `SoftInvoke` 将摘要写入链上（经 TPBFT + 排序服务共识） |
| "形成对应的审计记录...映射关系" | 链上存储 session_id → {digest_hash, subject_did, peer_did, related_tx_hashes} |
| "原始通信日志保留在本地" | NF 本地 `audit-events.jsonl` 保留全量日志，链上只存摘要 |
| "审计方...重新进行哈希校验" | BCF 提供验证端点，比对 NF 提交的本地日志与链上摘要 |

---

## 三、三层审计证据模型

```
┌─────────────────────────────────────────────────────────────────┐
│  Tier 0: 链上业务事实（第一证据，BCF 共识产生）                    │
│  ─────────────────────────────────────────────────────────────── │
│  • DID 注册交易 (SetNFProfile tx)                                │
│  • 认证确认交易 (VerifyAuthChallenge tx)                          │
│  • 授权状态交易 (Token 签发记录)                                  │
│  • 服务发现交易 (DiscoverNFByType tx)                             │
│  • 订阅管理交易 (CreateSubscription tx)                           │
│  └→ 每笔交易自带: TxHash, 发送方签名, 时间戳, 共识投票凭证        │
└─────────────────────────────────────────────────────────────────┘
                              ↓ related_tx_hash 关联
┌─────────────────────────────────────────────────────────────────┐
│  Tier 1: 会话审计摘要（第二证据，NF 计算 + BCF 共识锚定）          │
│  ─────────────────────────────────────────────────────────────── │
│  • session_digest = SHA-256(rolling_hash + summary_metadata)     │
│  • 链上存储: session_id, subject_did, peer_did, digest_hash,     │
│              event_count, stage, related_tx_hashes[], timestamp   │
│  └→ 用途: 事后验证 NF 本地日志完整性，跨 NF 对账                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓ session_id 关联
┌─────────────────────────────────────────────────────────────────┐
│  Tier 2: NF 本地结构化审计日志（第三证据，NF 本地保留）            │
│  ─────────────────────────────────────────────────────────────── │
│  • JSONL 格式，每事件一行                                         │
│  • 包含: event_seq, session_id, timestamp, event_type, phase,    │
│          result, local_DID, peer_DID, rolling_hash, ...          │
│  └→ 用途: 故障排查、详细追溯、争议仲裁时作为原始证据               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 四、p3-chain（BCF 侧）最终设计

> 说明：BCF 当前代码中，摘要锚定与验证的基础端点已经存在。本节重点是统一 contract、字段命名和对账语义，而不是从零新增接口。

### 4.1 保留现有 AuditService 的定位调整

现有 `AuditService` + `CreateAuditLog` 合约 **保留但重新定位为"业务事实索引层"**：

- **不再定位为**：独立的审计真理来源
- **重新定位为**：将 Tier 0 链上业务交易结构化为可按 DID / 时间 / 操作类型查询的审计索引
- **写入内容**：仍然是每次业务操作的索引记录，但明确标注其 `evidence_level: "index"` 而非 "primary"
- **关键字段 `related_tx_hash`**：指向真正的业务交易哈希（这才是第一证据）

### 4.2 会话审计摘要锚定（统一 contract）

#### 4.2.1 链上合约方法

```
合约: DID::SPECTRUM::TRADE
合约方法（统一后）:
  - AnchorSessionDigest(session_id, digest_json)    // 锚定会话摘要
  - GetSessionDigest(session_id)                    // 查询摘要
  - GetSessionDigestsByDID(did)                     // 按 DID 查询所有会话摘要
  - VerifySessionDigest(session_id, claimed_hash)   // 链上验证
```

#### 4.2.2 链上摘要存储结构

```json
{
  "session_id": "lifecycle:AMF:amf-instance-001",
  "subject_did": "did:oai5gc:<hash>:<pubkey>",
  "peer_did": "did:oai5gc:<hash>:<pubkey>",
  "subject_nf_type": "AMF",
  "peer_nf_type": "AUSF",
  "digest_hash": "sha256-hex-string",
  "prev_digest_hash": "sha256-hex-string",
  "event_count": 12,
  "summary_seq": 3,
  "stage": "bcf_auth_completed",
  "summary_type": "checkpoint",
  "related_tx_hashes": ["tx_hash_1", "tx_hash_2"],
  "anchored_at": "2026-05-21T10:30:00Z",
  "anchor_tx_hash": "..."
}
```

#### 4.2.3 存储键设计（DID 为根索引）

```
链上键:
  audit:session:{session_id}                    → 摘要记录
  audit:did-sessions:{subject_did}              → [session_id_1, session_id_2, ...]
  audit:peer-sessions:{peer_did}                → [session_id_1, ...]
  audit:session-chain:{session_id}:{seq}        → 第 N 次摘要（摘要链）

现有键(保留):
  audit:log:{audit_id}                          → 业务索引记录
  audit:operator:{operator_did}                 → [audit_id_1, ...]
  audit:operation:{operation_type}              → [audit_id_1, ...]
  audit:day:{yyyy-mm-dd}                        → [audit_id_1, ...]
```

### 4.3 摘要接收端点

```
POST /nbcf_audit/v1/session-digests
  Request Body: {
    "session_id": "...",
    "subject_did": "...",
    "peer_did": "...",
    "subject_nf_type": "...",
    "peer_nf_type": "...",
    "digest_hash": "...",
    "prev_digest_hash": "...",
    "event_count": N,
    "summary_seq": N,
    "stage": "...",
    "summary_type": "checkpoint|final",
    "related_tx_hashes": [...],
    "timestamp": 1716000000000
  }
  
  Auth: Bearer Token (需 permission: audit_anchor)
  
  Response 201: {
    "anchor_tx_hash": "...",
    "anchored_at": "..."
  }
```

### 4.4 审计验证端点

```
POST /nbcf_audit/v1/verify
  Request Body: {
    "session_id": "...",
    "claimed_digest_hash": "...",
    "summary_seq": N
  }
  
  Response 200: {
    "verified": true|false,
    "on_chain_digest_hash": "...",
    "anchor_tx_hash": "...",
    "mismatch_reason": "..."  // 仅当 verified=false
  }
```

```
POST /nbcf_audit/v1/verify-events
  Request Body: {
    "session_id": "...",
    "events": [  // NF 提交原始事件用于重新计算
      {"event_seq": 1, "canonical_json": "..."},
      {"event_seq": 2, "canonical_json": "..."},
      ...
    ],
    "initial_hash": "e3b0c44298fc..."  // SHA-256("")
  }
  
  Response 200: {
    "recomputed_digest": "...",
    "on_chain_digest": "...",
    "verified": true|false,
    "event_count_match": true|false
  }
```

### 4.5 现有 AuditService 字段扩展

在现有 `AuditEvent` / `AuditLog` 基础上增加以下字段：

| 新增字段 | 类型 | 说明 |
|---------|------|------|
| `session_id` | string | NF 认证会话 ID（从 Token claims 或请求中提取） |
| `interaction_id` | string | 跨 NF 交互 ID（AMF↔AUSF 双方共享） |
| `subject_did` | string | 操作主体 DID（= operator_did 的别名，为对齐用） |
| `peer_did` | string | 对端 DID |
| `subject_nf_type` | string | 主体 NF 类型 |
| `peer_nf_type` | string | 对端 NF 类型 |
| `evidence_level` | string | "index" / "tier0" / "tier1"（标明证据层级） |
| `token_fingerprint` | string | Token 的 SHA-256 前 16 字符 |

### 4.6 interaction_id 协议

**定义**：标识一次完整的跨 NF 交互（如 AMF 向 AUSF 请求认证服务的完整往返）。

**生成规则**：
- 由**发起方（Initiator）**在交互开始时生成，格式为 `interaction:{initiator_did_short}:{timestamp_ms}:{random_4bytes_hex}`
- 通过 HTTP Header `X-Interaction-ID` 传递给对端
- 对端在响应和本地日志中使用相同的 interaction_id

**与 session_id 的区别**：
- `session_id`：NF 本地的生命周期标识（如 `lifecycle:AMF:amf-001`），跨越多次交互
- `interaction_id`：一次具体的跨 NF 请求-响应交互

**BCF 如何使用**：
- 业务索引记录中记录 `interaction_id`
- 新增链上索引键：`audit:interaction:{interaction_id}` → [相关 audit_id 列表]
- 用于跨 NF 审计对账：双方的 interaction_id 一致则可对账

### 4.7 审计查询权限模型

| 角色 | 可查范围 | 触发场景 |
|------|---------|---------|
| NF 自身 (subject_did = 自己) | 自己的全部审计记录 + 摘要 | 自审计、故障排查 |
| 对端 NF (peer_did = 自己) | 共同 interaction_id 下的 Tier 1 摘要 | 对账、争议 |
| 域管理员 | 本域所有 NF 的 Tier 0 + Tier 1 | 合规审计 |
| 跨域仲裁者 | 指定 interaction_id 的双方 Tier 1 摘要 | 争议仲裁 |

当前实现：粗粒度 `PermAuditRead` → 未来细化为上述模型。短期内先增加 `purpose` 参数用于日志记录"谁查了什么、为什么查"。

---

## 五、AMF / AUSF 对齐要求

### 5.1 AMF 现状确认（基于代码分析）

AMF 已实现：
- `security_audit` 类：完整的本地审计框架
- `session_id` 管理：`lifecycle:{component}:{anchor}` 格式
- `rolling_hash` 滚动哈希：每条事件累积 SHA-256
- `checkpoint` / `finalize_all`：阶段性/最终摘要生成
- `summary_submit_callback`：摘要外发回调接口（已实现，但当前仍使用 legacy `/nbcf_audit/v1/summaries` contract）
- 字段对齐：`local_DID`, `peer_DID`, `local_type`, `peer_type`, `hash`, `prev_summary_hash`, `event_count`, `summary_seq`, `summary_type`, `token_fingerprint`, `phase`

AMF 缺失/需补充：
| 项目 | 现状 | 需要做 |
|------|------|--------|
| 摘要提交到 BCF | callback 已实现，但仍指向 legacy `/summaries` | 切换到统一接口 `/nbcf_audit/v1/session-digests`，并统一 `local_DID/hash` → `subject_did/digest_hash` 映射 |
| interaction_id | 无 | 在发起 AUSF 请求时生成并传递 `X-Interaction-ID` |
| session_id 格式 | `lifecycle:AMF:amf-001`（固定） | 保持，这是 NF 生命周期 session；另外在 interaction 级别使用 interaction_id |
| Token 携带 | DID auth 已有 session_id 在 Token claims | 确认 BCF Token 的 claims 中包含 `session_id` |
| 事件类型 | 自定义的 event_type + phase | 统一为下方 5.3 的标准事件类型 |

### 5.2 AMF 需要的代码改动

#### 5.2.1 实现 summary_submit_callback

```cpp
// amf_app.cpp 初始化时
m_security_audit->set_summary_submit_callback(
    [this](const security_audit_summary& summary, 
           std::string& response_body, uint32_t& response_code) -> bool {
      // 构建请求 body
      nlohmann::json body = {
          {"session_id", summary.session_id},
          {"subject_did", summary.local_DID},
          {"peer_did", summary.peer_DID},
          {"subject_nf_type", summary.local_type},
          {"peer_nf_type", summary.peer_type},
          {"digest_hash", summary.hash},
          {"prev_digest_hash", summary.prev_summary_hash},
          {"event_count", summary.event_count},
          {"summary_seq", summary.summary_seq},
          {"stage", summary.stage},
          {"summary_type", summary.summary_type},
          {"related_tx_hashes", nlohmann::json::array()},  // 从上下文中收集
          {"timestamp", summary.timestamp}
      };
      // 统一后的目标 contract：BCF 侧以 /session-digests 为准
      return http_post(bcf_url + "/nbcf_audit/v1/session-digests", 
                       body.dump(), response_body, response_code);
    });
```

> 注：现有 AMF 代码已经有回调框架，但外发路径仍需从旧的 `/summaries` contract 切到这里的统一接口。

#### 5.2.2 添加 interaction_id 生成与传递

```cpp
// 在发起 AUSF 服务请求时
std::string interaction_id = "interaction:" + short_did(local_did) + ":" 
                           + std::to_string(current_timestamp_ms()) + ":" 
                           + random_hex(4);
// 设置到 HTTP Header
request.set_header("X-Interaction-ID", interaction_id);
// 记录到审计事件
audit_event.request_scope_id = interaction_id;  // 复用现有字段或新增字段
```

#### 5.2.3 在认证流程中传递 session_id

AMF 的 `did_session_manager` 已经管理认证 session_id。需要确保：
- 认证完成后，session_id 写入 Token claims
- 后续对 BCF 的请求（注册、发现、订阅）在 Header 中携带 `X-Session-ID`

### 5.3 统一事件类型对照表

| 统一事件类型 | AMF event_type + phase | BCF operation_type | 触发时机 |
|-------------|----------------------|-------------------|---------|
| `IDENTITY_SETUP` | identity_setup / identity_setup_completed | — | NF DID 生成完成 |
| `NF_REGISTER` | bcf_register / register_response_received | NF_REGISTER | DID Document 注册 |
| `NF_DEREGISTER` | bcf_deregister / deregister_response_received | NF_DEREGISTER | NF 注销 |
| `AUTH_INIT` | bcf_auth / challenge_sent | — | 认证发起 |
| `AUTH_CHALLENGE` | bcf_auth / challenge_received | — | 收到挑战 |
| `AUTH_VERIFY` | bcf_auth / auth_result_received | AUTH_VERIFY | 认证确认 |
| `TOKEN_ISSUED` | bcf_token / token_issued | — | Token 签发 |
| `SERVICE_DISCOVERY` | nf_discovery / discovery_result_received | DISCOVERY | 服务发现 |
| `TARGET_SELECTED` | nf_discovery / target_selected | — | 目标选定 |
| `SUBSCRIPTION_CREATE` | bcf_subscription / subscription_response_received | SUBSCRIPTION_CREATE | 创建订阅 |
| `SUBSCRIPTION_DELETE` | — | SUBSCRIPTION_DELETE | 删除订阅 |
| `SERVICE_REQUEST` | ausf_service_request / ausf_request_sent | — | 跨 NF 服务调用 |
| `SERVICE_RESPONSE` | ausf_service_request / ausf_response_received | — | 跨 NF 服务响应 |
| `MUTUAL_AUTH_INIT` | mutual_auth / init_sent | — | 双向认证发起 |
| `MUTUAL_AUTH_COMPLETE` | mutual_auth / complete_received | — | 双向认证完成 |

### 5.4 AUSF 对齐要求

AUSF（作为 Responder）需要：

1. **实现同样的 `security_audit` 模块**（复用 AMF 的 C++ 类）
2. **接收 `X-Interaction-ID` Header**，在本地审计中记录
3. **生成自己的 session_id**：`lifecycle:AUSF:ausf-001`
4. **checkpoint 时机**：
   - 收到 mutual_auth/init → checkpoint("mutual_auth_challenge_sent")
   - 收到 mutual_auth/complete 并验证成功 → checkpoint("mutual_auth_completed")
5. **摘要提交到 BCF**：同 AMF 的 callback 机制

### 5.5 双方对账协议

```
AMF 视角的 interaction:
  interaction_id = "interaction:amf-001:1716000000000:a1b2"
  session_id = "lifecycle:AMF:amf-001"
  events: [auth_init_sent, challenge_received, response_sent, auth_complete, 
           discovery_sent, discovery_received, service_request_sent, service_response_received]
  digest_hash_amf = SHA-256(rolling_hash_after_all_events + summary_metadata)

AUSF 视角的同一 interaction:
  interaction_id = "interaction:amf-001:1716000000000:a1b2"  (从 Header 获取)
  session_id = "lifecycle:AUSF:ausf-001"
  events: [auth_init_received, challenge_sent, response_received, auth_complete,
           service_request_received, service_response_sent]
  digest_hash_ausf = SHA-256(rolling_hash_after_all_events + summary_metadata)

对账：
  - BCF 链上同时有 AMF 和 AUSF 各自提交的摘要
  - 通过 interaction_id 关联
  - 审计方可分别获取双方摘要 + 本地日志，独立验证
```

---

## 六、与现有代码的兼容策略

### 6.1 BCF 侧（Go）

| 现有代码 | 保留/修改/新增 | 说明 |
|---------|--------------|------|
| `api/auditApi.go` (AuditService) | **保留 + 扩展字段** | 新增 session_id, interaction_id, peer_did 等字段 |
| `ginHttp/router/api/audit_middleware.go` | **保留** | 继续做 traceID + rawBody 捕获 |
| `ginHttp/router/api/audit_context.go` | **保留 + 扩展** | 新增从 Header 提取 X-Interaction-ID, X-Session-ID |
| `ginHttp/router/api/audit_api.go` | **保留 + 对齐字段** | 当前已具备 session-digests / verify / verify-events 端点，重点是与 AMF 字段名和鉴权语义统一 |
| `audit_contract.go` | **保留 + 对齐 contract** | 当前已具备 AnchorSessionDigest, GetSessionDigest, GetSessionDigestsByDID, VerifySessionDigest |
| `ginHttp/router/api/nf_registration.go` 中的 SubmitAudit 调用 | **保留** | 继续产生业务索引记录 |

### 6.2 AMF 侧（C++）

| 现有代码 | 保留/修改/新增 | 说明 |
|---------|--------------|------|
| `security_audit.cpp/hpp` | **保留** | 核心框架完整，无需重写 |
| `amf_app.cpp` 中 callback | **修改** | 将现有 callback 的 legacy 路径和字段名统一为 `/session-digests` contract |
| `amf_sbi.cpp` 中 audit_protected_request | **扩展** | 添加 interaction_id 传递 |
| `did_session_manager` | **保留** | session_id 管理已完整 |

---

## 七、实施优先级

```
Phase 1 (立即): 思路对齐 + 专利支撑
  ├── BCF: AuditEvent/AuditLog 结构扩展（加 session_id, interaction_id, peer_did）
  ├── BCF: 对齐 POST /nbcf_audit/v1/session-digests 端点和字段映射
  ├── BCF: 对齐 AnchorSessionDigest 合约方法与校验逻辑
  └── AMF: 将现有 summary_submit_callback 迁移到统一 contract

Phase 2 (验证专利流程): 完成端到端演示
  ├── BCF: 对齐验证端点 POST /nbcf_audit/v1/verify
  ├── AMF: 添加 X-Interaction-ID Header
  ├── AUSF: 实现 security_audit + 摘要提交
  └── 端到端测试: AMF注册→认证→发现→AUSF交互→双方摘要上链→验证

Phase 3 (论文/演进): 精细化
  ├── 权限细化（purpose-driven 动态权限）
  ├── 多层审计适配（Meso 层 Subnet DID 级别审计）
  ├── 失败补偿队列
  └── 索引分片优化
```

---

## 八、关键共识点（双方必须统一）

1. **链上业务交易 = 第一审计证据**，AuditService 产生的记录 = 索引，NF 提交的摘要 = 第二证据。
2. **session_id 是 NF 本地生命周期概念**，格式 `lifecycle:{component}:{anchor}`；**interaction_id 是跨 NF 交互概念**，由发起方生成并通过 Header 传递。
3. **摘要 ≠ 真理**：BCF 只能验证摘要的签名和格式，不能验证摘要内容的真实性。摘要的价值在于"NF 自己承诺了这些事件发生过"，事后可验可追溯。
4. **Token 只存指纹** (`SHA-256(token)[0:16]`)，绝不明文上链。
5. **related_tx_hash 是审计索引与链上事实的唯一桥梁**。每条审计索引记录必须关联到具体的业务交易哈希。
6. **checkpoint 触发时机由 NF 自主决定**（基于 `derive_summary_stage` 逻辑），BCF 不强制。
7. **对账基于 interaction_id**：双方各自独立产生摘要，通过共同的 interaction_id 在链上关联。
8. **敏感字段永远不上链**：authorization, token_plaintext, signature_value, nonce_value, private_key, did_document_full。

---

## 九、本方案如何描述（论文/专利表述参考）

> p3-chain 的审计系统不独立产生审计真理，而是将 BCF 共识网络中已发生的业务事实结构化为可查询、可关联、可验证的审计证据体系。网络功能在本地以会话为粒度采集结构化审计日志，通过滚动哈希机制累积计算会话审计摘要，并将摘要以状态提交请求的方式锚定至分布式可信控制装置。原始审计日志保留在网络功能本地，分布式可信状态记录中仅保存审计摘要及其与业务交易的映射关系。通过上述方式，在不影响网络功能实时通信性能的前提下，实现关键安全事件的完整性校验、防篡改验证与可信追溯。
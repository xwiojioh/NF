# BCF 链上审计功能验证报告（含 2026-04-19 复测）

验证日期：2026-04-18

## 1. 验证环境

- 项目路径：`/home/zhang/BCF/Lee-P3chainforOai-main`
- 已启动节点：8 个
- 主测试节点：`127.0.0.1:8004`
- 跨节点读取验证节点：`127.0.0.1:8001`
- 测试账户地址：`0xeee7e03ae392b7cf5d16f1d15891f3f8d7153267`
- 测试 DID：`did:test:audit:8004`
- 测试 NF Instance ID：`nf-audit-8004`

## 2. 本轮验证结论

本轮已验证：链上审计主功能可用。

已确认通过的核心能力：

- 业务操作可触发审计记录写链
- 审计记录支持按 `auditId`、`operatorDid`、`operationType`、`targetObjectId`、时间范围查询
- 审计记录支持分页与总数统计
- 审计记录可跨节点读取，说明为链上共享数据
- 查询接口具备参数校验，不允许无过滤条件全量扫描

## 3. 已验证通过的场景

### 3.1 NF 注册审计

执行接口：

```bash
curl -i -X PUT "http://127.0.0.1:8004/nbcf_management/v1/nf_instances/nf-audit-8004" \
  -H "Content-Type: application/json" \
  -d '{
    "did":"did:test:audit:8004",
    "didDocument":{
      "id":"did:test:audit:8004",
      "verificationMethod":[
        {
          "id":"did:test:audit:8004#key-1",
          "type":"EcdsaSecp256k1VerificationKey2019",
          "controller":"did:test:audit:8004",
          "blockchainAccountId":"0xeee7e03ae392b7cf5d16f1d15891f3f8d7153267"
        }
      ]
    },
    "nfType":"AMF",
    "nfStatus":"REGISTERED"
  }'
```

结果：

- 业务返回 `201 Created`
- 审计查询可查到 `NF_REGISTER`
- 单条详情查询可查到对应 `audit_id`
- 跨节点 `8001` 可查到同一条记录

关键字段示例：

- `operation_type = NF_REGISTER`
- `operator_did = did:test:audit:8004`
- `target_object_id = nf-audit-8004`
- `result_code = 201`
- `method = PUT`
- `resource_path = /nbcf_management/v1/nf_instances/nf-audit-8004`
- `tx_hash` 有值
- `related_tx_hash` 有值

### 3.2 审计单条详情查询

执行接口：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/audit-logs/<audit_id>"
```

结果：

- 可按 `audit_id` 正常返回单条审计详情

### 3.3 订阅创建审计

执行接口：

```bash
curl -i -X POST "http://127.0.0.1:8004/nbcf_management/v1/subscriptions" \
  -H "Content-Type: application/json" \
  -d '{
    "subscriberDid":"did:test:audit:8004",
    "targetNfType":"AMF",
    "callbackUrl":"http://127.0.0.1:9999/callback",
    "eventTypes":["NF_REGISTERED","NF_DEREGISTERED"]
  }'
```

结果：

- 业务返回 `201 Created`
- 返回 `subscription_id = sub-1776524836471171358`
- 审计查询可查到 `SUBSCRIPTION_CREATE`

关键字段示例：

- `operation_type = SUBSCRIPTION_CREATE`
- `target_object_id = sub-1776524836471171358`
- `result_code = 201`
- `method = POST`
- `resource_path = /nbcf_management/v1/subscriptions`
- `tx_hash` 有值
- `related_tx_hash` 有值

### 3.4 订阅查询审计

执行接口：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/subscriptions?subscriber-did=did:test:audit:8004"
```

业务结果：

- 返回空列表 `{"subscriptions":[]}`

随后查询审计：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/audit-logs?operatorDid=did:test:audit:8004&operationType=SUBSCRIPTION_QUERY&startTime=2026-04-18"
```

结果：

- 审计可查到 `SUBSCRIPTION_QUERY`
- 即使业务返回空结果，审计仍会记录
- `metadata.result_count = 0`

### 3.5 NF 注销审计

执行接口：

```bash
curl -i -X DELETE "http://127.0.0.1:8004/nbcf_management/v1/nf_instances/nf-audit-8004?did=did:test:audit:8004"
```

结果：

- 业务返回 `204 No Content`
- 审计查询可查到 `NF_DEREGISTER`

关键字段示例：

- `operation_type = NF_DEREGISTER`
- `target_object_id = nf-audit-8004`
- `result_code = 204`
- `method = DELETE`
- `resource_path = /nbcf_management/v1/nf_instances/nf-audit-8004`
- `tx_hash` 有值
- `related_tx_hash` 有值

### 3.6 NF 发现审计

执行接口：

```bash
curl -s "http://127.0.0.1:8004/nbcf_discovery/v1/nf_instances?target-nf-type=AMF"
```

业务结果：

- 返回空列表 `{"nfInstances":[]}`

随后查询审计：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/audit-logs?operationType=DISCOVERY&targetObjectId=AMF&startTime=2026-04-18"
```

结果：

- 审计可查到 `DISCOVERY`
- `target_object_id = AMF`
- `metadata.target_nf_type = AMF`
- `metadata.result_count = 0`
- 跨节点 `8001` 可读到同一条记录

说明：

- 本次请求未携带 token，因此 `operator_did` 为空，属于当前实现下的正常现象

## 4. 查询接口能力验证

### 4.1 按时间范围检索

执行接口：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/audit-logs?operationType=DISCOVERY&startTime=2026-04-18T15:25:00Z&endTime=2026-04-18T15:26:00Z"
```

结果：

- 正常返回目标时间窗口内的 `DISCOVERY` 审计记录
- `total = 1`

### 4.2 分页与排序

执行接口：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/audit-logs?operatorDid=did:test:audit:8004&operationType=NF_DEREGISTER&startTime=2026-04-18&page=1&pageSize=1"
```

结果：

- `total = 3`
- `pageSize = 1`
- 仅返回 1 条最新记录
- 当前排序行为符合“按时间倒序返回”的预期

### 4.3 无过滤条件限制

执行接口：

```bash
curl -i "http://127.0.0.1:8004/nbcf_management/v1/audit-logs"
```

结果：

- 返回 `400 Bad Request`
- 错误信息：`audit query requires at least one filter`

说明：

- 该行为符合设计稿中“不支持无条件全量扫描”的要求

### 4.4 非法时间参数校验

执行接口：

```bash
curl -i "http://127.0.0.1:8004/nbcf_management/v1/audit-logs?operationType=DISCOVERY&startTime=bad-time"
```

结果：

- 返回 `400 Bad Request`
- 错误信息：`invalid startTime: unsupported time format: bad-time`

## 5. 2026-04-18 首轮发现的问题

### 5.1 AUTH_VERIFY 场景未完成实测

现象：

- 调用 `POST /nbcf_auth/v1/challenges` 时返回：

```json
{"code":500,"data":{"error":"NF profile not found for did"},"msg":"fail"}
```

同时：

- `GET /nbcf_management/v1/nf_instances?did=did:test:audit:8004` 可以读到该 NF profile

判断：

- 当前问题不在审计查询接口本身
- 更像是认证前置业务链路在读取/解析 NF profile 时存在问题，导致 `AUTH_VERIFY` 场景本轮无法继续完成

### 5.2 DISCOVERY 审计记录的 `tx_hash` 为空

现象：

- `DISCOVERY` 审计记录可正常查到、可跨节点查到
- 但 `tx_hash` 字段为空
- 延时再次查询后仍为空

判断：

- 说明该审计记录已经写链成功
- 但 `tx_hash` 回填在该场景下未成功

### 5.3 订阅业务读路径待单独确认

现象：

- `SUBSCRIPTION_CREATE` 业务返回成功
- 但 `GET /nbcf_management/v1/subscriptions?subscriber-did=did:test:audit:8004` 返回空列表
- `GET /nbcf_management/v1/subscriptions/sub-1776524836471171358?subscriber-did=did:test:audit:8004` 返回 `subscription not found`

判断：

- `SUBSCRIPTION_CREATE` 审计链路已确认正常
- 当前问题更像订阅业务读路径/索引问题，需独立排查

## 6. 2026-04-19 复测与修复结果

复测日期：2026-04-19

复测节点与数据：

- 主测试节点：`127.0.0.1:8004`
- 测试账户地址：`0x36a0b787f90766a62994b6188a6b5795dff2d2e3`
- 新测试 DID：`did:test:audit:8004:v2`
- 新测试 NF Instance ID：`nf-audit-8004-v2`

### 6.1 NF Profile 读链路恢复正常

复测步骤：

```bash
curl -i -X PUT "http://127.0.0.1:8004/nbcf_management/v1/nf_instances/nf-audit-8004-v2" ...
curl -i "http://127.0.0.1:8004/nbcf_management/v1/nf_instances?did=did:test:audit:8004:v2"
```

复测结果：

- 新注册 NF 返回 `201 Created`
- `GET /nbcf_management/v1/nf_instances?did=...` 可正常读取
- 返回内容中的 `data` 已为标准 JSON 字符串，不再是非标准 map 样式

判断：

- NF profile 写入与读取格式问题已修复

### 6.2 AUTH_VERIFY 场景已恢复正常

复测步骤：

```bash
curl -s -X POST "http://127.0.0.1:8004/nbcf_auth/v1/challenges" ...
curl -s -X POST "http://127.0.0.1:8004/dper/signaturereturn" ...
curl -s -X POST "http://127.0.0.1:8004/nbcf_auth/v1/verify" ...
```

关键返回：

- `challengeId = chal-ed1a5fd5d553c050`
- `nonce = 4244ce8f32c2610dcda9eed0e9df493e`
- `VerifyChallenge` 成功返回：
  - `authStatus = AUTHENTICATED`
  - `tokenType = Bearer`
  - `token` 正常签发

随后查询审计：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/audit-logs?operatorDid=did:test:audit:8004:v2&operationType=AUTH_VERIFY&startTime=2026-04-19"
```

复测结果：

- 成功查询到 `AUTH_VERIFY` 审计记录
- `target_object_id = chal-ed1a5fd5d553c050`
- `metadata.verify_mode = challenge`
- `tx_hash` 有值

进一步检查单条详情：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/audit-logs/AUTH_VERIFY-1776567313634132542-51f7e40f-81b7-4de9-b4f3-4e56a176923f"
```

结论：

- `signature`、`nonce` 未出现在链上审计记录中
- `AUTH_VERIFY` 场景已完成验证
- 首轮报告中的 `AUTH_VERIFY` 未完成问题已修复

### 6.3 订阅业务读路径已恢复正常

复测步骤：

```bash
curl -i -X POST "http://127.0.0.1:8004/nbcf_management/v1/subscriptions" ...
curl -s "http://127.0.0.1:8004/nbcf_management/v1/subscriptions?subscriber-did=did:test:audit:8004:v2"
curl -s "http://127.0.0.1:8004/nbcf_management/v1/subscriptions/sub-1776567422645176283?subscriber-did=did:test:audit:8004:v2"
```

关键返回：

- 新订阅 `subscription_id = sub-1776567422645176283`
- 创建返回中的 `target_nf_list` 不再为空
- 列表查询可返回该订阅
- 按 ID 查询可正常返回该订阅详情

结论：

- 首轮报告中的“订阅创建成功但列表为空/按 ID 查询不到”的问题已修复

### 6.4 DISCOVERY 审计的 `tx_hash` 回填已恢复正常

复测步骤：

使用 `AUTH_VERIFY` 签发的 Bearer token 调用发现接口：

```bash
curl -s "http://127.0.0.1:8004/nbcf_discovery/v1/nf_instances?target-nf-type=AMF" \
  -H 'Authorization: Bearer <token>'
```

业务结果：

- 返回 1 条 `AMF` 实例

随后查询审计：

```bash
curl -s "http://127.0.0.1:8004/nbcf_management/v1/audit-logs?operatorDid=did:test:audit:8004:v2&operationType=DISCOVERY&targetObjectId=AMF&startTime=2026-04-19"
```

复测结果：

- 成功查询到新的 `DISCOVERY` 审计记录
- `operator_did = did:test:audit:8004:v2`
- `metadata.result_count = 1`
- `tx_hash = 2c8f080e058b15c117053c453891b2125680947b9f9210f239a1a8221b72547b`

结论：

- 首轮报告中的“DISCOVERY 审计记录 `tx_hash` 为空”问题已修复

### 6.5 复测后确认通过的能力补充

在 2026-04-19 复测基础上，除 2026-04-18 已通过能力外，新增确认：

- `AUTH_VERIFY` 业务链路与审计链路均已通过验证
- 订阅创建后的业务读路径已恢复正常
- 带 token 的 `DISCOVERY` 可正确写入 `operator_did`
- 新生成的 `DISCOVERY` 审计记录 `tx_hash` 可正常回填

## 7. 最终结论

截至 2026-04-19 两轮实机验证结果：

- BCF 链上审计主功能已经完成并通过实测
- 审计写链、链上查询、跨节点读取、分页、时间过滤、参数校验均已通过验证
- 审计已覆盖并实测通过的操作类型包括：
  - `NF_REGISTER`
  - `SUBSCRIPTION_CREATE`
  - `SUBSCRIPTION_QUERY`
  - `NF_DEREGISTER`
  - `DISCOVERY`
  - `AUTH_VERIFY`
- 敏感字段不上链要求已通过实测验证：
  - `AUTH_VERIFY` 审计记录中未出现 `signature`
  - 未出现 `nonce`
- 首轮报告中记录的 3 个问题在 2026-04-19 复测中均已确认修复：
  - `AUTH_VERIFY` 前置 NF profile 读取问题已修复
  - `DISCOVERY` 审计 `tx_hash` 回填问题已修复
  - 订阅业务读路径异常已修复

最终判断：

- 该项目当前链上审计实现已经达到设计稿对应开发目标，可作为当前版本的验收结论

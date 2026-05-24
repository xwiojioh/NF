# BCF 链上审计实现说明

## 1. 这套审计功能现在能做什么

当前项目中的链上审计实现，已经具备以下能力：

- 对关键业务接口的操作行为生成审计事件
- 审计事件异步写链，不阻塞主业务返回
- 审计记录可按多种条件查询
- 审计记录可跨节点读取
- 审计中保留请求摘要、操作主体、操作对象、结果、时间、链上交易信息等关键元数据
- 对敏感字段进行清洗，不把敏感原文直接上链

目前已接入并实测通过的操作类型包括：

- `NF_REGISTER`
- `NF_DEREGISTER`
- `DISCOVERY`
- `SUBSCRIPTION_CREATE`
- `SUBSCRIPTION_QUERY`
- `AUTH_VERIFY`

## 2. 这套审计功能有什么用

这套审计功能的核心价值有四点：

### 2.1 不可篡改

审计记录写入区块链后，不再依赖单机日志文件保存，因此相比普通本地日志更难被篡改或删除。

### 2.2 不可抵赖

每条审计记录都会保留：

- 谁做的：`operator_did`
- 做了什么：`operation_type`
- 操作对象是谁：`target_object_id`
- 结果如何：`result`、`result_code`
- 什么时候做的：`timestamp`
- 对应哪次请求：`trace_id`、`request_hash`

这样后续追责、排查、溯源时可以形成完整链路。

### 2.3 可检索

当前查询接口支持：

- 按 `auditId` 查询单条
- 按 `operatorDid` 查询
- 按 `operationType` 查询
- 按 `targetObjectId` 做进一步过滤
- 按 `startTime` / `endTime` 做时间范围过滤
- 分页查询

这让它不仅是“记日志”，而是“可查、可审、可追踪”的审计系统。

### 2.4 低侵入

项目并没有把审计写链强耦合在每个业务成功返回之前，而是采用：

- 主业务先完成
- 审计事件入队
- 后台 worker 异步写链

这样能尽量避免拖慢 5G 控制面这种本身对时延敏感的业务路径。

## 3. 审计是怎么实现的

整体实现可以理解成 5 层：

1. 请求上下文采集
2. 业务 handler 识别业务语义
3. 审计服务异步写链
4. 审计链码负责落库存储和索引
5. 查询接口按索引检索并返回结果

下面按流程说明。

### 3.1 请求进入时：审计上下文中间件

位置：

- `ginHttp/router/api/audit_middleware.go`
- `ginHttp/router/api/audit_context.go`

作用：

- 为每个 HTTP 请求生成 `trace_id`
- 记录请求开始时间
- 缓存原始请求体
- 为后续审计计算请求摘要提供原始材料

这个阶段还不决定“是否写审计”，只负责把通用上下文准备好。

### 3.2 业务 handler 决定审计语义

位置示例：

- `ginHttp/router/api/nf_registration.go`
- `ginHttp/router/api/nf_discovery.go`
- `ginHttp/router/api/nf_subscription.go`
- `ginHttp/router/api/nf_auth.go`
- `ginHttp/router/api/bcf_auth.go`

这一步是整个设计里最关键的思想之一：

- 中间件只知道“来了一个请求”
- 真正知道“这次业务是什么含义”的，是具体 handler

比如：

- NF 注册时，handler 知道这是 `NF_REGISTER`
- 订阅创建时，handler 知道这是 `SUBSCRIPTION_CREATE`
- challenge 验证成功时，handler 知道这是 `AUTH_VERIFY`

因此由 handler 显式构造 `AuditEvent`，填写：

- `OperatorDID`
- `OperationType`
- `TargetObjectID`
- `Result`
- `ResultCode`
- `RelatedTxHash`
- `Metadata`

然后再调用 `SubmitAudit(...)`。

### 3.3 SubmitAudit 做统一补齐

位置：

- `ginHttp/router/api/audit_context.go`

`SubmitAudit` 的作用是把 handler 没有显式填的公共字段统一补齐，比如：

- 自动生成 `audit_id`
- 自动带上 `trace_id`
- 自动带上 `method`
- 自动带上 `resource_path`
- 自动带上 `timestamp`
- 自动计算 `request_hash`

这样业务代码不用在每个 handler 里重复写这些公共逻辑。

### 3.4 AuditService 异步写链

位置：

- `api/auditApi.go`

`AuditService` 是这套系统的中枢。它做了几件事：

- 持有一个内存队列 `queue`
- 支持 `Enqueue(event)` 非阻塞入队
- 启动多个 worker goroutine 后台消费
- worker 把 `AuditEvent` 转成 `AuditLog`
- worker 调用 `SoftInvoke(CreateAuditLog)` 写链
- 写链失败自动重试
- 重试耗尽只告警，不拖垮主业务

这套设计实现了“主业务优先，审计异步补记”的原则。

### 3.5 链码负责主记录和索引

位置：

- `chain_code_example/example_didSpectrumTrade/audit_contract.go`

链码层实现了：

- `CreateAuditLog`
- `GetAuditLogByID`
- `GetAuditLogsByOperator`
- `GetAuditLogsByOperation`
- `GetAuditLogsByDay`
- `SetAuditLogTxHash`

链上存储不是只放一份主记录，而是同时维护索引。

当前键设计：

- 主记录：`audit:log:{audit_id}`
- 操作人索引：`audit:operator:{operator_did}`
- 操作类型索引：`audit:operation:{operation_type}`
- 日期索引：`audit:day:{yyyy-mm-dd}`

这样查询时就不需要全链扫一遍，而是先通过索引缩小范围，再逐条回查主记录。

### 3.6 查询接口层

位置：

- `ginHttp/router/api/audit_api.go`

当前提供两个查询接口：

- `GET /nbcf_management/v1/audit-logs`
- `GET /nbcf_management/v1/audit-logs/:auditId`

它的查询策略是：

1. 先校验参数
2. 至少要求一个过滤条件
3. 通过 `operator` / `operation` / `day` 索引拿到候选 `audit_id`
4. 根据 `audit_id` 回查主记录
5. 在 Go 层做时间过滤、目标对象过滤、排序、分页

这样实现比较容易控制，也方便后续优化。

## 4. 审计数据里都有哪些字段

当前链上审计记录核心字段包括：

- `audit_id`
- `operator_did`
- `operation_type`
- `target_object_id`
- `request_hash`
- `result`
- `result_code`
- `timestamp`
- `tx_hash`
- `related_tx_hash`
- `resource_path`
- `method`
- `trace_id`
- `metadata`

可以这样理解：

- `tx_hash`：审计记录自己这笔上链交易的 hash
- `related_tx_hash`：业务本身那笔交易的 hash

例如：

- NF 注册成功时，业务调用 `SetNFProfile`
- 审计记录会额外再写一笔 `CreateAuditLog`
- 这两笔交易分别就对应 `related_tx_hash` 和 `tx_hash`

## 5. 请求摘要是怎么做的

位置：

- `ginHttp/router/api/audit_context.go`

项目没有把原始敏感请求直接上链，而是计算一个请求摘要 `request_hash`。

摘要输入包括：

- HTTP 方法
- 请求路径
- 调用方 DID
- 目标对象 ID
- 规范化查询参数
- 清洗后的请求体

摘要算法：

- `SHA-256`
- 十六进制编码

这个摘要的作用是：

- 后续可以证明“当时的请求内容就是这一份”
- 但又不会把敏感原文直接暴露到链上

## 6. 审计如何保证安全性

这部分是你最适合拿去讲给老师/师兄听的。

### 6.1 敏感字段不上链

位置：

- `ginHttp/router/api/audit_context.go`

当前会在计算摘要前清洗以下敏感字段：

- `authorization`
- `token`
- `signature`
- `nonce`
- `challenge`
- `didDocument`
- `publicKey`

这意味着：

- 这些值不会以明文形式进入审计正文
- 链上只保留摘要和必要元数据

实际复测也已经证明：

- `AUTH_VERIFY` 审计记录中没有 `signature`
- 没有 `nonce`

### 6.2 审计与主业务解耦

安全性不仅是防泄露，也包括系统稳定性。

如果审计失败就让主业务一起失败，会导致：

- 可用性下降
- 业务被审计链路拖垮

当前实现采用：

- 主业务优先返回
- 审计异步入队
- 写链失败仅告警

这符合“降级可用”的工程安全思路。

### 6.3 链上存证提升防篡改能力

普通日志文件的问题是：

- 可以删
- 可以改
- 可以只留一部分

链上审计的优势是：

- 一旦写入区块后篡改成本高
- 多节点共享副本
- 可跨节点读取验证

这次实测里也已经验证：

- 同一条审计记录可在 `8004` 和 `8001` 两个节点读到

### 6.4 trace_id + request_hash 提供关联能力

`trace_id` 的作用：

- 标识一次请求在系统里的唯一链路

`request_hash` 的作用：

- 标识这次请求的规范化摘要

两者结合后，后续可以做：

- 审计记录和业务日志关联
- 同类请求归并分析
- 安全排查时的链路追踪

### 6.5 权限控制

查询接口不是裸开放的。

位置：

- `ginHttp/router/api/token_validator.go`
- `ginHttp/router/api/router.go`

项目为审计查询增加了权限：

- `PermAuditRead = "audit_read"`

并在查询路由上使用了：

- `TokenAuthMiddleware(PermAuditRead)`

这意味着：

- 审计读接口可以纳入统一权限体系控制
- 在严格鉴权模式下，不是任意调用方都能读取审计记录

## 7. 现在这套实现是如何平衡“可审计”和“性能”的

这是设计上的一个亮点。

系统做了两个平衡：

### 7.1 不把审计同步塞到主链路里

主业务接口成功后：

- 审计只负责入队
- 后台异步写链

所以业务侧不会因为审计写链阻塞太久。

### 7.2 查询不做无条件全量扫描

当前查询要求至少带一个过滤条件，不允许直接全量扫：

- 这是为了避免性能失控
- 也是为了避免未来数据量变大后接口失去可用性

## 8. 当前实现最适合怎么理解

如果用一句话概括：

这不是“顺手打几条日志”，而是一套围绕关键业务操作建立的、异步写链的、支持索引查询的、带敏感信息清洗的链上审计机制。

它解决的是：

- 关键操作如何留痕
- 留痕后如何不可篡改
- 出了问题如何按人、按操作、按时间追查
- 在保证可审计的同时，尽量不拖慢主业务

## 9. 当前版本的边界

虽然当前版本已经达到设计目标，但从工程角度看，仍然有可继续增强的方向：

- 本地失败补偿目前以告警日志为主，还可以继续做持久化补偿队列
- 查询能力目前依赖现有索引，后续可继续扩展更细粒度索引
- 审计统计分析类能力目前未做，可在现有数据基础上继续扩展

这些属于增强项，不影响当前版本已经具备的主功能价值。

# AMF/BCF 性能测试脚本使用说明

本文说明 `/home/zhang/BCF/amf/scripts` 目录下三个 AMF/BCF 性能测试脚本的用途、常用运行方式，以及生成的 CSV 文件如何理解。

## 运行前准备

建议都从 AMF 目录执行：

```bash
cd /home/zhang/BCF/amf
```

运行前需要确认：

- BCF 已启动，默认地址是 `http://127.0.0.1:8004`。
- BCF 链上账号已经就绪，`/dper/currentAccount` 不能是全零地址。
- 如果要测 AMF 真实注册或严格端到端发现，`./build-local/amf` 已经编译好，并且 `./etc/config.local.yaml` 指向当前 BCF。
- 如果要测发现 AUSF，BCF 中需要已经有可发现的 `AUSF` 实例；严格端到端脚本会要求发现结果非空。
- 严格端到端脚本默认读取 `/tmp/oai/extended_amf_profile.json`，里面需要有 `did`、`nfInstanceId` 和 `privateKey`。

三个脚本默认都会把结果追加写入：

```text
/home/zhang/BCF/amf/scripts/amf_bcf_registration_timings.csv
```

也可以用 `--csv` 指定其他输出文件。

## 脚本一：measure_amf_bcf_registration.py

用途：启动真实 AMF，测量 AMF 向 BCF 注册和 BCF DID 认证相关耗时。

这个脚本适合回答：“AMF 从发起 BCF 注册，到注册成功和 token ready 分别花了多久？”

默认命令：

```bash
./scripts/measure_amf_bcf_registration.py
```

一次跑 10 条成功样本：

```bash
./scripts/measure_amf_bcf_registration.py --runs 10
```

打印 AMF 实时日志，方便排查失败原因：

```bash
./scripts/measure_amf_bcf_registration.py --runs 10 --print-live-log
```

常用参数：

- `--runs N`：收集 N 次成功测量，默认 `1`。
- `--attempts-per-run N`：每个成功样本最多重试 N 次，默认 `3`。
- `--inter-run-delay S`：两次运行之间等待 S 秒，默认 `3.0`。
- `--timeout S`：单次 AMF 启动、注册、认证等待超时，默认 `90.0`。
- `--keep-amf-running`：成功后不停止 AMF；这个参数不能和 `--runs > 1` 一起用。
- `--csv PATH`：指定 CSV 输出路径。

每次成功运行会写入 4 行 CSV：

- `AMF_BCF_Register_E2E`：AMF 发起 BCF NF 注册请求到 AMF 日志打印注册成功的耗时。
- `AMF_BCF_Auth_Init`：AMF 调用 BCF `/nbcf_auth/v1/auth/init` 的请求到响应耗时。
- `AMF_BCF_Auth_Verify`：AMF 调用 BCF `/nbcf_auth/v1/auth/verify` 的请求到响应耗时。
- `AMF_BCF_Auth_E2E`：从 auth/init 开始到 AMF 进入 `TOKEN_READY` 状态的总耗时。

## 脚本二：measure_bcf_discovery.py

用途：直接调用 BCF discovery API，测量 BCF 接口本身的响应耗时。

这个脚本不会启动 AMF，也不会走 AMF 的 discovery C++ 代码路径。它适合做 BCF 发现接口的基准测试或快速健康检查。

默认命令：

```bash
./scripts/measure_bcf_discovery.py
```

一次跑 10 条：

```bash
./scripts/measure_bcf_discovery.py --runs 10
```

要求发现结果不能是空数组：

```bash
./scripts/measure_bcf_discovery.py --runs 10 --require-nonempty
```

查看 BCF 返回的 JSON：

```bash
./scripts/measure_bcf_discovery.py --print-response
```

常用参数：

- `--target-nf-type AUSF`：指定要发现的 NF 类型，默认 `AUSF`。
- `--bcf-base URL`：指定 BCF 地址，默认 `http://127.0.0.1:8004`。
- `--runs N`：测量 N 次，默认 `1`。
- `--require-nonempty`：如果 `nfInstances` 为空，就认为测试失败。
- `--csv PATH`：指定 CSV 输出路径。

写入 CSV 的事件名默认是：

```text
BCF_Discovery_API
```

它表示一次直接 `GET /nbcf_discovery/v1/nf_instances?target-nf-type=...` 的接口耗时。

## 脚本三：measure_amf_bcf_discovery_e2e.py

用途：更严格的 AMF 到 BCF 服务发现端到端测试。

这个脚本会启动真实 AMF，等待 AMF 完成 BCF 注册和 DID 认证，然后使用 AMF 的 DID/privateKey 向 BCF 获取 Bearer token，再带 token 调用：

```text
/nbcf_discovery/v1/nf_instances?target-nf-type=AUSF
```

它还会要求 discovery 返回非空 `nfInstances`，并从结果里选出一个 `REGISTERED` 的目标 NF 实例。因此这个脚本比直接调用 BCF discovery 更接近真实端到端链路。

默认命令：

```bash
./scripts/measure_amf_bcf_discovery_e2e.py
```

预热 2 次，不写入 CSV，然后正式测 10 次：

```bash
./scripts/measure_amf_bcf_discovery_e2e.py --warmups 2 --runs 10
```

如果 AMF 已经手动启动并且已经注册到 BCF，可以不让脚本启动 AMF：

```bash
./scripts/measure_amf_bcf_discovery_e2e.py --no-start-amf --warmups 2 --runs 10
```

每次正式测量前都重新申请 token：

```bash
./scripts/measure_amf_bcf_discovery_e2e.py --warmups 2 --runs 10 --auth-per-run
```

检查 BCF 是否真的强制 discovery 鉴权；未带 token 的请求必须返回 HTTP 401：

```bash
./scripts/measure_amf_bcf_discovery_e2e.py --expect-strict-auth
```

常用参数：

- `--runs N`：正式写入 CSV 的测量次数，默认 `1`。
- `--warmups N`：预热次数，不写入 CSV，默认 `0`。
- `--interval S`：两次 discovery 请求之间等待 S 秒，默认 `1.0`。
- `--no-start-amf`：不启动 AMF，假设 AMF 已经注册并可见。
- `--profile PATH`：指定 AMF DID/privateKey profile，默认 `/tmp/oai/extended_amf_profile.json`。
- `--auth-per-run`：每次正式测量前重新走一次 BCF auth 获取新 token。
- `--token-file PATH`：直接从文件读取已有 Bearer token，不重新认证。
- `--print-response`：打印每次 discovery 返回体。
- `--csv PATH`：指定 CSV 输出路径。

写入 CSV 的事件名默认是：

```text
AMF_BCF_Discovery_E2E
```

它表示一次带 AMF 身份 token 的 BCF discovery 请求耗时，不包含脚本启动 AMF、等待 AMF 注册、获取 token、预热请求的耗时。

## CSV 文件含义

CSV 表头固定是：

```csv
Timestamp,Event_Name,Duration_ms
```

字段含义：

- `Timestamp`：该事件结束时的本机时间，带时区，例如 `2026-04-27T15:20:01.123456+08:00`。
- `Event_Name`：事件类型，用来区分注册、认证、直接发现、严格端到端发现。
- `Duration_ms`：耗时，单位毫秒，保留 3 位小数。

常见事件名：

| Event_Name | 含义 |
| --- | --- |
| `AMF_BCF_Register_E2E` | AMF 发起 BCF 注册到注册成功的耗时 |
| `AMF_BCF_Auth_Init` | AMF 调用 BCF auth/init 的耗时 |
| `AMF_BCF_Auth_Verify` | AMF 调用 BCF auth/verify 的耗时 |
| `AMF_BCF_Auth_E2E` | AMF 从 auth/init 开始到 token ready 的认证总耗时 |
| `BCF_Discovery_API` | 直接调用 BCF discovery API 的耗时 |
| `AMF_BCF_Discovery_E2E` | 带 AMF DID/token 的严格 discovery 端到端请求耗时 |

示例：

```csv
Timestamp,Event_Name,Duration_ms
2026-04-27T15:20:01.123456+08:00,AMF_BCF_Register_E2E,35.742
2026-04-27T15:20:01.180123+08:00,AMF_BCF_Auth_Init,12.384
2026-04-27T15:20:01.230456+08:00,AMF_BCF_Auth_Verify,18.905
2026-04-27T15:20:05.442000+08:00,AMF_BCF_Discovery_E2E,1.168
```

注意：CSV 是追加写入。如果多次运行脚本，旧结果不会自动清空。做正式实验时，建议用 `--csv` 指向一个新的文件，或者先备份旧结果。

## 推荐测试顺序

1. 先跑 `measure_amf_bcf_registration.py --runs 3`，确认 AMF 注册和 BCF 认证链路稳定。
2. 再跑 `measure_bcf_discovery.py --runs 3 --require-nonempty`，确认 BCF discovery API 能返回目标 NF。
3. 最后跑 `measure_amf_bcf_discovery_e2e.py --warmups 2 --runs 10`，采集严格端到端 discovery 性能数据。


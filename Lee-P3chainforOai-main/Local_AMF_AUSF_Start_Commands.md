# 本地 AMF / AUSF 启动指令

本文记录当前机器上可用的 AMF、AUSF 本地启动、后台启动、查看进程和关闭进程指令。

## 1. 启动前注意事项

- AMF 可执行文件：`/home/zhang/BCF/amf/build-local/amf`
- AUSF 可执行文件：`/home/zhang/BCF/ausf/build-local/ausf`
- AMF 配置文件：`/home/zhang/BCF/amf/etc/config.local.yaml`
- AUSF 配置文件：`/home/zhang/BCF/ausf/etc/config.local.yaml`+

## 2. 生成 DID Profile

启动 AMF 前生成 AMF profile：

```bash
/home/zhang/BCF/amf/src/did-proxy/did-proxy \
  -config /home/zhang/BCF/amf/etc/config.local.yaml \
  -hwid-path /tmp/oai/hardware_id
```

启动 AUSF 前生成 AUSF profile：

```bash
/home/zhang/BCF/ausf/src/did-proxy/did-proxy \
  -config /home/zhang/BCF/ausf/etc/config.local.yaml
```

检查 profile 是否生成：

```bash
ls -l /tmp/oai/extended_amf_profile.json
ls -l /tmp/oai/extended_ausf_profile.json
```

## 3. 前台启动 AMF

```bash
cd /home/zhang/BCF/amf
./build-local/amf -c ./etc/config.local.yaml -o
```

## 4. 前台启动 AUSF

```bash
cd /home/zhang/BCF/ausf
./build-local/ausf -c ./etc/config.local.yaml -o
```

## 5. 后台启动 AMF

```bash
cd /home/zhang/BCF/amf
nohup ./build-local/amf -c ./etc/config.local.yaml -o > /tmp/amf.log 2>&1 &
```

查看 AMF 日志：

```bash
tail -f /tmp/amf.log
```

## 6. 后台启动 AUSF

```bash
cd /home/zhang/BCF/ausf
nohup ./build-local/ausf -c ./etc/config.local.yaml -o > /tmp/ausf.log 2>&1 &
```

查看 AUSF 日志：

```bash
tail -f /tmp/ausf.log
```

## 7. 查看进程

查看 AMF：

```bash
pgrep -af '/home/zhang/BCF/amf/build-local/amf|./build-local/amf'
```

查看 AUSF：

```bash
pgrep -af '/home/zhang/BCF/ausf/build-local/ausf|./build-local/ausf'
```

查看端口监听：

```bash
ss -lntp | grep -E '8080|8084|8004'
```

说明：

- AUSF 本地配置的 SBI 端口是 `8084`。
- BCF 本地配置的端口是 `8004`。
- AMF 的 SBI/NGAP 端口请以 `/home/zhang/BCF/amf/etc/config.local.yaml` 为准。

## 8. 关闭进程

关闭 AMF：

```bash
pkill -TERM -f '/home/zhang/BCF/amf/build-local/amf|./build-local/amf'
```

关闭 AUSF：

```bash
pkill -TERM -f '/home/zhang/BCF/ausf/build-local/ausf|./build-local/ausf'
```

如果进程没有退出，再确认 PID 后单独结束：

```bash
pgrep -af 'build-local/(amf|ausf)'
kill -TERM <PID>
```

## 9. AUSF 首次本地编译

如果 `/home/zhang/BCF/ausf/build-local/ausf` 不存在，先编译：

```bash
cd /home/zhang/BCF/ausf
cmake -S ./src/oai_ausf -B ./build-local \
  -DOPENAIRCN_DIR=/home/zhang/BCF/ausf \
  -DSRC_TOP_DIR=/home/zhang/BCF/ausf/src \
  -DMOUNTED_COMMON=common-src
cmake --build ./build-local --target ausf -j$(nproc)
```

编译成功后再执行：

```bash
./build-local/ausf -c ./etc/config.local.yaml -o
```

## 10. 常见问题

### Failed to open extended profile file

说明 DID Proxy 没有先生成对应 profile，或者 `register_bcf.general` 开启但文件不存在。

处理方式：

```bash
/home/zhang/BCF/amf/src/did-proxy/did-proxy -config /home/zhang/BCF/amf/etc/config.local.yaml -hwid-path /tmp/oai/hardware_id
/home/zhang/BCF/ausf/src/did-proxy/did-proxy -config /home/zhang/BCF/ausf/etc/config.local.yaml
```

### ./build-local/ausf: 没有那个文件或目录

说明 AUSF 还没有编译。先执行第 9 节的编译命令。

### /tmp/ausf-local-manual/build/oai_ausf/ausf: 没有那个文件或目录

这是旧路径，当前环境已经不用它。请使用：

```bash
/home/zhang/BCF/ausf/build-local/ausf -c /home/zhang/BCF/ausf/etc/config.local.yaml -o
```

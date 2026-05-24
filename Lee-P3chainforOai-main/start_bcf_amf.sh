#!/bin/bash
# BCF 和 AMF 启动脚本
# 确保 BCF 完全启动后再启动 AMF

set -e

echo "=== Starting BCF and AMF ==="

# 1. 清理旧的 BCF 数据（可选，如果 leveldb 损坏）
# echo "Cleaning old BCF data..."
# rm -rf /path/to/bcf/data/*

# 2. 启动 BCF（在后台）
echo "Starting BCF..."
cd /home/oai/Lee-P3chainforOai-main/dper/client/auto/dper_dper1

# 清理旧的 socket 文件
rm -f /tmp/mypipename*.sock

# 启动 BCF
../../p3Chain -mode=multi_http > /tmp/bcf.log 2>&1 &
BCF_PID=$!
echo "BCF started with PID: $BCF_PID"

# 3. 等待 BCF HTTP 服务就绪
echo "Waiting for BCF HTTP service to be ready..."
MAX_RETRIES=60
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -s http://10.29.124.26:8004/nbcf_management/v1/nf_instances > /dev/null 2>&1; then
        echo "BCF HTTP service is ready!"
        break
    fi
    
    # 检查 BCF 是否还在运行
    if ! kill -0 $BCF_PID 2>/dev/null; then
        echo "ERROR: BCF process died! Check /tmp/bcf.log for details"

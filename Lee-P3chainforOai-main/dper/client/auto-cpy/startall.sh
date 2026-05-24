#!/bin/bash

echo "========== 1. 正在启动 Booter 引导节点 =========="
cd ./dper_booter1
# nohup: 后台运行
# > node.log: 日志写入文件
# 2>&1: 错误信息也写入同一个日志
# &: 立即在后台执行，不阻塞脚本
nohup ./start.sh > node.log 2>&1 &
cd ..

echo "Booter 启动完成，等待 2 秒..."
sleep 2

echo "========== 2. 正在启动 8 个 Dper 共识节点 =========="
for i in {1..8}; do
    dir="dper_dper$i"
    # 判断文件夹是否存在，防止报错
    if [ -d "$dir" ]; then
        cd $dir
        echo "正在启动 $dir ..."
        nohup ./start.sh > node.log 2>&1 &
        cd ..
    fi
done

echo "========== 3. 等待 25 秒让网络完成组网 =========="
# 这个时间很重要，必须等节点连上 Booter 才能启动合约
sleep 25

echo "========== 4. 正在启动智能合约引擎 =========="
for i in {1..8}; do
    dir="dper_dper$i"
    if [ -d "$dir" ]; then
        cd $dir
        echo "正在启动合约引擎 $dir ..."
        nohup ./run_contract.sh > contract.log 2>&1 &
        cd ..
    fi
done

echo "✅ 所有节点启动完毕！"
echo "你可以进入某个节点目录（如 cd dper_dper1），使用 'tail -f node.log' 查看实时日志。"
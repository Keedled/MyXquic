#!/bin/bash

# =================配置区域=================
SERVER_IP="127.0.0.1"
PORT="8443"

# 发送数据大小：1GB (字节)
# 解释：本地回环极快，必须用大文件才能捕捉到稳定的性能数据
#TOTAL_SIZE=$((1 * 1024 * 1024 * 1024))
#419430400大小为400MB
TOTAL_SIZE = $(419430400)
# 日志级别：n (None)
# 解释：必须关闭 Debug 日志，否则你测的其实是“写日志的速度”而不是“网络传输速度”
LOG_LEVEL="e"
# =========================================

# 检查客户端程序是否存在
if [ ! -f "../build/tests/test_client" ]; then
    echo "错误：当前目录下未找到 test_client 可执行文件。"
    exit 1
fi

echo "-----------------------------------------------------"
echo "启动 XQUIC 客户端性能测试"
echo "目标: $SERVER_IP:$PORT"
echo "数据量: $((TOTAL_SIZE / 1024 / 1024)) MB"
echo "日志级别: $LOG_LEVEL (已禁用以提升准确性)"
echo "-----------------------------------------------------"

# 记录开始时间（纳秒级）
start_time=$(date +%s%N)

# === 核心运行命令 ===
# 注意：保留了你原来的 -E 参数（如果是退出标志的话），并追加了优化参数
./test_client -a "$SERVER_IP" -p "$PORT" -s "$TOTAL_SIZE" -l "$LOG_LEVEL" -E

# 获取退出状态
status=$?
# 记录结束时间
end_time=$(date +%s%N)

if [ $status -eq 0 ]; then
    # 计算耗时（秒）
    duration=$(( (end_time - start_time) / 1000000000 ))
    # 防止除以0
    if [ $duration -eq 0 ]; then duration=1; fi
    
    # 计算吞吐量 (Mbps) = (Bytes * 8) / (Seconds * 1000 * 1000)
    throughput=$(( (TOTAL_SIZE * 8) / duration / 1000000 ))

    echo ""
    echo "-----------------------------------------------------"
    echo "测试完成！"
    echo "总耗时:约 $duration 秒"
    echo "估算吞吐量: $throughput Mbps"
    echo "-----------------------------------------------------"
else
    echo ""
    echo "测试异常退出，请检查 Server 是否已启动。"
fi
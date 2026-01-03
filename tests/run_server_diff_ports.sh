#!/usr/bin/env bash

# 检查是否提供了必要的参数
if [ $# -lt 1 ]; then
    echo "请提供一个或多个端口号"
    exit 1
fi

# 遍历所有传入的端口号并执行命令
for port in "$@"; do
    echo "启动服务器，使用端口：$port"
    ../build/tests/test_server -l e --qlog_disable -p "$port" > /dev/null &
    # 启动后台进程
    echo "服务器已在端口 $port 上启动"
done


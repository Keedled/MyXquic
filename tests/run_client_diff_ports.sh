#!/usr/bin/env bash
#调用不同的端口号，开启不同的进程
# 检查是否提供了必要的参数
if [ $# -lt 1 ]; then
    echo "请提供一个或多个端口号"
    exit 1
fi

# 遍历所有传入的端口号并执行命令
for port in "$@"; do
    echo "启动客户端，连接到 127.0.0.1:$port" #这里改为新的主机ip，300MB的数据包
    ./test_client -a 127.0.0.1 -p "$port" -s 314572800 -E > /dev/null &
    # 启动后台进程
    echo "客户端已连接到端口 $port"
done


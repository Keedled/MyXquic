#!/usr/bin/env bash

# 多进程并发运行 test_client，统计总吞吐量（基于 rr_benchmark 的 request_time）
# 用法示例：
#   chmod +x run_multi_clients.sh
#   ./run_multi_clients.sh 4

set -u  # 变量未定义时报错

# 并发进程数，默认 4 个
PROC_NUM=${1:-6}

# ====== 根据你的环境修改这里 ======
CLIENT="../build/tests/test_client"          # test_client 可执行文件路径
ADDR="127.0.0.1"                             # 服务端地址
PORT=8443                                    # 服务端端口
SEND_SIZE=104857600                          # 每个连接发送的 body 大小（字节）
#419430400 400MB
#314572800 300MB
#209715200 200MB
#104857600 100MB
#52428800  50MB
#20971520  20MB
#EXTRA_OPTS="-l e -t 5 -E --qlog_disable"                # 其它 test_client 参数
EXTRA_OPTS="-l e -t 5 -E "                              # 调试模式
#EXTRA_OPTS="-l e -t 5 -E"                # 其它 test_client 参数
# ==================================

# 日志目录：按时间戳区分
LOG_DIR="./logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo "========== XQUIC multi-process benchmark =========="
echo "Clients      : $PROC_NUM"
echo "Server       : $ADDR:$PORT"
echo "Send size    : $SEND_SIZE bytes per client"
echo "Log dir      : $LOG_DIR"
echo "Cmd template : $CLIENT -a $ADDR -p $PORT -s $SEND_SIZE $EXTRA_OPTS"
echo "==================================================="

# 记录实验开始时间（只是信息，不参与吞吐计算）
start_ns=$(date +%s%N)

# 启动多个 client 进程
for i in $(seq 1 "$PROC_NUM"); do
    log_file="$LOG_DIR/client_${i}.log"
    echo "Starting client $i, log -> $log_file"
    $CLIENT -a "$ADDR" -p "$PORT" -s "$SEND_SIZE" $EXTRA_OPTS >"$log_file" 2>&1 &
done

# 等所有子进程结束
wait

# 记录实验结束时间
end_ns=$(date +%s%N)
duration_ns=$((end_ns - start_ns))
duration_sec=$(awk "BEGIN { printf \"%.6f\", $duration_ns/1000000000 }")

# 统计
total_bytes=0          # 所有成功连接的总发送字节数（只算 request_size）
sum_speed_kbit=0       # 所有成功连接的 test_result_speed(Kbit/s) 之和
success_conns=0
failed_conns=0
max_req_time_us=0      # 所有连接中最大的 request_time（us）

echo
echo "========== Parsing client logs =========="

for f in "$LOG_DIR"/client_*.log; do
    # 找 rr_benchmark 行： [rr_benchmark]|request_time:...|request_size:...|response_size:...|
    rr_line=$(grep '\[rr_benchmark\]' "$f" | tail -n 1)
    if [[ -z "$rr_line" ]]; then
        echo "WARN: $(basename "$f"): no [rr_benchmark] line (probably failed early)"
        failed_conns=$((failed_conns + 1))
        continue
    fi

    # 解析 request_time(us) 和 request_size(bytes)
    # FS='[|:]' => 字段: 1:[rr_benchmark] 2:request_time 3:时间 4:request_size 5:大小 6:response_size 7:大小
    req_time_us=$(echo "$rr_line" | awk -F'[|:]' '{print $3}')
    req_size_bytes=$(echo "$rr_line" | awk -F'[|:]' '{print $5}')

    # 更新最大 request_time，用于“并发窗口时间”
    if [[ $req_time_us -gt $max_req_time_us ]]; then
        max_req_time_us=$req_time_us
    fi

    # 找 send_body_size 那行，看 err 是否为 0
    body_line=$(grep 'send_body_size:' "$f" | tail -n 1)
    if [[ -z "$body_line" ]]; then
        echo "WARN: $(basename "$f"): no send_body_size line"
        failed_conns=$((failed_conns + 1))
        continue
    fi

    # 从 send_body_size:... err:XXX 里提取 err
    err=$(echo "$body_line" | sed -E 's/.*err:([0-9-]+).*/\1/')

    if [[ "$err" != "0" ]]; then
        echo "FAIL: $(basename "$f"): err=$err (ignore in throughput)"
        failed_conns=$((failed_conns + 1))
        continue
    fi

    # 只统计成功连接
    success_conns=$((success_conns + 1))
    total_bytes=$((total_bytes + req_size_bytes))

    # 解析 test_result_speed: 33483 Kbit/s. request_cnt: 1.
    speed_line=$(grep 'test_result_speed:' "$f" | tail -n 1)
    if [[ -n "$speed_line" ]]; then
        speed_kbit=$(echo "$speed_line" | awk '{print $2}')
        sum_speed_kbit=$((sum_speed_kbit + speed_kbit))
    fi

    # 打印每个 client 简要情况（基于自己的 request_time）
    req_time_sec=$(awk "BEGIN { printf \"%.6f\", $req_time_us/1000000 }")
    per_conn_mbps=$(awk "BEGIN { printf \"%.3f\", ($req_size_bytes*8)/$req_time_sec/1000000 }")
    echo "OK  : $(basename "$f"): size=${req_size_bytes}B, time=${req_time_sec}s, throughput≈${per_conn_mbps} Mbit/s"
done

# 总比特数（只算发送字节）
total_bits=$((total_bytes * 8))

# 1) 基于“并发窗口”的总吞吐量（不包含 pass:0 之后 idle 的时间）
if [[ $max_req_time_us -gt 0 ]]; then
    max_req_time_sec=$(awk "BEGIN { printf \"%.6f\", $max_req_time_us/1000000 }")
    total_mbps_reqwin=$(awk "BEGIN { printf \"%.3f\", $total_bits/$max_req_time_sec/1000000 }")
else
    max_req_time_sec=0
    total_mbps_reqwin=0
fi

# 2) 把各连接的 test_result_speed 累加（理论值，只参考）
total_mbps_sum=$(awk "BEGIN { printf \"%.3f\", $sum_speed_kbit/1000 }")

echo
echo "================= Summary ================="
echo "Clients launched            : $PROC_NUM"
echo "Success connections         : $success_conns"
echo "Failed connections          : $failed_conns"
echo "Total data sent (requests)  : $total_bytes bytes"
echo
echo "Max request_time (req-win)  : $max_req_time_sec seconds"
echo "Total throughput (req-win)  : $total_mbps_reqwin Mbit/s   # << 你主要关心这个"
echo
echo "Process wall time           : $duration_sec seconds"
echo "Sum of per-conn speeds      : $total_mbps_sum Mbit/s      # test_result_speed 之和，仅参考"
echo "Log directory               : $LOG_DIR"
echo "==========================================="

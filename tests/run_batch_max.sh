#!/usr/bin/env bash

# 批量运行 run_client.sh，并记录每次输出到 result.txt
# 同时统计 "Total throughput (req-win)" 的最大值

LOOPS=${1:-30}            # 运行次数，默认 5 次；也可以在命令行传参，例如 ./run_batch.sh 10
RESULT_FILE="result.txt"

max_tp=0                 # 当前观测到的最大 throughput
max_run=0                # 取得最大 throughput 的轮次

# 如果你想每次重新生成 result.txt 就清空它：
# : 是一个 shell 内建命令，叫做“null command”/空命令
: > "$RESULT_FILE"

for ((i=1; i<=LOOPS; i++)); do
    echo "========== RUN $i / $LOOPS ==========" | tee -a "$RESULT_FILE"

    # 执行一次 run_client.sh，保存输出到变量，同时追加到 result.txt
    output=$(./run_client.sh)
    echo "$output" >> "$RESULT_FILE"

    # 从本次输出里抓取 "Total throughput (req-win)" 那一行的数值
    tp=$(printf '%s\n' "$output" | awk '
        /Total throughput \(req-win\)/ {
            for (i = 1; i <= NF; i++) {
                if ($i == ":") {
                    print $(i+1);  # 冒号后面那个就是数值，例如 1064.141
                    exit
                }
            }
        }')

    if [[ -n "$tp" ]]; then
        # 用 awk 做浮点比较，更新最大值
        new_max=$(awk -v a="$max_tp" -v b="$tp" 'BEGIN{ if (b > a) print b; else print a }')

        # 如果这次更大，则更新记录
        if [[ "$new_max" != "$max_tp" ]]; then
            max_tp="$new_max"
            max_run=$i
        fi

        echo "RUN $i throughput = ${tp} Mbit/s, current max = ${max_tp} Mbit/s (from run #${max_run})" | tee -a "$RESULT_FILE"
    else
        echo "WARN: RUN $i 没找到 \"Total throughput (req-win)\" 行，可能这次连接都失败了。" | tee -a "$RESULT_FILE"
    fi

    echo "" >> "$RESULT_FILE"
done

echo "============= FINAL SUMMARY =============" | tee -a "$RESULT_FILE"
echo "Max Total throughput (req-win): ${max_tp} Mbit/s (from run #${max_run})" | tee -a "$RESULT_FILE"
echo "All outputs saved to: ${RESULT_FILE}" | tee -a "$RESULT_FILE"

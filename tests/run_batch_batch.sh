#!/usr/bin/env bash
# 调用 run_batch_average.sh 脚本，每次运行 30 轮，每轮并发数从 12 递增到 20，每轮之间间隔 1 秒

# 设置参数
RUNS=30            # 总轮数
SLEEP_SEC=1        # 每轮之间休息 1 秒

# 调用 run_batch_average.sh 脚本
for r in $(seq 1 "$RUNS"); do
  # 计算并发数，从 12 到 20 递增
  PROC_NUM=$((17 + (r - 1) % 9))  # 通过 (r-1) % 9 来保证并发数从 12 到 20 循环

  echo "========== Starting run $r / $RUNS =========="
  echo "Concurrent clients: $PROC_NUM"

  # 调用 run_batch_average.sh 脚本，传递 30 轮、并发数、休息时间等参数
  ./run_batch_average.sh "$RUNS" "$PROC_NUM" "$SLEEP_SEC"

  # 轮次间 sleep
  if [[ "$r" -lt "$RUNS" && "$SLEEP_SEC" -gt 0 ]]; then
    sleep "$SLEEP_SEC"
  fi
done

echo "========== All runs completed =========="

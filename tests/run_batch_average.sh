#!/usr/bin/env bash
# 批量调用 run_client.sh，并统计：
# 1) 平均 Total throughput (req-win)
#
# 用法示例：
#   chmod +x run_batch_average.sh
#   ./run_batch_average.sh 5 5
#     -> 运行 5 轮，每轮并发 5 个 client
#
# 可选：第三个参数为两轮间 sleep 秒数（默认 1 秒）
#   ./run_batch_average.sh 10 5 2
#   ./run_batch_average.sh 30 6 1

set -euo pipefail

RUNS=${1:-5}          # 批量跑多少轮
PROC_NUM=${2:-5}      # 每轮并发 client 数
SLEEP_SEC=${3:-1}     # 每轮之间休息

# ====== 按需修改 ======
RUN_SCRIPT="./run_client.sh"
BATCH_DIR="./batch_average_logs_$(date +%Y%m%d_%H%M%S)"
# =====================

mkdir -p "$BATCH_DIR"

echo "========== Batch benchmark =========="
echo "Run script  : $RUN_SCRIPT"
echo "Runs        : $RUNS"
echo "Clients/run : $PROC_NUM"
echo "Sleep(sec)  : $SLEEP_SEC"
echo "Batch dir   : $BATCH_DIR"
echo "====================================="

sum_total_reqwin=0
cnt_total_reqwin=0

# 每轮记录（仅保留 req-win）
per_run_csv="$BATCH_DIR/summary.csv"
echo "run_idx,total_reqwin_mbps" > "$per_run_csv"

for r in $(seq 1 "$RUNS"); do
  out_file="$BATCH_DIR/run_${r}.out"
  echo
  echo "========== Run $r / $RUNS =========="

  # 执行一轮
  bash "$RUN_SCRIPT" "$PROC_NUM" >"$out_file" 2>&1 || true

  # 解析 Total throughput (req-win)
  total_reqwin=$(awk '
    /Total throughput \(req-win\)/ {
      for (i=1; i<=NF; i++) {
        if ($(i) ~ /^[0-9]+(\.[0-9]+)?$/) {
          print $(i); exit
        }
      }
    }
  ' "$out_file")

  echo "Run $r parsed:"
  echo "  Total throughput (req-win): ${total_reqwin:-NA} Mbit/s"
  echo

  # 汇总
  if [[ -n "${total_reqwin:-}" ]]; then
    sum_total_reqwin=$(awk -v a="$sum_total_reqwin" -v b="$total_reqwin" 'BEGIN{ printf "%.6f", a+b }')
    cnt_total_reqwin=$((cnt_total_reqwin + 1))
  fi

  # 写 CSV
  echo "${r},${total_reqwin:-}" >> "$per_run_csv"

  # 轮次间 sleep
  if [[ "$r" -lt "$RUNS" && "$SLEEP_SEC" -gt 0 ]]; then
    sleep "$SLEEP_SEC"
  fi
done

# 计算最终均值
if [[ "$cnt_total_reqwin" -gt 0 ]]; then
  avg_total_reqwin=$(awk -v s="$sum_total_reqwin" -v c="$cnt_total_reqwin" 'BEGIN{ printf "%.6f", s/c }')
else
  avg_total_reqwin="0"
fi

echo
echo "================ Batch Summary ================"
echo "Runs executed                    : $RUNS"
echo "Runs successfully parsed (reqwin) : $cnt_total_reqwin"
echo
echo "Average Total throughput (req-win): $avg_total_reqwin Mbit/s"
echo "Average Total throughput (req-win): $avg_total_reqwin Mbit/s" >> "$per_run_csv"
echo
echo "Per-run CSV saved to              : $per_run_csv"
echo "All run outputs saved under       : $BATCH_DIR"
echo "==============================================="

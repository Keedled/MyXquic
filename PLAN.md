# 新增一个真正的 xquic 示例模块 `chunk_transfer`

## Summary
- 新目录不是“文档目录”，而是和 `demo`、`mini`、`tests` 一样的真实 xquic 示例模块。
- 目录位置固定为 `/home/ubuntu/xquic/xquic/chunk_transfer`，与 `mini`、`demo`、`tests` 同级。
- 该模块提供两个可执行程序：`chunk_client` 和 `chunk_server`。
- 实现必须完全基于 xquic 的 transport API，不单独造协议栈，不走 HTTP/3/HQ。
- 目标行为固定为：文件按应用层 chunk 拆分；每个 chunk 用一个连接发送；每个连接只创建一个 QUIC stream；每个连接由一个线程负责。

## Module Layout
```text
/home/ubuntu/xquic/xquic/chunk_transfer/
├── CMakeLists.txt
├── README.md
├── chunk_common.h
├── chunk_common.c
├── chunk_protocol.h
├── chunk_protocol.c
├── chunk_client.c
├── chunk_client_cb.c
├── chunk_client_worker.c
├── chunk_server.c
└── chunk_server_cb.c
```

## Build Integration
- 在顶层 `CMakeLists.txt` 的 `if(XQC_ENABLE_TESTING)` 分支内新增 `add_subdirectory(chunk_transfer)`。
- `chunk_transfer/CMakeLists.txt` 风格对齐 `demo`/`mini`：
  - 定义共享源文件 `chunk_common.c`、`chunk_protocol.c`
  - 定义客户端目标 `chunk_client`
  - 定义服务端目标 `chunk_server`
  - `include_directories` 与 `demo`/`mini` 保持一致
  - `target_link_libraries` 复用 `xquic-static`、`libevent`、`pthread`、`ssl` 等现有依赖
- 平台兼容策略对齐 `demo`/`mini`：
  - 复用 `../tests/platform.h`
  - Windows 下沿用 `getopt` 兼容路径
  - 非 Windows 下使用 `socket + libevent + pthread`

## Public Interfaces And Behavior
- 新增自定义 ALPN：`chunk-transfer`
- 服务端通过 `xqc_engine_register_alpn` 注册 `chunk-transfer`
- 客户端通过 `xqc_connect(..., "chunk-transfer", ...)` 建立连接
- 客户端 stream API 固定使用：
  - `xqc_stream_create`
  - `xqc_stream_send`
  - `xqc_stream_recv`
- 服务端固定使用 transport 回调：
  - `conn_create_notify`
  - `conn_close_notify`
  - `stream_read_notify`
  - `stream_write_notify`
  - `stream_close_notify`
- 明确不使用：
  - `xqc_h3_connect`
  - `xqc_h3_request_create`
  - HQ 回调体系

## Protocol Design
- 每个连接只允许一个业务 stream。客户端只创建一次 stream；服务端若在同一连接上看到第二个业务 stream，直接关闭该连接。
- 每个 stream 的发送内容固定为：
  1. 固定长度 chunk 头
  2. chunk body
  3. `fin=1`
- chunk 头字段固定为：
  - `magic`
  - `version`
  - `header_len`
  - `file_id`
  - `file_size`
  - `chunk_id`
  - `chunk_count`
  - `offset`
  - `chunk_len`
  - `crc32`
- ACK 结构固定为：
  - `magic`
  - `version`
  - `status`
  - `file_id`
  - `chunk_id`
  - `received_len`
  - `crc32`
- 所有头字段按网络字节序序列化，禁止直接 `memcpy` 原始 struct 上线。
- v1 语义固定：
  - 一个客户端进程一次只发送一个文件
  - 服务端同一时刻只组装一个目标文件
  - 当前文件完成后，服务端收到新的 `file_id` 会重置组装状态并开始下一轮
  - 服务端输出文件路径通过命令行指定

## Client Implementation
- `chunk_client.c`
  - 负责参数解析、文件打开、获取文件大小、切分 chunk、调度 worker、等待结果汇总
  - 默认参数：
    - `-a` 服务端地址
    - `-p` 服务端端口
    - `-h` SNI/host
    - `-i` 输入文件
    - `-k` chunk 大小，默认 `1 MiB`
    - `-j` 最大并发连接数，默认 `4`
    - `-r` chunk 最大重试次数，默认 `3`
    - `-t` 连接超时
    - `-l` 日志级别
- `chunk_client_worker.c`
  - 每个 chunk attempt 对应一个 worker 线程
  - 每个 worker 独立创建：
    - `event_base`
    - `xqc_engine`
    - socket
    - 单个 QUIC 连接
    - 单个 stream
  - worker 生命周期固定为：
    - 建连
    - 发 header
    - 发 chunk body
    - 等 ACK
    - 关闭 stream/connection
    - 上报结果并退出线程
- `chunk_client_cb.c`
  - 负责 transport 回调
  - `stream_write_notify` 中推进 header/body 发送
  - `stream_read_notify` 中接收并解析 ACK
  - `conn_close_notify` 中将非成功完成的 chunk attempt 标记为失败
- 主线程调度策略固定为：
  - 预先生成全部 `chunk_task`
  - 同时最多运行 `-j` 个 worker
  - 失败 chunk 重新排队，直到超过 `-r`
  - 全部 chunk 成功后退出，否则整体失败

## Server Implementation
- `chunk_server.c`
  - 负责参数解析、监听 socket、xquic engine 初始化、输出文件准备
  - 默认参数：
    - `-a` 监听地址
    - `-p` 监听端口
    - `-w` 输出文件路径
    - `-t` 空闲超时
    - `-l` 日志级别
- `chunk_server_cb.c`
  - 负责 ALPN transport 回调
  - 每个连接维护 `server_conn_ctx`
  - 每个 stream 维护 `server_stream_ctx`
  - 接收逻辑固定为：
    - 先累计读取固定头
    - 解析 chunk 元信息
    - 校验边界：`offset + chunk_len <= file_size`
    - 继续读 body，累计 CRC32
    - body 收齐后用 `pwrite` 写入输出文件对应偏移
    - 回 ACK
    - 主动关闭该 stream/connection
- 服务端文件组装策略固定为：
  - 启动时打开输出文件
  - 首个 chunk 到达时按 `file_size` 做 `ftruncate`
  - 使用 `chunk_count` 创建接收位图
  - 已接收 chunk 重复到达时不重复写入，直接回成功 ACK
  - 全部 chunk 收齐后 `fsync` 并打印完成日志
  - 完成后保留组装状态以处理迟到的重复 chunk；之后收到新的 `file_id` 时重置状态并复用同一输出路径

## Shared Types
- `chunk_common.h`
  - 公共宏、日志辅助、平台兼容声明
- `chunk_protocol.h`
  - `chunk_header_v1`
  - `chunk_ack_v1`
  - 序列化/反序列化函数
  - CRC32 接口
- 客户端核心类型固定为：
  - `chunk_task`
  - `chunk_worker_ctx`
  - `chunk_stream_ctx`
  - `chunk_result`
- 服务端核心类型固定为：
  - `server_conn_ctx`
  - `server_stream_ctx`
  - `file_assembly_ctx`

## Test Plan
- 构建检查：
  - `XQC_ENABLE_TESTING=1` 时可同时编译 `chunk_client`、`chunk_server`
- 功能验证：
  - 单文件单 chunk
  - 单文件多 chunk
  - 限并发 `1/2/4/8`
  - 大文件发送
  - 人为断链后 chunk 重试
  - 重复 chunk 再发
- 正确性验证：
  - 输出文件与输入文件 `sha256` 一致
  - 服务端按 `offset` 落盘正确
  - 乱序完成不影响最终文件
- 约束验证：
  - 每个连接只创建一个 stream
  - 每个 worker 线程只持有一个 `xqc_engine`
  - 不共享 `xqc_engine` 到多个线程
- 失败场景：
  - ACK 不合法
  - CRC32 不匹配
  - `chunk_len` 越界
  - 服务端中途退出
  - 客户端超时关闭

## Assumptions
- 新模块是“真实示例实现”，不是单纯方案文档。
- 仍然只基于 xquic 提供的 engine/conn/stream/callback 体系实现。
- 首版不做 HTTP/3 兼容、不做 multipath、不做断点续传、不做零拷贝优化。
- 首版线程模型固定为“一个 chunk attempt 一个线程，一个线程一个连接，一个连接一个 stream”，后续再考虑线程池化。

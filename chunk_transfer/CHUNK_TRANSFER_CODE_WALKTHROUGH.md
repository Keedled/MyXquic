# chunk_transfer 代码梳理

这份文档是对 `chunk_transfer/` 目录内代码的一份阅读说明，重点讲三件事：

1. 这套代码整体是怎么组织的。
2. 一个文件从客户端发送到服务端落盘，中间经过了哪些步骤。
3. 哪些细节最容易看不懂，应该怎么理解。

## 1. 这个目录在做什么

`chunk_transfer` 是一个基于 xquic transport API 的示例程序。

它做的事情并不复杂：

- 客户端把一个输入文件按固定大小切成多个 chunk。
- 每个 chunk 的一次发送尝试都独立使用：
  - 一个 worker 线程
  - 一条 QUIC 连接
  - 一个 QUIC stream
- 服务端收到 chunk 后，按 header 里的 `offset` 把数据写到目标文件的对应位置。
- 服务端再返回一个固定长度的 ACK，告诉客户端这个 chunk 是否成功。

它不是 HTTP/3，也不是一个通用文件传输框架，而是一个“按块传输文件”的示例实现。

## 2. 代码按什么层次组织

可以把当前目录下的代码分成 4 层。

### 2.1 协议层

文件：

- `chunk_protocol.h`
- `chunk_protocol.c`

职责：

- 定义 chunk header 和 ack 的二进制格式
- 负责结构体和字节流之间的编解码
- 提供 CRC32 计算

这里定义了两个最重要的协议对象：

- `chunk_header_v1`
- `chunk_ack_v1`

其中：

- `CHUNK_HEADER_V1_LEN = 48`
- `CHUNK_ACK_V1_LEN = 28`

所以后面的很多代码会直接使用固定长度数组：

- `header_buf[48]`
- `ack_buf[28]`

这层可以理解成“线上传输格式”。

### 2.2 公共层

文件：

- `chunk_common.h`
- `chunk_common.c`

职责：

- 放公共配置结构体
- 放客户端和服务端共享的上下文结构体
- 提供文件 IO、位图、日志、socket 初始化等工具函数

这一层最重要的是几个结构体：

- `chunk_task`
  - 描述一个 chunk 任务，包含 `chunk_id`、`offset`、`chunk_len`、`attempts`
- `chunk_result`
  - 描述一次 worker 执行结果，包含是否成功、错误码、ACK 信息
- `chunk_stream_ctx`
  - 客户端单个 stream 的发送/接收状态
- `chunk_worker_ctx`
  - 客户端单个 worker 的完整上下文
- `server_stream_ctx`
  - 服务端单个 stream 的接收状态
- `file_assembly_ctx`
  - 服务端整个目标文件的组装状态

如果你读源码时总觉得“状态怎么这么分散”，其实状态基本都集中在这些上下文结构体里了。

### 2.3 客户端层

文件：

- `chunk_client.c`
- `chunk_client_worker.c`
- `chunk_client_cb.c`

职责划分很清楚：

- `chunk_client.c`
  - 客户端入口
  - 解析参数
  - 把文件切成任务
  - 维护调度队列
  - 控制并发和重试
- `chunk_client_worker.c`
  - 负责单个 chunk 的一次发送尝试
  - 创建 socket、event loop、xquic engine、connection、stream
  - 准备 header/body
- `chunk_client_cb.c`
  - 放 xquic 回调
  - 真正执行 stream send、stream recv ACK、连接关闭处理

一句话概括：

- `chunk_client.c` 负责“调度”
- `chunk_client_worker.c` 负责“启动一次 chunk 发送”
- `chunk_client_cb.c` 负责“在回调里把这个 chunk 真正发完并收 ACK”

### 2.4 服务端层

文件：

- `chunk_server.c`
- `chunk_server_cb.c`

职责：

- `chunk_server.c`
  - 服务端入口
  - 初始化监听 socket 和 xquic engine
  - 打开输出文件
  - 进入 libevent 循环
- `chunk_server_cb.c`
  - 处理连接接受、stream 创建、stream 读写
  - 解析 header
  - 校验 chunk
  - 写回文件
  - 回 ACK

## 3. 最重要的心智模型

理解这套代码，最重要的是先建立下面这个模型：

- 客户端主线程不是直接传文件，它只是调度器。
- 真正做网络发送的是多个 worker 线程。
- 每个 worker 只负责一个 chunk 的一次尝试。
- 每个 worker 内部有自己的一套：
  - UDP socket
  - event base
  - xquic engine
  - QUIC connection
  - QUIC stream
- 服务端则是单进程、单事件循环，接收很多客户端连过来的独立连接。

所以，这不是“一个连接里传很多块”的设计，而是“每个块自己开一条连接”。

这也是这份代码最容易让人误解的地方。

## 4. 客户端总体流程

客户端的主流程在 `chunk_client.c` 里。

### 4.1 解析参数和计算 chunk 列表

客户端先读取输入文件的 `stat`，得到：

- 文件大小 `file_size`
- 文件标识 `file_id`
- chunk 数量 `chunk_count`

然后为每个 chunk 生成一个 `chunk_task`：

- `chunk_id`
- `chunk_count`
- `offset`
- `chunk_len`

其中最后一个 chunk 往往不是完整块，所以 `chunk_len` 可能小于 `chunk_size`。

如果输入文件是空文件，也会生成一个 `chunk_len = 0` 的任务，这样协议路径可以保持统一。

### 4.2 调度队列

客户端维护一个简单的待发送队列 `queue`。

初始时，所有 chunk id 都入队。

主循环逻辑大致是：

1. 看当前还有没有空闲 slot。
2. 如果有，就从队列里拿出 chunk id。
3. 为这个 chunk 启动一个 worker 线程。
4. 等待某个 worker 完成。
5. 成功则计数加一。
6. 失败但没超过重试次数，则重新入队。
7. 失败且超过重试次数，则整个传输失败。

所以客户端主线程做的是“调度和回收”，不是“收发 QUIC 数据”。

### 4.3 worker 为什么单独成文件

因为一个 worker 内部逻辑已经接近一个完整的小客户端：

- 创建 event base
- 创建 UDP socket
- 配置超时
- 准备 stream 内容
- 创建 xquic engine
- 建连
- 建 stream
- 进入事件循环
- 等待 ACK

所以作者把它从 `chunk_client.c` 拆到了 `chunk_client_worker.c`。

## 5. 单个 chunk 在客户端是怎么发送的

这部分是 `chunk_client_worker.c` 和 `chunk_client_cb.c` 的核心。

### 5.1 先准备 stream 内容

函数：`chunk_client_prepare_stream`

这一步会做三件事：

1. 初始化 `chunk_stream_ctx`
2. 从输入文件读出这个 chunk 的数据到 `body_buf`
3. 填充 `chunk_header_v1`，然后编码到 `header_buf`

你可以把客户端单个 stream 里的数据理解成：

- 前 48 字节：固定长度 header
- 后面若干字节：chunk body

客户端并不是边读文件边发，而是先把这一块完整读进内存，再发。

### 5.2 创建连接和 stream

函数：`chunk_client_init_connection`

这里会：

- 调用 `xqc_connect()` 创建一条连接
- 调用 `xqc_stream_create()` 创建一个业务 stream
- 立即调用 `chunk_client_stream_send()` 尝试发送 header 和 body

所以连接一建好，数据就开始发了。

### 5.3 为什么 send 要写成“能重复调用”

函数：`chunk_client_stream_send`

这个函数不是“调用一次就一定把数据发完”。

原因是 QUIC send 可能返回：

- 发了一部分
- `-XQC_EAGAIN`

所以代码要记住进度：

- `header_sent`
- `body_sent`

如果没发完，下次 `stream_write_notify` 再进来时继续发。

这就是为什么 `chunk_stream_ctx` 里不仅有 buffer，还有很多长度和偏移字段。

### 5.4 客户端怎么收 ACK

函数：`chunk_client_stream_read_notify`

客户端用一个固定长度 `ack_buf[CHUNK_ACK_V1_LEN]` 累积 ACK 字节。

流程是：

1. 从 stream 读数据
2. 追加到 `ack_buf`
3. 收满 28 字节后 decode 成 `chunk_ack_v1`
4. 校验：
   - `magic`
   - `version`
   - `file_id`
   - `chunk_id`
   - `received_len`
   - `crc32`
5. 全部通过才把本 chunk 标记为成功

这里再强调一次：

- 客户端不是只要收到 ACK 就算成功
- 而是要校验 ACK 里的信息是否和本地这个 chunk 完全一致

## 6. 服务端总体流程

服务端入口在 `chunk_server.c`。

整体流程比较直：

1. 解析监听参数
2. 打开输出文件
3. 创建 event base
4. 创建监听 UDP socket
5. 初始化 xquic server engine
6. 注册 socket 可读事件
7. 进入 `event_base_dispatch`

服务端这里没有 worker 线程模型，所有事情都在事件循环里推进。

## 7. 单个 chunk 在服务端是怎么接收的

最关键的函数是：

- `chunk_server_stream_create_notify`
- `chunk_server_stream_read_notify`
- `chunk_server_finalize_chunk`

### 7.1 一条连接只允许一个业务 stream

在 `chunk_server_stream_create_notify` 里，服务端会检查：

- `conn_ctx->stream_count >= 1`

如果已经有一个业务 stream 了，就关闭连接并返回 `CHUNK_STATUS_BAD_STREAM`。

这和客户端“一次尝试只用一个 stream”的设计完全对齐。

所以服务端状态处理可以简单很多。

### 7.2 服务端先攒 header，再解析

`chunk_server_stream_read_notify` 每次从 QUIC stream 里读取一块数据到临时 buffer：

- `uint8_t buf[4096]`

然后用 `consumed` 指针在这块数据里往前推进。

优先做的事情是：

- 先把前 48 字节攒进 `header_buf`
- `header_received == CHUNK_HEADER_V1_LEN` 后再 decode

这说明服务端假设：

- header 可能一次收不完整
- body 也可能和 header 一起出现在同一次回调里

所以代码写成了“状态机式”的处理，而不是简单的一次性读取。

### 7.3 服务端如何校验 header

函数：`chunk_server_validate_header`

它会检查：

- `magic` 是否正确
- `version` 是否正确
- `header_len` 是否正确
- `chunk_id/chunk_count` 是否合理
- `offset + chunk_len` 是否越界

这里还会初始化服务端全局的 `file_assembly_ctx`。

第一次收到合法 chunk 时，服务端会记录：

- `file_id`
- `file_size`
- `chunk_count`
- `bitmap`

以后收到的 chunk 都必须跟这三个全局信息一致，否则会被判成错误。

这说明服务端在一个进程生命周期里，默认只组装一个目标文件。

### 7.4 duplicate chunk 是怎么处理的

服务端有一个位图 `bitmap`，每个 bit 表示一个 chunk 是否已经成功写入。

如果某个 chunk 已经收过：

- `duplicate = 1`

那么服务端仍然会：

- 把流读完
- 继续计算 CRC
- 正常回 ACK

但它不会再次把 body 写进输出文件。

这是一种幂等处理方式。

### 7.5 body 为什么还要存到内存里

服务端收到 body 时会一边做两件事：

1. 更新 `crc_state`
2. 如果不是 duplicate，就把 body 拷到 `body_buf`

之后在 `chunk_server_finalize_chunk` 中：

1. 先计算最终 CRC
2. 和 header 里的 `crc32` 对比
3. 通过后才调用 `chunk_write_all_at()` 落盘

也就是说，服务端不是流式边收边写，而是：

- 先完整收下一个 chunk
- 校验 CRC
- 再按 `offset` 一次性写入文件

这么做的好处是逻辑直观。

代价是：

- chunk 越大，内存占用越大
- 并发 chunk 越多，服务端瞬时内存压力越大

## 8. ACK 是怎么组织的

ACK 是固定长度结构 `chunk_ack_v1`，里面包含：

- `magic`
- `version`
- `status`
- `file_id`
- `chunk_id`
- `received_len`
- `crc32`

服务端生成 ACK 的函数是 `chunk_server_prepare_ack`。

客户端收到后会校验这个 ACK 是否真的是针对当前 chunk 的。

所以 ACK 不只是一个“OK/FAIL”，而是把服务端对本 chunk 的理解也带回来了。

## 9. 几个关键结构体应该怎么理解

### 9.1 `chunk_task`

它是“调度层对象”。

意思是：

- 这个 chunk 在整个文件里是谁
- 它对应文件的哪一段
- 它已经尝试发送了多少次

它不关心 socket、stream、ACK。

### 9.2 `chunk_worker_ctx`

它是“客户端单次尝试的总上下文”。

里面包含：

- 任务信息
- socket
- event base
- xquic engine
- connection
- 一个 `chunk_stream_ctx`
- 最终结果 `chunk_result`

可以把它当成“客户端一次 chunk attempt 的进程内状态盒子”。

### 9.3 `chunk_stream_ctx`

它是“客户端 stream 级状态”。

核心成员：

- `header_buf`
- `header_sent`
- `body_buf`
- `body_sent`
- `ack_buf`
- `ack_received`

也就是说，这里既管“我要发出去什么”，也管“我已经收回来了什么 ACK”。

### 9.4 `server_stream_ctx`

它是“服务端单个 stream 的接收状态机”。

核心成员：

- `header_buf`
- `header_received`
- `header_parsed`
- `body_buf`
- `body_received`
- `crc_state`
- `ack_buf`
- `ack_ready`

这基本就是一个标准的“分段接收状态机”。

### 9.5 `file_assembly_ctx`

它不是某个 stream 的上下文，而是服务端整个目标文件的组装状态。

它关心的是：

- 当前组装的是哪个文件
- 文件总大小是多少
- 一共有多少个 chunk
- 哪些 chunk 已经完成

所以它是全局的，而不是 per-connection 的。

## 10. 这份代码里最容易误解的点

### 10.1 `file_id` 不是稳定文件哈希

`chunk_make_file_id()` 会混入当前时间。

这意味着：

- 同一个输入文件重复发送
- 也会得到新的 `file_id`

所以这里的 `file_id` 更像一次传输会话标识，而不是内容寻址 ID。

### 10.2 客户端并发不是一个连接里开多个 stream

这里的并发是：

- 多个线程
- 多条连接
- 每条连接一个 stream

不是：

- 一条连接里多个 stream 并发发 chunk

这是设计选择，不是 xquic 的限制。

### 10.3 服务端天然只适合“单目标文件组装”

由于 `assembly` 是 `chunk_server_ctx` 里的单实例，所以一个服务端进程默认只追踪一个文件组装过程。

这也是 README 里说的 “single target file per process lifetime” 的含义。

### 10.4 body 先缓存再写盘

服务端先缓存一个完整 chunk，再校验 CRC，再 `pwrite`。

所以这里不是严格意义上的流式文件写入实现。

### 10.5 ACK 校验做得比表面看起来更严格

客户端会比：

- 文件 ID
- chunk ID
- 长度
- CRC

所以就算服务端“回了一个 OK”，只要内容对不上，客户端还是会判失败。

## 11. 推荐的阅读顺序

如果你准备重新读这套代码，建议按这个顺序：

1. 先看 `README.md`
2. 再看 `chunk_protocol.h` 和 `chunk_protocol.c`
3. 再看 `chunk_common.h`
4. 再看 `chunk_client.c`
5. 再看 `chunk_client_worker.c`
6. 再看 `chunk_client_cb.c`
7. 最后看 `chunk_server.c` 和 `chunk_server_cb.c`

原因是：

- 先理解协议格式
- 再理解状态结构体
- 再理解客户端调度
- 最后再看回调驱动的细节

这样不容易一上来就被 `*_notify` 这些回调绕晕。

## 12. 如果只抓主线，记住这几句话就够了

- 这是一个“按 chunk 传文件”的 xquic 示例。
- 客户端主线程只负责调度，真正发 chunk 的是 worker 线程。
- 每个 chunk attempt 独立用一条连接和一个 stream。
- 服务端先收 header，再收 body，再校验 CRC，最后按 `offset` 写文件。
- 服务端用位图跟踪哪些 chunk 已完成。
- 客户端只有在 ACK 的文件、块号、长度、CRC 全对上时，才认为这个 chunk 成功。

## 13. 后续如果你继续读不懂，最值得继续精讲的函数

如果后面你还想继续深挖，我建议优先继续拆这几个函数：

- `chunk_client_prepare_stream`
- `chunk_client_stream_send`
- `chunk_client_stream_read_notify`
- `chunk_server_stream_read_notify`
- `chunk_server_finalize_chunk`

这里面：

- 客户端发送状态推进
- 服务端接收状态推进
- ACK 校验
- CRC 校验

基本都齐了。


# xquic transport API 梳理

这份文档专门整理 `chunk_transfer/` 里实际用到的 xquic transport API。

目标不是把 `xquic.h` 全部抄一遍，而是回答下面几个问题：

1. xquic transport API 到底是什么。
2. 它和 HTTP/3 那套 API 的区别是什么。
3. 应用程序自己要负责什么，xquic 负责什么。
4. `chunk_transfer` 这份示例代码是怎么把这些接口串起来的。

---

## 1. 什么是 xquic transport API

xquic transport API 是“直接操作 QUIC 连接和流”的接口层。

它的核心对象有三个：

- `xqc_engine_t`
- `xqc_connection_t`
- `xqc_stream_t`

可以简单理解成：

- `engine`
  - xquic 的总控对象
  - 管理连接、ALPN、配置、回调、定时推进
- `connection`
  - 一条 QUIC 连接
- `stream`
  - 一条 QUIC stream

在仓库文档里，这几个对象的定义入口在：

- `docs/API.md`
- `include/xquic/xquic.h`

如果说 HTTP/3 API 是“请求/响应语义层”，那么 transport API 就是更底层的“QUIC 连接/流语义层”。

`chunk_transfer` 用的是 transport API，不是 HTTP/3 API。

---

## 2. transport API 和 HTTP/3 API 的区别

### 2.1 transport API

你直接面对的是：

- 连接
- stream
- datagram
- ALPN (Application-Layer Protocol Negotiation,应用层协议协商)
- 连接建立/关闭
- stream 收发

你自己定义应用协议格式。

`chunk_transfer` 就是这种情况：

- 它自己定义了 `chunk_header_v1`
- 自己定义了 `chunk_ack_v1`
- 自己决定 header 和 body 怎么拼

### 2.2 HTTP/3 API

HTTP/3 API 会再往上包一层，帮你处理：

- 请求/响应模型
- header frame
- data frame
- request stream

所以：

- `chunk_transfer` 这种自定义协议，适合 transport API
- 如果你做浏览器式请求/响应，更适合 HTTP/3 API

---

## 3. xquic 和应用程序的分工

这是理解 transport API 最关键的一点。

### 3.1 xquic 负责什么

xquic 负责 QUIC 协议内部机制，例如：

- 握手
- 包解析
- 包组装
- ACK
- 重传
- 拥塞控制
- 流控
- QUIC stream 状态推进

### 3.2 应用负责什么

应用自己必须负责：

- 创建 UDP socket
- 收 UDP 包
- 发 UDP 包
- 管理事件循环
- 实现 timer
- 决定业务协议
- 在回调里读写 stream 数据
- 管理自己的上下文内存

这也是为什么 xquic 给你的不是一个“自动跑起来”的库，而是一组需要嵌入你事件循环中的接口。

---

## 4. callback 分层

xquic 的 callback 分层非常重要，`chunk_transfer` 里也是按这个结构接的。

可以分成三层：

1. engine callbacks
2. transport callbacks
3. app-protocol callbacks

---

## 5. engine callbacks 是什么

结构体：

- `xqc_engine_callback_t`

这层是“运行环境回调”。

它主要告诉 xquic：

- 定时器到了应该怎么唤醒应用
- 日志怎么写
- 时间怎么取

### 5.1 最关键的是 timer callback

接口：

- `set_event_timer`

它的含义不是“xquic 自己有定时器”。

恰恰相反：

- xquic 不自己实现 timer
- xquic 只告诉你“过多久你应该再来叫我”

应用必须做的事情是：

1. 收到 `set_event_timer(wake_after, ...)`
2. 在自己的事件系统里设置一个定时器
3. 定时器到时后调用 `xqc_engine_main_logic()`

在 `chunk_transfer` 里：

- 客户端：`chunk_client_set_event_timer`
- 服务端：`chunk_server_set_event_timer`

它们都把这个时间塞进 libevent 的 timer event 里。

### 5.2 日志 callback

这层还有：

- `xqc_log_write_err`
- `xqc_log_write_stat`
- `xqc_qlog_event_write`
- `keylog_cb`

`chunk_transfer` 里这些基本都只是占位实现，没做复杂处理。

---

## 6. transport callbacks 是什么

结构体：

- `xqc_transport_callbacks_t`

这层是“QUIC 传输层和应用之间的回调”。

它不关心你的业务协议具体是什么，而关心：

- 底层 socket 怎么发包
- 服务端是否接受新连接
- token / session ticket / transport parameter 怎么保存

### 6.1 write_socket

最核心的是：

- `write_socket`
- `write_socket_ex`

意思是：

- xquic 内部已经生成了一个 QUIC packet
- 现在要你立刻把这个 packet 通过 UDP 发出去

所以 xquic 并不直接操作你的 socket fd。

它只会回调你：

- 这是要发的字节
- 这是目标地址
- 你去 `sendto()`

在 `chunk_transfer` 里：

- 客户端：`chunk_client_write_socket` / `chunk_client_write_socket_ex`
- 服务端：`chunk_server_write_socket` / `chunk_server_write_socket_ex`

本质上都只是把 xquic 给的 buffer 再交给系统调用 `sendto()`。

### 6.2 server_accept

服务端还有一个很关键的回调：

- `server_accept`

意思是：

- xquic 发现一个新的 QUIC 连接来了
- 先问应用要不要接

应用如果返回负数，就拒绝这个连接。

在 `chunk_transfer` 里对应：

- `chunk_server_accept`

它会给新连接创建一个 `server_conn_ctx`。

### 6.3 save_token / save_session / save_tp

客户端 transport callbacks 里还有：

- `save_token`
- `save_session_cb`
- `save_tp_cb`

这些是为了：

- 地址验证
- 会话恢复
- 0-RTT

`chunk_transfer` 里虽然把这些 callback 接上了，但实现基本是空的，没有真的持久化这些数据。

这意味着它是一个“能跑通示例”，不是“面向生产优化的客户端”。

---

## 7. app-protocol callbacks 是什么

结构体：

- `xqc_app_proto_callbacks_t`

它又分成三块：

- `conn_cbs`
- `stream_cbs`
- `dgram_cbs`

这层的含义是：

- 你已经基于 QUIC 定义了一个应用层协议
- 现在要告诉 xquic：当连接和流发生事件时，应该回调哪些函数

这层通常跟某个 ALPN 绑定。

所以你会看到：

- 先 `xqc_engine_create()`
- 再 `xqc_engine_register_alpn()`

也就是说：

- transport callbacks 是“协议无关”的
- app-protocol callbacks 是“某个 ALPN 专属”的

在 `chunk_transfer` 里，ALPN 是：

- `chunk-transfer`

客户端和服务端都注册了这组 ALPN 回调。

---

## 8. connection callbacks 怎么理解

结构体：

- `xqc_conn_callbacks_t`

主要有：

- `conn_create_notify`
- `conn_close_notify`
- `conn_handshake_finished`

### 8.1 conn_create_notify

连接建好后触发。

你通常在这里做：

- 创建连接级上下文
- 把自定义状态挂到连接上

在 `chunk_transfer` 里：

- 客户端 `chunk_client_conn_create_notify`
  - 把 `worker` 和 `conn` 对上
- 服务端 `chunk_server_conn_create_notify`
  - 把 `server_conn_ctx` 挂到连接上

### 8.2 conn_close_notify

连接彻底关闭后触发。

你通常在这里做：

- 回收连接级资源
- 标记业务结束

在 `chunk_transfer` 里：

- 客户端这里会把 event loop break 掉
- 服务端这里会 `free(conn_ctx)`

### 8.3 conn_handshake_finished

握手完成时触发。

`chunk_transfer` 里虽然实现了这个 callback，但基本没做额外逻辑。

---

## 9. stream callbacks 怎么理解

结构体：

- `xqc_stream_callbacks_t`

最重要的是四个：

- `stream_create_notify`
- `stream_read_notify`
- `stream_write_notify`
- `stream_close_notify`

### 9.1 stream_write_notify

这是最容易误解的回调。

它不是“有数据已经发出去了通知你一下”。

它更接近：

- “现在流又可写了，你可以继续发剩下的数据”

因为 `xqc_stream_send()` 可能：

- 只发一部分
- 返回 `-XQC_EAGAIN`

所以正确用法通常是：

1. 你自己维护发送缓冲区和发送进度
2. 调一次 `xqc_stream_send()`
3. 如果没发完，等 `stream_write_notify`
4. 再继续发

`chunk_transfer` 里客户端就是这么做的：

- `header_buf + header_sent`
- `body_buf + body_sent`

### 9.2 stream_read_notify

这个回调表示：

- stream 上有可读数据了

这时你需要主动调用：

- `xqc_stream_recv()`

把数据读出来。

注意：

- 这也不是“一次就一定能读完”
- 你要自己累积、自己解析、自己判断消息边界

`chunk_transfer` 里：

- 客户端在这里读 ACK
- 服务端在这里读 header 和 body

### 9.3 stream_create_notify

服务端常用。

因为客户端一般是主动调用 `xqc_stream_create()` 建流，已经知道自己的 stream 上下文是什么。

但服务端的 stream 往往是“对端发起来的”，所以在这个回调里通常要：

- 创建服务端自己的 stream 上下文
- 挂到这个 stream 上

`chunk_transfer` 里服务端就是在这里创建 `server_stream_ctx`。

### 9.4 stream_close_notify

流彻底关闭时触发。

通常在这里：

- 释放流级上下文

`chunk_transfer` 里服务端在这里 `free(stream_ctx->body_buf)` 再 `free(stream_ctx)`。

---

## 10. user_data 设计

xquic transport API 很依赖 `user_data`。

这是为了让库在回调时把控制权和你的业务状态关联起来。

### 10.1 connection 级 user_data

客户端建连时：

- `xqc_connect(..., user_data)`

这里传进去的 `user_data` 会在后续很多连接相关回调里回来。

服务端则通常在接到连接后显式设置：

- `xqc_conn_set_transport_user_data()`
- `xqc_conn_set_alp_user_data()`

### 10.2 stream 级 user_data

客户端建 stream 时：

- `xqc_stream_create(..., user_data)`

服务端则在 `stream_create_notify` 里：

- `xqc_stream_set_user_data()`

### 10.3 为什么需要两套 connection user_data

这是初学者最容易乱的点。

大致可以这么理解：

- transport user_data
  - 更靠近传输层公共回调
- alp user_data
  - 更靠近某个 ALPN 的连接/流回调

在 `chunk_transfer` 里，服务端会在不同场景下分别挂这些数据。

---

## 11. xquic 的基本驱动模式

这套 transport API 不是“我调用一个 run 就完事了”的模型。

它更像一个嵌入式协议栈，驱动顺序通常是这样：

1. 应用创建 UDP socket
2. 应用创建 `xqc_engine_t`
3. 应用注册 transport callbacks
4. 应用注册某个 ALPN 的 app-protocol callbacks
5. 应用收到 UDP 包
6. 调 `xqc_engine_packet_process()`
7. xquic 内部推进状态，必要时通过 `write_socket` 回调让你发包
8. 一批包处理完后调 `xqc_engine_finish_recv()`
9. 定时器到期时调 `xqc_engine_main_logic()`

这就是典型的“应用驱动协议栈”模式。

---

## 12. client 侧典型调用链

以 `chunk_transfer` 为例，客户端大致是这样：

### 12.1 初始化

1. `xqc_engine_get_default_config()`
2. `xqc_engine_create(XQC_ENGINE_CLIENT, ...)`
3. `xqc_engine_register_alpn(..., "chunk-transfer", ...)`

### 12.2 建连

1. 应用先自己解析目标地址
2. 应用自己创建 UDP socket
3. 调 `xqc_connect()`

这里要注意：

- `peer_addr` 是真实网络地址
- `server_host` 是连接里声明的主机名

### 12.3 建 stream

客户端主动调用：

- `xqc_stream_create()`

并把自己的 `chunk_stream_ctx` 作为 stream user_data 传进去。

### 12.4 发数据

应用调用：

- `xqc_stream_send()`

如果：

- 没发完
- 或者返回 `-XQC_EAGAIN`

就等待下一次 `stream_write_notify` 再继续。

### 12.5 收数据

当 `stream_read_notify` 到来时：

- 调 `xqc_stream_recv()`

然后自己做协议解析。

### 12.6 关闭

如果成功或失败：

- 调 `xqc_conn_close()` 或等待对端关闭

关闭结束后会走到：

- `conn_close_notify`
- `stream_close_notify`

---

## 13. server 侧典型调用链

服务端的模型和客户端不太一样。

### 13.1 初始化

1. 应用创建监听 UDP socket
2. `xqc_engine_create(XQC_ENGINE_SERVER, ...)`
3. `xqc_engine_register_alpn(..., "chunk-transfer", ...)`
4. `xqc_server_set_conn_settings()`

### 13.2 收包

服务端自己在 socket 可读时：

1. `recvfrom()`
2. `xqc_engine_packet_process()`
3. `xqc_engine_finish_recv()`

### 13.3 接受连接

新连接到来后，xquic 会先调：

- `server_accept`

应用决定是否接受。

接受后，再进入连接回调：

- `conn_create_notify`

### 13.4 被动创建 stream

当客户端开出新 stream 时，服务端会收到：

- `stream_create_notify`

应用在这里创建 `server_stream_ctx`。

### 13.5 读业务数据

当 stream 可读时：

- `stream_read_notify`

应用再调用：

- `xqc_stream_recv()`

把数据读出来，自己按应用协议解析。

### 13.6 回 ACK

如果应用要回数据：

- 调 `xqc_stream_send()`

如果没发完，就等：

- `stream_write_notify`

### 13.7 关闭

连接或流结束时，会进入：

- `stream_close_notify`
- `conn_close_notify`

由应用回收资源。

---

## 14. `chunk_transfer` 为什么非常适合学习 transport API

因为它把 transport API 的关键点几乎都踩了一遍：

- 自己管理 UDP socket
- 自己管理 libevent
- 自己实现 timer callback
- 自己注册 ALPN
- 客户端主动建连、建流
- 服务端被动 accept、被动收流
- 自己处理 stream 分段发送
- 自己处理 stream 分段接收
- 自己定义业务协议 header/ack
- 自己管理 connection/stream user_data

同时它又没有 HTTP/3 的复杂语义干扰。

所以非常适合拿来理解 xquic 的 transport 层接口。

---

## 15. transport API 最容易误解的几个点

### 15.1 xquic 不帮你开 socket

xquic 不是“传进地址它自己连网络”的黑盒。

应用必须自己：

- 创建 fd
- 收包
- 发包

### 15.2 `xqc_stream_send()` 不保证一次发完

这个接口是“尽力发送”。

你必须自己维护：

- buffer
- 偏移
- fin

### 15.3 `stream_read_notify` 不是已经把完整消息给你了

它只说明：

- 这个 stream 上现在有数据可读

至于是不是完整一条业务消息，应用自己判断。

### 15.4 ALPN 回调和 transport 回调不是一回事

transport callbacks 是通用传输层事件。

app-protocol callbacks 是某个 ALPN 对应的业务流/连接事件。

这也是为什么 `chunk_transfer` 既要传 `transport_cbs`，又要 `register_alpn()`。

### 15.5 关闭回调是资源回收的重要时机

应用不能假设自己某一步逻辑结束就自然没事了。

对于 xquic：

- connection/stream 真正结束时，还是要以 close callback 为准

---

## 16. 如果你继续读源码，推荐关注哪些函数

如果你想继续从 `chunk_transfer` 反推 transport API，建议重点看这些函数：

- `chunk_client_init_engine`
- `chunk_client_init_connection`
- `chunk_client_stream_send`
- `chunk_client_stream_read_notify`
- `chunk_server_accept`
- `chunk_server_conn_create_notify`
- `chunk_server_stream_create_notify`
- `chunk_server_stream_read_notify`

理解了这几处，你对 xquic transport API 的核心用法就基本掌握了。

---

## 17. 一句话总结

xquic transport API 的本质是：

- 应用自己掌控网络和事件循环
- xquic 负责 QUIC 协议状态机
- 双方通过 engine / connection / stream / callback 这套接口协作

而 `chunk_transfer` 就是一份很典型的“自己定义 ALPN 和 stream 协议，然后直接基于 QUIC transport API 跑起来”的示例。


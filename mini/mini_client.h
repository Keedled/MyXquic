#ifndef XQC_MINI_CLIENT_H
#define XQC_MINI_CLIENT_H

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <xquic/xquic_typedef.h>

#ifdef XQC_SYS_WINDOWS
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"event.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Bcrypt.lib")
#include "../tests/getopt.h"
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netdb.h>
#endif


#include "../tests/platform.h"
#include "common.h"
#include "mini_client_cb.h"


#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_PORT 8443
#define DEFAULT_HOST "test.xquic.com"

#define SESSION_TICKET_BUF_MAX_SIZE 8192
#define TRANSPORT_PARAMS_MAX_SIZE 8192
#define TOKEN_MAX_SIZE 8192
#define MAX_PATH_CNT 2
#define XQC_PACKET_BUF_LEN 1500

#define SESSION_TICKET_FILE         "session_ticket"
#define TRANSPORT_PARAMS_FILE       "transport_params"
#define TOKEN_FILE                  "token"

#define LOG_PATH "clog.log"
#define KEY_PATH "ckeys.log"
#define OUT_DIR  "."

/**
 * net config definition
 * net config is those arguments about socket information
 * all configuration on net should be put under this section
 */

typedef struct xqc_mini_cli_net_config_s {
    int                 conn_timeout;
    /*
    int conn_timeout; —— 熔断器（连接超时时间）
    含义： 设定一个“最长等待时间”（单位通常是秒）。
    作用： 防止程序死等。
        如果客户端尝试连接服务器，或者在传输过程中，超过这个时间没有任何动静，程序就会自动退出，而不是一直卡在那里。
    */
    xqc_usec_t          last_socket_time;
    /*
    xqc_usec_t last_socket_time; —— 心跳监测仪（最后活动时间）
    含义： 记录上一次 socket 发生读写操作的 时间戳（微秒级）。
    作用： 用来判断连接是否“还活着”或者“空闲了多久”。
    */
    // /* server addr info */
    // struct sockaddr    *addr;
    // socklen_t           addr_len;
    // char                server_addr[64];
    // short               server_port;
} xqc_mini_cli_net_config_t;

/**
 * quic config definition
 * quic config is those arguments required by quic features, including connection settings, ssl configs, etc.
 * all configuration on quic should be put under this section
 */

typedef struct xqc_mini_cli_quic_config_s {
    /* cipher config */
    char        ciphers[CIPHER_SUIT_LEN];
    char        groups[TLS_GROUPS_LEN];

    /* connection ssl config */
    char        session_ticket[SESSION_TICKET_BUF_MAX_SIZE];
    int         session_ticket_len;
    char        transport_parameter[TRANSPORT_PARAMS_MAX_SIZE];
    int         transport_parameter_len;

    char        token[TOKEN_MAX_SIZE];
    int         token_len;
    
    int         no_encryption;

    /* multipath */
    int         multipath;     // mp option, 0: disable, 1: enable
    char        mp_sched[32];  // mp scheduler, minrtt/backup

    /* congestion control */
    CC_TYPE     cc;             // cc algrithm, bbr/cubic
} xqc_mini_cli_quic_config_t;

/**
 * the environment config definition
 * environment config is those arguments about IO inputs and outputs
 * all configuration on environment should be put under this section
 */

typedef struct xqc_mini_cli_env_config_s {
    /* log config */
    char log_path[PATH_LEN];

    /* tls certificates */
    char private_key_file[PATH_LEN];
    char cert_file[PATH_LEN];

    /* key export */
    char key_out_path[PATH_LEN];

    /* output file */
    char out_file_dir[PATH_LEN];
} xqc_mini_cli_env_config_t;


/**
 * the request config definition
 * request config is those arguments about request information
 * all configuration on request should be put under this section
 */
typedef struct xqc_mini_cli_req_config_s {
    char            path[RESOURCE_LEN];         /* request path */
    char            scheme[8];                  /* request scheme, http/https */
    REQUEST_METHOD  method;
    char            host[256];                  /* request host */
    // char            auth[AUTHORITY_LEN];
    char            url[URL_LEN];               /* original url */
} xqc_mini_cli_req_config_t;


typedef struct xqc_mini_cli_args_s {
    /* network args */
    xqc_mini_cli_net_config_t   net_cfg;

    /* xquic args */
    xqc_mini_cli_quic_config_t  quic_cfg;

    /* environment args */
    xqc_mini_cli_env_config_t   env_cfg;

    /* request args */
    xqc_mini_cli_req_config_t   req_cfg;
} xqc_mini_cli_args_t;

/*
struct event_base *eb; —— 核心驱动器（心脏）
类型： libevent 库的核心结构体指针。
作用： 它是 事件循环（Event Loop） 的底座。
    你的程序是单线程的，如何同时处理网络包、定时器和用户输入？全靠它。
    所有的 socket 读写事件（ev_socket）和定时器事件（ev_engine）都必须注册到这个 eb 上。
    main 函数最后调用的 event_base_dispatch(ctx->eb) 就是让这颗心脏开始跳动。

xqc_mini_cli_args_t *args; —— 配置清单（蓝图）
类型： 自定义的参数结构体指针（在代码其它地方定义）。
作用： 存储所有的配置信息。
    包括：目标 IP、端口、URL 路径、加密套件配置、拥塞控制算法选择、日志文件路径等。
    为什么要放在这里？ 因为 XQUIC 的回调函数（比如 xqc_mini_cli_init_conn_settings）需要读取这些配置来初始化连接。通过 ctx->args 就能随时随地获取配置。

xqc_engine_t *engine; —— XQUIC 引擎（大脑）
类型： XQUIC 库的核心句柄。
作用： 这是 XQUIC 协议栈的 实体对象。
    它负责管理所有的连接（Connection）、流（Stream）、加密上下文（SSL）和拥塞控制状态。
    关键操作： 当网卡收到数据时，你调用 xqc_engine_packet_process(ctx->engine, ...) 就是把数据喂给这个大脑去处理。

struct event *ev_engine; —— 引擎定时器（闹钟）
类型： libevent 的事件对象指针。
作用： 这是专门给 XQUIC 引擎用的 定时器事件。
    场景： QUIC 协议非常依赖时间（比如：发包后 200ms 没收到 ACK 就要重传）。XQUIC 引擎本身不会自动醒来，它会通过回调函数告诉你：“请在 200ms 后叫醒我”。
    实现： 你的代码会把这个请求转换成 ev_engine 的超时设置。当时间到了，libevent 触发这个事件，调用 xqc_engine_main_logic，引擎醒来处理重传。
    注意： 它不是用来监控网卡的（监控网卡的是 user_conn 里的 ev_socket），它是用来做内部调度的。

int log_fd; —— 日志文件描述符（日记本）
类型： 整数（Linux 文件句柄）。
作用： 指向 通用日志文件（如 client.log）。
    当 XQUIC 内部发生错误或状态变化时，日志回调函数会把字符串写入这个 fd。
    如果不保存这个 fd，每次写日志都要 open 和 close 文件，性能会极差。

int keylog_fd; —— 密钥日志文件描述符（解密钥匙）
类型： 整数（Linux 文件句柄）。
作用： 指向 SSL Keylog 文件（如 ssl_key.log）。
    为什么需要它？ QUIC 是强制加密的（TLS 1.3）。如果你用 Wireshark 抓包，看到的全是乱码。
    XQUIC 会通过 keylog_cb 回调把本次连接协商出来的 Session Secret（会话密钥） 写入这个文件。
    你在 Wireshark 里导入这个文件，就能解密看到明文的 HTTP/3 请求了。

    */
typedef struct xqc_mini_cli_ctx_s {
    struct event_base   *eb;

    xqc_mini_cli_args_t *args;      // server arguments for current context

    xqc_engine_t        *engine;    // xquic engine for current context
    struct event        *ev_engine;

    int                 log_fd;
    int                 keylog_fd;
} xqc_mini_cli_ctx_t;


typedef struct xqc_mini_cli_user_conn_s {
    xqc_cid_t               cid;    //含义： Connection ID（连接 ID）。作用： 这是 QUIC 世界里的“身份证号”。
    xqc_h3_conn_t          *h3_conn;//含义： HTTP/3 连接句柄。作用： 这是通往应用层（HTTP 层）的桥梁。

    xqc_mini_cli_ctx_t     *ctx;    //含义： 指向全局上下文的指针。
                                    //场景： 当这个连接的回调函数被触发时（比如收到数据），它手里只有 user_conn 结构体。
                                    //      如果它需要记日志（需要 log_fd）或者需要查配置（需要 args），它就可以通过 user_conn->ctx 找到那个全局的“指挥部”。
    /* ipv4 server */
    int                     fd;     //含义： Linux 文件描述符（Socket File Descriptor）。
                                    //作用： 真正用来发包的“网线插口”。sendto(fd, ...) 就靠它。
    int                     get_local_addr;
                                    //含义： 一个标志位（Flag）。
                                    //作用： 记录“我有没有调用过 getsockname 获取本地 IP？”
                                    //优化： 只需要获取一次本地 IP，之后存起来就行，避免重复系统调用。
    struct sockaddr        *local_addr;
    socklen_t               local_addrlen;
    struct sockaddr        *peer_addr;
    socklen_t               peer_addrlen;
    //含义： 本地地址（我方 IP:端口）和 对端地址（服务器 IP:端口）。
    //作用：
    //  peer_addr: 发包的时候告诉内核“发给谁”。
    //  local_addr: 某些协议逻辑需要校验“我是谁”。
    
    struct event            *ev_socket;
    //含义： Socket 读写事件。
    //作用： “看门大爷”。
    //工作模式： 它盯着上面的 fd。一旦网卡收到数据，它就触发 xqc_mini_cli_socket_event_callback，喊醒程序来收包。
    struct event            *ev_timeout;
    //含义： 连接级超时定时器。
    //作用： “倒计时炸弹”。
    //工作模式： 就是之前 args 里那个 9 秒超时。如果 9 秒内没连上或断了，它会触发超时回调，强制断开连接，防止程序挂死。

} xqc_mini_cli_user_conn_t;

typedef struct xqc_mini_cli_user_stream_s {
    xqc_mini_cli_user_conn_t   *user_conn;

    /* save file */
    // char                        file_name[RESOURCE_LEN];
    // FILE                        *recv_body_fp;

    /* stat for IO */
    size_t                      send_body_len;
    size_t                      recv_body_len;
    int                         recv_fin;
    xqc_msec_t                  start_time;


    /* h3 request content */
    xqc_h3_request_t           *h3_request;

    xqc_http_headers_t          h3_hdrs;
    uint8_t                     hdr_sent;

    char                       *send_body_buff;
    int                         send_body_size;
    size_t                      send_offset;

} xqc_mini_cli_user_stream_t;



void xqc_mini_cli_init_engine_ssl_config(xqc_engine_ssl_config_t *ssl_cfg, xqc_mini_cli_args_t *args);

void xqc_mini_cli_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *tcb, xqc_mini_cli_args_t *args);

int xqc_mini_cli_init_xquic_engine(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args);

void xqc_mini_cli_convert_text_to_sockaddr(int type,
    const char *addr_text, unsigned int port,
    struct sockaddr **saddr, socklen_t *saddr_len);

void xqc_mini_cli_init_args(xqc_mini_cli_args_t *args);

int xqc_mini_cli_init_ctx(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args);

int xqc_mini_cli_init_env(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args);

xqc_scheduler_callback_t xqc_mini_cli_get_sched_cb(xqc_mini_cli_args_t *args);
xqc_cong_ctrl_callback_t xqc_mini_cli_get_cc_cb(xqc_mini_cli_args_t *args);
void xqc_mini_cli_init_conn_settings(xqc_conn_settings_t *settings, xqc_mini_cli_args_t *args);

int xqc_mini_cli_init_alpn_ctx(xqc_mini_cli_ctx_t *ctx);
int xqc_mini_cli_init_engine_ctx(xqc_mini_cli_ctx_t *ctx);

void xqc_mini_cli_free_ctx(xqc_mini_cli_ctx_t *ctx);

void xqc_mini_cli_init_0rtt(xqc_mini_cli_args_t *args);

void xqc_mini_cli_init_conn_ssl_config(xqc_conn_ssl_config_t *conn_ssl_config, xqc_mini_cli_args_t *args);

int xqc_mini_cli_format_h3_req(xqc_http_header_t *headers, xqc_mini_cli_req_config_t* req_cfg);

int xqc_mini_cli_request_send(xqc_h3_request_t *h3_request, xqc_mini_cli_user_stream_t *user_stream);

int xqc_mini_cli_send_h3_req(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_user_stream_t *user_stream);

int xqc_mini_cli_init_socket(xqc_mini_cli_user_conn_t *user_conn);

void xqc_mini_cli_socket_write_handler(xqc_mini_cli_user_conn_t *user_conn, int fd);

void xqc_mini_cli_socket_read_handler(xqc_mini_cli_user_conn_t *user_conn, int fd);

static void xqc_mini_cli_socket_event_callback(int fd, short what, void *arg);
int xqc_mini_cli_init_xquic_connection(xqc_mini_cli_user_conn_t *user_conn);

int xqc_mini_cli_main_process(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_ctx_t *ctx);
xqc_mini_cli_user_conn_t *xqc_mini_cli_user_conn_create(xqc_mini_cli_ctx_t *ctx);

void xqc_mini_cli_free_user_conn(xqc_mini_cli_user_conn_t *user_conn);
void xqc_mini_cli_on_connection_finish(xqc_mini_cli_user_conn_t *user_conn);
#endif
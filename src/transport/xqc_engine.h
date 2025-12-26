
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_ENGINE_H_INCLUDED_
#define _XQC_ENGINE_H_INCLUDED_


#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/tls/xqc_tls.h"
#include "src/common/xqc_list.h"
#include "src/transport/xqc_defs.h"
#define XQC_RESET_CNT_ARRAY_LEN 16384


typedef enum {
    XQC_ENG_FLAG_RUNNING    = 1 << 0,
    XQC_ENG_FLAG_NO_DESTROY = 1 << 1,
} xqc_engine_flag_t;


typedef struct xqc_alpn_registration_s {
    xqc_list_head_t             head;

    /* content of application layer protocol */
    char                       *alpn;

    /* length of alpn string */
    size_t                      alpn_len;

    /* Application-Layer-Protocol callback functions */
    xqc_app_proto_callbacks_t   ap_cbs;

    void                       *alp_ctx;

} xqc_alpn_registration_t;


typedef struct xqc_engine_s {
    /* for engine itself */
    xqc_engine_type_t               eng_type;//引擎类型。通常用于区分当前引擎是 Client（客户端）还是 Server（服务端）。
    xqc_engine_callback_t           eng_callback;//引擎级别的回调函数。用于处理一些全局性的事件（如日志输出或特定的引擎初始化事件）。
    xqc_engine_flag_t               eng_flag;//引擎标志位。用于存储引擎的状态或配置开关。

    /* for connections */
    xqc_config_t                   *config;//指向全局配置的指针。包含超时时间、拥塞控制算法选择等配置。
    xqc_str_hash_table_t           *conns_hash;             /* scid 基于 SCID (Source Connection ID) 的哈希表。这是处理入站数据包的主要查找方式，通过包头中的 ID 找到对应的连接对象。*/
    xqc_str_hash_table_t           *conns_hash_dcid;        /* For reset packet 基于 DCID (Destination Connection ID) 的哈希表。通常用于处理 Reset 包等特殊情况。*/
    xqc_str_hash_table_t           *conns_hash_sr_token;    /* For stateless reset 基于 Stateless Reset Token 的哈希表。用于识别收到的无状态重置包，快速断开连接。*/
    xqc_pq_t                       *conns_active_pq;        /* In process 活跃连接队列。存放当前有数据需要处理（发送/接收/处理ACK）的连接。引擎的 process 循环会优先处理这里的连接。*/
    xqc_pq_t                       *conns_wait_wakeup_pq;   /* Need wakeup after next tick time 等待唤醒队列。存放处于等待状态（如等待重传超时、Pacing 间隔）的连接。按时间排序，时间到了就会被移入活跃队列。*/
    uint8_t                         reset_sent_cnt[XQC_RESET_CNT_ARRAY_LEN]; /* remote addr hash */
    xqc_usec_t                      reset_sent_cnt_cleared;
                /*reset_sent_cnt / reset_sent_cnt_cleared: 用于 DDoS 防护。记录发送 Stateless Reset 包的数量和清零时间，防止服务端被利用进行反射攻击。*/

    /* tls context TLS 上下文。QUIC 强制使用 TLS 1.3，这里封装了 SSL 库（如 BoringSSL 或 BabaSSL）的上下文句柄。*/
    xqc_tls_ctx_t                  *tls_ctx;

    xqc_log_t                      *log;//日志句柄。整个引擎的日志输出通道。
    xqc_random_generator_t         *rand_generator;//随机数生成器。用于生成 Connection ID、Packet Number 的掩码、加密 Nonce 等。

    /* for user */
    void                           *user_data;//用户数据指针。这是一个 void*，允许上层应用将自己的上下文绑定到这个引擎上，方便在回调中取回。

    /* callback functions for connection transport events */
    xqc_transport_callbacks_t       transport_cbs;

    /* list of xqc_alpn_registration_t */
    xqc_list_head_t                 alpn_reg_list;//ALPN (Application-Layer Protocol Negotiation) 注册列表。用于协商应用层协议（如 h3 代表 HTTP/3）。

    xqc_conn_settings_t             default_conn_settings;

    char                            scid_buf[XQC_MAX_CID_LEN * 2 + 1];
    char                            dcid_buf[XQC_MAX_CID_LEN * 2 + 1];
    char                            sr_token_buf[XQC_STATELESS_RESET_TOKENLEN * 2 + 1];
    char                            conn_flag_str_buf[1024];
    char                            frame_type_buf[128];
    char                            local_addr_str[INET6_ADDRSTRLEN];
    char                            peer_addr_str[INET6_ADDRSTRLEN];

    void                           *priv_ctx;
    unsigned char                   token_secret_list[XQC_TOKEN_MAX_KEY_VERSION][XQC_TOKEN_SECRET_LEN];
    uint8_t                         cur_ts_index;
    /*token_secret_list / cur_ts_index: 用于生成和验证 Address Token（地址令牌）。服务端在握手阶段通过 Token 验证客户端地址的所有权，防止地址欺骗和放大攻击。*/
} xqc_engine_t;



xqc_usec_t xqc_engine_wakeup_after(xqc_engine_t *engine);


/**
 * Create engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_config_t *xqc_engine_config_create(xqc_engine_type_t engine_type);

void xqc_engine_config_destroy(xqc_config_t *config);


/**
 * @return > 0 : user should call xqc_engine_main_logic after N ms
 */
xqc_usec_t xqc_engine_wakeup_after(xqc_engine_t *engine);

void xqc_engine_wakeup_once(xqc_engine_t *engine);

xqc_connection_t *xqc_engine_conns_hash_find(xqc_engine_t *engine, const xqc_cid_t *cid, char type);

void xqc_engine_process_conn(xqc_connection_t *conn, xqc_usec_t now);

void xqc_engine_main_logic_internal(xqc_engine_t *engine);

void xqc_engine_conn_logic(xqc_engine_t *engine, xqc_connection_t *conn);

xqc_int_t xqc_engine_add_wakeup_queue(xqc_engine_t *engine, xqc_connection_t *conn);

xqc_int_t xqc_engine_remove_wakeup_queue(xqc_engine_t *engine, xqc_connection_t *conn);

xqc_int_t xqc_engine_add_active_queue(xqc_engine_t *engine, xqc_connection_t *conn);

xqc_int_t xqc_engine_remove_active_queue(xqc_engine_t *engine, xqc_connection_t *conn);

xqc_int_t xqc_engine_get_alpn_callbacks(xqc_engine_t *engine, const char *alpn,
    size_t alpn_len, xqc_app_proto_callbacks_t *cbs);

xqc_bool_t xqc_engine_is_sendmmsg_on(xqc_engine_t *engine, xqc_connection_t *conn);

#endif

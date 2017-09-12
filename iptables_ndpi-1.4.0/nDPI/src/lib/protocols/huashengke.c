#include "ndpi_main.h"

#ifdef NDPI_PROTOCOL_HUASHENGKE

//#define LOCAL_DEBUG

#ifdef __KERNEL__
# define printf printk
#endif

#undef _D
#ifdef LOCAL_DEBUG
# define _D(fmt, ...)    do { printf("%s: %d: ", __FILE__, __LINE__); printf(fmt, ## __VA_ARGS__); } while (0)
#else
# define _D(fmt, ...)    ((void)0)
#endif

#if 0
static char const *status[] = {
    "220",    /* server hello */
    "334",    /* key salt */
    "536",    /* redirect */
    "250",    /* ok, runing */
    "221",    /* bye */
};
static char const *client_cmds[] = {
    "auth router6", "regi a", "cnfm", "stat user", "stat domain", "quit",
};
#endif

/*
 * 花生壳协议 2.0 版本
 */
static int ndpi_search_tcp_2_0(struct ndpi_detection_module_struct *ndpi, struct ndpi_flow_struct *flow)
{
    /* 服务器回应 xxx 十进制3位的状态 字符串信息 \r\n */
    struct ndpi_packet_struct *pkt = &flow->packet;
    _D("Call ndpi_search_tcp_2_0| %d %s.\n", flow->huashengke_stage, pkt->payload);
    switch (flow->huashengke_stage) {
    case 0:
        if (pkt->payload_packet_len > 3 && (0 == strncmp(pkt->payload, "220", 3))) {
            flow->huashengke_stage = 1;
            return 2;
        } else {
            flow->huashengke_stage = 0;
            return 0;
        }
    case 1:
        if (pkt->payload_packet_len > 12 &&  (0 == strncmp(pkt->payload, "auth router6", 12))) {
            flow->huashengke_stage = 2;
            return 2;
        } else {
            flow->huashengke_stage = 0;
            return 0;
        }
    case 2:
        if (pkt->payload_packet_len > 3 && (0 == strncmp(pkt->payload, "334", 3))) {
            flow->huashengke_stage = 3;
            return 2;
        } else {
            flow->huashengke_stage = 0;
            return 0;
        }
        /* huashengke_stage > 2 */
    default:
        if ((pkt->payload_packet_len == 50) || (pkt->payload_packet_len > 3 && (!strncmp(pkt->payload, "250", 3)
                        || !strncmp(pkt->payload, "221", 3)
                        || !strncmp(pkt->payload, "stat user", 9)
                        || !strncmp(pkt->payload, "stat domain", 11)
                        || !strncmp(pkt->payload, "quit", 4)))) {
            NDPI_LOG(NDPI_PROTOCOL_HUASHENGKE, ndpi, NDPI_LOG_DEBUG, "found HuaShengKe 2.0 .\n");
            ndpi_int_add_connection(ndpi, flow, NDPI_PROTOCOL_HUASHENGKE, NDPI_REAL_PROTOCOL);
            return 1;
        } else {
            flow->huashengke_stage = 0;
            return 0;
        }
    }

    return 0;
}
static int ndpi_search_tcp_3(struct ndpi_detection_module_struct *ndpi, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *pkt = &flow->packet;
    u_int8_t const *data = pkt->payload;
    int pktlen = pkt->payload_packet_len;
    static char const post[] = "POST multiplex PHREMT_HTTPS/1.0";
    _D("Call ndpi_search_tcp_3| %s.\n", data);
    /* 心跳启始包 */
    if ((pktlen >= NDPI_STATICSTRING_LEN(post)) && (0 == strncmp(post, data, NDPI_STATICSTRING_LEN(post)))) {
        NDPI_LOG(NDPI_PROTOCOL_HUASHENGKE, ndpi, NDPI_LOG_DEBUG, "found HuaShengKe 3.\n");
        ndpi_int_add_connection(ndpi, flow, NDPI_PROTOCOL_HUASHENGKE, NDPI_REAL_PROTOCOL);
        return 1;
    }
    /* TODO 对于 TLS 加密的 tcp 流量，在 iptables 规则里添加 `-p tcp -m string --string "*.oray.net"` */
    /* TODO 加入详细的心跳过滤 */
    return 0;
}

extern void ndpi_search_huashengke(struct ndpi_detection_module_struct *ndpi, struct ndpi_flow_struct *flow)
{
    NDPI_LOG(NDPI_PROTOCOL_HUASHENGKE, ndpi, NDPI_LOG_DEBUG, "Call ndpi_search_huashengke.\n");
    struct ndpi_packet_struct *pkt = &flow->packet;
    int found = 0;
    if (pkt->tcp) {
        found = ndpi_search_tcp_3(ndpi, flow);
        _D("for ndpi_search_tcp_3 found: %d\n", found);
        if (found) return;

        found = ndpi_search_tcp_2_0(ndpi, flow);
        _D("for ndpi_search_tcp_2_0 found: %d\n", found);
        if (!found)
            goto not_found;

        return;
    }

not_found:
    NDPI_LOG(NDPI_PROTOCOL_HUASHENGKE, ndpi, NDPI_LOG_DEBUG, "exclude HuaShengKe.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HUASHENGKE);
}

#endif /* NDPI_PROTOCOL_HUASHENGKE */

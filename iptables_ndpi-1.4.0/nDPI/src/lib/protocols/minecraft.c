#include "ndpi_main.h"

/* Base on TCP */
#ifdef NDPI_PROTOCOL_MINECRAFT  /* game Minecraft */

#define MINECRAFT_PORT  25565

#ifdef __KERNEL__
# define PRINT      printk
#else
# define PRINT      printf
#endif

#ifdef DEBUG
# define _D(...)    PRINT(__VA_ARGS__)
#else
# define _D(...)    ((void)0)
#endif

/**
 * Parse VarInt
 */
static int parse_varint(u_int8_t const *data, u_int16_t *len)
{
    int num = 0;
    int i;
    for (i = 0; i < 5 && i < *len; i++) {
        u_int8_t r = data[i];
        num |= (r&0x7f)<<(7*i);
        if (!(r&0x80)) { /* 0x80 == 0b1000,0000 */
            *len = i+1;
            return num;
        }
    }
    return -1;
}

/**
 * Judge `pkt' is or not minecraft packet.
 * more details <http://wiki.vg/Protocol#Handshake>
 *
 * pkt: point to data
 * len: the length of `pkt'
 * @return: !0: yes
 *           0: no
 */
static int is_minecraft(u_int8_t const *pkt, int len, char *compressed)
{
    u_int32_t orglen = len;
    u_int16_t nbyte = len;
    _D("%02x%02x%02x\n", pkt[0], pkt[1], pkt[2]);
    int length = parse_varint(pkt, &nbyte);
    if (length < 0) return 0;
    pkt += nbyte;
    len -= nbyte;
    if (len <= 0) return 0;

    nbyte = len;
    int pktid = parse_varint(pkt, &nbyte);
    int pktidlen = nbyte;
    if (pktid < 0) return 0;
    pkt += nbyte;
    len -= nbyte;
    if (len <= 0) return 0;

    if (!*compressed) {
        _D("%s: %d: UnCompress!\n", __FILE__, __LINE__);
        _D("%s: %d: orglen(%d) = length(%d)+pktidlen(%d)?\n",
                __FILE__, __LINE__, orglen, length, pktidlen);
        _D("%s: %d: pktid: %d compressed: %d\n", __FILE__, __LINE__, pktid, *compressed);
        if (orglen != length+pktidlen) return 0;

        /* parse the `set compression` packet. */
        if (0x03 == pktid) *compressed = 1;

        /* ok, this is valid minecraft packet. */
        return 1;
    } else {
        _D("%s: %d: Compressed!\n", __FILE__, __LINE__);
        _D("%s: %d: length(%d) = pktidlen(%d)+len(%d)\n",
                __FILE__, __LINE__, length, pktidlen, len);
        return ((0 == pktid) && (length == pktidlen+len));
    }
}

extern void ndpi_search_minecraft(struct ndpi_detection_module_struct *ndpi, struct ndpi_flow_struct *flow)
{
    _D("Call ndpi_search_minecraft\n");
#define LOG(...)    NDPI_LOG(NDPI_PROTOCOL_MINECRAFT, ndpi, NDPI_LOG_DEBUG, __VA_ARGS__)
    struct ndpi_packet_struct *packet = &flow->packet;
    if (!packet->tcp) goto not_found;

    u_int8_t const *data = packet->payload;
    int len = packet->payload_packet_len;
    /* IMPORTANT flow->minecraft_compressed 必须在 flow 初始化时被赋值为0 */
    char compressed = flow->minecraft_compressed;

    /* 初始的 minecraft_compressed 是没有压缩的，那么在初始化这个流的时候需要赋值0 */
    if (is_minecraft(data, len, &compressed)) {
        flow->minecraft_compressed = compressed;
        goto found;
    } else
        goto not_found;

found:
    /* found */
    ndpi_int_add_connection(ndpi, flow, NDPI_PROTOCOL_MINECRAFT, NDPI_REAL_PROTOCOL);
    LOG("found Minecraft.\n");
    return;

not_found:
    /* not found */
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MINECRAFT);
    LOG("exclude Minecraft.\n");
    return;
#undef LOG
}

#endif

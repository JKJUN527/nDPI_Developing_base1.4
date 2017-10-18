#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_TFTP

static void ndpi_int_tftp_add_connection(struct ndpi_detection_module_struct
        *ndpi_struct, struct ndpi_flow_struct *flow)
{
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TFTP, NDPI_REAL_PROTOCOL);
}

static void tftp_add_server_port(struct ndpi_detection_module_struct *ndpi,
        struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    /* server ip, server port, client ip, client port, udp */
    int ipsize = sizeof(u_int32_t);
    u_int8_t key_buff[2*sizeof(u_int32_t) + 2*2 +1] = {0};  /* set zero */
    int offset = ipsize+2;
    /* I'm sorry for that it cant support ipv4 now */
    if (!packet->iph) return;
    /* This packet is from CLIENT to SERVER */
    memcpy(key_buff+offset, &packet->iph->saddr, ipsize);   /* client ip */
    offset += ipsize;
    memcpy(key_buff+offset, &packet->udp->source, 2);       /* client port */
    offset += 2;
    key_buff[offset] = IPPROTO_UDP;
    offset += 1;

    ndpi_hash_add(ndpi->meta2protocol, key_buff, offset, NDPI_PROTOCOL_TFTP);
}

/**
 * detect tftp data from hash table
 * @return: 0: not found
 *         !0: found
 */
static int tftp_detected_data(struct ndpi_detection_module_struct *ndpi,
        struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    /* server ip, server port, client ip, client port, udp */
    int ipsize = sizeof(u_int32_t);
    u_int8_t key_buff[2*sizeof(u_int32_t) + 2*2 +1] = {0};  /* set zero */
    int offset = ipsize+2;
    int pro;
    /* TODO tftp: support ipv6 */
    /* I'm sorry for that it cant support ipv4 now */
    if (!packet->iph) return 0;
    /* This packet is from SERVER to CLIENT */
    memcpy(key_buff+offset, &packet->iph->daddr, ipsize);   /* client ip */
    offset += ipsize;
    memcpy(key_buff+offset, &packet->udp->dest, 2);         /* client port */
    offset += 2;
    key_buff[offset] = IPPROTO_UDP;
    offset += 1;

    pro = ndpi_hash_remove(ndpi->meta2protocol, key_buff, offset);

    return (-1 != pro);
}

void ndpi_search_tftp(struct ndpi_detection_module_struct *ndpi_struct,
        struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;

    const char *ascii = "netascii";
    const char *binary = "octet";
    const char *payload = (const char *)packet->payload;
    int paylen = packet->payload_packet_len;
    const char *end = payload+paylen-1;

    NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG, "search TFTP.\n");
    /* It must be udp packet */
    if (!packet->udp) return;

    /* search tftp data packets */
    if (tftp_detected_data(ndpi_struct, flow)) {
        NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG, "found TFTP data via server-port.\n");
        ndpi_int_tftp_add_connection(ndpi_struct, flow);
        return;
    }


    if (0 == payload[0] && (1 == payload[1] || 2 == payload[1])) {
        const char *method = memchr(payload+2, '\0', paylen-2);
        if (!method) goto exclude_tftp;

        method++;
        if ((end-method >= 8 && !strncmp(ascii, method, 8)) || (end-method >= 5 && !strncmp(binary, method, 5))) {
            NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG, "found TFTP get command.\n");
            ndpi_int_tftp_add_connection(ndpi_struct, flow);
            tftp_add_server_port(ndpi_struct, flow);
        }
        return;
    }

    if (packet->payload_packet_len > 3 && flow->l4.udp.tftp_stage == 0
            && ntohl(get_u_int32_t(packet->payload, 0)) == 0x00030001) {
        NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG, "maybe TFTP. need next packet.\n");
        flow->l4.udp.tftp_stage = 1;
        return;
    }
    if (packet->payload_packet_len > 3 && (flow->l4.udp.tftp_stage == 1)
            && ntohl(get_u_int32_t(packet->payload, 0)) == 0x00040001) {

        NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG, "found TFTP via ack packet.\n");
        ndpi_int_tftp_add_connection(ndpi_struct, flow);
        return;
    }
    if (packet->payload_packet_len > 1
            && ((packet->payload[0] == 0 && packet->payload[packet->payload_packet_len - 1] == 0)
                || (packet->payload_packet_len == 4 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x00040000))) {
        NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG, "skip initial packet.\n");
        return;
    }

exclude_tftp:
    NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG, "exclude TFTP.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TFTP);
}
#endif

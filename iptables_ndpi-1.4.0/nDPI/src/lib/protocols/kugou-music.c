#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_KUGOUMUSIC

// ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_KUGOUMUSIC, NDPI_REAL_PROTOCOL);
/**
 * search KuGouMusic over udp protocol
 */
static void search_udp(struct ndpi_detection_module_struct *ndpi, struct ndpi_flow_struct *flow)
{
    NDPI_LOG(NDPI_PROTOCOL_KUGOUMUSIC, ndpi, NDPI_LOG_DEBUG, "In ndpi_search_kugou_music, called search_udp.\n");
}

extern void ndpi_search_kugou_music(struct ndpi_detection_module_struct *ndpi, struct ndpi_flow_struct *flow)
{
    NDPI_LOG(NDPI_PROTOCOL_KUGOUMUSIC, ndpi, NDPI_LOG_DEBUG, "Called ndpi_search_kugou_music.\n");
    if (flow->kugou_music_type != 0 || flow->kugou_music_type != 2)
        return;

    if (flow->packet.udp) {
        flow->kugou_music_type = 2;
        search_udp(ndpi, flow);
    }
}

#endif /* NDPI_PROTOCOL_KUGOUMUSIC */

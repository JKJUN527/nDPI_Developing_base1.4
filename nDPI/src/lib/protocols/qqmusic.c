#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_QQMUSIC

#if 0
static void ndpi_int_qqmusic_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
        struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QQMUSIC, NDPI_REAL_PROTOCOL);
}
#endif

extern void ndpi_search_qqmusic(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
}

#endif

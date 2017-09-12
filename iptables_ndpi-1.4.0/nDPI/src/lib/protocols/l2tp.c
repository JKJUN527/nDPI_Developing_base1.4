#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_L2TP
void ndpi_search_l2tp(struct ndpi_detection_module_struct *ndpi_struct,struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

    if((packet->payload_packet_len>= 6)
		&& ((packet->payload[1]&0xff) == 0x02)
		&& ((packet->payload[0]&0x34) == 0)
		&& (packet->udp != NULL && (packet->udp->dest==1701 ||packet->udp->source==1701))//默认端口为1701，jkjun添加
	){
    NDPI_LOG(NDPI_PROTOCOL_RTP, ndpi_struct, NDPI_LOG_DEBUG, "Found l2tp.\n");
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_L2TP, NDPI_REAL_PROTOCOL);	
    } else {
		NDPI_LOG(NDPI_PROTOCOL_RTP, ndpi_struct, NDPI_LOG_DEBUG, "exclude l2tp.\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_L2TP);
	  }
}

#endif

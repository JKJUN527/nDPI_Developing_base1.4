
#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_GAME_QQWUXIA

/*
 * 腾讯游戏
 *
 *
 *
 * */

static void ndpi_int_qqwuxia_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_QQWUXIA, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_qqwuxia_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if(packet->payload_packet_len >=16
		&&get_u_int16_t(packet->payload, 0) == htons(0x550e)
		&&get_u_int16_t(packet->payload,4) == htonl(0x0000)
		&&get_u_int16_t(packet->payload, 8) == htons(0x0000)
	 ){
		NDPI_LOG(NDPI_PROTOCOL_GAME_QQWUXIA, ndpi_struct, NDPI_LOG_DEBUG,"search qqwuxia tcp");
		ndpi_int_qqwuxia_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
  	NDPI_LOG(NDPI_PROTOCOL_GAME_QQWUXIA, ndpi_struct, NDPI_LOG_DEBUG, "exclude qqwuxia tcp.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_QQWUXIA);
}

void ndpi_search_qqwuxia(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_GAME_QQWUXIA, ndpi_struct, NDPI_LOG_DEBUG,"search qqwuxia \n");
		ndpi_search_qqwuxia_tcp(ndpi_struct, flow);
	}
}

#endif


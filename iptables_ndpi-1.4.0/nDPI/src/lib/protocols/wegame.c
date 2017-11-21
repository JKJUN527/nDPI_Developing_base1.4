
#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_GAME_WEGAME

/*
 * 腾讯游戏管理客户端
 *
 *
 *
 * */

static void ndpi_int_wegame_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_WEGAME, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_wegame_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if(packet->payload_packet_len >=16
		&&get_u_int16_t(packet->payload, 0) == htons(0x550e)
		&&get_u_int16_t(packet->payload, 2) == htons(0x0300)
		&&packet->payload[7]==packet->payload_packet_len
		&&get_u_int16_t(packet->payload,4) == htonl(0x0000)
		&&get_u_int16_t(packet->payload, 8) == htons(0x0000)
	 ){
		NDPI_LOG(NDPI_PROTOCOL_GAME_WEGAME, ndpi_struct, NDPI_LOG_DEBUG,"search wegame tcp");
		ndpi_int_wegame_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
  	NDPI_LOG(NDPI_PROTOCOL_GAME_WEGAME, ndpi_struct, NDPI_LOG_DEBUG, "exclude WEGAME tcp.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_WEGAME);
}

extern void ndpi_search_wegame(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_GAME_WEGAME, ndpi_struct, NDPI_LOG_DEBUG,"search WEGAME \n");
		ndpi_search_wegame_tcp(ndpi_struct, flow);
	}
}

#endif


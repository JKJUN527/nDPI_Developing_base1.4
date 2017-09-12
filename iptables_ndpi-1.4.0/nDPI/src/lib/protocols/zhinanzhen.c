/*
 * zhinanzhen.c
 * BY--JK
 */
/*

*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static void ndpi_int_zhinanzhen_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ZHINANZHEN, NDPI_REAL_PROTOCOL);
}
void ndpi_search_zhinanzhen_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	flow->zhinanzhen_stage++;
	if(flow->dazhihui_stage >=6){
		NDPI_LOG(NDPI_PROTOCOL_ZHINANZHEN, ndpi_struct, NDPI_LOG_DEBUG, "exclude zhinanzhen.zhinanzhen_stage :%d\n",flow->zhinanzhen_stage);
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ZHINANZHEN);
	}
	if(packet->payload_packet_len >= (16)
	&&packet->payload[0]==0x74
	&&packet->payload[1]==0x00
	&&packet->payload[16]==0x30
	&&packet->payload[17]==0x1b
		){
		NDPI_LOG(NDPI_PROTOCOL_ZHINANZHEN, ndpi_struct, NDPI_LOG_DEBUG,"found zhinanzhen------tcp \n");
		ndpi_int_zhinanzhen_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
		return;	
	}
  if(packet->payload_packet_len >= (64)
  	//&&(get_u_int64_t(packet->payload, 0) == htonl( 0xfdfdfdfd30303030)
  	//|| get_u_int64_t(packet->payload, 8) == htonl( 0x3034383609010700))
  	&&((packet ->payload[0]==0x77||packet ->payload[0]==0x64)&&
  		((packet ->payload[4]==0x00&&packet ->payload[5]==0x00)||
  		(get_u_int64_t(packet->payload, 64) == htonl( 0x0000000000000000))))
  ){			
  		NDPI_LOG(NDPI_PROTOCOL_ZHINANZHEN, ndpi_struct, NDPI_LOG_DEBUG,"found zhinanzhen------tcp \n");
		ndpi_int_zhinanzhen_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
		return;	
	}
}
void ndpi_search_zhinanzhen(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_ZHINANZHEN, ndpi_struct, NDPI_LOG_DEBUG,"search zhinanzhen tcp\n");
		ndpi_search_zhinanzhen_tcp(ndpi_struct, flow);
	}
	
}


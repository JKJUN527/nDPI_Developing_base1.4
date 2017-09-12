/*
 * tonghuashun.c
 * BY--JK
 */
/*
00000000  fd fd fd fd 30 30 30 30  30 34 38 63 09 01 0a 00 ....0000 048c....
*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static void ndpi_int_tonghuashun_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TONGHUASHUN, NDPI_REAL_PROTOCOL);
}
void ndpi_search_tonghuashun_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  if((packet->payload_packet_len >= (16)
  	//&&(get_u_int64_t(packet->payload, 0) == htonl( 0xfdfdfdfd30303030)
  	//|| get_u_int64_t(packet->payload, 8) == htonl( 0x3034383609010700))
  	&&packet ->payload[0]==0xfd
  	&&packet ->payload[1]==0xfd
  	&&packet ->payload[2]==0xfd
  	&&packet ->payload[3]==0xfd
  	&&packet ->payload[4]==0x30
  	&&packet ->payload[5]==0x30
  	&&packet ->payload[6]==0x30
  	&&packet ->payload[7]==0x30
        &&packet ->payload[8]==0x30
	)||(packet->payload_packet_len >=(48)
	&&packet->payload[4*8+5]==70
	&&packet->payload[4*8+6]==61
	&&packet->payload[4*8+7]==67
	&&packet->payload[4*8+8]==65
	&&packet->payload[4*8+9]==69
	&&packet->payload[4*8+10]==64	
	)
  ){			
  		NDPI_LOG(NDPI_PROTOCOL_TONGHUASHUN, ndpi_struct, NDPI_LOG_DEBUG,"found tonghuashun------tcp[0[fd]:%x]tcp[8[30]:%x]tcp[37[70]:%x] \n",packet->payload[0],packet->payload[8],packet->payload[37]);
		ndpi_int_tonghuashun_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
		return;	
	}	
}
void ndpi_search_tonghuashun_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  if(packet->payload_packet_len >= (16)
  	&&packet ->payload[0]==0x31
  	&&packet ->payload[1]==0x5f
  	&&packet ->payload[2]==0x6c
  	&&packet ->payload[3]==0x62
  	&&packet ->payload[4]==0x74
  	&&packet ->payload[5]==0x36
  	&&packet ->payload[6]==0x5f
  	&&packet ->payload[7]==0x30
        &&packet ->payload[8]==0x23
  ){			
  		NDPI_LOG(NDPI_PROTOCOL_TONGHUASHUN, ndpi_struct, NDPI_LOG_DEBUG,"found tonghuashun------udp[0:%x]tcp[8:%x] \n",packet->payload[0],packet->payload[8]);
		ndpi_int_tonghuashun_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
		return;	
	}	
}

void ndpi_search_tonghuashun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_TONGHUASHUN, ndpi_struct, NDPI_LOG_DEBUG,
									"search TONGHUASHUN tcp\n");
		ndpi_search_tonghuashun_tcp(ndpi_struct, flow);
	}
       if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_TONGHUASHUN, ndpi_struct, NDPI_LOG_DEBUG,
									"search TONGHUASHUN udp\n");
		ndpi_search_tonghuashun_udp(ndpi_struct, flow);
	}
	
}

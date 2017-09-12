/*
 * qianlong.c
 * BY-JK
 */
/*
1\
24 03 03 01 00 00 00 b4  00 40 00 00 40 e5 00 00
24 32 00 01 00 00 00 00  00 40 00 00 00 00 01 00
24 32 01 01 00 00 00 05  00 40 00 00 1d 9c 02 00
24 32 01 01 00 00 00 05  00 40 00 00 4c 36 03 00
24 32 01 01 00 00 00 05  00 40 00 00 07 02 04 00
24 32 01 01 00 00 00 05  00 40 00 00 c9 03 30 00
24 32 12 01 00 00 00 3a  00 40 00 00 e0 a0 49 00

2\
24 03 03 01 00 00 00 0c  00 40 00 00 1e d8 00 00
24 32 01 03 00 00 00 64  09 48 00 00 cc 08 02 00
24 32 01 03 00 01 00 fa  09 48 00 00 56 64 02 00
24 32 01 03 00 02 00 86  0b 48 00 00 c0 63 02 00
24 32 01 03 00 00 00 9e  09 48 00 00 29 99 03 00

3\
23 78 00 36 8a 0d 40 00  00 00 00 13 02 00 00 08
23 02 00 00 00 0d 41 01  00 00 00 00 00
23 04 00 00 00 0d 42 02  00 00 00 00 00 00 00
23 05 00 a1 0d 0d 40 00  00 64 00 31 3d 32 30 01
23 30 33 48 ab 0d 42 02  00 20 03 82 5f 00 40 87
23 35 33 e4 74 0d 42 02  00 21 03 eb 6e 0a 80 80
23             0d        00             


*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static void ndpi_int_qianlong_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QIANLONG, NDPI_REAL_PROTOCOL);
}
void ndpi_search_qianlong_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	flow->qianlong_stage++;
	if(flow->qianlong_stage >=4){
		NDPI_LOG(NDPI_PROTOCOL_QIANLONG, ndpi_struct, NDPI_LOG_DEBUG, "exclude qianlong  qianlong_stage:%d\n",flow->qianlong_stage);
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QIANLONG);
	}
  if(packet->payload_packet_len >= (10)){
  	if((packet->payload[0]==0x24
		&&(packet->payload[1]==0x03||packet->payload[1]==0x32)
		&&packet->payload[6]==0x00
		&&(packet->payload[9]==0x40||packet->payload[9]==0x48))
	||(packet->payload[0]==0x23
	  &&packet->payload[5]==0x0d
	  &&packet->payload[8]==0x00)
	){
  		NDPI_LOG(NDPI_PROTOCOL_QIANLONG, ndpi_struct, NDPI_LOG_DEBUG,"found qianlong------tcp[0[24]:%x]tcp[1[03|32]:%x]tcp[9[40|48]:%x] \n",packet->payload[0],packet->payload[1],packet->payload[9]);
		ndpi_int_qianlong_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
		return;	
	}
  }
}
void ndpi_search_qianlong(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_QIANLONG, ndpi_struct, NDPI_LOG_DEBUG,
									"search qianlong tcp\n");
		ndpi_search_qianlong_tcp(ndpi_struct, flow);
	}
	
}


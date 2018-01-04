/*
 * pinganzhengquan.c
 * BY-JK
 */
/*
1\
01 01 48 65 00 01 52 00  52 00 54 24 28 3e 5c a0
01 02 48 69 00 01 02 00  02 00 f4 23
01 03 48 66 00 01 02 00  02 00 f0 23
01 04 48 67 00 01 08 00  08 00 f5 23 00 00 00 00

2\
b1 cb 74 00 11 01 48 65  00 00 54 24 30 00 2b 01 ..t...He ..T$0.+.
b1 cb 74 00 01 03 48 66  00 00 f0 23 1f 00 1f 00 ..t...Hf ...#....
99 ca 00 f1 a0 02 df e5  3f b1 f9 d7 69 94 db 39 ........ ?...i..9
fd 27 09 eb 17 8c 22 d5  8f 30 fb f1 e9 bc fe 13 .'....". .0......
1b 8c ac a8 f5 63 0f bc  ff e3 8a a0 fa a3 55 ae .....c.. ......U.

3\
b1 cb 74 00 11 01 48 65  00 00 54 24 30 00 2b 01
b1 cb 74 00 11 02 48 69  00 00 f4 23 cb 02 82 1f
b1 cb 74 00 01 03 48 66  00 00 f0 23 1f 00 1f 00
b1 cb 74 00 11 04 48 67  00 00 f5 23 86 20 06 7d

*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static void ndpi_int_pinganzhengquan_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PINGANZHENGQUAN, NDPI_REAL_PROTOCOL);
}
void ndpi_search_pinganzhengquan_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
		
        if(packet->payload_packet_len >(16*7)
			&&packet->payload[0]==0x0c
			&&packet->payload[2]==0x18){
			if(get_u_int32_t(packet->payload, 16*7) == htonl( 0x2f977585)){
				NDPI_LOG(NDPI_PROTOCOL_PINGANZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG,"found pinganzhengquan------tcp[0->0c]:%x]tcp[1->01|02]:%x]tcp[7*16->2f]:%x]\n",packet->payload[0],packet->payload[1],packet->payload[7*16]);
				ndpi_int_pinganzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
				return;	
			}else{
				NDPI_LOG(NDPI_PROTOCOL_PINGANZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG, "exclude pinganzhengquan  pinganzhengquan_stage:%d\n",flow->pinganzhengquan_stage);
  				NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_PINGANZHENGQUAN);
				return;
			}
		}else if(packet->payload_packet_len >(32)){
			if((packet ->payload[0]==0x0c&&packet ->payload[2]==0x18&&packet ->payload[4]==0x00&&packet ->payload[5]==0x01)
	  	    	||(packet->payload[0]==0xb1&&packet->payload[1]==0xcb&&packet->payload[2]==0x74)
	  	    	||(packet->payload[0]==0x01&&packet->payload[2]==48)){

				if(packet->payload[0]==0x0c&&packet->payload[1]==0x06
					&&packet->payload[22]==0x70
					&&packet->payload[23]==0x61){
						NDPI_LOG(NDPI_PROTOCOL_PINGANZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG,"found pinganzhengquan------tcp[0[0c|b1]:%x]tcp[2[18|74]:%x]tcp[4[00|0c]:%x] \n",packet->payload[0],packet->payload[2],packet->payload[4]);
						ndpi_int_pinganzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
						return;	
				}
                /*
				if(packet ->payload[0]==0xb1
			  		 &&packet ->payload[1]==0xcb
			   		&&packet ->payload[2]==0x74){
						NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found pingan after login------tcp");
						ndpi_int_pinganzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);			
				}*/
			}	
	}else if(packet->payload_packet_len >16){
			if(packet ->payload[0]==0x0c
				&&packet ->payload[3]==0x0a
				&&packet ->payload[4]==0x00
				&&get_u_int32_t(packet->payload, 6) == htonl( 0x14001400)){
					NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found pingan after login------tcp");
					ndpi_int_pinganzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			}

		}
}
void ndpi_search_pinganzhengquan(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_PINGANZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG,
									"search pinganzhengquan tcp\n");
		ndpi_search_pinganzhengquan_tcp(ndpi_struct, flow);
	}
	
}



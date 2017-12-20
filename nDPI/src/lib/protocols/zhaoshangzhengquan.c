/*
 * zhaoshangzhengquan.c
 * BY-JK
 */
/*


*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static void ndpi_int_zhaoshangzhengquan_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN, NDPI_REAL_PROTOCOL);
}
void ndpi_search_zhaoshangzhengquan_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
if(packet->payload_packet_len >(16*8)
			&&packet->payload[0]==0x0c
			&&packet->payload[2]==0x18){
			//if(get_u_int32_t(packet->payload, 16*8) == htonl( 0xe28ef175)){
			//if(get_u_int32_t(packet->payload, 16*8) == htonl( 0x0ac1f86a)){
			if(get_u_int32_t(packet->payload, 16*8) == htonl(0xb0ea824d) //...M.... .T.gt.3.
              ||get_u_int32_t(packet->payload, 16*8) == htonl(0x0ac1f86a)
              ||get_u_int32_t(packet->payload, 16*8) == htonl(0x4d2d6b85)//M-k...;..b(,t.3. 
              ){
				NDPI_LOG(NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG,"found zhaoshang------tcp[0->0c]:%x]tcp[1->01|02]:%x]tcp[8*16->e2]:%x]\n",packet->payload[0],packet->payload[1],packet->payload[8*16]);
				ndpi_int_zhaoshangzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
				return;	
			}else{
            goto exit;
            }
		}else if(packet->payload_packet_len >(32)){
			if((packet ->payload[0]==0x0c&&packet ->payload[2]==0x18&&packet ->payload[4]==0x00&&packet ->payload[5]==0x01)){
				if(packet->payload[0]==0x0c&&packet->payload[1]==0x06
					&&packet->payload[22]==0x7a
					&&packet->payload[23]==0x73){
						NDPI_LOG(NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG,"found zhaoshang------tcp\n");
					ndpi_int_zhaoshangzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
					return;	
				}
			}	
	}else if(packet->payload_packet_len >16){
			if(packet ->payload[0]==0x0c
				&&packet ->payload[3]==0x0a
				&&packet ->payload[4]==0x00
				&&get_u_int32_t(packet->payload, 6) == htonl( 0x14001400)){
					NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found zhaoshang after login------tcp");
					ndpi_int_zhaoshangzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			}

		}
exit:
NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN);
return;
}
void ndpi_search_zhaoshangzhengquan(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG,
									"search zhaoshang tcp\n");
		ndpi_search_zhaoshangzhengquan_tcp(ndpi_struct, flow);
	}
	
}


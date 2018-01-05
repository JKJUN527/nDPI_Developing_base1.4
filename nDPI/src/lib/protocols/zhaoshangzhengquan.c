/*
 * zhaoshangzhengquan.c
 * BY-JK
 */
/*


*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
#define STR0ZS "\x63\x75\x73\x74\x6f\x6d\x63\x66\x67\x5f\x7a\x73\x7a\x71\x7a\x64"//customcfg_zszqzd
#define STR1ZS "\x36\x36\x38\x33\x61\x36\x63\x63\x32\x33\x33\x33\x31\x36\x30\x38"//668 3a6cc23331608
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
			&&packet->payload[2]==0x18
            &&flow->zszq_stage ==0
            ){
			//if(get_u_int32_t(packet->payload, 16*8) == htonl( 0xe28ef175)){
			//if(get_u_int32_t(packet->payload, 16*8) == htonl( 0x0ac1f86a)){
            flow->zszq_stage++;
			if(get_u_int32_t(packet->payload, 16*8) == htonl(0xb0ea824d) //...M.... .T.gt.3.
              ||get_u_int32_t(packet->payload, 16*8) == htonl(0x0ac1f86a)
              ||get_u_int32_t(packet->payload, 16*8) == htonl(0x4d2d6b85)//M-k...;..b(,t.3. 
              ||get_u_int32_t(packet->payload, 16*8) == htonl(0x6377c1f0)//cw...w.. .LZ.t.3. 
              ){
				NDPI_LOG(NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG,"found zhaoshang------tcp[0->0c]:%x]tcp[1->01|02]:%x]tcp[8*16->e2]:%x]\n",packet->payload[0],packet->payload[1],packet->payload[8*16]);
				ndpi_int_zhaoshangzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
				return;	
			}
		}
        /*else if(packet->payload_packet_len >(32)){
			if((packet ->payload[0]==0x0c&&packet ->payload[2]==0x18&&packet ->payload[4]==0x00&&packet ->payload[5]==0x01)){
				if(packet->payload[0]==0x0c&&packet->payload[1]==0x06
					&&packet->payload[22]==0x7a
					&&packet->payload[23]==0x73){
						NDPI_LOG(NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN, ndpi_struct, NDPI_LOG_DEBUG,"found zhaoshang------tcp\n");
					ndpi_int_zhaoshangzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
					return;	
				}
			}	
	}
    */else if(packet->payload_packet_len >16){
			if(packet ->payload[0]==0x0c
				&&packet ->payload[3]==0x0a
				&&packet ->payload[4]==0x00
				&&get_u_int32_t(packet->payload, 6) == htonl( 0x14001400)){
					NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found zhaoshang after login------tcp");
					ndpi_int_zhaoshangzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
                    return;
			}

		}
//特征1---某个16字节码，暂时不清楚意义，每个tdx码字不同
      if(packet->payload_packet_len >19
        &&packet->payload[0]==0xb1&&packet->payload[1]==0xcb&&packet->payload[2]==0x74
      ){
           NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"comming 1\n");
           if(memcmp(&packet->payload[packet->payload_packet_len-17],STR1ZS,NDPI_STATICSTRING_LEN(STR1ZS))==0){
             NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"found zhaoshang------tcp\n");
             ndpi_int_zhaoshangzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
             return;
           }
      }

//特征2---customcfg_zszqzd.zip
      if(packet->payload_packet_len >2*16
        &&packet->payload[0] == 0x0c
        &&packet->payload[2] == 0x18
        ){
           NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"comming 2\n");
           if(memcmp(&packet->payload[12],STR0ZS,NDPI_STATICSTRING_LEN(STR0ZS))==0){
             NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"found zhaoshang------tcp\n");
             ndpi_int_zhaoshangzhengquan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
           }
        }
        return;
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


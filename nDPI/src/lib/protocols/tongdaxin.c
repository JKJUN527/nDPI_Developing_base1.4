/*
 * tongdaxin.c
 * BY-JK
 */
/*


*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
#define STR0TDX "\x63\x75\x73\x74\x6f\x6d\x63\x66\x67\x5f\x6c\x65\x76\x65\x6c\x32"//customcfg_level2
#define STR1TDX "\x74\x64\x78\x6c\x65\x76\x65\x6c\x32"//tdxlevel2
#define STR2TDX "\x27\x70\x03\x57\x74\x99\x33\xae"//'p.Wt.3. 'p.Wt.3.
static void ndpi_int_tongdaxin_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TONGDAXIN, NDPI_REAL_PROTOCOL);
}
void ndpi_search_tongdaxin_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
/*
    if(packet->payload_packet_len >(16*8)
            &&packet->payload[0]==0x0c
            &&packet->payload[2]==0x18
            &&flow->tdx_stage ==0
      ){
        flow->tdx_stage++;
        if(get_u_int32_t(packet->payload, 16*8) == htonl( 0x5e1e66f8)
           ||get_u_int32_t(packet->payload, 16*8) == htonl( 0xb2a9ae51)// ...Q...L .U..t.3.
          ){
            NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"found tongdaxin------tcp[0->0c]:%x]tcp[1->01|02]:%x]tcp[8*16->5e]:%x]\n",packet->payload[0],packet->payload[1],packet->payload[8*16]);
            ndpi_int_tongdaxin_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
            return;	
        }
    }else if(packet->payload_packet_len >(32)){
        if(packet->payload[0]==0xb1&&packet->payload[1]==0xcb&&packet->payload[2]==0x74
           &&flow->packet_counter > 18
           ){
            if(packet ->payload[0]==0xb1
                    &&packet ->payload[1]==0xcb
                    &&packet ->payload[2]==0x74){
                NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found tongdaxin after login------tcp");
                ndpi_int_tongdaxin_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);			
            }
           
        }	
    }else if(packet->payload_packet_len >16){
        if(packet ->payload[0]==0x0c
                &&packet ->payload[3]==0x0a
                &&packet ->payload[4]==0x00
                &&get_u_int32_t(packet->payload, 6) == htonl( 0x14001400)){
            NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found tongdaxin after login------tcp");
            ndpi_int_tongdaxin_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
        }

    }
    NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"tongdaxin stage is %u\n",flow->tdx_stage);
    
    if(flow->tdx_stage >0
        &&packet->payload_packet_len >2*16
        &&packet->payload[0]==0x0c
        &&packet->payload[2]==0x18
    ){
        if(memcmp(&packet->payload[12],STR1TDX,NDPI_STATICSTRING_LEN(STR1TDX))==0){
            NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"found tongdaxin------tcp\n");
            ndpi_int_tongdaxin_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
        }
    }
    return;
*/
    u_int16_t len = packet->payload_packet_len;
    if(len >16*7
        &&packet->payload[0] == 0x0c
        &&packet->payload[2] == 0x18
    ){
       int i = 0;
       
       NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"tongdaxin stage is %u\n",flow->tdx_stage);
       for(i=0;i<8;i++){
          NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"tongdaxin payload 16*2+%u*8 is %x\n",i,packet->payload[16*2+i*8]);
          if(memcmp(&packet->payload[16*2+i*8],STR2TDX,NDPI_STATICSTRING_LEN(STR2TDX))==0
         // ||memcmp(&packet->payload[packet->payload_packet_len -16*2],STR2TDX,NDPI_STATICSTRING_LEN(STR2TDX))==0
          ){
            continue;
          }else{
            goto exit;
          }
       }
       flow->tdx_stage++;
       return;
    }else if(len > 16
        &&flow->tdx_stage >0
        &&packet->payload[0] == 0xb1
        &&packet->payload[1] == 0xcb
        &&packet->payload[2] == 0x74
    ){
        goto found;
    }

    //进入软件后流量特征
    //if(len >8 && packet->payload[0] == 0x0c) flow->tdx_stage++;
    if(len >8
        &&memcmp(&packet->payload[0],"\xb1\xcb\x74",NDPI_STATICSTRING_LEN("\xb1\xcb\x74")) ==0
    ){
        goto found;
    }
    return;

exit:
    NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG, "exclude tongdaxin \n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TONGDAXIN);
    return;
found:
    NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,"found tongdaxin------tcp\n");
    ndpi_int_tongdaxin_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
    return;
}
void ndpi_search_tongdaxin(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_TONGDAXIN, ndpi_struct, NDPI_LOG_DEBUG,
									"search tongdaxin tcp\n");
		ndpi_search_tongdaxin_tcp(ndpi_struct, flow);
	}
	
}


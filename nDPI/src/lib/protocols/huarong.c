/*
 * huarong.c
 * BY-JK
 */
/*
00000000  b1 cb 74 00 01 00 00 54  00 00 4c 1f 14 04 14 04 ..t....T ..L.....
00000010  10 04 00 00 5b 63 6f 6d  70 61 6e 79 5d 0d 0a 63 ....[com pany]..c
00000020  6f 6d 70 61 6e 79 5f 6e  75 6d 3d 31 0d 0a 63 6f ompany_n um=1..co
00000030  6d 70 61 6e 79 73 74 72  5f 30 31 3d b8 db b0 c4 mpanystr _01=....
00000040  d7 ca d1 b6 0d 0a 63 6f  6d 70 61 6e 79 69 64 5f ......co mpanyid_
00000050  30 31 3d 30 0d 0a 4c 61  73 74 4e 3d 32 30 31 34 01=0..La stN=2014

00000000  0c 01 18 7b 00 01 1a 01  1a 01 0b 00 4b e6 b0 4f ...{.... ....K..O
00000010  c5 6f 88 77 30 2b 74 c5  42 ee f1 e3 74 99 33 ae .o.w0+t. B...t.3.
00000020  27 70 03 57 74 99 33 ae  27 70 03 57 74 99 33 ae 'p.Wt.3. 'p.Wt.3.
00000030  27 70 03 57 74 99 33 ae  27 70 03 57 74 99 33 ae 'p.Wt.3. 'p.Wt.3.
00000040  27 70 03 57 74 99 33 ae  27 70 03 57 74 99 33 ae 'p.Wt.3. 'p.Wt.3.

2\tdx 
000001C3  0c 06 18 69 00 01 2a 00  2a 00 c5 02 63 75 73 74   ...i..*. *...cust
000001D3  6f 6d 63 66 67 5f 68 72  7a 71 76 36 2e 7a 69 70   omcfg_hr zqv6.zip
000001E3  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
000001F3  00 00 00 00                                        ....


*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static void ndpi_int_huarong_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HUARONG, NDPI_REAL_PROTOCOL);
}
void ndpi_search_huarong_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    if(packet->payload_packet_len >(16*8)
            &&packet->payload[0]==0x0c
            &&packet->payload[2]==0x18){
        if(get_u_int32_t(packet->payload, 16*8) == htonl( 0x99396e39)
          ||get_u_int32_t(packet->payload, 16*8) == htonl( 0x01b553bb)
          ){
            NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found HUARONG login------tcp[0->0c]:%x]tcp[1->01]:%x]tcp[8*16->99]:%x]\n",packet->payload[0],packet->payload[1],packet->payload[8*16]);
            ndpi_int_huarong_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
            return;	
        }else{
            NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG, "exclude huarong  huarong_stage:%d\n",flow->huarong_stage);
            NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HUARONG);
            return;
        }
    }else if(packet->payload_packet_len >(32)){
        if((packet ->payload[0]==0x0c&&packet ->payload[2]==0x18&&packet ->payload[4]==0x00&&packet ->payload[5]==0x01)
                ||(packet->payload[0]==0xb1&&packet->payload[1]==0xcb&&packet->payload[2]==0x74)
                ||(packet->payload[0]==0x01&&packet->payload[2]==48)){

            if(packet->payload[0]==0x0c&&packet->payload[1]==0x06
                    &&packet->payload[22]==0x68
                    &&packet->payload[23]==0x72){
                NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found HUARONG login------tcp[0->0c]:%x]tcp[1->01]:%x]tcp[8*16->99]:%x]\n",packet->payload[0],packet->payload[1],packet->payload[8*16]);
                ndpi_int_huarong_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
                return;	
            }
            /*
               if(packet ->payload[0]==0xb1
               &&packet ->payload[1]==0xcb
               &&packet ->payload[2]==0x74){
               NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found HUARONG after login------tcp");
               ndpi_int_huarong_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);			
               }*/
        }	
    }else if(packet->payload_packet_len >16){
        if(packet ->payload[0]==0x0c
                &&packet ->payload[3]==0x0a
                &&packet ->payload[4]==0x00
                &&get_u_int32_t(packet->payload, 6) == htonl( 0x14001400)){
            NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found HUARONG after login------tcp");
            ndpi_int_huarong_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
        }

    }

}
void ndpi_search_huarong_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	if(packet->payload_packet_len >= (24)
	   &&packet->payload[0]==0x00
           &&packet->payload[1]==0x0a
	   &&packet->payload[16]==0x8c
	   &&packet->payload[17]==0x3d
	){

		NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,"found huarong------udp");
		ndpi_int_huarong_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;	

}
}
void ndpi_search_huarong(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,
									"search huarong tcp\n");
		ndpi_search_huarong_tcp(ndpi_struct, flow);
	}
	if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_HUARONG, ndpi_struct, NDPI_LOG_DEBUG,
									"search huarong udp\n");
		ndpi_search_huarong_udp(ndpi_struct, flow);
	}
	
}


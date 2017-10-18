/*
 * dazhihui365.c
 * BY--JK
 */
/*
00000000  [36 10] 5c [00 00 00] 03 00  71 a4 5d cc b3 1b 54 63 6.\..... q.]...Tc
00000010  6b 66 ca 14 e2 d3 ea 2b  9b 62 9a 76 cc 17 04 e3 kf.....+ .b.v....
00000020  dc d2 75 1b 06 f7 ea 20  2e cc ab 62 ea 9e a1 77 ..u....  ...b...w
00000030  0f ac 7c e4 73 c3 25 3f  43 de cd 77 ed 46 f7 e1 ..|.s.%? C..w.F..
00000040  7d 54 60 34 67 1f b2 d5  9e f3 26 e5 5f 32 f4 d1 }T`4g... ..&._2..
00000050  88 a6 4c 76 c5 50 fe 4a  65 7c 30 7c 0d 0a 3c 2f ..Lv.P.J e|0|..</
00000060  41 3e 0d 0a                                      A>..


00000000  [31 10] 30 [00 00 00] 03 00  50 5e 7c c0 a2 2e 6c 32 1.0..... P^|...l2
00000010  4e 50 db dd 6b f4 ef 87  02 36 11 8e 7a 4e 02 26 NP..k... .6..zN.&
00000020  bf 15 e8 8f c9 fc db 42  fd 90 ea ab 54 d5 74 89 .......B ....T.t.
00000030  04 bb 79 40 c4 ff 43 82                          ..y@..C.


2\
00000000  3e 10 10 00 00 00 00 00  53 48 80 0a 24 00 19 00   >....... SH..$...
    00000010  ff ff 00 00 00 00 00 00                            ........ 
    00000018  3e 10 10 00 00 00 00 00  53 48 80 0a 27 00 19 00   >....... SH..'...
    00000028  ff ff 00 00 00 00 00 00                            ........ 
0000026D  3e 10 74 00 00 00 00 00  53 48 80 0a 24 00 19 00   >.t..... SH..$...
0000027D  ff ff 00 00 00 00 00 00  01 00 cc 16 00 00 04 2e   ........ ........
0000028D  00 00 68 2e 01 00 89 15  00 00 65 2e 01 00 db 17   ..h..... ..e.....
0000029D  00 00 03 2e 01 00 07 05  01 00 dc 00 01 00 25 00   ........ ......%.

*/

#include "ndpi_protocols.h"
/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static void ndpi_int_dazhihui_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DAZHIHUI365, NDPI_REAL_PROTOCOL);
}
void ndpi_search_dazhihui_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	flow->dazhihui_stage++;
	if(flow->dazhihui_stage >=5){
		NDPI_LOG(NDPI_PROTOCOL_DAZHIHUI365, ndpi_struct, NDPI_LOG_DEBUG, "exclude dazhihui365.\n");
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DAZHIHUI365);
	}
  if(packet->payload_packet_len >= (16)
  	//&&(get_u_int64_t(packet->payload, 0) == htonl( 0xfdfdfdfd30303030)
  	//|| get_u_int64_t(packet->payload, 8) == htonl( 0x3034383609010700))
          &&((((packet ->payload[0]==0x36||packet ->payload[0]==0x31)
                      &&packet ->payload[1]==0x10
                      &&(packet ->payload[3]==0x00||packet ->payload[3]==0x02)
                      &&packet ->payload[4]==0x00
                      &&packet ->payload[5]==0x00)
                  ||(packet->payload[0]==0x2a
                      &&packet->payload[1]==0x10
                      &&packet->payload[2]==0xd6
                      &&packet->payload[12]==0x22)
                  ||(packet->payload[0]==0x48
                      &&packet->payload[1]==0x04
                      &&packet->payload[2]==0x00)
                  ||(packet->payload[0]==0x3e
                      &&packet->payload[1]==0x10
                      &&packet->payload[8]==0x53))
              &&packet->payload[9]==0x48
              &&packet->payload[10]==0x80)
    ){			
  		NDPI_LOG(NDPI_PROTOCOL_DAZHIHUI365, ndpi_struct, NDPI_LOG_DEBUG,"found dazhihui365------tcp[0[36|31]:%x]tcp[3[00]:%x]tcp[5[00]:%x] \n",packet->payload[0],packet->payload[3],packet->payload[5]);
		ndpi_int_dazhihui_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);		
		return;	
	}
}
void ndpi_search_dazhihui(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_DAZHIHUI365, ndpi_struct, NDPI_LOG_DEBUG,
									"search DAZHIHUI365 tcp\n");
		ndpi_search_dazhihui_tcp(ndpi_struct, flow);
	}
	
}


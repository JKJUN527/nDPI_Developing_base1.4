/*
 * webqq.c
 *
 */


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_WEBQQ
/*LIVE SERVER
00000000  fe ba 00 00 ba df 0b 2e  3c 14 07 b9 17 34 9a ae   ........ <....4..
00000010  6a 81 84 8e 54 7b ad ff  9a 57 5e 0b 86 26 54 01   j...T{.. .W^..&T.
00000020  f7 81 44 8a ae 46 48 9b  8c ce e6 7c d2 23 25 00   ..D..FH. ...|.#%.
00000030  e5 f3 73 a4 87 31 cf 19  0c c1 83 ba 66 eb 38 c8   ..s..1.. ....f.8.
00000040  6c e3 a2 c3 40 d2 90 b6  96 b7 c4 bd 4c ca a1 11   l...@... ....L...
00000050  08 a6 32 42 86 e1 9b 5a  63 74 0f fd 79 36 0c 1a   ..2B...Z ct..y6..
00000060  d7 30 e6 ba f0 c0 12 b4  31 70 0e 92 7f 72 3c 82   .0...... 1p...r<.
00000070  5b 9d 10 62 8f 27 fd bf  76 ef 3a 1a 53 c1 7d d1   [..b.'.. v.:.S.}.
00000080  d1 3c 0a 59 da 13 52 1c  c1 f1 69 88 44 02 cd ee   .<.Y..R. ..i.D...
00000090  bf 9b 8c 43 1c 35 d3 a0  ee dd 3b 86 f8 ba 4a c9   ...C.5.. ..;...J.
000000A0  ed 8c 44 fd b5 0e 9f 81  9e 93 df 22 45 ca 91 94   ..D..... ..."E...
000000B0  3f c5 ae 74 ae 32 2f 6a  6f 88 4a 52 6b            ?..t.2/j o.JRk
    00000000  fe 23 00 00 23 df 87 2e  3c 14 07 b9 17 00 b0 0f   .#..#... <.......
    00000010  0b f1 d3 88 a4 e3 6f 8c  28 a8 5a 55 2a bc 33 a7   ......o. (.ZU*.3.
    00000020  fc a9 a2 56 51 a0                                  ...VQ.
加密流量
00000000  17 03 03 00 29 00 00 00  00 00 00 00 b7 ab 64 a2   ....)... ......d.
00000010  58 52 e3 7f ac aa 56 3e  13 a4 35 27 db 3f f7 3b   XR....V> ..5'.?.;
00000020  6e 51 13 5b 10 a4 16 2d  8c 58 25 29 33 76         nQ.[...- .X%)3v
    00000000  17 03 03 00 29 01 62 90  e3 69 13 5f 51 3d ed 4c   ....).b. .i._Q=.L
    00000010  ad 94 97 b8 22 eb 91 ed  39 4f 0f 52 e3 73 a3 41   ...."... 9O.R.s.A
    00000020  0d 96 90 7c bd d2 ca c8  e2 1b a9 8c 45 d8         ...|.... ....E.
*/

static void ndpi_int_webqq_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WEBQQ, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_webqq_tcp(struct ndpi_detection_module_struct*ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    //禁止ip（101.226.211.174）
    /* NOTE exclude ipv6 */
    if(packet->payload_packet_len > 0 && packet->iph && ntohl(packet->iph->daddr)==1709364142) {
        NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG,"found webqq tcp jiami \n");
        ndpi_int_webqq_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
        return;
    }

    //	if(packet->payload_packet_len >32 
    //		&&get_u_int16_t(packet->payload, 0)==htons(0x1703)){
    //		if(get_u_int32_t(packet->payload, 8)==htons(0x00000000)
    //		    ||get_u_int32_t(packet->payload, 8)==htons(0xe369135f)
    //		    ||get_u_int32_t(packet->payload, 8)==htons(0x24f0217c)){
    //		NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG,"found webqq tcp:%u\n",ntohl(packet->iph->daddr));
    //		NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG,"found webqq tcp \n");
    //		ndpi_int_webqq_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);	
    //		}

    NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG, "exclude webqq.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WEBQQ);
}
void ndpi_search_webqq_udp(struct ndpi_detection_module_struct*ndpi_struct, struct ndpi_flow_struct *flow)
{
		struct ndpi_packet_struct *packet = &flow->packet;
	
		if(flow->webqq_direction==0 && packet->payload_packet_len == 189){
			if(get_u_int32_t(packet->payload, 0)==htons(0xfeba0000)&&packet->payload[8]==0x3c){
				flow->webqq_direction=1;
				NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG,"pass direction = 0 \n");
				return ;
			}
		}else if (flow->webqq_direction==1 && packet->payload_packet_len == 38){
			if(get_u_int32_t(packet->payload, 0)==htons(0xfe230000)&& packet->payload[8]==0x3c){
			NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG,"found webqq \n");
			ndpi_int_webqq_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		}else{
			NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG, "exclude webqq.\n");
  			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WEBQQ);
		}
}
}
void ndpi_search_webqq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG,
									"search webqq tcp \n");
		ndpi_search_webqq_tcp(ndpi_struct, flow);
	}
	if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_WEBQQ, ndpi_struct, NDPI_LOG_DEBUG,
									"search webqq udp \n");
		ndpi_search_webqq_udp(ndpi_struct, flow);
	}
}

#endif



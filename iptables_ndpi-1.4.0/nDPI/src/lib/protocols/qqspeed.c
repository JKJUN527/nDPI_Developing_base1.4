/*
 * qqspeed.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_GAME_QQSPEED

/*
 JKJUN:阻断登录
qqspeed
1:
00000000  fe 1a 00 00 1a 03 12 00  05 00 00 00 00 53 ef 87   ........ .....S..
00000010  f7 27 db 5f 1a 5f 79 06  5d 47 8d c8 cd            .'._._y. ]G...

2:
00000000  d8 5c 00 d2 00 01 17 56  00 00 00 00 00 00 00 00   .\.....V ........
00000010  00 00 2f 85 15 21 e9 71  31 39 9f a9 a3 38 47 fe   ../..!.q 19...8G.
00000020  db 01 93 7a df 64 5f 32  c7 33 46 4c 43 b5 90 7b   ...z.d_2 .3FLC..{
00000030  b1 58 28 51 8a 18 bf a9  0a 7e 2a 47 e2 43 aa 8d   .X(Q.... .~*G.C..
00000040  42 ed 19 6e 3c ae fb 1c  16 84 7e 82 34 f3 1b c0   B..n<... ..~.4...
00000050  1f 92 bc 61 db 89 e2 14  87 7e 4e 08 ac 97 5b fe   ...a.... .~N...[.
00000060  9f 2f 38 47 ab 68 53 0c  d2 5d 60 4f 9f b7 f3 e1   ./8G.hS. .]`O....
00000070  6e dd bf ba 0f 6e 7a 28  a6 95 2d 8d f3 08 5e d6   n....nz( ..-...^.
00000080  71 d6 94 3b 14 e1 00 00  3c 70 91 6e c0 60 aa c7   q..;.... <p.n.`..
00000090  20 ca e7 87 ba ef 7f c3  d0 cb 3a aa 83 96 28 26    ....... ..:...(&
000000A0  bd d4 b6 f2 41 79 4b 75  69 06 e6 2d dd a1 90 d2   ....AyKu i..-....
000000B0  df 8c d7 18 d1 df 3a 75  af f5 ee 4c f6 75 0b fe   ......:u ...L.u..
000000C0  cf 60 17 aa 20 07 1c 4e  d4 c7 54 3e 5f 4e 74 76   .`.. ..N ..T>_Ntv
000000D0  5b 49                                              [I
    00000000  d8 5d 00 14 00 01 17 56  00 00 00 00 7d 47 c8 13   .].....V ....}G..
    00000010  4b d9 00 00                                        K...
3:登陆流量\TCP
 00 00 01 0a 35 0f ff ff  00 00 00 5c 25 a6 1a 81   ....5... ...\%...
00000010  01 78 00 01 59 8d 0a 0a  00 70 99 3f 4b 70 5f 1f   .x..Y... .p.?Kp_.
00000020  97 69 95 f5 55 3b 89 21  5e 8d cf 6a d3 a9 a1 a2   .i..U;.! ^..j....

*/

static void ndpi_int_qqspeed_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_QQSPEED, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_qqspeed_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,"comming 1 \n");
	if(packet->payload_packet_len>=16){
		if(get_u_int16_t(packet->payload, 0)==htons(0x0000)
			&&(get_u_int16_t(packet->payload, 6)==htons(0xffff)//客户端请求
			   ||get_u_int16_t(packet->payload, 6)==htons(0x02ee))//服务端响应
			&&(packet->payload[4]==0x35)
			&&(get_u_int32_t(packet->payload, 12)==htonl(0x25a61a81)
			   ||get_u_int32_t(packet->payload, 12)==htonl(0x6fb362d3))
		){//登录后特征
			flow->qqspeed_stage++;
			if(flow->qqspeed_stage==2){
			    NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,"found qqspeed-----tcp1 \n");
			    ndpi_int_qqspeed_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			}
			return;	
		}else if((get_u_int32_t(packet->payload, 0)==htonl(0xd85c00d2)
				||get_u_int32_t(packet->payload, 0)==htonl(0xd85d0014))
			&&get_u_int32_t(packet->payload, 4)==htonl(0x00011756)
		){
		NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,"found qqspeed-----tcp2 \n");
		ndpi_int_qqspeed_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
		}
	
		if(get_u_int16_t(packet->payload, 0)==htons(0x0000)
		   &&(packet->payload[4]==0x35)
		   &&get_u_int16_t(packet->payload,6)==htons(0xffff)
		){
			NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,"found qqspeed-----tcp3 \n");
	                ndpi_int_qqspeed_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		}
	}
	NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG, "exclude qqspeed.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_QQSPEED);

}
void ndpi_search_qqspeed_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
		struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,"comming 1 \n");
	return;
if(packet->payload_packet_len>=16){
	if(packet->payload[0]==0xfe
		&&get_u_int16_t(packet->payload, 2)==htons(0x0000)
		&&get_u_int32_t(packet->payload, 9)==htonl(0x00000000)
		){
			NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,"found qqspeed-----udp1 \n");
			ndpi_int_qqspeed_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
	}else if(get_u_int32_t(packet->payload, 0)==htonl(0x02500708)){
		flow->qqspeed_stage++;
		if(flow->qqspeed_stage==3){
		    NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,"found qqspeed-----udp3 \n");
		    ndpi_int_qqspeed_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		}
		return;
	}else if (memcmp(&packet ->payload[0], "\x00\x00\x00\x12\x35\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 16)
	){
		NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,"found qqspeed-----udp4 \n");
		ndpi_int_qqspeed_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}
}
	NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG, "exclude qqspeed.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_QQSPEED);
}
void ndpi_search_qqspeed(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,
									"search qqspeed tcp \n");
		ndpi_search_qqspeed_tcp(ndpi_struct, flow);
	}
	if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_GAME_QQSPEED, ndpi_struct, NDPI_LOG_DEBUG,
									"search qqspeed udp \n");
		ndpi_search_qqspeed_udp(ndpi_struct, flow);
	}
	
}

#endif


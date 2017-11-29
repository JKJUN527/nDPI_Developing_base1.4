/*
 * DNF.c
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
#ifdef NDPI_PROTOCOL_GAME_DNF

/*
 JKJUN:阻断登录
DNF
1:与cf流量冲突
00000000  d8 5c 00 d2 00 01 17 56  00 00 00 00 00 00 00 00   .\.....V ........
00000010  00 00 2f 85 15 21 e9 71  31 39 9f a9 a3 38 47 fe   ../..!.q 19...8G.
00000020  db 01 93 7a df 64 5f 32  c7 33 46 4c 43 b5 90 7b   ...z.d_2 .3FLC..{
2:与cf流量冲突
00000000  55 0e 03 00 00 00 00 65  00 00 00 00 00 00 00 03   U......e ........
00000010  00 00 00 01 00 00 00 03  25 a6 1a 81 48 00 01 59   ........ %...H..Y
3:游戏运行中流量//与cf冲突
00000000  01 00 00 00 5a 11 00 00  00 01 25 a6 1a 81 00 00   ....Z... ..%.....
00000010  00 05 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
00000020  00 00 59 8d 74 d9 00 01  00 04 0b 03 00 00 00 00   ..Y.t... ........
00000030  00 28 c3 30 e0 b0 af 4e  10 b9 65 7f 3f 18 52 55   .(.0...N ..e.?.RU
00000040  6c 03 2d a2 fd 9e 81 30  89 e2 2f 63 7b fa 74 9c   l.-....0 ../c{.t.
00000050  16 1f 4a f0 ab a0 80 f1  67 b8                     ..J..... g.
    00000000  01 00 00 01 02 13 00 00  00 00 00 00 00 00 00 00   ........ ........
    00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
    00000020  00 00 00 00 00 d8 00 00  00 d8 ac 95 52 ad 1f df   ........ ....R...
4:游戏登录后连接频道流量，成功阻断
00000000  00 01 00 e8 01 00 00 f0  a7 ef 96 f0 a7 ef 96 d2	 ........ ........
00000010  d5 be d7 93 cc ea 69 32  d0 ee 46 af 75 6c b8 98	 ......i2 ..F.ul..
...
000001C0  f2 d6 d6 f6 f2 d6 d6 d2  d6 d6 d6 ea d6 d6 d6 12	 ........ ........
000001D0  12 32 6e 12 06 0a 6e 12  12 16 6e 12 06 1e d2 da	 .2n...n. ..n.....
000001E0  73 c2 d6 d6 0e c2 d6 d6							 s....... 


*/

static void ndpi_int_dnf_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_DNF, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_dnf_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,"comming 1 \n");
	if(packet->payload_packet_len>16){
		if(packet->payload[0]==0xd8
			&&packet->payload[2]==0x00
			&&packet->payload[4]==0x00
			&&packet->payload[5]==0x01
			&&get_u_int16_t(packet->payload, 6)==htons(0x1756)
			&&get_u_int32_t(packet->payload, 8)==htonl(0x00000000)
			){
			NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,"found DNF----tcp1 \n");
			ndpi_int_dnf_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
		}else if (get_u_int16_t(packet->payload, 0)==htons(0x550e)
				&&get_u_int16_t(packet->payload, 5)==htons(0x0000)
				&&get_u_int16_t(packet->payload, 8)==htons(0x0000)
		){
			flow->dnf_stage++;
			if(flow->dnf_stage>=2){
				NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,"found DNF----tcp2 \n");
				ndpi_int_dnf_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				}
			return;
		}else if(get_u_int32_t(packet->payload, 0)==(htonl(0x01000000)||htonl(0x01000001))
				&&get_u_int16_t(packet->payload, 6)==htons(0x0000)
				//&&packet->payload[12]==0x1a
				//&&packet->payload[13]==0x81
				&&get_u_int16_t(packet->payload, 14)==htons(0x0000)
				&&(packet->payload[17]==0x05||packet->payload[17]==0x00)
		){
			flow->dnf_stage++;
			if(flow->dnf_stage>=2){
				NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,"found DNF----tcp3 \n");
				ndpi_int_dnf_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				}
			return;
		}else if(((packet->payload[0]==0x00 || packet->payload[0]==0x01)
				&&packet->payload[1]==0x01 
				&&packet->payload[2]==0x00)
			||get_u_int32_t(packet->payload, packet->payload_packet_len-4)==htonl(0x99ee30fe)
		){
			if(packet->payload[15]==0xd2
			    &&get_u_int32_t(packet->payload, packet->payload_packet_len-4)==htonl(0x0ec2d6d6)){
				//flow->dnf_stage++;
				NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,"found DNF----tcp4 \n");
				
				ndpi_int_dnf_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;
			}
			if(packet->payload[15]==0x00
			    &&get_u_int16_t(packet->payload, 5)==htons(0x0000)
			   // &&get_u_int32_t(packet->payload, packet->payload_packet_len-4)==htonl(0x99ee30fe)
			){
				flow->dnf_stage++;
				NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,"found DNF----tcp5 \n");
				ndpi_int_dnf_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;
			}
			if(get_u_int16_t(packet->payload, 3)==htons(0x76010000)){
				flow->dnf_stage++;
				NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,"found DNF----tcp6 \n");
				ndpi_int_dnf_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;			
			}
			
		}
		
	}
	NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG, "exclude DNF.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_DNF);

}
void ndpi_search_dnf_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
}
void ndpi_search_dnf(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,
									"search dnf tcp \n");
		ndpi_search_dnf_tcp(ndpi_struct, flow);
	}
	if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG,
									"search dnf udp \n");
		ndpi_search_dnf_udp(ndpi_struct, flow);
	}
	
}

#endif


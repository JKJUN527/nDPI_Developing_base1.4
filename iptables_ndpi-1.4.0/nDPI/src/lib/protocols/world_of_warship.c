/*
 * worldofwarship.c
 *
 * Copyright (C) 2016-2017 by PENGTIAN
 * Copyright (C) 2016-2017 - ntop.org
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
#ifdef NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP

/*
1:tcp登录流量
00000000  3c 3f 78 6d 6c 20 76 65  72 73 69 6f 6e 3d 27 31   <?xml ve rsion='1
00000010  2e 30 27 20 3f 3e 3c 73  74 72 65 61 6d 3a 73 74   .0' ?><s tream:st
00000020  72 65 61 6d 20 74 6f 3d  27 77 6f 77 73 63 6e 73   ream to= 'wowscns
00000030  2e 6c 6f 63 27 20 78 6d  6c 6e 73 3d 27 6a 61 62   .loc' xm lns='jab
00000040  62 65 72 3a 63 6c 69 65  6e 74 27 20 78 6d 6c 6e   ber:clie nt' xmln
00000050  73 3a 73 74 72 65 61 6d  3d 27 68 74 74 70 3a 2f   s:stream ='http:/
00000060  2f 65 74 68 65 72 78 2e  6a 61 62 62 65 72 2e 6f   /etherx. jabber.o
00000070  72 67 2f 73 74 72 65 61  6d 73 27 20 20 78 6d 6c   rg/strea ms'  xml
00000080  3a 6c 61 6e 67 3d 27 65  6e 27 20 76 65 72 73 69   :lang='e n' versi
00000090  6f 6e 3d 27 31 2e 30 27  3e                        on='1.0' >
2://和战舰世界登录流量相同，需要进行区分
00000000  01 00 00 bd bd 00 00 00  00 75 60 8b 63 00 02 00   ........ .u`.c...
    00000000  9c 2a 4e c6 70 6c 88 65  ea db 7b f3 cd 12 e8 1e   .*N.pl.e ..{.....
    00000010  a9 bd 49 24 ab d3 fa 3f  2a 9e 90 1b 98 dd 58 6f   ..I$...? *.....Xo
00000010  b3 cb dc c7 47 7c 4f 56  65 fd e6 a7 e1 bf 35 41   ....G|OV e.....5A
00000020  61 05 7f d6 08 f5 af 7e                            a......~ 
00000028  19 19 31 f1 92 6d c1 2a  c4 25 dc 6b 0d d6 81 bf   ..1..m.* .%.k....
00000038  20 9a 85 49 0e 84 4b 3b                             ..I..K; 
    00000020  5d b6 5d 5d a8 52 67 42  8b 9f 2c 11 f2 d6 b4 f1   ].]].RgB ..,.....
    00000030  82 c2 f3 41 ca f5 08 68  3b d5 d7 d5 f0 ff f0 63   ...A...h ;......c

*/

#define STR0TCP "\x77\x6f\x77\x73\x63\x6e\x73\x2e\x6c\x6f\x63"

static void ndpi_int_worldofwarship_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_worldofwarship_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG,"search worldofwarship tcp \n");
	if(packet->payload_packet_len >3*16+4){
		if (memcmp(&packet->payload[5*8+1], STR0TCP, NDPI_STATICSTRING_LEN(STR0TCP)) == 0){
	
		NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG,"found worldofwarship tcp \n");
		ndpi_int_worldofwarship_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
		}
	}
	NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude worldofwarship.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP);
}
void ndpi_search_worldofwarship_udp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	flow->worldofwarship_count++;
	NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG,"search worldofwarship udp STAGE:%u\n",flow->worldofwarship_stage);
NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG,"search worldofwarship udp packet[0]:%x len:%u\n",packet->payload[0],packet->payload_packet_len);	
	if(packet->payload_packet_len ==16 && flow->worldofwarship_stage == 0
		&&packet->payload[0]==0x01
		&&packet->payload[1]==0x00
		&&packet->payload[2]==0x00
		&&packet->payload[14]==0x02
		&&packet->payload[15]==0x00){
		flow->worldofwarship_stage++;
		NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG,"STAGE:%u\n",flow->worldofwarship_stage);
		return;
	}
	
	if((packet->payload_packet_len ==32 ||packet->payload_packet_len ==24 )
	   && flow->worldofwarship_stage >= 1){
		flow->worldofwarship_stage++;
		NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG,"STAGE:%u\n",flow->worldofwarship_stage);
		return;
	}

	if(flow->worldofwarship_stage >= 2
	   &&flow->worldofwarship_count<=5){
		NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG,"found worldofwarship udp \n");
		ndpi_int_worldofwarship_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	}

	if(flow->worldofwarship_stage==0 ||flow->worldofwarship_count >5){
		NDPI_LOG(NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude worldofwarship.\n");
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP);
	}
	
}
void ndpi_search_worldofwarship(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	if (packet->tcp != NULL) {
		ndpi_search_worldofwarship_tcp(ndpi_struct, flow);
	}
	if (packet->udp != NULL) {
		ndpi_search_worldofwarship_udp(ndpi_struct, flow);
	}
}

#endif


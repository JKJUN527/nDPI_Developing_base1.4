/*
 * qiannyh.c
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
#ifdef NDPI_PROTOCOL_GAME_QIANNYH

/*
00000000  45 06 0d 31 30 2e 31 32  30 2e 31 38 36 2e 32 36   E..10.12 0.186.26
00000010  6c 41 00 00 2b 38 32 31  65 33 32 30 38 64 34 39   lA..+821 e3208d49
00000020  62 65 63 65 30 37 39 33  36 35 31 62 64 35 36 65   bece0793 651bd56e
00000030  64 36 65 34 30 30 30 30  33 37 39 32 33 39 34 33   d6e40000 37923943
00000040  00                                                 .
    00000000  68 00 53 00 38 32 31 65  33 32 30 38 64 34 39 62   h.S.821e 3208d49b
    00000010  65 63 65 30 37 39 33 36  35 31 62 64 35 36 65 64   ece07936 51bd56ed
    00000020  36 65 34 30 30 30 30 33  37 39 32 33 39 34 33 31   6e400003 79239431
    00000030  32 37 32 35 30 38 38 38  39 30 30 34 36 36 38 30   27250888 90046680
    00000040  38 34 37 30 30 30 30 30  30 30 30 30 30 31 35 30   84700000 00000150
    00000050  35 32 38 37 33 37 31 67  00 53 00 38 32 31 65 33   5287371g .S.821e3


00000000  16 03 01 01 38 01 00 01  34 03 03 9f c6 95 8c e9   ....8... 4.......
00000010  73 0b 2c ea 68 92 c7 08  f3 5c a6 d1 aa 96 80 fe   s.,.h... .\......
00000020  68 b8 ea 62 4f 76 d3 b1  d6 1b 62 00 00 b6 c0 30   h..bOv.. ..b....0
00000030  c0 2c c0 28 c0 24 c0 14  c0 0a 00 a5 00 a3 00 a1   .,.(.$.. ........
00000040  00 9f 00 6b 00 6a 00 69  00 68 00 39 00 38 00 37   ...k.j.i .h.9.8.7
00000050  00 36 00 88 00 87 00 86  00 85 c0 32 c0 2e c0 2a   .6...... ...2...*
00000060  c0 26 c0 0f c0 05 00 9d  00 3d 00 35 00 84 c0 2f   .&...... .=.5.../
00000070  c0 2b c0 27 c0 23 c0 13  c0 09 00 a4 00 a2 00 a0   .+.'.#.. ........
00000080  00 9e 00 67 00 40 00 3f  00 3e 00 33 00 32 00 31   ...g.@.? .>.3.2.1
00000090  00 30 00 9a 00 99 00 98  00 97 00 45 00 44 00 43   .0...... ...E.D.C
000000A0  00 42 c0 31 c0 2d c0 29  c0 25 c0 0e c0 04 00 9c   .B.1.-.) .%......

*/

static void ndpi_int_qiannyh_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_QIANNYH, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
#define STR0XQNYH "\x00\x6b\x00\x6a\x00\x69\x00\x68\x00"//.k.j.i .h.
void ndpi_search_qiannyh_tcp(struct ndpi_detection_module_struct*ndpi_struct, struct ndpi_flow_struct *flow)
{

	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG(NDPI_PROTOCOL_GAME_QIANNYH, ndpi_struct, NDPI_LOG_DEBUG,"comming 1 \n");
	if(packet->payload_packet_len >=16*4){
		if(flow->qiannyh_stage==0 
			&&get_u_int16_t(packet->payload, 0)==htons(0x4506)
			&&get_u_int32_t(packet->payload, 4)==htonl(0x302e3132)
			){
				flow->qiannyh_stage++;
				return;
			}
		if(flow->qiannyh_stage==1
			&&get_u_int32_t(packet->payload, 0)==htonl(0x68005300)
			){
				NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"found qiannyh-----tcp0 \n");
				ndpi_int_qiannyh_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
                return;
			}
		
	}
    if(packet->payload_packet_len >=16*5
        &&get_u_int32_t(packet->payload,0)==htonl(0x16030101)
        &&packet->payload[4]==0x38
        &&packet->payload[8]==0x34
        &&memcmp(&packet->payload[4*16+2],STR0XQNYH,NDPI_STATICSTRING_LEN(STR0XQNYH))==0
    ){
				NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"found qiannyh-----tcp1 \n");
				ndpi_int_qiannyh_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
                return;
    }
	NDPI_LOG(NDPI_PROTOCOL_GAME_QIANNYH, ndpi_struct, NDPI_LOG_DEBUG,
										"exclude qiannyh\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_QIANNYH);
	

}

void ndpi_search_qiannyh(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_GAME_QIANNYH, ndpi_struct, NDPI_LOG_DEBUG,
									"search qiannyh \n");
		ndpi_search_qiannyh_tcp(ndpi_struct, flow);
  		}
	
}

#endif

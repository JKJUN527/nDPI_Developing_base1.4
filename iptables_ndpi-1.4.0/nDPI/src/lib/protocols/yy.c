/*
 * yy.c
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


#include "ndpi_protocols.h"i

#ifdef NDPI_PROTOCOL_YY

/*
jkjun:
1
          66 00 00 00 04 32 00 00  c8 00 40 00 d6 9f 24 62   f....2.. ..@...$b
00000010  96 ed d7 c5 77 26 55 61  00 58 a0 29 41 1c a7 31   ....w&Ua .X.)A..1
00000020  0b 46 4f 4c cd 5f 8e 5f  da 28 2a 3d e0 f6 0c 23   .FOL._._ .(*=...#
00000030  6c 3c 1a 5e a3 f1 ae 3a  00 b6 31 5b bf 50 81 48   l<.^...: ..1[.P.H
00000040  17 4b 68 f0 a1 ff b0 dd  e1 c6 d9 ed 01 00 03 13   .Kh..... ........
00000050  00 00 00 13 00 00 00 04  e8 0b 00 c8 00 00 00 05   ........ ........
00000060  00 6c 6f 67 69 6e                                  .login
    00000000  2c 09 00 00 04 33 00 00  c8 00 40 00 c8 a1 2e c9   ,....3.. ..@.....
2
00000000  53 00 00 00 04 11 00 00  c8 00 40 00 c7 d7 7b 85   S....... ..@...{.
00000010  0f cc c8 95 07 da f2 ae  fe 2e dd 80 fb 32 29 b0   ........ .....2).
00000020  fa 36 f6 03 09 68 2e ff  71 6a 59 c6 1c 76 3f b9   .6...h.. qjY..v?.
00000030  4d 30 1d 9c 99 e3 d7 b5  da 33 3d 75 d6 9c 12 9b   M0...... .3=u....
00000040  98 3a 86 10 1e 9c 2b 19  0a 8c 05 3d 01 00 03 00   .:....+. ...=....
00000050  00 00 00                                           ...
    00000000  50 00 00 00 04 15 00 00  c8 00 40 00 4c 10 07 72   P....... ..@.L..r
    00000010  46 8d 5a a3 18 1b f4 8a  fe bb be 54 47 7a 42 9b   F.Z..... ...TGzB.
    00000020  57 9f 0a 58 8f 01 c6 b5  e9 61 67 38 cf ce d5 6a   W..X.... .ag8...j
    00000030  81 7a cd 71 c8 d7 bb 7a  82 1b ce ec b9 80 19 6d   .z.q...z .......m
    00000040  d0 e9 ee bf 46 d0 b3 ca  ae 70 ab 3f 00 00 00 00   ....F... .p.?....
*/

static void ndpi_int_yy_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_YY, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
#define STR0YY "\x66\x00\x00\x00\x04\x32\x00\x00\xc8\x00\x40\x00"
#define STR1YY "\x00\x6c\x6f\x67\x69\x6e"

//#define STR1FUNSHION "\x32\x91\x9d\x59\x30\x1e\x30\x07\x30\x0e\x31\x1f\x18\xf5\x30\x1e"	 
void ndpi_search_yy_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if(packet->payload_packet_len >= (6 * 16 + 6) ){
		if(memcmp(&packet->payload[0],STR0YY,NDPI_STATICSTRING_LEN(STR0YY))==0
			&&memcmp(&packet->payload[6*16],STR1YY,NDPI_STATICSTRING_LEN(STR1YY))==0){
				flow->yy_stage = 1;	
				NDPI_LOG(NDPI_PROTOCOL_YY, ndpi_struct, NDPI_LOG_DEBUG,"yy_stage:%u",flow->yy_stage)
				return;
			}
		if(flow->yy_stage==1
			&&get_u_int32_t(packet->payload, 4)==htonl(0x04330000)
			&&get_u_int32_t(packet->payload, 8)==htonl(0xc8004000)){
				NDPI_LOG(NDPI_PROTOCOL_YY, ndpi_struct, NDPI_LOG_DEBUG,"found yy------1 \n");
				ndpi_int_yy_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;				
			}
	}
	if(packet->payload_packet_len >=(16)
	  &&packet->payload_packet_len == packet->payload[0]
	  &&packet->payload[4]==0x04
	  &&get_u_int32_t(packet->payload,8)==htonl(0xc8004000)	
	){
				NDPI_LOG(NDPI_PROTOCOL_YY, ndpi_struct, NDPI_LOG_DEBUG,"found yy------2 \n");
				ndpi_int_yy_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;				
	}
	NDPI_LOG(NDPI_PROTOCOL_YY, ndpi_struct, NDPI_LOG_DEBUG, "exclude yy.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_YY);
}
void ndpi_search_yy(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_YY, ndpi_struct, NDPI_LOG_DEBUG,
									"search yy tcp\n");
		ndpi_search_yy_tcp(ndpi_struct, flow);
	}
}

#endif


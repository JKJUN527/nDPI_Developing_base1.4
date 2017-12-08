/*
 * wendao.c
 *
 * Copyright (C) 2009-2017 by pengtian
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
#ifdef NDPI_PROTOCOL_WENDAO

/*
 PT:
 wendao 1.611.1227
block wendao get server packet 

00000000  4d 5a 00 00 00 82 cb 56  00 64 0b 05 20 36 41 34   MZ.....V .d.. 6A4
00000010  30 45 31 41 31 31 30 39  45 35 44 39 33 36 33 36   0E1A1109 E5D93636
00000020  42 46 30 34 36 45 37 33  38 36 31 44 45 40 32 31   BF046E73 861DE@21
00000030  41 37 36 44 45 36 33 44  37 34 42 44 34 37 45 42   A76DE63D 74BD47EB
00000040  31 32 31 31 46 33 38 32  43 30 38 46 39 43 46 33   1211F382 C08F9CF3
00000050  39 35 38 35 34 45 46 31  46 41 32 37 36 35 41 33   95854EF1 FA2765A3
00000060  45 32 38 34 37 39 41 33  39 33 46 44 42 41         E28479A3 93FDBA
    00000000  4d 5a 00 00 00 00 00 00  00 08 1b 06 00 00 00 00   MZ...... ........
    00000010  01 01                                              ..
0000006E  4d 5a 00 00 00 82 cb 94  00 03 1b 03 00            MZ...... .....
    00000012  4d 5a 00 00 00 00 00 00  00 0f 2b 04 00 00 00 01   MZ...... ..+.....
    00000022  07 31 32 39 36 32 37 34  00                        .1296274 .
    0000002B  4d 5a 00 00 00 00 00 00  00 06 20 d2 26 9f 7e 09   MZ...... .. .&.~.
0000007B  4d 5a 00 00 00 82 cf bb  00 06 f9 c3 00 82 cf bb   MZ...... ........
0000008B  4d 5a 00 00 00 82 f2 56  00 0a 20 d2 00 82 f2 56   MZ.....V .. ....V
0000009B  ff ff ff ff                                        ....
    0000003B  4d 5a 00 00 00 00 00 00  00 06 f9 c3 26 9f a0 f6   MZ...... ....&...
    0000004B  4d 5a 00 00 00 00 00 00  00 06 20 d2 26 9f a5 1a   MZ...... .. .&...
0000009F  4d 5a 00 00 00 82 f6 cb  00 06 f9 c3 00 82 f6 cb   MZ...... ........
000000AF  4d 5a 00 00 00 83 19 86  00 0a 20 d2 00 83 19 86   MZ...... .. .....
000000BF  26 9f a0 f6                                        &...
    0000005B  4d 5a 00 00 00 00 00 00  00 06 f9 c3 26 9f c8 2e   MZ...... ....&...
    0000006B  4d 5a 00 00 00 00 00 00  00 06 20 d2 26 9f cc 2b   MZ...... .. .&..+
000000C3  4d 5a 00 00 00 83 1d bc  00 06 f9 c3 00 83 1d bc   MZ...... ........
000000D3  4d 5a 00 00 00 83 3b 85  00 8a 23 50 05 61 64 6d   MZ....;. ..#P.adm
000000E3  69 6e 40 45 30 45 46 44  45 38 43 44 41 36 39 42   in@E0EFD E8CDA69B
000000F3  39 42 41 46 37 30 41 45  43 43 41 34 36 34 38 44   9BAF70AE CCA4648D
00000103  30 39 32 36 43 43 41 42  35 31 44 44 44 32 45 38   0926CCAB 51DDD2E8
00000113  44 30 38 34 46 42 46 38  30 33 36 43 32 35 41 36   D084FBF8 036C25A6
00000123  42 43 45 10 30 30 30 30  37 38 34 35 63 34 61 35   BCE.0000 7845c4a5
00000133  66 38 36 66 00 02 7c 31  08 b2 bb cd fc b3 f5 d0   f86f..|1 ........
00000143  c4 00 20 36 31 35 37 37  35 42 36 46 33 37 35 31   .. 61577 5B6F3751
00000153  33 44 38 44 36 33 34 38  35 46 44 45 34 44 30 34   3D8D6348 5FDE4D04
00000163  31 36 34 00                                        164.
    0000007B  4d 5a 00 00 00 00 00 00  00 1c 53 51 00 00 00 03   MZ...... ..SQ....
    0000008B  00 00 00 00 00 10 d5 ca  ba c5 ba cd c3 dc c2 eb   ........ ........
    0000009B  b2 bb c6 a5 c5 e4                                  ......

*/



static void ndpi_int_wendao_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WENDAO, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_wendao_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_WENDAO, ndpi_struct, NDPI_LOG_DEBUG, "search for wendao.\n");
	NDPI_LOG(NDPI_PROTOCOL_WENDAO, ndpi_struct, NDPI_LOG_DEBUG, "payload len:%u. wendaostage:%u\n",packet->payload_packet_len,flow->wendao_stage);

	if( packet->payload_packet_len >= 16 &&
		(( ndpi_mem_cmp(packet->payload,"\x4d\x5a",2) == 0 && packet->payload[8]==0x00 )
		||(ndpi_mem_cmp(packet->payload,"\x4d\x5a\x00\x00",4) == 0))
		
	){
			flow->wendao_stage++;
			NDPI_LOG(NDPI_PROTOCOL_WENDAO, ndpi_struct, NDPI_LOG_DEBUG,"add wendao_stage:%u\n",flow->wendao_stage);
			
			if(flow->wendao_stage >= 2 ){  
				ndpi_int_wendao_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				NDPI_LOG(NDPI_PROTOCOL_WENDAO, ndpi_struct, NDPI_LOG_DEBUG,"found wendao\n");
			}
			return;
	}

	NDPI_LOG(NDPI_PROTOCOL_WENDAO, ndpi_struct, NDPI_LOG_DEBUG,
									"exclude wendao\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WENDAO);

}

void ndpi_search_wendao(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_wendao_tcp(ndpi_struct, flow);
	}
}

#endif

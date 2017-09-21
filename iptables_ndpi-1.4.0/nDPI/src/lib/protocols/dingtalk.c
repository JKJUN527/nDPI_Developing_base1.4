/*
 * dingtalk.c
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
/*
00000050  00 01 00 00 00 00 11 00  0f 00 00 0c 67 2e 61 6c   ........ ....g.al
00000060  69 63 64 6e 2e 63 6f 6d  00 17 00 00 00 23 00 00   icdn.com .....#..

00000050  00 01 00 00 00 00 14 00  12 00 00 0f 79 6e 75 66   ........ ....ynuf
00000060  2e 61 6c 69 70 61 79 2e  63 6f 6d 00 17 00 00 00   .alipay. com.....

00000050  00 01 00 00 00 00 1f 00  1d 00 00 1a 63 6c 6f 75   ........ ....clou
00000060  64 64 61 74 61 2e 64 69  6e 67 74 61 6c 6b 61 70   ddata.di ngtalkap

00000000  10 53 87 80 01 00 01 00  02 00 02 64 6b 03 00 20   .S...... ...dk.. 
00000010  b6 21 54 70 0f f4 fc fc  03 c2 f4 f3 17 0f ee 7b   .!Tp.... .......{
00000020  51 5b d5 13 0d 7a 05 bb  6b 86 74 49 94 b2 61 49   Q[...z.. k.tI..aI
00000030  04 00 08 16 42 ac 04 a2  59 78 93 05 00 08 03 75   ....B... Yx.....u
00000040  9b e6 b4 2c 88 25 82 00  02 57 4b 84 00 09 57 4b   ...,.%.. .WK...WK
00000050  2f 70 31 2e 30 2e 30                               /p1.0.0
*/

#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_DINGTALK
#define STR0DING "\x10\x53\x87\x80\x01\x00\x01\x00\x02\x00\x02\x64\x6b\x03\x00\x20"
#define STR1DING "\x2f\x70\x31\x2e\x30"

static void ndpi_int_dingtalk_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DINGTALK, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_dingtalk_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if(packet->payload_packet_len >=5*16+7){
		if(memcmp(&packet->payload[0],STR0DING,NDPI_STATICSTRING_LEN(STR0DING)) == 0
	  	   && memcmp(&packet->payload[5*16],STR1DING,NDPI_STATICSTRING_LEN(STR1DING)) == 0
		){
			NDPI_LOG(NDPI_PROTOCOL_DINGTALK, ndpi_struct, NDPI_LOG_DEBUG,"find dingtalk 1");
			ndpi_int_dingtalk_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
		}
	}
	if(packet->payload_packet_len >= (160) 
	){
		NDPI_LOG(NDPI_PROTOCOL_DINGTALK, ndpi_struct, NDPI_LOG_DEBUG,"payload[64696e67]:%x%x%x%x \n",packet->payload[125],packet->payload[126],packet->payload[127],packet->payload[128]);
		if(get_u_int32_t(packet->payload, 125) == htonl(0x64696e67)
		   ||get_u_int32_t(packet->payload, 222) == htonl(0x64696e67)
		   ||get_u_int64_t(packet->payload, 92) == htonl(0x796e75662e616c69)
		   ||get_u_int32_t(packet->payload, 92) == htonl(0x672e616c)
		   ||get_u_int32_t(packet->payload, 102) == htonl(0x64696e67)){
			NDPI_LOG(NDPI_PROTOCOL_DINGTALK, ndpi_struct, NDPI_LOG_DEBUG,"payload[222:64]:%x",packet->payload[222]);
			ndpi_int_dingtalk_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
		}else{
			NDPI_LOG(NDPI_PROTOCOL_DINGTALK, ndpi_struct, NDPI_LOG_DEBUG, "exclude dingtalk.\n");
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DINGTALK);
			
		}
	}
}
void ndpi_search_dingtalk(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_DINGTALK, ndpi_struct, NDPI_LOG_DEBUG,
									"search dingtalk tcp\n");
		ndpi_search_dingtalk_tcp(ndpi_struct, flow);
	}

}

#endif

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
*/

#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_DINGTALK

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


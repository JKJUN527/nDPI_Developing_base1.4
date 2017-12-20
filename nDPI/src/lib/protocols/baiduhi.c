/*
 * baiduhi.c
 *
 * Copyright (C) 2009-2016 by   pengtianabc@hotmail.com
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
#ifdef NDPI_PROTOCOL_BAIDUHI

/*
 PT:
 baiduhi SSL
 - == -
00 00 01 00 31 56 4d 49  __ 00 00 00 __ __ 00 00
__ 0- 00 00 __ 0- 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
*/

static void ndpi_int_baiduhi_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow )
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_BAIDUHI, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_int_search_baiduhi_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_BAIDUHI, ndpi_struct, NDPI_LOG_DEBUG,
											"search baiduhi in baiduhi.c \n");
	if(packet->actual_payload_len >= 40 
	&& (get_u_int32_t(packet->payload, 0) == htonl(0x00000100))){
		NDPI_LOG(NDPI_PROTOCOL_BAIDUHI, ndpi_struct, NDPI_LOG_DEBUG,
											"may baiduhi in baiduhi.c \n");

	}
	if(packet->actual_payload_len >= 40 
	&& (get_u_int32_t(packet->payload, 0) == htonl(0x00000100))
	&& (get_u_int32_t(packet->payload, 4) == htonl(0x31564d49))
	&& packet->payload[9] == 0x00
	&& (ntohs(get_u_int16_t(packet->payload, 10)) == 0x0000)
	&& (ntohs(get_u_int16_t(packet->payload, 18)) == 0x0000)
	&& packet->payload[2*8 + 1] == packet->payload[2*8 + 5]
	&& (ntohs(get_u_int16_t(packet->payload, 2*8 + 6 )) == 0x0000)
	&& (get_u_int64_t(packet->payload, 8*3 ) == htonl(0x0000000000000000))
	&& (get_u_int64_t(packet->payload, 8*4 ) == htonl(0x0000000000000000))){
	
		NDPI_LOG(NDPI_PROTOCOL_BAIDUHI, ndpi_struct, NDPI_LOG_DEBUG,
									"found baiduhi in baiduhi.c\n");
		ndpi_int_baiduhi_add_connection(ndpi_struct, flow);
	}else{
		NDPI_LOG(NDPI_PROTOCOL_BAIDUHI, ndpi_struct, NDPI_LOG_DEBUG, "exclude baiduhi.\n");
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_BAIDUHI);

	}
}

void ndpi_search_baiduhi(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_int_search_baiduhi_tcp(ndpi_struct, flow);
	}
}

#endif

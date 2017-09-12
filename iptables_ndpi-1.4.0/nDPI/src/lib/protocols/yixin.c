/*
 * yixin.c
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
#ifdef NDPI_PROTOCOL_YIXIN

/*
 PT:
 yixin
	yixin.im
	YX-PN: yxmc
	User-Agent: NETEASE-YIXIN     => http.c
	
	登陆：1 c-s (9305500a00000dc800000000000000000000000000)：
	00000000  93 05 50 0a 00 00 0d c8  00 00 00 00 00 00 00 00   ..P..... ........
	00000010  00 00 00 00 00 ————————  ———————————————————————   .....*3. ....L..5
*/

#define STR0AT0 "\x93\x05\x50\x0a\x00\x00\x0d\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

static void ndpi_int_yixin_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_YIXIN, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_yixin_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (memcmp(&packet->payload[0], STR0AT0, NDPI_STATICSTRING_LEN(STR0AT0)) == 0){
	
		NDPI_LOG(NDPI_PROTOCOL_YIXIN, ndpi_struct, NDPI_LOG_DEBUG,
									"found yixin \n");
		ndpi_int_yixin_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	}
}

void ndpi_search_yixin(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_yixin_tcp(ndpi_struct, flow);
	}
}

#endif

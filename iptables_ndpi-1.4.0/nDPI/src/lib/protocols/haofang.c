/*
 * haofang.c
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
#ifdef NDPI_PROTOCOL_HAOFANG

/*
 PT:
 haofang 
 remote port 1201,1203
*/



static void ndpi_int_haofang_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HAOFANG, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_haofang_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_HAOFANG, ndpi_struct, NDPI_LOG_DEBUG, "search for haofang port.\n");
	u_int16_t sport = ntohs(packet->tcp->source);
	u_int16_t dport = ntohs(packet->tcp->dest);
	  
	if(	 (sport == 1201) 
	  || (dport == 1201)
	  || (sport == 1203) 
	  || (dport == 1203)
	){  
		ndpi_int_haofang_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		NDPI_LOG(NDPI_PROTOCOL_HAOFANG, ndpi_struct, NDPI_LOG_DEBUG,"found haofang port\n");
		return;
	}

	NDPI_LOG(NDPI_PROTOCOL_HAOFANG, ndpi_struct, NDPI_LOG_DEBUG,
									"exclude haofang\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HAOFANG);

}

void ndpi_search_haofang(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_haofang_tcp(ndpi_struct, flow);
	}
}

#endif

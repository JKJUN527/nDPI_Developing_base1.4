/*
 * fetion.c
 *BY--JKJUN
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
#ifdef NDPI_PROTOCOL_FETION

/*
NEG fetion.com.cn SIP-C/4.0
F: 1994880749
I: 1
Q: 1 NEG
A: com

SIP-C/4.0 201 Successful
F: 1994880749
I: 1
Q: 1 NEG
W: com
*/

static void ndpi_int_fetion_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FETION, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_fetion_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if(packet->payload_packet_len >= NDPI_STATICSTRING_LEN("NEG fetion.com.cn SIP-C/4.0")){
		if(memcmp(packet->payload, "NEG fetion.com.cn", 17) == 0
		 || memcmp(packet->payload, "SIP-C/4.0", 9) == 0){
		NDPI_LOG(NDPI_PROTOCOL_FETION, ndpi_struct, NDPI_LOG_DEBUG,
									"found fetion------1 \n");
		ndpi_int_fetion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		}
	}
	NDPI_LOG(NDPI_PROTOCOL_FETION, ndpi_struct, NDPI_LOG_DEBUG, "exclude funshion.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FETION);
}

void ndpi_search_fetion(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_FETION, ndpi_struct, NDPI_LOG_DEBUG,
									"search fetion tcp \n");
		ndpi_search_fetion_tcp(ndpi_struct, flow);
	}
}

#endif

/*
 * eudemons.c
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
#ifdef NDPI_PROTOCOL_GAME_EUDEMONS

/*

*/

#define STR0EUD "\x22\x87\xd7\xcf"
#define STR1EUD "\x6e\xb7\x16\xcf\xa1\x87\xa9\x8f"

static void ndpi_int_eudemons_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_EUDEMONS, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_eudemons_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if(packet->payload_packet_len==8
		&&memcmp(&packet->payload[0], STR0EUD, NDPI_STATICSTRING_LEN(STR0EUD)) == 0
		){
			NDPI_LOG(NDPI_PROTOCOL_GAME_EUDEMONS, ndpi_struct, NDPI_LOG_DEBUG,"found Eudemons first packet \n");
			flow ->eudemons_stage++;
			return;
	}else if(packet->payload_packet_len >=16
			&&flow->eudemons_stage==1
			&&memcmp(&packet->payload[0],STR1EUD, NDPI_STATICSTRING_LEN(STR1EUD))==0){
			NDPI_LOG(NDPI_PROTOCOL_GAME_EUDEMONS, ndpi_struct, NDPI_LOG_DEBUG,"found EUDEMONS \n");
			ndpi_int_eudemons_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
	}
	NDPI_LOG(NDPI_PROTOCOL_GAME_EUDEMONS, ndpi_struct, NDPI_LOG_DEBUG, "exclude EUDEMONS.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_EUDEMONS);
	
}

void ndpi_search_eudemons(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_eudemons_tcp(ndpi_struct, flow);
	}
}

#endif


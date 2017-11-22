
/*
 * cf.c
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
#ifdef NDPI_PROTOCOL_GAME_CF


static void ndpi_int_game_cf_add_connection(struct ndpi_detection_module_struct *ndpi_struct,struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_CF, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
 void ndpi_search_game_cf_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"search game_cf\n");
	//48 0d 03 fd 00 00 00 0c
	if(packet->payload_packet_len == 1460
	&& get_u_int32_t(packet->payload, 0)==htonl(0xf1a00601)
	&& get_u_int16_t(packet->payload, 4)==htons(0x0000)
    && packet->payload[9]==0x0c
	&& get_u_int16_t(packet->payload, 10)==htons(0x0001)
	&& get_u_int16_t(packet->payload, 16)==htons(0x0070)	
	){	
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------1 \n");
		ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;	
	}
  	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG, "exclude game_cf.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_CF);
}

void ndpi_search_game_cf(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {

		ndpi_search_game_cf_tcp(ndpi_struct, flow);
	}

}

#endif

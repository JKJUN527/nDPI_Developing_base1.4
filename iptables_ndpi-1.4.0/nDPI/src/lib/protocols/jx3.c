/*
 * jx3.c
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
#ifdef NDPI_PROTOCOL_GAME_JX3

/*

*/
static void ndpi_int_jx3_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_JX3, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_jx3_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int8_t a ;
	NDPI_LOG(NDPI_PROTOCOL_GAME_JX3, ndpi_struct, NDPI_LOG_DEBUG, "jx3_packet[0]:%x,jx3_len:%x\n",packet->payload[0],packet->payload_packet_len);
	
	ndpi_parse_packet_line_info_unix(ndpi_struct, flow);
	NDPI_LOG(NDPI_PROTOCOL_GAME_JX3, ndpi_struct, NDPI_LOG_DEBUG, "[jx3_lines:]: %u.\n",packet->parsed_unix_lines);
    	for (a = 0; a < packet->parsed_unix_lines; a++) {      		
      		NDPI_LOG(NDPI_PROTOCOL_GAME_JX3, ndpi_struct, NDPI_LOG_DEBUG, "[line_len:]: %u.\n",packet->unix_line[a].len);
		if(packet->unix_line[a].len >12 
		  &&strstr(packet->unix_line[a].ptr,"jx3")){
			NDPI_LOG(NDPI_PROTOCOL_GAME_JX3, ndpi_struct, NDPI_LOG_DEBUG, "found jx3_tcp1 \n");
			ndpi_int_jx3_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
 			return;
		}
		continue;
	}
	
	if(packet->payload_packet_len == packet->payload[0]){
		
		if(get_u_int32_t(packet->payload, 0)==htonl(0x2c002000)
			||get_u_int16_t(packet->payload, 0)==htons(0xbf00)
			||get_u_int16_t(packet->payload, 0)==htons(0x1000)
			||get_u_int16_t(packet->payload, 0)==htons(0xa300)
			||get_u_int16_t(packet->payload, 0)==htons(0x0700)
			||get_u_int16_t(packet->payload, 0)==htons(0x5e00)){
				flow->jx3_stage++;
			NDPI_LOG(NDPI_PROTOCOL_GAME_JX3, ndpi_struct, NDPI_LOG_DEBUG, "jx3_stage:%u,jx3_count:%u\n",flow->jx3_stage,flow->packet_counter);
			}
		if(flow->jx3_stage >=2 && flow->packet_counter < 5){
			NDPI_LOG(NDPI_PROTOCOL_GAME_JX3, ndpi_struct, NDPI_LOG_DEBUG, "found jx3_tcp2\n");
			ndpi_int_jx3_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			}
		return;
	}else{
		NDPI_LOG(NDPI_PROTOCOL_GAME_JX3, ndpi_struct, NDPI_LOG_DEBUG, "exclude jx3.\n");
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_JX3);
	}
}

void ndpi_search_jx3(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_jx3_tcp(ndpi_struct, flow);
	}
}

#endif


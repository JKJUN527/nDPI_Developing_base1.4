/*
 * youku.c
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
#ifdef NDPI_PROTOCOL_YOUKU

/*


*/
#define STR0YOUKU "\x73\x74\x61\x74\x69\x63\x2e\x79\x6f\x75\x6b\x75\x2e\x63\x6f\x6d"
#define STR1YOUKU "\x79\x6b\x72\x65\x63\x2e\x79\x6f\x75\x6b\x75\x2e\x63\x6f\x6d"
static void ndpi_int_youku_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_YOUKU, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_youku_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
      	//ndpi_parse_packet_line_info(ndpi_struct, flow);
      	//u_int8_t a ;

	//flow->youku_http_stage++;
	if( (packet->payload_packet_len >= 16 
		&& packet->payload[0] == 0x4b 
    		&& packet->payload[1] == 0x55
    		&& packet->payload[2] == 0x00)
	   ||(packet->payload_packet_len >=112
		&&packet->payload[0]==0x16
		&&packet->payload[1]==0x03
		&&(memcmp(&packet->payload[5*16+9], STR0YOUKU, NDPI_STATICSTRING_LEN(STR0YOUKU)) == 0
		   ||memcmp(&packet->payload[5*16+9], STR1YOUKU, NDPI_STATICSTRING_LEN(STR1YOUKU)) == 0))
		){
	
		NDPI_LOG(NDPI_PROTOCOL_YOUKU, ndpi_struct, NDPI_LOG_DEBUG,"youku found tcp youku---[0]: %x     [1]:%x   [2] :%x  ---1 \n",packet->payload[0],packet->payload[1],packet->payload[2]);
		ndpi_int_youku_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
}

void ndpi_search_youku_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if((packet->payload_packet_len >= 16 
		&& packet->payload[0] == 0x4b
		&& packet->payload[1] == 0x55
		&& packet->payload[2] == 0x00
		&& packet->payload[9] == 0x00
        	&& packet->payload[13] == 0x00)
        || (packet->payload[0] == 0x4b
		&& packet->payload[1] == 0x55
		&& packet->payload[2] == 0x00)){
	
		//NDPI_LOG(NDPI_PROTOCOL_YOUKU, ndpi_struct, NDPI_LOG_DEBUG,"found udp youku------1 \n");
		NDPI_LOG(NDPI_PROTOCOL_YOUKU, ndpi_struct, NDPI_LOG_DEBUG,"youku found udp youku---[0]: %x     [1]:%x   [2] :%x  ---1 \n",packet->payload[0],packet->payload[1],packet->payload[2]);
		ndpi_int_youku_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
  		NDPI_LOG(NDPI_PROTOCOL_YOUKU, ndpi_struct, NDPI_LOG_DEBUG, "exclude youku udp.\n");
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_YOUKU);
}
void ndpi_search_youku(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_YOUKU, ndpi_struct, NDPI_LOG_DEBUG,
									"search tcp youku \n");
		ndpi_search_youku_tcp(ndpi_struct, flow);
	}
	else if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_YOUKU, ndpi_struct, NDPI_LOG_DEBUG,
									"search udp youku \n");
		ndpi_search_youku_udp(ndpi_struct, flow);
	}
}

#endif

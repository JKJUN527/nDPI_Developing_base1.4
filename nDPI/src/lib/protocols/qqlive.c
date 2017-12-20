/*
 * qqlive.c
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
#ifdef NDPI_PROTOCOL_QQLIVE

/*

*/
#define STR0QQLIVE "\x6c\x74\x73\x64\x6c\x2e\x71\x71\x2e\x63\x6f\x6d"
#define STR1QQLIVE "\x6c\x74\x73\x62\x73\x79\x2e\x71\x71\x2e\x63\x6f\x6d"

static void ndpi_int_qqlive_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QQLIVE, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_qqlive_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if(packet->payload_packet_len >= 16 && (
		  (packet->payload[0] == 0x26
		&& packet->payload[1] == 0x00
		&& packet->payload[2] == 0x00
		&& packet->payload[5] == 0x01
		&& packet->payload[6] == 0x00
		&& packet->payload[7] == 0x00)
	//|| (packet->payload[0] == 0x26
	//	&& packet->payload[1] == 0x00
	//	&& packet->payload[2] == 0x00)
	//|| (packet->payload[12] == 0x06
	//	&& packet->payload[13] == 0x10)
	//|| (packet->payload[0] == 0xd8
	//	&& packet->payload[1] == 0x5c
	//	&& packet->payload[2] == 0x00)
	|| (memcmp(&packet->payload[14*16+1], STR0QQLIVE, NDPI_STATICSTRING_LEN(STR0QQLIVE)) == 0)
	|| (memcmp(&packet->payload[4*16+9], STR1QQLIVE, NDPI_STATICSTRING_LEN(STR1QQLIVE)) == 0))
	){
	
		NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG,"qqlive found tcp qqlive---[0]: %x     [1]:%x   [2] :%x  ---1 \n",packet->payload[0],packet->payload[1],packet->payload[2]);
		ndpi_int_qqlive_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
	if(packet->payload_packet_len >=32
          &&packet->payload[0]==0x16
	  &&packet->payload[1]==0x03
	){
		int a;
		for(a=32;a<packet->payload_packet_len;a++){
			if(memcmp(&packet->payload[a], STR0QQLIVE, NDPI_STATICSTRING_LEN(STR0QQLIVE)) == 0
			   ||memcmp(&packet->payload[a], STR1QQLIVE, NDPI_STATICSTRING_LEN(STR1QQLIVE)) == 0){
				NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG,"qqlive found tcp qqlive \n");
				ndpi_int_qqlive_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;			
			}
		}
	}
  		NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG, "exclude qqlive tcp.\n");
 		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QQLIVE);
}

void ndpi_search_qqlive_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if(packet->payload_packet_len >= 16 
	&& (//(packet->payload[0] == 0x1a
		//&& (packet->payload[1] == 0x10
		//	|| packet->payload[1] == 0x1c)
		//&& (packet->payload[2] == 0x01 
		//	|| packet->payload[2] == 0x20))
	 (packet->payload[0] == 0x26
		&& packet->payload[1] == 0x00
		&& packet->payload[2] == 0x00)
	|| (packet->payload[7] == 0x4c
		&& packet->payload[8] == 0x51
		&& packet->payload[11] == 0x61))
    ){
	
		//NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG,"found udp qqlive------1 \n");
		NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG,"qqlive found udp qqlive---[0]: %x     [1]:%x   [2] :%x  ---1 \n",packet->payload[0],packet->payload[1],packet->payload[2]);
		ndpi_int_qqlive_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
  		NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG, "exclude qqlive udp.\n");
 		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QQLIVE);
}
void ndpi_search_qqlive(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG,
									"search udp qqlive \n");
		ndpi_search_qqlive_udp(ndpi_struct, flow);
	}
	else if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG,
									"search tcp qqlive \n");
		ndpi_search_qqlive_tcp(ndpi_struct, flow);
	}
}

#endif

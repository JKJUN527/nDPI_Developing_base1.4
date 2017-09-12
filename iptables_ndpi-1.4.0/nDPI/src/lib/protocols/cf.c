
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
	if(packet->payload_packet_len >= 8
	&& (packet->payload[0] == 0x48
	&& packet->payload[1]  == 0x0d
	&& packet->payload[2]  == 0x03
	//&& packet->payload[3]  == 0xfd
	&& packet->payload[4]  == 0x00
	&& packet->payload[5]  == 0x00
	&& packet->payload[6]  == 0x00
	&& packet->payload[7]  == 0x0c)){
	
	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------2 \n");
	ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;	
	}
	//00 00 00 xx 43 55 00 07
	else if(packet->payload_packet_len >= 9
	&& (packet->payload[0] == 0x00
	&& packet->payload[1]  == 0x00
	&& packet->payload[2]  == 0x00
	//&& packet->payload[3]  == 0x40
	&& packet->payload[4]  == 0x43
	&& packet->payload[5]  == 0x55
	&& packet->payload[6]  == 0x00
	//&& packet->payload[7]  == 0x07
	&& packet->payload[8]  == 0x00)){
	
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------3 \n");
		ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;
	}
	//55 0e 03 00 00 00 00 95
	else if(packet->payload_packet_len >= 11 
	&& (packet->payload[0] == 0x55
	&& packet->payload[1]  == 0x0e
	//&& packet->payload[2]  == 0x03
	//&& packet->payload[3]  == 0x00
	&& packet->payload[4]  == 0x00
	&& packet->payload[5]  == 0x00
	&& packet->payload[6]  == 0x00
	//&& packet->payload[7]  == 0x95
	&& packet->payload[8]  == 0x00
	&& packet->payload[9]  == 0x00
	&& packet->payload[10]  == 0x00
	)){
	
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------4 \n");
		ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;
	}
	else if(packet->payload_packet_len >= 16
	&& (packet->payload[0] == 0x01 && packet->payload[1]  == 0x00
	&& packet->payload[2]  == 0x00 && packet->payload[3]  == 0x00
	&& packet->payload[10]  == 0x07 && packet->payload[11]  == 0x5b
	&& packet->payload[12]  == 0xcd && packet->payload[13]  == 0x15)){
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------5 \n");
		ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;
	}
	else if(packet->payload_packet_len >= 16
	&& (packet->payload[0] == 0x01 && packet->payload[1]  == 0x00
	&& packet->payload[2]  == 0x00 && packet->payload[3]  == 0x00
	&& packet->payload[6]  == 0x00 && packet->payload[7]  == 0x00
	&& packet->payload[14]  == 0x00 && packet->payload[15]  == 0x00)){
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------6 \n");
		ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;
	}
	//d8 5c 00 d2 00 01 17 56
	//d8 5d 00 14 00 01 17 56
	else if(packet->payload_packet_len >= 12
	&& (packet->payload[0] == 0xd8
	//&& (packet->payload[1] == 0x5c
	//|| packet->payload[1]  == 0x5d)
	//&& packet->payload[2]  == 0x00
	//&& (packet->payload[3] == 0xd2
	//|| packet->payload[3]  == 0x14)
	&& packet->payload[4]  == 0x00
	&& packet->payload[5]  == 0x01
	//&& packet->payload[6]  == 0x17
	&& packet->payload[8]  == 0x00
	&& packet->payload[9]  == 0x00
	&& packet->payload[10]  == 0x00
	&& packet->payload[11]  == 0x00
	)){
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------7 \n");
		ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;
	}
	else if(packet->payload_packet_len >= 8
	&& (packet->payload[0] == 0x44
	&& packet->payload[1] == 0x55
	&& packet->payload[2]  == 0x20
	&& packet->payload[3] == 0x88
	&& packet->payload[4]  == 0x08
	&& packet->payload[6]  == 0x00
	&& packet->payload[7]  == 0x00
	&& packet->payload[8]  == 0x00
	)){
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------8 \n");
		ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;
	}
	else if(packet->payload_packet_len >= 9
	&& (packet->payload[0] == 0x00
	&& packet->payload[1] == 0x02
	//|| packet->payload[1]  == 0x5d)
	&& packet->payload[2]  == 0x82
	&& packet->payload[3] == 0x83
	//|| packet->payload[3]  == 0x14)
	&& packet->payload[4]  == 0x00
	&& packet->payload[5]  == 0x08
	&& packet->payload[6]  == 0x00
	&& packet->payload[8]  == 0x00
	)){
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------9 \n");
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

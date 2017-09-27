/*
 * csgo.c
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
#ifdef NDPI_PROTOCOL_GAME_CSGO

/*
csgo 流量

*/

static void ndpi_int_csgo_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_CSGO, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
#define STR0CSGO "\x01\x00\x73\x64\x70\x69\x6e\x67"
#define STR1CSGO "\x02\x12\x54\x6c\x74\x61\x00\x6d\x6f\x62\x00\x62\x78\x64\x00\x74"	
#define STR2CSGO "\x00\x42\x43\x49\x55\x51\x41\x57\x52\x44\x42\x4f\x49\x43\x41\x00"//探测局域网联机主机	
void ndpi_search_csgo_udp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if(packet->payload_packet_len >= 16
             //        ||memcmp(&packet->payload[0],STR1CSGO,NDPI_STATICSTRING_LEN(STR1CSGO))==0)
	){
		if(memcmp(&packet->payload[0],STR0CSGO,NDPI_STATICSTRING_LEN(STR0CSGO))==0
		  ||memcmp(&packet->payload[0],STR2CSGO,NDPI_STATICSTRING_LEN(STR2CSGO))==0
		){
			NDPI_LOG(NDPI_PROTOCOL_GAME_CSGO, ndpi_struct, NDPI_LOG_DEBUG,"found csgo------0 \n");
			ndpi_int_csgo_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
		}
		if(get_u_int32_t(packet->payload,0) == htonl(0x56533031)){
		/*	u_int8_t i = 0;
			for(i=0;i<8;i++){
				if(get_u_int16_t(packet->payload,i+8) == htonl(0x2641)
				   ||packet->payload[i+8] == 0x02
				){	
		*/		NDPI_LOG(NDPI_PROTOCOL_GAME_CSGO, ndpi_struct, NDPI_LOG_DEBUG,"found csgo------1 \n");
				ndpi_int_csgo_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;
		//		}
		//	}
		}
		//return;
	}
	NDPI_LOG(NDPI_PROTOCOL_GAME_CSGO, ndpi_struct, NDPI_LOG_DEBUG, "exclude csgo.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_CSGO);
}

void ndpi_search_csgo(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->udp != NULL){
		NDPI_LOG(NDPI_PROTOCOL_GAME_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
									"search csgo udp \n");
		ndpi_search_csgo_udp(ndpi_struct, flow);
	}
}

#endif

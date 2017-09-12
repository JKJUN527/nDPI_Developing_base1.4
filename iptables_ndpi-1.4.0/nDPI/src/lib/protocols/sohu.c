/*
 * sohu.c
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
#ifdef NDPI_PROTOCOL_SOHU

/*
00000000 [07]b3 c1[00]b5 00 b5 36  b3 01 b5 02 b7 b1 ec be   .......6 ........
00000010  4c 61 65 68 08 ae ec 59  4a b2 95 ea 6e 76 5a 75   Laeh...Y J...nvZu
00000020  e6 21 00 03 fb dd[00]34 [12 00]f3 58 10 78 d2 9b   .!.....4 ...X.x..
00000030 [10 18 0a]9d 39 3e



*/

static void ndpi_int_sohu_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SOHU, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_sohu_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if(packet->payload_packet_len >= 16 
	&& ((packet->payload[1] == 0x00
		&& packet->payload[2] == 0x2a
		&& packet->payload[4] == 0xf8
		&& packet->payload[5] == 0x5e
		&& packet->payload[3] == 0x3c)

	)){
	
		NDPI_LOG(NDPI_PROTOCOL_SOHU, ndpi_struct, NDPI_LOG_DEBUG,"sohu found tcp sohu---[1<00>]: %x     [2<2a>]:%x   [3<3c>] :%x  ---1 \n",packet->payload[1],packet->payload[2],packet->payload[3]);
		ndpi_int_sohu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
  		NDPI_LOG(NDPI_PROTOCOL_SOHU, ndpi_struct, NDPI_LOG_DEBUG, "exclude sohu tcp.\n");
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOHU);
}

void ndpi_search_sohu_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if((packet->payload_packet_len >= 8 
		&& packet->payload[5] == 0x27
		&& packet->payload[6] == 0x00
		&& packet->payload[7] == 0x00)
        ||(packet->payload_packet_len >= 2
        	&& ((packet->payload[packet->payload_packet_len] == 0x55
        		&& packet->payload[packet->payload_packet_len-1] == 0x55)
        	|| (packet->payload[packet->payload_packet_len-1] == 0x55
        		&& packet->payload[packet->payload_packet_len-2] == 0x55)
        ))){
	
		//NDPI_LOG(NDPI_PROTOCOL_SOHU, ndpi_struct, NDPI_LOG_DEBUG,"found udp sohu------1 \n");
		NDPI_LOG(NDPI_PROTOCOL_SOHU, ndpi_struct, NDPI_LOG_DEBUG,"sohu found udp sohu---[0]: %x     [1]:%x   [2] :%x  ---1 \n",packet->payload[0],packet->payload[1],packet->payload[2]);
		ndpi_int_sohu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
  		NDPI_LOG(NDPI_PROTOCOL_SOHU, ndpi_struct, NDPI_LOG_DEBUG, "exclude sohu udp.\n");
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOHU);
}
void ndpi_search_sohu(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_SOHU, ndpi_struct, NDPI_LOG_DEBUG,
									"search tcp sohu \n");
		ndpi_search_sohu_tcp(ndpi_struct, flow);
	}
	else if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_SOHU, ndpi_struct, NDPI_LOG_DEBUG,
									"search udp sohu \n");
		ndpi_search_sohu_udp(ndpi_struct, flow);
	}
}

#endif

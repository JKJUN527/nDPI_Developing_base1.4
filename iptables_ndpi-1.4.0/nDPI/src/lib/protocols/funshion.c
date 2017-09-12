/*
 * funshion.c
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
#ifdef NDPI_PROTOCOL_FUNSHION

/*
 PT:
 funshion
07394100cd1ccd2acb1dcd1ecd64064e612e7c66d1442e13014778fed1d4ba5501ad070342aa00e812004a274437e68310180a95e01e
0718d100ae02ae34a803ae00af88064e612e7c66d1442e13014778fed1d4ba5501ad060042aa001912004a204437e68310180a92e01e
07b2f100809980af8698809b8228ecbe4c61656808aeec594ab295ea6e765a75e6210003fbdd00341200f3581078d29b10180a9d393e
07aa9100eb35eb03ed34eb37e994812381fc4a5594196e52312df442aa1184aab15f0003fbdd00341200f3581078d29b10180a9d393e
07b3c100b500b536b301b502b7b1ecbe4c61656808aeec594ab295ea6e765a75e6210003fbdd00341200f3581078d29b10180a9d393e
07    00                                                                    00  1200            10180a	
1	  3

00000000 [07]b3 c1[00]b5 00 b5 36  b3 01 b5 02 b7 b1 ec be   .......6 ........
00000010  4c 61 65 68 08 ae ec 59  4a b2 95 ea 6e 76 5a 75   Laeh...Y J...nvZu
00000020  e6 21 00 03 fb dd[00]34 [12 00]f3 58 10 78 d2 9b   .!.....4 ...X.x..
00000030 [10 18 0a]9d 39 3e



*/

static void ndpi_int_funshion_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FUNSHION, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
#define STR0FUNSHION "\x6f\xa1\x9d\x59\x97\x4a\x97"
#define STR1FUNSHION "\x32\x91\x9d\x59\x30\x1e\x30\x07\x30\x0e\x31\x1f\x18\xf5\x30\x1e"	 
void ndpi_search_funshion_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if(packet->payload_packet_len >= 16
	   //&&(get_u_int16_t(packet->payload, 0)==htons(0x0273)||
	//	get_u_int16_t(packet->payload, 0)==htons(0x0528)||
	//	get_u_int16_t(packet->payload, 0)==htons(0x0329))
	   &&packet->payload[3]==0x00
	   &&packet->payload[4]==packet->payload[6]
	   &&packet->payload[4]==packet->payload[10]){
		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"found funshion------0 \n");
		ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}
	
	if(packet->payload_packet_len >= (6 * 8 + 2) 
	//&& (packet->payload[0] == 0x07 || packet->payload[0] == 0x00)
	//&& (packet->payload[5*8] == 0x12
	//&& packet->payload[4*8+6] == 0x00
	//&& (get_u_int16_t(packet->payload, 5*8) == htonl( 0x1200)
	//&& (get_u_int16_t(packet->payload, 6*8) == htonl(0x1018)
	&& (packet->payload[5*8 + 1] == 0x00
	&& packet->payload[6*8]   == 0x10
	&& packet->payload[6*8+1] == 0x18
	&& packet->payload[6*8+2] == 0x0a)){
	
		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,
									"found funshion------1 \n");
		ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}
	if(packet->payload_packet_len >= (6 * 8 + 2) 
	//&& (packet->payload[0] == 0x07 || packet->payload[0] == 0x00)
	//&& (packet->payload[5*8] == 0x60
	//(get_u_int16_t(packet->payload, 5*8) == htonl( 0x0600)
	//&& (get_u_int16_t(packet->payload, 6*8) == htonl(0x1018)
	&& (packet->payload[5*8+1] == 0x00
	&& packet->payload[6*8]   == 0xe0
	&& packet->payload[6*8+1] == 0x00
	&& packet->payload[6*8+2] == 0x0a)){
	
		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,
									"found funshion-----2 \n");
		ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}
	if(packet->payload_packet_len ==26 
	   && get_u_int16_t(packet->payload, 14)==htons(0x0000)
	   && get_u_int16_t(packet->payload, 2*8+5)==htons(0x0000)
	   && get_u_int16_t(packet->payload, 3*8)==htons(0x0000)
	){
		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,
									"found funshion-----5 \n");
		ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}

        if(packet->payload_packet_len ==18
		&& packet->payload[1]>=0x91 && packet->payload[1]<=0x9f
		&& get_u_int16_t(packet->payload, 14)==htons(0x0000)){
		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,
									"found funshion-----3 \n");
		ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}else if(packet->payload_packet_len==54
		||(packet->payload[14]==0x57&&packet->payload[15]==0x83&&packet->payload[22]==0x78&&packet->payload[23]==0x38)
		||(get_u_int16_t(packet->payload, 5*8+6)==htons(0x6ac1)&&get_u_int16_t(packet->payload, 6*8+4)==htons(0x413a))
	){
		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,
									"found funshion-----4 \n");
		ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}

	NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG, "exclude funshion.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FUNSHION);
}
void ndpi_search_funshion_udp(struct ndpi_detection_module_struct*ndpi_struct, struct ndpi_flow_struct *flow)
{
		struct ndpi_packet_struct *packet = &flow->packet;

		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"comming 1 \n");
		if(packet->payload_packet_len >=16
		   && (memcmp(&packet->payload[0],STR0FUNSHION,NDPI_STATICSTRING_LEN(STR0FUNSHION))==0
			||memcmp(&packet->payload[0],STR1FUNSHION,NDPI_STATICSTRING_LEN(STR1FUNSHION))==0)
		){
				NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"found funshion-----udp0 \n");
				ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		}

		if(packet->payload_packet_len >=43
		   && (get_u_int16_t(packet->payload, 2)==htons(0x3759)||get_u_int16_t(packet->payload, 2)==htons(0x4259))
		){
			NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"comming 2 \n");
			if(get_u_int32_t(packet->payload, 32)==ntohl(0x00004000)||get_u_int32_t(packet->payload, 32)==htonl(0x00000000)){
				NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"found funshion-----udp1 \n");
				ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			}
		}
		if(packet->payload_packet_len >=25
		   && get_u_int16_t(packet->payload, 2)==htons(0x4259)
		){
			if(get_u_int32_t(packet->payload, 5)==get_u_int32_t(packet->payload, 5+16)
			   &&packet->payload[5]==packet->payload[3*8]){
				NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"found funshion-----udp2 \n");
				ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			}
		}
		if(packet->payload_packet_len >=24
		   //&&get_u_int16_t(packet->payload, 2)==htons(0x9d59)
		   &&packet->payload[4]==packet->payload[6]
		   &&packet->payload[4]==packet->payload[8]
		   &&packet->payload[4]==packet->payload[14]
		   &&packet->payload[4]==packet->payload[18]
		   &&packet->payload[4]==packet->payload[22]
		   &&packet->payload[4]==packet->payload[24]){
			NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,"found funshion-----udp3 \n");
			ndpi_int_funshion_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		}
		
}
void ndpi_search_funshion(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,
									"search funshion \n");
		ndpi_search_funshion_tcp(ndpi_struct, flow);
  		//NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG, "exclude funshion.\n");
  		//NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FUNSHION);
	}
	if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG,
									"search funshion udp \n");
		ndpi_search_funshion_udp(ndpi_struct, flow);
  		//NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG, "exclude funshion.\n");
  		//NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FUNSHION);
	}
  		//NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG, "exclude funshion.\n");
  		//NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FUNSHION);
}

#endif

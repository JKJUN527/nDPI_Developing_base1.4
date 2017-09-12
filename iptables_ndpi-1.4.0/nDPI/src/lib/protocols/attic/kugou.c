/*
 * kugou.c
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
#ifdef NDPI_PROTOCOL_KUGOU

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

static void ndpi_int_kugou_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_KUGOU, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_kugou_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_KUGOU, ndpi_struct, NDPI_LOG_DEBUG,"search kugou \n");
	
	if( (packet->payload_packet_len >= 32)
	&& (packet->payload[0] == 0x32
	&& packet->payload[25]   == 0x00
	&& (packet->payload[28] == 0x00
	&& packet->payload[29] == 0x00
	&& packet->payload[30] == 0x00
	&& packet->payload[31] == 0x04))){
	
		NDPI_LOG(NDPI_PROTOCOL_KUGOU, ndpi_struct, NDPI_LOG_DEBUG,
									"found kugou------1 \n");
		ndpi_int_kugou_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}
	else if( (packet->payload_packet_len >= 32)
	//&& (packet->payload[0] == 0x32
	//&& packet->payload[25]   == 0x00
	&& (packet->payload[28] == 0x00
	&& packet->payload[29] == 0x00
	&& packet->payload[30] == 0x00
	&& packet->payload[31] == 0x04)){
	
		NDPI_LOG(NDPI_PROTOCOL_KUGOU, ndpi_struct, NDPI_LOG_DEBUG,
									"found kugou-----2 \n");
		ndpi_int_kugou_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return ;
	}

}

void ndpi_search_kugou(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->udp != NULL) {
		ndpi_search_kugou_udp(ndpi_struct, flow);
	}
  		NDPI_LOG(NDPI_PROTOCOL_KUGOU, ndpi_struct, NDPI_LOG_DEBUG, "exclude kugou.\n");
  		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_KUGOU);
}

#endif

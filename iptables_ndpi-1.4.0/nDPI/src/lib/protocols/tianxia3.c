/*
 * tianxia3.c
 *
 * Copyright (C) 2009-2017 by pengtian
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
#ifdef NDPI_PROTOCOL_TIANXIA3

/*
 PT:
 tianxia3 
 NEW Login:
 	pkt1: tcp[20:17]==b7 00 00 00 04 00 0a b2  01 41 50 4b 4f 79 75 63
    new pkt1: tcp[20:17]==b7 00 00 00 05 00 0a b2  01 41 50 4b 4f 79 75 63

	pkt2: tcp[20:8] == 2c 00 00 00 03 00 0a 20

Version=2.0.633
ServerList=https://tx2.update.netease.com/server12.txt?
ServerList2=http://update.tx2.163.com/server12.txt?
UpdateURL=https://tx2.update.netease.com/patch_list9.txt?
UpdateURL2=http://update.tx2.163.com/patch_list9.txt?
UpdateURL3=http://update.tx2.163.com/patch_list9.txt
UpdateURL4=http://update.tx2.163.com:38088/patch_list9.txt?
UpdateURL5=http://update.tx2.163.com:38088/patch_list9.txt


OLD Login: TODOudp....
*/

/*new login*/
#define STR1_AT0 "\xb7\x00\x00\x00\x05\x00\x0a\xb2"
#define STR1_AT0_LEN 8
#define STR2_AT0 "\x2c\x00\x00\x00\x03\x00\x0a\x20"
#define STR2_AT0_LEN 8

static void ndpi_int_tianxia3_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TIANXIA3, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_tianxia3_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_TIANXIA3, ndpi_struct, NDPI_LOG_DEBUG, "search for tianxia3.\n");
	NDPI_LOG(NDPI_PROTOCOL_TIANXIA3, ndpi_struct, NDPI_LOG_DEBUG, "payload len:%u. tianxia3stage:%u\n",packet->payload_packet_len,flow->tianxia3_stage);

	/*new login */
NDPI_LOG(NDPI_PROTOCOL_TIANXIA3, ndpi_struct, NDPI_LOG_DEBUG, "payload-0:%x. payload-8:%x\n",ntohl(get_u_int32_t(packet->payload, 0)),ntohl(get_u_int32_t(packet->payload, 8)));
	if(
		flow->tianxia3_stage == 0
		&&  packet->payload_packet_len >= STR1_AT0_LEN
		&&  ndpi_mem_cmp(packet->payload,STR1_AT0,STR1_AT0_LEN) == 0
		//&&  get_u_int32_t(packet->payload, 0) == htonl(0xb7000000)
		//&&  get_u_int32_t(packet->payload, 8) == htonl(0x0141504b)
	){
		flow->tianxia3_stage++;
		NDPI_LOG(NDPI_PROTOCOL_TIANXIA3, ndpi_struct, NDPI_LOG_DEBUG,
								"add tianxia3_stage:%u\n",flow->tianxia3_stage);
		return;
	}else if (flow->tianxia3_stage == 1 
			&& packet->payload_packet_len >= STR2_AT0_LEN
			&& ndpi_mem_cmp(packet->payload,STR2_AT0,STR2_AT0_LEN) == 0){
		ndpi_int_tianxia3_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		NDPI_LOG(NDPI_PROTOCOL_TIANXIA3, ndpi_struct, NDPI_LOG_DEBUG,"found tianxia3\n");
		return;
	}

	/*TODO old login*/

	NDPI_LOG(NDPI_PROTOCOL_TIANXIA3, ndpi_struct, NDPI_LOG_DEBUG,
									"exclude tianxia3\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TIANXIA3);

}

void ndpi_search_tianxia3(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_tianxia3_tcp(ndpi_struct, flow);
	}
}

#endif

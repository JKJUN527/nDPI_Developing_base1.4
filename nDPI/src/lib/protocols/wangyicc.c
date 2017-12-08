/*
 * wangyicc.c
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
#ifdef NDPI_PROTOCOL_WANGYICC

/*
 PT:
 wangyicc
 	cc.163.com
	User Agent: cc_ext
	# pull.v.cc.163.com
	登陆：1 c-s；tcp[20:42](2a00000001400000000000000000000000000000010000001000dfb05356f9bf4d2d62f695d917eda9ea)
		
	00000000  2a 00 00 00 01 40 00 00  00 00 00 00 00 00 00 00   *....@.. ........
	00000010  00 00 00 00 01 00 00 00  10 00 df b0 53 56 f9 bf   ........ ....SV..
	00000020  4d 2d 62 f6 95 d9 17 ed  a9 ea                     M-b..... ..
		2 s-c：tcp[20:32]:(3000000001400000000000000000000000000000010000000000000000001000)
	00000000  30 00 00 00 01 40 00 00  00 00 00 00 00 00 00 00   0....@.. ........
    00000010  00 00 00 00 01 00 00 00  00 00 00 00 00 00 10 00   ........ ........
    00000020  ————————————————————————————————————————————————   .....E.. .-.....d
		3:
		pass
		4:s-c
	00000030  42 15 59 77 73 d9 b6 2d  ec 19 _________________   B.Yws..- .....M..
    00000040  ________________________________________________   ...Wt_.B ....I...
    00000050  _______________________  01 e3 70 ed 60            ..}....  ..p.`
*/

#define STR1AT0 "\x2a\x00\x00\x00\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x10\x00\xdf\xb0\x53\x56\xf9\xbf\x4d\x2d\x62\xf6\x95\xd9\x17\xed\xa9\xea"

#define STR2AT0 "\x30\x00\x00\x00\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00"

#define STR3AT0 "\x42\x15\x59\x77\x73\xd9\xb6\x2d\xec\x19"
#define STR3AT40 "\x01\xe3\x70\xed\x60"

static void ndpi_int_wangyicc_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WANGYICC, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_wangyicc_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_WANGYICC, ndpi_struct, NDPI_LOG_DEBUG, "search for wangyicc.\n");

	if (
		(packet->payload_packet_len > NDPI_STATICSTRING_LEN(STR1AT0)
		&& memcmp(&packet->payload[0], STR1AT0, NDPI_STATICSTRING_LEN(STR1AT0)) == 0
		)
	|| (
		packet->payload_packet_len > NDPI_STATICSTRING_LEN(STR2AT0)
		&& memcmp(&packet->payload[0], STR2AT0, NDPI_STATICSTRING_LEN(STR2AT0)) == 0
		)
	|| (
		packet->payload_packet_len >  NDPI_STATICSTRING_LEN(STR3AT0)
		&& memcmp(&packet->payload[0], STR3AT0, NDPI_STATICSTRING_LEN(STR3AT0)) == 0
		&& memcmp(&packet->payload[40], STR3AT40, NDPI_STATICSTRING_LEN(STR3AT40)) == 0
		)
	) {
	
		NDPI_LOG(NDPI_PROTOCOL_WANGYICC, ndpi_struct, NDPI_LOG_DEBUG,
									"found wangyicc \n");
		ndpi_int_wangyicc_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	}else{
		NDPI_LOG(NDPI_PROTOCOL_WANGYICC, ndpi_struct, NDPI_LOG_DEBUG, "exclude wangyicc.\n");	
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WANGYICC);
	}
}

void ndpi_search_wangyicc(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_wangyicc_tcp(ndpi_struct, flow);
	}
}

#endif

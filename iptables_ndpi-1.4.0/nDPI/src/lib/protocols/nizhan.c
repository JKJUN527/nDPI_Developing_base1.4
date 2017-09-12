/*
 * nizhan.c
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
#ifdef NDPI_PROTOCOL_NIZHAN

/*
 PT:
 nizhan
block nizhan get server packet 
00000000  0a 05 64 1a 00 00 00 00  00 20 23 01 00 00 17 71   ..d..... . #....q
00000010  00 00 00 03 00 00 00 00  01 00                     ........ ..
    00000000  0a 05 64 1a 00 00 01 45  00 20 23 01 00 00 17 72   ..d....E . #....r
    00000010  00 00 00 03 00 00 00 00  01 00 00 05 81 00 05 01   ........ ........
    00000020  3e 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   >....... ........
    00000030  00 00 09 64 69 72 5f 72  6f 6f 74 00 00 00 00 05   ...dir_r oot.....
    00000040  00 00 00 00 00 00 00 01  00 01 00 00 00 00 00 00   ........ ........
    00000050  00 01 00 00 00 00 00 00  00 01 00 00 00 07 b5 e7   ........ ........
    00000060  d0 c5 c7 f8 00 00 00 00  01 00 00 00 00 00 00 00   ........ ........
    00000070  08 31 2e 30 2e 31 2e 30  00 01 00 00 00 00 00 00   .1.0.1.0 ........
    00000080  00 02 00 00 00 00 00 00  00 01 00 00 00 07 c1 aa   ........ ........
    00000090  cd a8 c7 f8 00 00 00 00  02 00 00 00 00 00 00 00   ........ ........
    000000A0  08 31 2e 30 2e 31 2e 30  00 01 00 00 00 01 00 00   .1.0.1.0 ........
    000000B0  01 01 00 00 00 01 00 00  00 00 00 00 00 09 b5 e7   ........ ........
    000000C0  d0 c5 d2 bb c7 f8 00 00  00 00 00 00 00 00 01 00   ........ ........
    000000D0  00 00 00 01 00 00 00 00  03 00 00 00 01 00 00 00   ........ ........
    000000E0  08 31 2e 30 2e 31 2e 30  00 01 00 00 00 16 31 31   .1.0.1.0 ......11
    000000F0  39 2e 31 34 37 2e 31 30  37 2e 31 30 33 3a 36 34   9.147.10 7.103:64
    00000100  30 30 30 00 00 00 00 01  00 00 02 02 00 00 00 02   000..... ........
    00000110  00 00 00 00 00 00 00 09  c1 aa cd a8 d2 bb c7 f8   ........ ........
    00000120  00 00 00 00 00 00 00 00  01 00 00 00 00 01 00 00   ........ ........
    00000130  00 00 04 00 00 00 01 00  00 00 08 31 2e 30 2e 31   ........ ...1.0.1
    00000140  2e 30 00 01 00 00 00 15  31 31 31 2e 31 36 31 2e   .0...... 111.161.
    00000150  35 34 2e 31 33 39 3a 36  34 30 30 30 00 00 00      54.139:6 4000...

*/



static void ndpi_int_nizhan_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_NIZHAN, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_nizhan_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "search for nizhan.\n");
	NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "payload len:%u. nzstage:%u\n",packet->payload_packet_len,flow->nizhan_stage);

	if(packet->payload_packet_len >= 26
	  && get_u_int32_t(packet->payload,0) == htonl(0x0a05641a)
	  && get_u_int16_t(packet->payload,4) == htons(0x0)
	  && get_u_int32_t(packet->payload,8) == htonl(0x00202301)
	  && get_u_int16_t(packet->payload,8+4) == htons(0x0)
	  && packet->payload[8+6] == 0x17
	  && (
	  	packet->payload[8+7] == 0x71
	     || packet->payload[8+7] == 0x72
	    )
	  && get_u_int16_t(packet->payload,2*8) == htons(0x0)
	){
			flow->nizhan_stage = 1;
			NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG,
									"add nizhan_stage:%u\n",flow->nizhan_stage);
			if(packet->payload_packet_len > 90 && ndpi_mem_cmp(packet->payload + 6*8+3, "dir_root",8) == 0)
				flow->nizhan_stage = 2;
			NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG,"may nzdir_root:[%s]\n",packet->payload+6*8+3);
			/*fisrt, sec, sec+dir_root*/
			if(flow->nizhan_stage == 2 ){  
				ndpi_int_nizhan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG,"found nizhan\n");
			}
			return;
	}

	NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG,
									"exclude nizhan\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_NIZHAN);

}
void ndpi_search_nizhan_udp(struct ndpi_detection_module_struct
											   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "search for nizhan udp.\n");
	if(packet->payload[3]==packet->payload_packet_len
		&&get_u_int32_t(packet->payload, 12)==htons(0x25a61a81)){
		ndpi_int_nizhan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG,"found nizhan udp1\n");
	}
        NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "pacaet_len:%u.\n",packet->payload_packet_len);
	if(packet->payload_packet_len==260)
	{
		//flow->nizhan_stage++;
		u_int32_t equal;
		equal = ntohl(get_u_int32_t(packet->payload, 6*16));
		NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "nizhan_equal:%x.\n",equal);
		if(ntohl(get_u_int32_t(packet->payload, 6*16))==equal
		  &&ntohl(get_u_int32_t(packet->payload, 7*16))==equal
		  &&ntohl(get_u_int32_t(packet->payload, 8*16))==equal
                  &&ntohl(get_u_int32_t(packet->payload, 10*16))==equal
		){
			flow->nizhan_stage++;
			NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "nizhan_stage:%u.\n",flow->nizhan_stage);
			}
		if(flow->nizhan_stage >= 1){
			ndpi_int_nizhan_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG,"found nizhan udp2\n");
		}	
		
	}else{
		NDPI_LOG(NDPI_PROTOCOL_NIZHAN, ndpi_struct, NDPI_LOG_DEBUG,
										"exclude nizhan\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_NIZHAN);
	}									   	

}
void ndpi_search_nizhan(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_nizhan_tcp(ndpi_struct, flow);
	}
	if (packet->udp != NULL) {
		ndpi_search_nizhan_udp(ndpi_struct, flow);
	}
}

#endif

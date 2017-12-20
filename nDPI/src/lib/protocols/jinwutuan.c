/*
 * jinwutuan.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_utils.h"
#include "ndpi_protocols.h"


#define STR1 "\x38\x00\x01\x07\xf2\xac\xac\xf0"
#define STR2 "\x57\x55\x4c\xaa\x57\x81\x5a\x1b"
#define STR1_LEN 8
#define STR2_LEN 32

#ifdef NDPI_PROTOCOL_GAME_JINWUTUAN
static void ndpi_int_jinwutuan_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_JINWUTUAN, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_jinwutuan(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;


  NDPI_LOG(NDPI_PROTOCOL_GAME_JINWUTUAN, ndpi_struct, NDPI_LOG_DEBUG, "search for game named jinwutuan.\n");

  if (packet->payload_packet_len >=6  &&
	    packet->payload[1] == 0xac  && 
	    packet->payload[2] == 0xac  &&
	    packet->payload[3] == 0xad  &&
	    packet->payload[4] == 0xac  &&
	    packet->payload[5] == 0xac  &&
	    packet->payload[6] == 0xac
	 ){
	      NDPI_LOG(NDPI_PROTOCOL_GAME_JINWUTUAN, ndpi_struct, NDPI_LOG_DEBUG, "found JINWUTUAN.\n");
	      ndpi_int_jinwutuan_add_connection(ndpi_struct, flow);
    	}
  if(packet->payload_packet_len >= STR2_LEN
	&& ndpi_mem_cmp(packet->payload,STR1,STR1_LEN) == 0
	&& get_u_int32_t(packet->payload, 24) == htonl(0x57554caa)){

	      NDPI_LOG(NDPI_PROTOCOL_GAME_JINWUTUAN, ndpi_struct, NDPI_LOG_DEBUG, "found JINWUTUAN.\n");
	      ndpi_int_jinwutuan_add_connection(ndpi_struct, flow);
	
	}

    NDPI_LOG(NDPI_PROTOCOL_GAME_JINWUTUAN, ndpi_struct, NDPI_LOG_DEBUG, "exclude JINWUTUAN.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_JINWUTUAN);
}
#endif


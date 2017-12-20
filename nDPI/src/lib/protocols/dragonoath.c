/*
 * new dragon_oath.c
 * v3.61.2502
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

/*

tl.sohu.com/xtlbb-jd  服务器列表刷新
mark.changyou.com/UQRCodeImage?from=game_tl  二维码登陆

*/
 
 
#include "ndpi_utils.h"
#ifdef NDPI_PROTOCOL_DRAGONOATH


static void ndpi_int_dragonoath_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
						    struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DRAGONOATH, NDPI_REAL_PROTOCOL);
}



void ndpi_search_dragonoath(struct ndpi_detection_module_struct
				 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  NDPI_LOG(NDPI_PROTOCOL_DRAGONOATH, ndpi_struct, NDPI_LOG_DEBUG, "search dragon_oath.\n");
  if(  packet->payload_packet_len > 8
    && ndpi_mem_cmp(packet->payload,"TLBB01",6) == 0){
	  ndpi_int_dragonoath_add_connection(ndpi_struct, flow);
	  NDPI_LOG(NDPI_PROTOCOL_DRAGONOATH, ndpi_struct, NDPI_LOG_DEBUG, "find dragon_oath.\n");
	  return;
  }
  NDPI_LOG(NDPI_PROTOCOL_DRAGONOATH, ndpi_struct, NDPI_LOG_DEBUG, "exclude dragon_oath.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DRAGONOATH);
}

#endif

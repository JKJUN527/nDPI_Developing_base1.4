/*
 * greenvpn.c
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

#ifdef NDPI_PROTOCOL_GREENVPN
static void ndpi_int_greenvpn_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GREENVPN, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_greenvpn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;


  NDPI_LOG(NDPI_PROTOCOL_GREENVPN, ndpi_struct, NDPI_LOG_DEBUG, "search for game named greenvpn.\n");

  if(packet->tcp != NULL ) {
  	if ( (packet->payload[146] == 0x51 &&
	    packet->payload[147] == 0x30  && 
	    packet->payload[148] == 0x4a  &&
	    packet->payload[149] == 0x49  &&
	    packet->payload[150] == 0x65  &&
	    packet->payload[151] == 0x6e  &&
	    packet->payload[152] == 0x64  &&
	    packet->payload[153] == 0x5a  &&
	    packet->payload[154] == 0x52  &&
	    packet->payload[155] == 0x47  
	 ))
	{
      NDPI_LOG(NDPI_PROTOCOL_GREENVPN, ndpi_struct, NDPI_LOG_DEBUG, "found GREENVPN.\n");
      ndpi_int_greenvpn_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_LOG(NDPI_PROTOCOL_GREENVPN, ndpi_struct, NDPI_LOG_DEBUG, "exclude GREENVPN.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GREENVPN);
  }
}
#endif


/*
 * jizhan.c
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

#ifdef NDPI_PROTOCOL_GAME_JIZHAN
static void ndpi_int_jizhan_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_JIZHAN, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_jizhan(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "search for game named JIZHAN.\n");
 //if(packet->tcp != NULL) {
//
   if((packet->payload_packet_len==4 && get_u_int32_t(packet->payload, 0)==htonl(0x35363230))
        ||(packet->payload_packet_len==5 && get_u_int32_t(packet->payload, 0)==htonl(0x52454144))
	){
	  	  NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "found jizhan.\n");
          ndpi_int_jizhan_add_connection(ndpi_struct, flow);
	  	  return;
   }
  //NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "packet_len:%u.\n",packet->payload_packet_len);
  //NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "packet_0:%x.\n",ntohl(get_u_int32_t(packet->payload, 0)));
  //NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "packet_14:%x.\n",ntohs(get_u_int16_t(packet->payload, 14)));
  //NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "packet_24:%x.\n",ntohl(get_u_int32_t(packet->payload, 24)));
   if(packet->payload_packet_len==28
		&&get_u_int32_t(packet->payload, 0)==htonl(0x3cf50a97)
		&&get_u_int16_t(packet->payload, 14)==htons(0xfd77)
		&&get_u_int32_t(packet->payload, 24)==htonl(0x08bd3e1b)){
	  NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "found jizhan.\n");
          ndpi_int_jizhan_add_connection(ndpi_struct, flow);
	  return;
     }
    if(packet->payload_packet_len>=32
		&&packet->payload[1]==0xf5
		&&packet->payload[7]==0x9f
		&&get_u_int16_t(packet->payload, 8)==htons(0x188d)
		&&get_u_int16_t(packet->payload, 14)==htons(0xca77)
		&&get_u_int32_t(packet->payload, 24)==htonl(0x08bd3e1b)){
		
		  NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "found jizhan.\n");
          	  ndpi_int_jizhan_add_connection(ndpi_struct, flow);
	  	  return;
    }
    if (packet->payload_packet_len>=13 &&
	packet->payload[0] == 0x74 &&
	packet->payload[1] == 0xf4 && 
	packet->payload[2] == 0x51 &&
	packet->payload[3] == 0x97 &&
	packet->payload[4] == 0x3C &&
	packet->payload[5] == 0x21 &&
	packet->payload[6] == 0x12 &&
	packet->payload[7] == 0x9f &&
	packet->payload[8] == 0x7e &&
	packet->payload[13] == 0xdf )
	{
      NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "found jizhan.\n");
      ndpi_int_jizhan_add_connection(ndpi_struct, flow);
      return;
    }
  
    

  //} else {
    NDPI_LOG(NDPI_PROTOCOL_GAME_JIZHAN, ndpi_struct, NDPI_LOG_DEBUG, "exclude JIZHAN.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_JIZHAN);
  //}
}
#endif


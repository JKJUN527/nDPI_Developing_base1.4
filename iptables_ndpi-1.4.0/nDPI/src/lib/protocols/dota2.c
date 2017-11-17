/*
 * dota2.c
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

#ifdef NDPI_PROTOCOL_GAME_DOTA2
#define STR0DOTA2 "\x63\x6d\x2e\x73\x74\x65\x61\x6d\x70\x6f"
static void ndpi_int_dota2_add_connection(struct ndpi_detection_module_struct
                *ndpi_struct, struct ndpi_flow_struct *flow)
{
        ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_DOTA2, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_dota2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
        struct ndpi_packet_struct *packet = &flow->packet;


        NDPI_LOG(NDPI_PROTOCOL_GAME_DOTA2, ndpi_struct, NDPI_LOG_DEBUG, "search for game named DOTA2.\n");

        if(packet->udp !=NULL && packet->payload_packet_len >= 7) {
                //when packet is udp,payload's 
                if ( (packet->payload[0] == 0x56 &&
                                        packet->payload[1] == 0x53 && 
                                        packet->payload[2] == 0x30)  
                                ||  (packet->payload[4] == 0x56 && 
                                        packet->payload[5] == 0x54 && 
                                        packet->payload[6] == 0x30)
                   )
                {
                        NDPI_LOG(NDPI_PROTOCOL_GAME_DOTA2, ndpi_struct, NDPI_LOG_DEBUG, "found dota2.\n");
                        ndpi_int_dota2_add_connection(ndpi_struct, flow);
                        return;
                }
        }
        if(packet->tcp !=NULL && packet->payload_packet_len >=222) {
               
                NDPI_LOG(NDPI_PROTOCOL_GAME_DOTA2, ndpi_struct, NDPI_LOG_DEBUG, "search for tcp dota2.\n");
                int i=0;
                for(i;i<6;i++){
                
//                NDPI_LOG(NDPI_PROTOCOL_GAME_DOTA2, ndpi_struct, NDPI_LOG_DEBUG, "payload start is :%x.\n",packet->payload[16*(7+i)-3]);
                   if(memcmp(&packet->payload[16*(7+i)+6],STR0DOTA2,NDPI_STATICSTRING_LEN(STR0DOTA2))==0){
                        NDPI_LOG(NDPI_PROTOCOL_GAME_DOTA2, ndpi_struct, NDPI_LOG_DEBUG, "found dota2.\n");
                        ndpi_int_dota2_add_connection(ndpi_struct, flow);
                        return;
                }
            }
        }
        NDPI_LOG(NDPI_PROTOCOL_GAME_DOTA2, ndpi_struct, NDPI_LOG_DEBUG, "exclude DOTA2.\n");
        NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_DOTA2);

}
#endif


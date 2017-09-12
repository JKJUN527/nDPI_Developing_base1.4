/*
 * zhengfu.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */


#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_GAME_ZHENGFU
static void ndpi_int_zhengfu_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_ZHENGFU, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_zhengfu(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENGFU, ndpi_struct, NDPI_LOG_DEBUG, "search game named ZHENGFU.\n");

   if(packet->tcp != NULL ) {
  	if (packet->payload_packet_len >=3 &&
	   (packet->payload[0] == 0xc5 &&
	    packet->payload[1] == 0x48 && 
	    packet->payload[2] == 0x69)  
	 )
	{
      NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENGFU, ndpi_struct, NDPI_LOG_DEBUG, "found zhengfu.\n");
      ndpi_int_zhengfu_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENGFU, ndpi_struct, NDPI_LOG_DEBUG, "exclude ZHENGFU.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_ZHENGFU);
  }
}
#endif


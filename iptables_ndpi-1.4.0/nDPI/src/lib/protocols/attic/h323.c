/*
 * h323.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */


#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_H323

void ndpi_search_h323(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "search H323.\n");

  if(packet->tcp != NULL) {
    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "calculated dport over tcp.\n");

    /* H323  */
    if(packet->payload[0] == 0x03 && packet->payload[1] == 0x00 && packet->payload[2] == 0x00)
      {
	NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_REAL_PROTOCOL);
	return;
      }
  }

  if(packet->udp != NULL) {
    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "calculated dport over udp.\n");

    if(packet->payload[0] == 0x80 && packet->payload[1] == 0x08 && (packet->payload[2] == 0xe7 || packet->payload[2] == 0x26) &&
       packet->payload[4] == 0x00 && packet->payload[5] == 0x00)
      {
	NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_REAL_PROTOCOL);
	return;
      }
    /* H323  */
    if(sport == 1719 || dport == 1719)
      {
        if(packet->payload[0] == 0x16 && packet->payload[1] == 0x80 && packet->payload[4] == 0x06 && packet->payload[5] == 0x00)
	  {
	    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_REAL_PROTOCOL);
	    return;
	  }
        else if(packet->payload_packet_len >= 20 || packet->payload_packet_len <= 117)
	  {
	    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_REAL_PROTOCOL);
	    return;
	  }
        else
	  {
	    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_H323);
	    return;
	  }
      }
  }

}
#endif

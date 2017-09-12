/*
 * edonkey.c
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
#ifdef NDPI_PROTOCOL_EDONKEY
/* debug defines */
#define NDPI_PROTOCOL_SAFE_DETECTION 		1

#define NDPI_PROTOCOL_PLAIN_DETECTION 	0
static void ndpi_add_connection_as_edonkey(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow,
					   const u_int8_t save_detection, const u_int8_t encrypted_connection)
{
	ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_EDONKEY, NDPI_REAL_PROTOCOL);
}

#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 u_int8_t check_edk_len(const u_int8_t * payload, u_int16_t payload_packet_len)
{
	u_int32_t edk_len_parsed = 0;
	// we use a do / while loop here, because we have checked the byte 0 for 0xe3 or 0xc5 already before this call
	do {
		u_int32_t edk_len;
		edk_len = get_l32(payload, 1 + edk_len_parsed);

		/* if bigger, return here directly with an error... */
		if (edk_len > payload_packet_len)
			return 0;
		/* this is critical here:
		 * if (edk_len + 5) provokes an overflow to zero, we will have an infinite loop...
		 * the check above does prevent this, bcause the edk_len must be ((u_int32_t)-5), which is always bigger than the packet size
		 */
		edk_len_parsed += 5 + edk_len;

		if (edk_len_parsed == payload_packet_len)
			return 1;
		if (edk_len_parsed > payload_packet_len)
			return 0;
	}
	while (payload[edk_len_parsed] == 0xe3 || payload[edk_len_parsed] == 0xc5 || payload[edk_len_parsed] == 0xd4);
	return 0;
}

static void ndpi_int_edonkey_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	int edk_stage2_len;

	/*len range increase if safe mode and also only once */
	if (ndpi_struct->edonkey_safe_mode == 0)
		edk_stage2_len = 140;
	else if (!flow->l4.tcp.edk_ext || packet->payload_packet_len == 212) {
		edk_stage2_len = 300;

	} else
		edk_stage2_len = 140;


	/* skip excluded connections */
	if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_EDONKEY) != 0)
		return;

	/* source and dst port must be 80 443 or > 1024 */
	if (ndpi_struct->edonkey_upper_ports_only != 0) {
		u_int16_t port;
		port = ntohs(packet->tcp->source);
		/* source and dst port must be 80 443 or > 1024 */
		if (port < 1024 && port != 80 && port != 443)
			goto exclude_edk_tcp;

		port = ntohs(packet->tcp->dest);
		if (port < 1024 && port != 80 && port != 443)
			goto exclude_edk_tcp;
	}

	/* return here for empty packets, we needed them only for bt port detection */
	if (packet->payload_packet_len == 0)
		return;

	/* skip marked packets */
	if (flow->edk_stage == 0 && packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
		return;

	/* first: check for unencrypted traffic */
	if (flow->edk_stage == 0) {
		/* check for client hello */
		if (packet->payload_packet_len >= 32 && get_l32(packet->payload, 1) <= (packet->payload_packet_len - 5)
			&& (packet->payload[0] == 0xe3 || packet->payload[0] == 0xc5)) {
			if (packet->payload[5] == 0x01 && ((packet->payload[6] == 0x10 && get_l32(packet->payload, 29) < 0x0F)
											   || (get_l32(packet->payload, 28) > 0x00
												   && get_l32(packet->payload, 28) < 0x0F))) {
				NDPI_LOG_EDONKEY(NDPI_PROTOCOL_EDONKEY, ndpi_struct, NDPI_LOG_DEBUG,
								"edk hello meta tag recognized\n");
				flow->edk_stage = 16 + packet->packet_direction;
				return;
			}
		}
	}
	if ((17 - packet->packet_direction) == flow->edk_stage) {
		if ((packet->payload_packet_len >= 32 && get_l32(packet->payload, 1) == 9 && (packet->payload[0] == 0xe3)
			 && packet->payload[5] == 0x40)
			|| (packet->payload_packet_len >= 32 && (packet->payload[0] == 0xe3)
				&& packet->payload[5] == 0x40 && check_edk_len(packet->payload, packet->payload_packet_len))
			|| (packet->payload_packet_len >= 32 && packet->payload[0] == 0xe3
				&& packet->payload[5] == 0x4c && (get_l32(packet->payload, 1) == (packet->payload_packet_len - 5)
												  || check_edk_len(packet->payload, packet->payload_packet_len)))
			|| (packet->payload_packet_len >= 32 && get_l32(packet->payload, 1) == (packet->payload_packet_len - 5)
				&& packet->payload[0] == 0xe3 && packet->payload[5] == 0x38)
			|| (packet->payload_packet_len >= 20 && get_l32(packet->payload, 1) == (packet->payload_packet_len - 5)
				&& packet->payload[0] == 0xc5 && packet->payload[5] == 0x92)
			|| (packet->payload_packet_len >= 20 && get_l32(packet->payload, 1) <= (packet->payload_packet_len - 5)
				&& packet->payload[0] == 0xe3 && packet->payload[5] == 0x58)
			|| (packet->payload_packet_len >= 20 && get_l32(packet->payload, 1) <= (packet->payload_packet_len - 5)
				&& (packet->payload[0] == 0xe3 || packet->payload[0] == 0xc5)
				&& packet->payload[5] == 0x01)) {
			NDPI_LOG_EDONKEY(NDPI_PROTOCOL_EDONKEY, ndpi_struct,
							NDPI_LOG_DEBUG, "edk 17: detected plain detection\n");
			ndpi_add_connection_as_edonkey(ndpi_struct, flow,
						       NDPI_PROTOCOL_SAFE_DETECTION, NDPI_PROTOCOL_PLAIN_DETECTION);
			return;
		}

		NDPI_LOG_EDONKEY(NDPI_PROTOCOL_EDONKEY, ndpi_struct, NDPI_LOG_DEBUG,
						"edk 17: id: %u, %u, %u not detected\n",
						packet->payload[0], get_l32(packet->payload, 1), packet->payload[5]);
	}
  exclude_edk_tcp:

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_EDONKEY);

	return;
}

/*-----From nDPI-1.8 Start------*/


static int ndpi_edonkey_payload_check(const u_int8_t *data, u_int32_t len) {
  
  if ((len >= 4) && (data[0] == 0xe3) && (data[2] == 0x00) && (data[3] == 0x00))
	return 1;
  
  if ((len >= 4) && (data[0] == 0xc5) && (data[2] == 0x00) && (data[3] == 0x00))
	return 1;  
  
  if ((len >= 2) && (data[0] == 0xe5) && (data[1] == 0x43))
	return 1;
  
  if ((len >= 4) && (data[0] == 0xe5) && (data[1] == 0x08) && (data[2] == 0x78) && (data[3] == 0xda))
	return 1;

  if ((len >= 4) && (data[0] == 0xe5) && (data[1] == 0x28) && (data[2] == 0x78) && (data[3] == 0xda))
	return 1;

  if ((len >= 2) && (data[0] == 0xc5) && (data[1] == 0x90))
	return 1;

  if ((len >= 2) && (data[0] == 0xc5) && (data[1] == 0x91))
	return 1;

  if ((len == 2) && (data[0] == 0xc5) && (data[1] == 0x92))
	return 1;

  if ((len == 2) && (data[0] == 0xc5) && (data[1] == 0x93))
	return 1;

  if ((len >= 38 && len <= 70) && (data[0] == 0xc5) && (data[1] == 0x94))
	return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x9a))
	return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x9b))
	return 1;

  if ((len == 6) && (data[0] == 0xe3) && (data[1] == 0x96))
	return 1;

  if ((len <= 34 && ((len - 2) % 4 == 0)) && (data[0] == 0xe3) && (data[1] == 0x97))
	return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x92))
	return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x94))
	return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x98))
	return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x99))
	return 1;

  if ((len == 6) && (data[0] == 0xe3) && (data[1] == 0xa2))
	return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0xa3))
	return 1;

  if ((len == 27) && (data[0] == 0xe4) && (data[1] == 0x00))
	return 1;

  if ((len == 529) && (data[0] == 0xe4) && (data[1] == 0x08))
	return 1;

  if ((len == 18) && (data[0] == 0xe4) && (data[1] == 0x01) && (data[2] == 0x00) && (data[3] == 0x00))
	return 1;

  if ((len == 523) && (data[0] == 0xe4) && (data[1] == 0x09))
	return 1;

  if ((len == 35) && (data[0] == 0xe4) && (data[1] == 0x21))
	return 1;

  if ((len == 19) && (data[0] == 0xe4) && (data[1] == 0x4b))
	return 1;

  if ((len >= 2) && (data[0] == 0xe4) && (data[1] == 0x11))
	return 1;

  if ((len == 22 || len == 38 || len == 28) && (data[0] == 0xe4) && (data[1] == 0x19))
	return 1;

  if ((len == 35) && (data[0] == 0xe4) && (data[1] == 0x20))
	return 1;

  if ((len == 27) && (data[0] == 0xe4) && (data[1] == 0x18))
	return 1;

  if ((len == 27) && (data[0] == 0xe4) && (data[1] == 0x10))
	return 1;

  if ((len == 6) && (data[0] == 0xe4) && (data[1] == 0x58))
	return 1;

  if ((len == 4) && (data[0] == 0xe4) && (data[1] == 0x50))
	return 1;

  if ((len == 36) && (data[0] == 0xe4) && (data[1] == 0x52))
	return 1;

  if ((len == 48) && (data[0] == 0xe4) && (data[1] == 0x40))
	return 1;

  if ((len == 225) && (data[0] == 0xe4) && (data[1] == 0x43))
	return 1;

  if ((len == 19) && (data[0] == 0xe4) && (data[1] == 0x48))
	return 1;

  if ((len == 119 || len == 69 || len == 294) && (data[0] == 0xe4) && (data[1] == 0x29))
	return 1;

  if ((len == 119 || len == 69 || len == 294 || len == 44 || len == 269) && (data[0] == 0xe4) && (data[1] == 0x28))
	return 1;

  return 0;
}

static void ndpi_check_edonkey(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(NDPI_PROTOCOL_EDONKEY, ndpi_struct, NDPI_LOG_DEBUG, "Exclude EDONKEY.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_EDONKEY);
    return;
  }

  /* Check if we so far detected the protocol in the request or not. */
  if (flow->edk_stage == 0) {
    NDPI_LOG(NDPI_PROTOCOL_EDONKEY, ndpi_struct, NDPI_LOG_DEBUG, "EDONKEY stage 0: \n");

    if (ndpi_edonkey_payload_check(packet->payload, payload_len)) {
      NDPI_LOG(NDPI_PROTOCOL_EDONKEY, ndpi_struct, NDPI_LOG_DEBUG, "Possible EDONKEY request detected, we will look further for the response...\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->edk_stage = packet->packet_direction + 1;
    }

  } else {
    NDPI_LOG(NDPI_PROTOCOL_EDONKEY, ndpi_struct, NDPI_LOG_DEBUG, "EDONKEY stage %u: \n", flow->edk_stage);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->edk_stage - packet->packet_direction) == 1) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if ((payload_len == 0) || (ndpi_edonkey_payload_check(packet->payload, payload_len))) {
      NDPI_LOG(NDPI_PROTOCOL_EDONKEY, ndpi_struct, NDPI_LOG_DEBUG, "Found EDONKEY.\n");
      //ndpi_int_edonkey_add_connection(ndpi_struct, flow);
	  ndpi_add_connection_as_edonkey(ndpi_struct, flow,
	  	NDPI_PROTOCOL_SAFE_DETECTION, NDPI_PROTOCOL_PLAIN_DETECTION);


    } else {
      NDPI_LOG(NDPI_PROTOCOL_EDONKEY, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to EDONKEY, resetting the stage to 0...\n");
      flow->edk_stage = 0;
    }

  }
}

/*-----From nDPI-1.8 End------*/


void ndpi_search_edonkey(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_EDONKEY) {
		/* check for retransmission here */
		if (packet->tcp != NULL && packet->tcp_retransmission == 0)
		  //ndpi_int_edonkey_tcp(ndpi_struct, flow);
		  ndpi_check_edonkey(ndpi_struct, flow); // From nDPI-1.8
	}
}
#endif

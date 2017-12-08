/*
 * alitong.c
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
#ifdef NDPI_PROTOCOL_ALITONG

/*
 PT:
 alitong like dns, guess to dns tunnel
udp[12:7]==31:57:3f:c6:7d:57:31
payload[12-8]
len:12+7-8=11
*/



static void ndpi_int_alitong_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ALITONG, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_alitong_tcp_or_udp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_ALITONG, ndpi_struct, NDPI_LOG_DEBUG, "search for alitong.\n");
	#ifdef DEBUG
	if(get_u_int32_t(packet->payload, 4 ) == htonl(0x31573fc6)){
		NDPI_LOG(NDPI_PROTOCOL_ALITONG, ndpi_struct, NDPI_LOG_DEBUG,
									"may alitong1 \n");
	}
	if (get_u_int16_t(packet->payload, 8 ) == htons( 0x7d57)){
		NDPI_LOG(NDPI_PROTOCOL_ALITONG, ndpi_struct, NDPI_LOG_DEBUG,
									"may alitong2 \n");
	} 
	else{
		NDPI_LOG(NDPI_PROTOCOL_ALITONG, ndpi_struct, NDPI_LOG_DEBUG,
									"not alitong2 =>8:[%x] 9:[%x] 10:[%x]\n",
									packet->payload[8],packet->payload[9],packet->payload[10]);
	}
	
	if(packet->payload[8+2]==0x31){
		NDPI_LOG(NDPI_PROTOCOL_ALITONG, ndpi_struct, NDPI_LOG_DEBUG,
									"may alitong3 \n");
	}
	#endif

	
	if(packet->payload_packet_len >= 11 
	&& (get_u_int32_t(packet->payload, 4 ) == htonl(0x31573fc6))
	&& (get_u_int16_t(packet->payload, 8 ) == htons( 0x7d57))
	&& packet->payload[8+2]==0x31){
	
		NDPI_LOG(NDPI_PROTOCOL_ALITONG, ndpi_struct, NDPI_LOG_DEBUG,
									"found alitong \n");
		ndpi_int_alitong_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	}else{
		NDPI_LOG(NDPI_PROTOCOL_ALITONG, ndpi_struct, NDPI_LOG_DEBUG, "exclude alitong.\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ALITONG);
	}
}

void ndpi_search_alitong(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	/*u_int16_t sport;
	u_int16_t dport ;
	if(packet->udp!=NULL){
		sport = ntohs(packet->udp->source);
		dport = ntohs(packet->udp->dest);
	}else if (packet->tcp!=NULL){
		sport = ntohs(packet->tcp->source);
		dport = ntohs(packet->tcp->dest);
	}
	if (sport!=53 && dport!=53) {
		ndpi_search_alitong_tcp_or_udp(ndpi_struct, flow);
		
	}*/
	if (packet->udp!=NULL || packet->tcp!=NULL)
		ndpi_search_alitong_tcp_or_udp(ndpi_struct, flow);
}

#endif

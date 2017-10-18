/*
 * thunder.c
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
#ifdef NDPI_PROTOCOL_THUNDER

static void ndpi_int_thunder_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;

	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_THUNDER, protocol_type);

	if (src != NULL) {
		src->thunder_ts = packet->tick_timestamp;
	}
	if (dst != NULL) {
		dst->thunder_ts = packet->tick_timestamp;
	}
}


	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_int_search_thunder_udp(struct ndpi_detection_module_struct
												 *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
/*
	if (packet->payload_packet_len > 8 && packet->payload[0] >= 0x30
		&& packet->payload[0] < 0x40 && packet->payload[1] == 0 && packet->payload[2] == 0 && packet->payload[3] == 0) {
		if (flow->thunder_stage == 3) {
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "THUNDER udp detected\n");
			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}

		flow->thunder_stage++;
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
				"maybe thunder udp packet detected, stage increased to %u\n", flow->thunder_stage);
		return;
	}
	*/
	NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp port:%u\n",ntohs(packet->udp->source));
	if(ntohs(packet->udp->source)==12345){
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp port 12345 detected\n");
		ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;
	}
	flow->thunder_stage++;
	if(flow->thunder_stage<=8  //检查前四个包长度，满足前三个包小于50，第四个包大于220
		&&packet->payload_packet_len<50
		&&packet->payload_packet_len>=40){
		flow->thunder_count++;
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp stage:%d,udp count:%d\n",flow->thunder_stage,flow->thunder_count);
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp packet len:%d\n",packet->payload_packet_len);
	}else if(flow->thunder_stage==flow->thunder_count+1
		  &&flow->thunder_stage>=3
		  &&packet->payload_packet_len>=220){
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp detected-new\n");
			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
	}
	if(packet->payload_packet_len>16){
		//flow->thunder_stage++;
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"search thunder udp\n");
		if(get_u_int16_t(packet->payload, 0) == htonl( 0x0100)
			&&get_u_int16_t(packet->payload, 3) == htonl( 0x2a6e)
			&&get_u_int16_t(packet->payload, 8) == htonl( 0x1327)){
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp detected 1\n");
			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}else if(get_u_int16_t(packet->payload, 0) == htonl( 0x4100)
					&&get_u_int16_t(packet->payload, 13) == htonl( 0x0800)
					&&get_u_int16_t(packet->payload, 18) == htonl( 0x0000)){
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp detected 2\n");
			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}else if(get_u_int16_t(packet->payload, 0) == htonl( 0x4300)//send source address
					&&get_u_int16_t(packet->payload, 4) == htonl( 0xff01)){
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp detected 3\n");
			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}else if(get_u_int64_t(packet->payload, 0) == htonl( 0x3e000000fc100000)){//send source address
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp detected 4\n");
			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}else if(get_u_int16_t(packet->payload, 0) == htonl( 0x6431)//request download nodes----[BT]
					&&packet->payload[2]==0x3a){
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp detected 5\n");
			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}else if(get_u_int32_t(packet->payload, 0) == htonl( 0x42000000)
					&&get_u_int16_t(packet->payload, 5) == htonl( 0x1000)){
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder udp detected 6\n");
			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}

	}
	if(flow->thunder_stage>8){
		
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
					"excluding thunder udp at stage %u\n", flow->thunder_stage);
		
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_THUNDER);
	}
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_int_search_thunder_tcp(struct ndpi_detection_module_struct
												 *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;
		flow->thunder_stage++;
		switch (flow->thunder_count)
			{
			case 0:
				if(packet->payload_packet_len==185)
					flow->thunder_count++;
				else{
					NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"excluding thunder tcp at stage %u\n", flow->thunder_stage);
					NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_THUNDER);
				}
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"thunder_count tcp: %u\n", flow->thunder_count);
				break;	
			case 1:
				if(packet->payload_packet_len>=9&&packet->payload_packet_len<=12)
					flow->thunder_count++;
				else{
					NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"excluding thunder tcp at stage %u\n", flow->thunder_stage);
					NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_THUNDER);
				}
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"thunder_count tcp: %u\n", flow->thunder_count);
				break;
			case 2:
				if(packet->payload_packet_len>=18&&packet->payload_packet_len<=21)
					flow->thunder_count++;
				else{
					NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"excluding thunder tcp at stage %u\n", flow->thunder_stage);
					NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_THUNDER);
				}
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"thunder_count tcp: %u\n", flow->thunder_count);
				break;
			case 3:
				if(packet->payload_packet_len==92)
					flow->thunder_count++;
				else{
					NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"excluding thunder tcp at stage %u\n", flow->thunder_stage);
					NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_THUNDER);
				}
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"thunder_count tcp: %u\n", flow->thunder_count);
				break;
			case 4:
				if(packet->payload_packet_len>=109&&packet->payload_packet_len<=111)
					flow->thunder_count++;
				else{
					NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"excluding thunder tcp at stage %u\n", flow->thunder_stage);
					NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_THUNDER);
				}
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"thunder_count tcp: %u\n", flow->thunder_count);
				break;
			case 5:
				if(packet->payload_packet_len==21){
					flow->thunder_count++;
					NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "THUNDER tcp detected 1\n");
					ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
					return;
					
				}else{
					NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"excluding thunder tcp at stage %u\n", flow->thunder_stage);
					NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_THUNDER);
				}
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"thunder_count tcp: %u\n", flow->thunder_count);
				break;
			default:
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,"thunder_count tcp: %u\n", flow->thunder_count);
				break;
			}
	if (get_u_int16_t(packet->payload, 0) == htonl( 0x0400)){
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "THUNDER tcp detected\n");
		ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;
	}
	
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_int_search_thunder_http(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;


	if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_THUNDER) {
		if (src != NULL && ((u_int32_t)
							(packet->tick_timestamp - src->thunder_ts) < ndpi_struct->thunder_timeout)) {
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
					"thunder : save src connection packet detected\n");
			src->thunder_ts = packet->tick_timestamp;
		} else if (dst != NULL && ((u_int32_t)
								   (packet->tick_timestamp - dst->thunder_ts) < ndpi_struct->thunder_timeout)) {
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
					"thunder : save dst connection packet detected\n");
			dst->thunder_ts = packet->tick_timestamp;
		}
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
					"thunder : return in http , proto is thunder\n");
		return;
	}
	
//	if (packet->payload_packet_len > 5
//		&& memcmp(packet->payload, "GET /", 5) == 0 && NDPI_SRC_OR_DST_HAS_PROTOCOL(src, dst, NDPI_PROTOCOL_THUNDER)) {
//		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "HTTP packet detected.\n");
//		ndpi_parse_packet_line_info(ndpi_struct, flow);
//
//		if (packet->parsed_lines > 7
//			&& packet->parsed_lines < 11
//			&& packet->line[1].len > 10
//			&& ndpi_mem_cmp(packet->line[1].ptr, "Accept: */*", 11) == 0
//			&& packet->line[2].len > 22
//			&& ndpi_mem_cmp(packet->line[2].ptr, "Cache-Control: no-cache",
//						   23) == 0 && packet->line[3].len > 16
//			&& ndpi_mem_cmp(packet->line[3].ptr, "Connection: close", 17) == 0
//			&& packet->line[4].len > 6
//			&& ndpi_mem_cmp(packet->line[4].ptr, "Host: ", 6) == 0
//			&& packet->line[5].len > 15
//			&& ndpi_mem_cmp(packet->line[5].ptr, "Pragma: no-cache", 16) == 0
//			&& packet->user_agent_line.ptr != NULL
//			&& packet->user_agent_line.len > 49
//			&& ndpi_mem_cmp(packet->user_agent_line.ptr,
//						   "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", 50) == 0) {
//			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
//					"Thunder HTTP download detected, adding flow.\n");
//			ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
//		}
//	}
	//NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder: will goto HTTP packet detect stage:%d payload_len:%d.\n",flow->thunder_stage,packet->payload_packet_len);
	//NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
		//							"thunder test adding all HTTP download .\n");
			//	ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	if (flow->thunder_stage >= 0 && packet->payload_packet_len > 17 
		&& ndpi_mem_cmp(packet->payload, "POST / HTTP/1.1\r\n", 17) == 0
		){
		ndpi_parse_packet_line_info(ndpi_struct, flow);
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder: HTTP packet detected. lines:%u \n",packet->parsed_lines);
		
		if (packet->parsed_lines > 5
			//&& ndpi_mem_cmp(packet->line[0].ptr, "POST / HTTP/1.1", 15) == 0
			&& packet->line[1].len > 6
			&& ndpi_mem_cmp(packet->line[1].ptr, "Host: ", 6) == 0
			&& packet->line[2].len == 38
			&& ndpi_mem_cmp(packet->line[2].ptr, "Content-type: application/octet-stream", 38) == 0
			&& packet->line[3].len > 16
			&& ndpi_mem_cmp(packet->line[3].ptr, "Content-Length: ", 16) == 0
			&& packet->line[4].len == 22
			&& ndpi_mem_cmp(packet->line[4].ptr, "Connection: Keep-Alive", 22) == 0
			&& packet->line[5].len ==0 ) {
			const char * media_ptr = packet->line[6].ptr;
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder: may thunder http header in thunder.c .\n");
		    
			//check media len and content-len
			// 0 88:58:03:26
			if(packet->payload_packet_len > 80
			&& ndpi_mem_cmp(media_ptr, "\x88\x58\x03\x26", 4) == 0
			&& media_ptr[7] == 0x00
			&& media_ptr[9] == 0x00
			&& media_ptr[10] == 0x00
			&& media_ptr[11] == 0x00
			&& media_ptr[142] == 0x00
			&& media_ptr[143] == 0x00

			){

				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
									"thunder HTTP download detected, adding flow thunder.c.\n");
				ndpi_int_thunder_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);

		}}

	}

	
	
}

void ndpi_search_thunder(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	//
	//struct ndpi_id_struct *src = flow->src;
	//struct ndpi_id_struct *dst = flow->dst;

	if (packet->tcp != NULL) {
		//ndpi_int_search_thunder_http(ndpi_struct, flow); //here has move to http.c, here is no any use -- PT 2016/10/19
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
									"thunder:search thunder tcp\n");
		ndpi_int_search_thunder_tcp(ndpi_struct, flow);
	} else if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
									"thunder:search thunder udp\n");
		ndpi_int_search_thunder_udp(ndpi_struct, flow);
	}
}

#endif


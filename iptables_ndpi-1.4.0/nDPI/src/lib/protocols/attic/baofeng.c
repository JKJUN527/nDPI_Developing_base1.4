/*
 * baofeng.c
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
#ifdef NDPI_PROTOCOL_FUNSHION

/*
 jkjun:
baofeng
 33 b0 49 7d 65 dd 7e 26 1c 55 00 00 00 fb eb 13 35 2a 00 00 00 00 10 00 00 00 55 57 44 f9 19 61 4a c4 8a d5 60 e5 92 b8  b3 75 f1 00 05 00 00 00 40 06 00 00 00 00 00 00 40 06 00 00 00 00 01
 f0 bd bf 4d 65 6e a6 11 31 55 00 00 00 40 bc c1 18 2a 00 00 00 00 10 00 00 00 55 57 44 f9 19 61 4a c4 8a d5 60 e5 92 b8  b3 75 f1 00 05 00 00 00 40 06 00 00 00 00 00 00 40 06 00 00 00 00 01
 9a b3 2e f1 65 2a 92 0a de 55 00 00 00 97 1f 6b c3 2a 00 00 00 00 10 00 00 00 55 57 44 f9 19 61 4a c4 8a d5 60 e5 92 b8  b3 75 f1 00 05 00 00 00 40 06 00 00 00 00 00 00 40 06 00 00 00 00 01
             65             55 00 00 00             2a 00 00 00 00 10 00 00 00 55 57 44 f9 19 61 4a c4 8a d5 60 e5 92 b8  b3 75 f1 00 05 00 00 00 40 06 00 00 00 00 00 00 40 06 00 00 00 00 01

00000000  9a b3 2e f1 65 2a 92 0a  de 55 00 00 00 97 1f 6b ....e*.. .U.....k
00000010  c3 2a 00 00 00 00 10 00  00 00 55 57 44 f9 19 61 .*...... ..UWD..a
00000020  4a c4 8a d5 60 e5 92 b8  b3 75 f1 00 05 00 00 00 J...`... .u......
00000030  40 06 00 00 00 00 00 00  40 06 00 00 00 00 01    @....... @......


0d 04 ef ac 67 88 8e 0e  83 55 00 00 00 a0 bf e1 e0 0b 00 00 00 64 01 00  00 00 41 00 dd 4c 9d 1e .....d.. ..A..L..
3d 55 37 1c 67 16 6e 18  ef 55 00 00 00 6d b8 b0 69 0b 00 00 00 64 01 00  00 00 41 00 82 00 4d 09 i....d.. ..A...M.
6a be bf 42 67 11 2d 71  08 55 00 00 00 8d e8 e5 ab 0b 00 00 00 64 01 00  00 00 41 00 4b 92 07 0a .....d.. ..A.K...
            67              55 00 00 00             0b 00 00 00 64 01 00  00 00 41 00         




*/

static void ndpi_int_baofeng_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_BAOFENG, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
void ndpi_search_baofeng_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if((packet->payload_packet_len >= (7 * 8 +6) 
	//&& (packet->payload[0] == 0x07 || packet->payload[0] == 0x00)
	//&& (packet->payload[5*8] == 0x12
	//&& packet->payload[4*8+6] == 0x00
	&& ((packet->payload[4] == 0x79 && packet->payload[9] == 0x52)
	||(packet->payload[4] == 0x2e && packet->payload[9] == 0x03))
	||(packet->payload[4]==0x6a && packet->payload[9]==0x52 && packet->payload[10]==0x00 && packet->payload[11]==0x00 && packet->payload[12]==0x00))
	||(packet->payload_packet_len >= 16 && packet->payload[9] == 0x55&& packet->payload[10] == 0x00&& packet->payload[11] ==0x00)
	||(packet->payload[0]==0x52 && packet->payload[1]==0x00 && packet->payload[2]==0x00)
	){
	
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"found baofeng------tcp[1] \n");
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"found baofeng------tcp [9:%x] [10:%x]  \n",packet->payload[9],packet->payload[10]);
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"baofeng tcp [4->79|2e|6a]:%x [9->52|03]:%x [10->00]:%x\n",packet->payload[4],packet->payload[9],packet->payload[10]);
		ndpi_int_baofeng_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}
	NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG, "exclude baofeng.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_BAOFENG);
}

void ndpi_search_baofeng_udp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	flow->baofeng_count +=1;
	NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"baofeng_count:%d,baofeng_stage:%d\n",flow->baofeng_count,flow->baofeng_stage);
	if(packet->udp->source==9909)
	{
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"found baofeng------udp[2] \n");
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"baofeng udp [0->2*|3*]:%x\n",packet->payload[0]);
		ndpi_int_baofeng_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}
	if(packet->payload_packet_len >= (3*8) 
	&& (packet->payload[7]==0x02)
	&& (packet->payload[8]==0x00)
	){
	
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"found baofeng------udp[1] \n");
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"baofeng udp [6->4a]:%x [7->02]:%x [8->00]:%x\n",packet->payload[6],packet->payload[7],packet->payload[8]);
		ndpi_int_baofeng_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}
	if(packet->payload_packet_len >=(5*8)
	&&(packet->payload[0]>=0x20&&packet->payload[0]<=0x3f)
	){
		flow->baofeng_stage +=1;
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"baofeng_count:%d,baofeng_stage:%d,[0:2*|3*]:%d\n",flow->baofeng_count,flow->baofeng_stage,packet->payload[0]);
		if(flow->baofeng_stage<3 && flow->baofeng_stage ==flow->baofeng_count){
			return;
		}
		else if(flow->baofeng_stage !=flow->baofeng_count){
			NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG, "exclude baofeng.\n");
  			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_BAOFENG);

			return;
		}
		else if(flow->baofeng_stage >= 3 && flow->baofeng_count >= 3){
			NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"found baofeng------udp[2] \n");
			NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,"baofeng udp [0->2*|3*]:%x\n",packet->payload[0]);
			ndpi_int_baofeng_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
		}
	}
	NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG, "exclude baofeng.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_BAOFENG);
}



void ndpi_search_baofeng(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,
									"search baofeng tcp\n");
		ndpi_search_baofeng_tcp(ndpi_struct, flow);
  		//NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG, "exclude funshion.\n");
  		//NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FUNSHION);
	}
	if (packet->udp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_BAOFENG, ndpi_struct, NDPI_LOG_DEBUG,
									"search baofeng udp\n");
		ndpi_search_baofeng_udp(ndpi_struct, flow);
  		//NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG, "exclude funshion.\n");
  		//NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FUNSHION);
	}
	

}

#endif

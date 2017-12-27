
/*
 * cf.c
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
#ifdef NDPI_PROTOCOL_GAME_CF
/*
 *00000550  00 00 00 00 00 00 00 00  00 00 00 00 46 00 39 33   ........ ....F.93
 00000560  37 61 61 33 35 30 61 65  30 34 61 62 38 37 36 33   7aa350ae 04ab8763
 00000570  65 61 32 33 66 31 63 63  32 66 62 39 39 63 00 31   ea23f1cc 2fb99c.1
 00000580  37 36 30 31 39 30 30 00  00 00 00 00 00 00 db e5   7601900. ........
 00000590  28 5a 30 37 00 00 d6 e5  28 5a 32 30 31 37 31 32   (Z07.... (Z201712
 000005A0  30 37 31 34 35 35 31 38  00 00 00 00 00 00 00 00   07145518 ........
 000005B0  00 00 00 00  
 //F.937aa3 50ae04ab8763ea23 f1cc2fb99c.17601 900 MAYBE THE feature
 * */

static void ndpi_int_game_cf_add_connection(struct ndpi_detection_module_struct *ndpi_struct,struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_CF, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
#define STR0CF "\x00\x70\x82\x42\xef\x2e\xbc\45"//.p.B...E
#define STR1CF "\x39\x33\x37\x61\x61\x33\x35\x30\x61\x65\x30\x34\x61\x62\x38\x37\x36\x33"//F.937aa3 50ae04ab8763ea23 f1cc2fb99c.17601 900
#define STR2CF "\x73\x74\x61\x72\x74\x5f\x65\x76\x65\x6e\x74\x31"//start_enven1
void ndpi_search_game_cf_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"search game_cf\n");
	//48 0d 03 fd 00 00 00 0c
	if(packet->payload_packet_len == 1460
	&& get_u_int32_t(packet->payload, 0)==htonl(0xf1a00601)
	&& get_u_int16_t(packet->payload, 4)==htons(0x0000)
	&& get_u_int16_t(packet->payload, 10)==htons(0x0001)
	&& get_u_int16_t(packet->payload, 16)==htons(0x0070)	
	){	
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------1 \n");
		ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
		return;	
	}
    if(packet->payload_packet_len >8*16+1
        &&packet->payload[0]==0xf1
       // &&memcmp(&packet->payload[16],STR0CF,NDPI_STATICSTRING_LEN(STR0CF)) == 0
    ){
		NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"comming cf  \n");
        int i = 0;
        int offset = packet->payload_packet_len-16*7;
	//	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"pcaket[%u]:%x \n",offset,packet->payload[offset]);
        for(i;i<16*2;i++){
	//	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"pcaket[%u]:%x \n",offset,packet->payload[offset]);
            if(packet->payload[offset]==0x00){
                offset++;
                continue;
            }else{
                if(memcmp(&packet->payload[offset+2],STR1CF,NDPI_STATICSTRING_LEN(STR1CF))==0){
                    NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf------2 \n");
                    ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
                    return;	
                }
                break;
               // goto exit;
            }
        }
	}
exit:
  	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG, "exclude game_cf.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_CF);
}
void ndpi_search_game_cf_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"search game_cf udp stage is: %u\n",flow->cf_stage);
    u_int16_t payload_len = packet->payload_packet_len;
    u_int16_t len = 0;
	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"udp packet_len is: %u\n",payload_len);
    //cf_udp first packet len == 57
    if(payload_len > 3*16){
        len = ntohs(get_u_int16_t(packet->payload,2));
	    NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"udp len is: %u\n",len);
    }else{
  	    NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG, "exclude game_cf 1.\n");
        goto EXIT;
    }
    if(len == payload_len){
        switch(flow->cf_stage){
            case 0:
                if(memcmp(&packet->payload[28],STR2CF,NDPI_STATICSTRING_LEN(STR2CF))==0)
                {
                    flow->cf_stage ++;
                    }
                return;
            case 1:
                if(get_u_int16_t(packet->payload,18)==htons(0x07d7)) goto FOUND;
                goto EXIT;
            default:
  	            NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG, "exclude game_cf 2.\n");
                goto EXIT;
        }
    }else
        goto EXIT;
FOUND:
    NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG,"found game_cf--UDP \n");
    ndpi_int_game_cf_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
    return;	
EXIT:
  	NDPI_LOG(NDPI_PROTOCOL_GAME_CF, ndpi_struct, NDPI_LOG_DEBUG, "exclude game_cf.\n");
  	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_CF);
}
void ndpi_search_game_cf(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_game_cf_tcp(ndpi_struct, flow);
	}
	if (packet->udp != NULL) {
		ndpi_search_game_cf_udp(ndpi_struct, flow);
	}

}

#endif

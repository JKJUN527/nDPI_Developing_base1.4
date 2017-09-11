/*
 * zhentu.c
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
#ifdef NDPI_PROTOCOL_GAME_ZHENTU

/*
 PT:
 zhentu v3.2.0.7
block zhentu get server packet 

00000000  0a 05 64 1a 00 00 00 00  00 20 17 01 00 00 17 71   ..d..... . .....q
00000010  00 00 00 03 00 00 00 00  01 11                     ........ ..
    00000000  0a 05 64 1a 00 00 1c e1  00 20 17 01 00 00 17 72   ..d..... . .....r
    00000010  00 00 00 03 00 00 00 00  01 11 00 1f 81 00 1f 1c   ........ ........
    00000020  da 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
    00000030  00 00 09 64 69 72 5f 72  6f 6f 74 00 00 00 00 b4   ...dir_r oot.....
    00000040  00 00 00 00 00 00 00 01  00 01 00 00 00 00 00 00   ........ ........
    00000050  00 01 00 00 00 00 00 00  00 00 00 00 00 05 b5 e7   ........ ........
    00000060  d0 c5 00 00 00 00 04 00  00 00 00 00 00 00 01 00   ........ ........
    00000070  01 00 00 00 00 00 00 00  02 00 00 00 00 00 00 00   ........ ........
    00000080  00 00 00 00 05 cd f8 cd  a8 00 00 00 00 04 00 00   ........ ........
    00000090  00 04 00 00 00 01 00 01  00 00 00 00 00 00 01 03   ........ ........
    000000A0  00 00 00 00 00 00 00 00  00 00 00 05 bd cc d3 fd   ........ ........
    000000B0  00 00 00 00 04 00 00 00  04 00 00 00 01 00 01 00   ........ ........
    000000C0  00 00 01 00 00 01 01 00  00 00 01 00 00 00 00 00   ........ ........
    000000D0  00 00 0e b0 ac c5 b7 c4  e1 d1 c7 20 b5 e7 d0 c5   ........ ... ....
    000000E0  00 00 00 00 00 00 00 00  01 00 00 00 00 05 4e 6f   ........ ......No
    000000F0  6e 65 00 00 00 00 01 00  00 00 01 00 00 00 af 2d   ne...... .......-
    00000100  2d 68 6f 73 74 3d 68 6e  31 2d 6e 65 77 2d 66 65   -host=hn 1-new-fe
    00000110  61 70 70 2e 6c 6f 6c 2e  71 71 2e 63 6f 6d 20 2d   app.zhentu. qq.com -
    00000120  2d 78 6d 70 70 5f 73 65  72 76 65 72 5f 75 72 6c   -xmpp_se rver_url
    00000130  3d 68 6e 31 2d 6e 65 77  2d 65 6a 61 62 62 65 72   =hn1-new -ejabber
    00000140  64 2e 6c 6f 6c 2e 71 71  2e 63 6f 6d 20 2d 2d 6c   d.zhentu.qq .com --l
    00000150  71 5f 75 72 69 3d 68 74  74 70 73 3a 2f 2f 68 6e   q_uri=ht tps://hn
    00000160  31 2d 6e 65 77 2d 6c 6f  67 69 6e 2e 6c 6f 6c 2e   1-new-lo gin.zhentu.
    00000170  71 71 2e 63 6f 6d 3a 38  34 34 33 20 2d 2d 67 65   qq.com:8 443 --ge
    00000180  74 43 6c 69 65 6e 74 49  70 55 52 4c 3d 68 74 74   tClientI pURL=htt
    00000190  70 3a 2f 2f 31 38 33 2e  36 30 2e 31 36 35 2e 32   p://183. 60.165.2
    000001A0  31 34 2f 67 65 74 5f 69  70 2e 70 68 70 00 02 00   14/get_i p.php...
    000001B0  00 00 14 31 38 33 2e 36  31 2e 32 33 32 2e 31 32   ...183.6 1.232.12
    000001C0  33 3a 39 30 33 30 00 00  00 00 01 00 00 02 01 00   3:9030.. ........
    000001D0  00 00 01 00 00 00 00 00  00 00 0a d7 e6 b0 b2 20   ........ ....... 
    000001E0  b5 e7 d0 c5 00 00 00 00  00 00 00 00 01 00 00 00   ........ ........
	..................
*/



static void ndpi_int_zhentu_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_ZHENTU, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_game_zhentu_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG, "search for zhentu.\n");
	NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG, "payload len:%u. zhentustage:%u\n",packet->payload_packet_len,flow->zhentu_stage);
/*	  
if (flow->zhentu_stage < 3 && packet->payload_packet_len >= 8 
		&& packet->payload[0] == 0x34 && packet->payload[1] == 0x96
		&& packet->payload[2] == 0x79 && packet->payload[3] == 0x7f
		&& packet->payload[4] == 0x7b && packet->payload[5] == 0xbf
		&& packet->payload[6] == 0xab && packet->payload[7] == 0xb8){
			//34 96 79 7f 7b bf ab b8
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,
									"add zhentu_stage:%u\n",flow->zhentu_stage);
			ndpi_int_zhentu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"found zhentu-1\n");
			return ;
		}
	  else if (packet->payload_packet_len >= 24 
		&& packet->payload[16] == 0x15 && packet->payload[17] == 0xab
		&& packet->payload[18] == 0x9b && packet->payload[19] == 0x27
		&& packet->payload[20] == 0xdf && packet->payload[21] == 0x63
		&& packet->payload[22] == 0xf8 && packet->payload[23] == 0x55){
		//15 AB 9B 27 DF 63 F8 55
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,
									"add zhentu_stage:%u\n",flow->zhentu_stage);
			ndpi_int_zhentu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"found zhentu-2\n");
			return ;
		}
	
	else if(packet->payload_packet_len >= 8
		&& packet->payload[0] == 0xda && packet->payload[1] == 0xed
		&& packet->payload[2] == 0x7e && packet->payload[3] == 0xab
		&& packet->payload[4] == 0x2f && packet->payload[5] == 0x45
		&& packet->payload[6] == 0xa1 && packet->payload[7] == 0xf8){
		 //da ed 7e ab 2f 45 a1 f8
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,
									"add zhentu_stage:%u\n",flow->zhentu_stage);
			ndpi_int_zhentu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"found zhentu-3\n");
			return ;
		}
	else if(flow->zhentu_stage < 3 && packet->payload_packet_len >= 8
		&& packet->payload[0] == 0x26 && packet->payload[1] == 0x88
		&& packet->payload[2] == 0x7e && packet->payload[3] == 0x8e
		&& packet->payload[4] == 0xe8 && packet->payload[5] == 0x2c
		&& packet->payload[6] == 0x67 ){		
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,
									"add zhentu_stage:%u\n",flow->zhentu_stage);
			ndpi_int_zhentu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"found zhentu-4\n");
			return ;
	     }
	else if(flow->zhentu_stage < 3 && packet->payload_packet_len >= 8
		&& packet->payload[0] == 0x1d && packet->payload[1] == 0x5f
		&& packet->payload[2] == 0x76 && packet->payload[3] == 0x9e
		&& packet->payload[4] == 0xd4 && packet->payload[5] == 0x0f
		&& packet->payload[6] == 0x4f && packet->payload[7] == 0xe5){
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,
									"add zhentu_stage:%u\n",flow->zhentu_stage);
			ndpi_int_zhentu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"found zhentu-5\n");
			return ;
	
		}
else if (flow->zhentu_stage == 3){
	NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,
									"exclude zhentu\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_ZHENTU);
	}
	flow->zhentu_stage++;
*/
	if(flow->zhentu_stage<3){
		//NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"comming---")
		if(packet->payload_packet_len==24
			&&get_u_int32_t(packet->payload, 16) == htonl(0x15ab9b27)
			&&get_u_int32_t(packet->payload, 20) == htonl(0xdf63f855)){
				ndpi_int_zhentu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"found zhentu-1\n");
				return ;
			}
		if(packet->payload_packet_len==32
			&&get_u_int32_t(packet->payload, 0) == htonl(0xdaed7eab)
			&&get_u_int32_t(packet->payload, 4) == htonl(0x2f45a1f8)){
				ndpi_int_zhentu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"found zhentu-2\n");
				return ;
			}
		if(packet->payload_packet_len==312
			&&get_u_int32_t(packet->payload, 0) == htonl(0xd35d30d4)
			&&get_u_int32_t(packet->payload, 4) == htonl(0xd3ea503a)){
				ndpi_int_zhentu_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,"found zhentu-3\n");
				return ;
			}
	}else{
	NDPI_LOG(NDPI_PROTOCOL_GAME_ZHENTU, ndpi_struct, NDPI_LOG_DEBUG,
									"exclude zhentu\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GAME_ZHENTU);
	}
	flow->zhentu_stage++;
}

void ndpi_search_game_zhentu(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_game_zhentu_tcp(ndpi_struct, flow);
	}
}

#endif

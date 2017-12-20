/*
 * wechat.c
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
#ifdef NDPI_PROTOCOL_WECHAT

/*
 PT:
 wechat

	tcp:
	00 00 [_len] 00 10 00 01     3b 9a ca 79 00 00 00 9b 
	bf _5 5f __  __ __ __ a0     65 77 f6 09 02 18 02 ed
	
	the shortest pkg is 
	00 00 00 14 00 10 00 01  00 00 00 18 00 00 00 00
	00 00 00 02
	
	typedef struct wx_header_s {
    u_int32_t packet_len; // 前4字节表示数据包长度，可变
    u_int16_t header_len; //2个字节表示头部长度,固定值，0x10
    u_int16_t thx_ver; //2个字节表示谢意版本，固定值，0x01
    u_int32_t operation_code; //4个字节操作说明数字，可变
    u_int32_t serial_number; //序列号，可变
}wx_header_t;

	operation_code:

	00 00 00 18 //may heart beat
	00 00 00 79
	3b 9a ca 79
	3b 9a ca be
	00 00 00 ed
	3b 9a ca ed
	3b 9a ca 13
	00 00 00 9b
	3b 9a ca 9b
    0x00000013 语音聊天
	0x000000ed 文字聊天
	0x0000009b 获取新闻（购物、大众点评）
	0x00000038 摇一摇
	0x00000039 摇一摇
	0x00000022 扫一扫（测试smart6公众号、搜索QQ号）
	0x0000002c 测试关注xxx公众号、增加QQ好友
*/

static void ndpi_int_wechat_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WECHAT, NDPI_REAL_PROTOCOL);
}
	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_wechat_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	#ifdef DEBUG
	
	if (get_u_int32_t(packet->payload, 4) == htonl(0x00100001)){
		NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,
		"may wechat(00100001) %x,%x,%x,%x \n",
		get_u_int32_t(packet->payload, 4),
		get_u_int16_t(packet->payload, 8),
		packet->payload[8+2],
		packet->payload[8+3]
		);
	
	}

	#endif
	if(
	    packet->payload_packet_len >= 14
	&& (get_u_int32_t(packet->payload, 0) == htonl(packet->payload_packet_len))
	&& (get_u_int32_t(packet->payload, 4) == htonl(0x00100001))
/*	&& (
	    //pre 3
		  (
		      (get_u_int16_t(packet->payload, 8) == htonl( 0x3b9a) && packet->payload[8+2] == 0xca )
		    ||(get_u_int16_t(packet->payload, 8) == htonl( 0x0000) && packet->payload[8+2] == 0x00)
		  )
		  &&(
		       packet->payload[8+3] == 0x18
			|| packet->payload[8+3] == 0x79
			|| packet->payload[8+3] == 0xbe
			|| packet->payload[8+3] == 0xed
			|| packet->payload[8+3] == 0x13
			|| packet->payload[8+3] == 0x9b
			|| packet->payload[8+3] == 0x06
			
		  )
	   )*/
	)
	{
		NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,
									"found wechat \n");
		ndpi_int_wechat_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	}
}

void ndpi_search_wechat(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_wechat_tcp(ndpi_struct, flow);
	}
}

#endif

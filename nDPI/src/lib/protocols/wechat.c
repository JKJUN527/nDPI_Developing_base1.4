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
/*
tcp 443 端口：
   ab 00 00 [01 02 ] 27 14 b0     [packet_len] [ab 00] 固定格式

   第29-31 位字节表示字符“ver”
   第32-35 字节表示版本号00000001
   第41-49 字节表示字符“weixinnum”

自定义加密流量：使用端口不确定
1: 16 f1 03 01 65 00 00 01 61 01 03 f1 02 c0 2b 00   ........最后四字节固定00000001
2: 16 f1 03 01 65 00 00 01 61 01 03 f1 02 c0 2b 00   ........最后四字节固定00000001
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
	)
	{
		NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,"found wechat \n");
		ndpi_int_wechat_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	}

    //may wechat change protocol
    //ab 00 00 01 01 27 14 3e  0b 9e 0f 00 00 00 00 00   .....'.> ........
    //00000010  00 00 00 00 00 00 00 00  e8 00 00 00 03 76 65 72   ........ .....ver
    //00000020  00 00 00 01 31 00 00 00  09 77 65 69 78 69 6e 6e   ....1... .weixinn
    //00000030  75 6d 00 00 00 09 32 36  32 30 31 35 38 30 36 00   um....26 2015806.
    //00000040  00 00 03 73 65 71 00 00  00 01 31 00 00 00 0d 63   ...seq.. ..1....c
    //00000050  6c 69 65 6e 74 76 65 72  73 69 6f 6e 00 00 00 0a   lientver sion....
    //00000060  31 36 34 34 35 36 30 37  31 35 00 00 00 0c 63 6c   16445607 15....cl
    //00000070  69 65 6e 74 6f 73 74 79  70 65 00 00 00 0a 57 69   ientosty pe....Wi
    //00000080  6e 64 6f 77 73 20 31 30  00 00 00 07 61 75 74 68   ndows 10 ....auth
    //00000090  6b 65 79 00 00 00 45 30  43 02 01 01 04 3c 30 3a   key...E0 C....<0:
    u_int16_t len = packet->payload_packet_len;
    char version = 0x01;
    #define VER            "\x76\x65\x72"
    #define WEIXINNUM      "\x77\x65\x69\x78\x69\x6e\x6e\x75\x6d"
    #define SEQ            "\x73\x65\x71"
    #define CLIENTVERSION  "\x63\x6c\x69\x65\x6e\x74\x76\x65\x72\x73\x69\x6f\x6e"
    #define CLIENTOSTYPE   "\x63\x6c\x69\x65\x6e\x74\x6f\x73\x74\x79\x70\x65"
    #define AUTHKEY        "\x61\x75\x74\x68\x6b\x65\x79"
    NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,"first b:%x \n",packet->payload[0]);
	NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,"len:%x \n",ntohs(get_u_int16_t(packet->payload,3)));
	NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,"packet[5*8+1]:%x \n",packet->payload[5*8+1]);
	NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,"packet[4*16+3]:%x \n",packet->payload[4*16+3]);
	NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,"packet[5*16-1]:%x \n",packet->payload[5*16-1]);
    
    if(len >=(10*16)
        &&packet->payload[0] == 0xab
        //&& len == ntohs(get_u_int16_t(packet->payload,3))
        && 0x01 == packet->payload[16*2+3]
        && memcmp(&packet->payload[3*8+5],VER,NDPI_STATICSTRING_LEN(VER))==0
        && memcmp(&packet->payload[5*8+1],WEIXINNUM,NDPI_STATICSTRING_LEN(WEIXINNUM))==0
        //&& memcmp(&packet->payload[4*16+3],SEQ,NDPI_STATICSTRING_LEN(SEQ))==0
    //    && memcmp(&packet->payload[5*16-1],CLIENTVERSION,NDPI_STATICSTRING_LEN(CLIENTVERSION))==0
    ){
        NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,
                                             "found wechat \n");
        ndpi_int_wechat_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
    }
    //登录后伪装成加密流经80端口发送文字及表情消息
    if(len >16
        &&(get_u_int32_t(packet->payload,0) == htonl(0x17f10300)||get_u_int32_t(packet->payload,0) == htonl(0x16f10300))
        &&len == ntohs(get_u_int16_t(packet->payload,3))+5
    ){
        NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,
                                             "found wechat 2\n");
        ndpi_int_wechat_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
        goto found;
    }
    /*
    if(get_u_int16_t(packet->payload,0) == htons(0xab00)
        &&packet->payload_packet_len > 3*16+2
        &&packet->payload_packet_len == ntohs(get_u_int16_t(packet->payload,3))
        &&memcmp(&packet->payload[5*8+1],"\x77\x65\x69\x78\x69\x6e\x6e\x75\x6d",9) == 0
    ){
        goto found;
    }
    if((packet->payload[0]==0x16
            ||packet->payload[0]==0x17)
        &&packet->payload[1]==0xf1
        &&packet->payload[2]==0x03
        &&packet->payload_packet_len >16
        &&packet->payload_packet_len == ntohs(get_u_int16_t(packet->payload,3))+5
       // &&get_u_int32_t(packet->payload,packet->payload_packet_len-4) == htonl(0x00000001)
    ){
        goto found;
    }
    */
    return;

found:
		NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,
									"found wechat \n");
		ndpi_int_wechat_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_wechat(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG,
									"search wechat \n");
		ndpi_search_wechat_tcp(ndpi_struct, flow);
	}
}

#endif

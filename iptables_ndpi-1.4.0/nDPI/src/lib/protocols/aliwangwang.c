/*
 * aliwangwang.c
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
#ifdef NDPI_PROTOCOL_ALIWANGWANG

/*
 PT:
 aliwangwang: old version
 first pkg len(40): 
	88 06 00 00 __ 00 00 7b  00 00 00 00 00 00 00 10   
	01 00 00 02 01 e7 00 00  01 40 00 00 00 08 38 2e    
	36 30 2e 30 31 43 00 00
 second: send RSA len(328)
 	88 06 00 00 00 00 00 __  00 00 00 00 00 00 01 30
 	01 ...							...
 	...							...
 	...							...		   [-  -  -
 	-  -  B  E  G  I  N      
	payload[4*16+8+5]="---BEGIN RSA PUBLIC KEY-----"
	payload[19*16+ki4]: "ER\x0a-----END RSA PUBLIC KEY"
	
third:
	payload[12*16+6:]=="taobao"
forth:
	88 06 00 00 __ 00 00 79  00 00 00 00 00 00 01 a0
 	01 __ __ __ __ __ 00 00 ....
 	    .............

	aliwangwang: new version v2.0.0.1
		新版：
	1. (打开客户端 400754636d436f7265400b65786368616e67654b657902000140 -- strncasecmp )
										  40 07 54 63 6d 43 6f   ........ .@.TcmCo
	00000010  72 65 40 0b 65 78 63 68  61 6e 67 65 4b 65 79 02   re@.exch angeKey.
	00000020  00 01 40
	2. 80端口(02400277784001730140)  回来的包，16字节之内必开始：02 40 02 77 78 40 01 73 01  【可能会出问题，不能放在http里面，http回来的包不会进入http.c】
	3.im.alisoft.com

first open client:
len = 10*16+5 || len = 5*16+7
payload[8+1]
payload[8-1]
00000000  a3 01 bb 87 01 00 00 9f  03 40 07 54 63 6d 43 6f   ........ .@.TcmCo
00000010  72 65 40 0b 65 78 63 68  61 6e 67 65 4b 65 79 02   re@.exch angeKey.
00000020  00 01 40 80 01 95 55 f1  24 25 9c 94 7b f3 8e 06   ..@...U. $%..{...
00000030  57 37 eb 13 23 9e b6 2d  a4 69 42 45 32 db fd ca   W7..#..- .iBE2...
00000040  47 3e 05 5f 8b a8 d0 f7  55 7b fd a5 54 97 7b 2f   G>._.... U{..T.{/
00000050  31 4a 88 4d 19 48 c0 b4  46 81 91 a4 d2 c0 cd fd   1J.M.H.. F.......
00000060  10 96 3c b9 25 63 ea 58  ad 7c 9a 7e 37 4d 46 74   ..<.%c.X .|.~7MFt
00000070  6d 4f 35 f9 0e 64 4f 40  77 47 63 fc 6e 57 39 bf   mO5..dO@ wGc.nW9.
00000080  d3 d1 01 85 68 1d b0 6d  9e 0b cc 44 24 66 6f 52   ....h..m ...D$foR
00000090  71 06 49 4c 9a da 71 72  15 e3 79 d4 7d 30 04 bb   q.IL..qr ..y.}0..
000000A0  9a 88 0e e5 52                                     ....R
    00000000  56 f8 42 00 00 ec 03 40  07 54 63 6d 43 6f 72 65   V.B....@ .TcmCore
    00000010  40 0b 65 78 63 68 61 6e  67 65 4b 65 79 02 01 00   @.exchan geKey...
    00000020  03 40 10 2f af e7 a1 2a  3b 4c 90 e3 48 20 63 99   .@./...* ;L..H c.
    00000030  87 ae 2b 05 44 40 20 70  6a 07 87 de da b1 9a 97   ..+.D@ p j.......
    00000040  74 cf c9 8c 11 b8 e6 73  5e 1e f3 e1 be 95 22 11   t......s ^.....".
    00000050  43 c8 8e f3 40 36 e9                               C...@6.


twice login:
first pkt
len = 7*16
payload[0] = 27
payload[2] => 0c 01 b6 c1 01
payload[8] => c3 0a 06 e6 1b 61 34 63 36 bf b1 4b 10 06 30 5b
00000000  27 __ 0c 01 b6 c1 01 __  c3 0a 06 e6 1b 61 34 63   '....... .....a4c
00000010  36 bf b1 4b 10 06 30 5b  ________________________   6..K..0[ ..+.....
....

second pkt : len = 5*16+6
		payload[0] => 0x55
		payload[2] int16 => 0x0100
		payload[6]  ==> 82 ec  42 b0 4d 63 34 b1 ff ff c8 34 80 cb c7 f1
		payload[4*8+6] ==>
    00000000  55 __ 25 01 00 __ 82 ec  42 b0 4d 63 34 b1 ff ff   U.%..... B.Mc4...
    00000010  c8 34 80 cb c7 f1 __ __  .....				    .4....-. '...P...
    00000020  __ __ __ __ __ __[76 0b  de 3a b4 e9 6e ae 82 e3   m$..T.v. .:..n...
    00000030  11 7d 1c 8b eb 8f a2 3a  5a 92 d1 f8 e7 a8 cb 9a   .}.....: Z.......
    00000040  9c 20 2e 06 f0 6b 68 0b  7b 9b c9 88 5c 56 69 31   . ...kh. {...\Vi1
    00000050  ec d4 88 82 d4 7e]                                  .....~

third pkt 
00000070  __ __ __ __ 02 05 b6 c1  01 __ _________________   ........ ........
00000080  c5 b0 18 93 52 35 a5 ae  22 af c1 2c c7 4d e1 16   ....R5.. "..,.M..
00000090  f7 68 a6 65 e9 ba 96 a8  fd be 17 91 b8 3f 38 46   .h.e.... .....?8F
000000A0  9a 1e 02 70 eb 71 ce b9  fb a2 08 96 f2 69 72 6b   ...p.q.. .....irk
000000B0  bd fe c1 5d b3 59 9a 65  9e ac 49 7e 43 4a 00 e7   ...].Y.e ..I~CJ..

forth pkt:

00000452  _______________________  14 6c a9 51 6f 66 d5 c7   G.)..... .l.Qof..
00000462  1c 04 99 6b 31 06 f0 2e   ...				         ...k1... ......$>
00000472         ...                      ...                j......3 .dC~.M.=
00000482         ...                      ...             a   .n....C. ..aC_A.Z
00000492         ...                                         w.x....k 

if payload_len < 128
	payload[0] = payload_len-1


change :

	000003D0  dc 02 -- -- 01 00 -- --  -- -- 02 40 02 77 78 40   ........ ...@.wx@
    000003E0  01 73 01 40 c8 02 88 06  00 00 00 00 00 -- 00 00   .s.@.... ........
    000003F0  00 00 00 00 01 30 01 01  00 02 55 0b 00 00 04 06   .....0.. ..U.....
    00000400  00 00 00 00 40 00 00 00  20 33 32 32 30 31 32 30   ....@...  3220120
    00000410  31 48 30 30 30 30 31 30  31 31 31 30 30 30 30 30   1H000010 11100000
    00000420  30 30 30 30 30 30 30 30  30 06 -- -- -- -- 40 00   00000000 0._...@.
    00000430  00 00 f7 2d 2d 2d 2d 2d  42 45 47 49 4e 20 52 53   ...----- BEGIN RS
    00000440  41 20 50 55 42 4c 49 43  20 4b 45 59 2d 2d 2d 2d   A PUBLIC  KEY----
    00000450  2d[0a 4d 49 47 48 41 6f  47 42 41 4f 4d 37 4d 7a   -.MIGHAo GBAOM7Mz
    00000460  43 76 52 57 51 46 2b 56  43 31 31 4a 49 53 42 6e   CvRWQF+V C11JISBn
    00000470  58 74 42 78 54 45 4d 4c  50 44 65 75 62 56 34 48   XtBxTEML PDeubV4H
    00000480  66 53 4c 6f 61 74 61 58  36 38 32 62 65 49 6d 61   fSLoataX 682beIma
    00000490  47 35 0a 61 2b 51 75 76  67 7a 51 33 58 47 52 55   G5.a+Quv gzQ3XGRU
    000004A0  70 66 57 70 4d 65 54 56  38 54 79 4d 61 55 73 70   pfWpMeTV 8TyMaUsp
    000004B0  72 7a 73 41 75 41 56 51  6c 4d 53 2b 75 4e 49 74   rzsAuAVQ lMS+uNIt
    000004C0  4d 2b 52 50 37 2f 75 65  76 5a 6a 4b 57 55 46 79   M+RP7/ue vZjKWUFy
    000004D0  48 52 46 0a 45 4f 5a 70  42 64 32 62 64 65 59 69   HRF.EOZp Bd2bdeYi
    000004E0  4b 76 46 68 77 63 72 68  39 51 72 2f 77 2b 6b 4a   KvFhwcrh 9Qr/w+kJ
    000004F0  69 54 33 66 6f 64 31 34  36 50 56 64 4a 48 69 73   iT3fod14 6PVdJHis
    00000500  63 6f 71 35 67 72 62 33  41 67 45 52]0a 2d 2d 2d   coq5grb3 AgER.---
    00000510  2d 2d 45 4e 44 20 52 53  41 20 50 55 42 4c 49 43   --END RS A PUBLIC
    00000520  20 4b 45 59 2d 2d 2d 2d  2d 0a 00 00 00 00          KEY---- -.....
  len:21*16+8+6
  payload[0:2]=dc02
  payload[4:2]=0100
  payload[10:] = 02 40 02 77 78 40 01 73 01 40
  payload[6*8+4]= 40 00 00 00  20 33 32 32 30 31 32 30 31 48 30 30 30 30 31 30  31 31 31 30 30 30 30 30 30 30 30 30 30 30 30 30  30 06 -- -- -- -- 40
  payload[6*16+3] = ----- BEGIN RSA PUBLIC  KEY-----

opened client, relogin

48e0e79f94e2e802bedab8945728e521

00000001  26 --[0c 01 a4 6f]52 48 [e0 e7 9f 94 e2 e8 02 be   &....oRH ........
00000011  da b8 94 57 28 e5] 21 --  ..........   ...W(.!. m.g.=v..
00000021  1b 01 0f 99 72 86 99 46  97 1f 01 a4 6f 04 9b 29   ....r..F ....o..)
00000031  75 40 0d 41 44 fb 1b c6  2a 45 04 01 3e eb 2b db   u@.AD... *E..>.+.
00000041  fe 0c a9 3f f1 a4 33 30  6c ea 25 42 99 d9 14 c2   ...?..30 l.%B....
00000051  53 88 6a c3 9c 62 91 7b  f5 6b 88 ad 28 9f bc e9   S.j..b.{ .k..(...
00000061  bf 84 a7 b5 63 5f 44 39  f2 1e 30 da 6f 74         ....c_D9 ..0.ot


*/

/*TcmCore may appear in 443*/
#define STR0AT7_9 "@\x07TcmCore@"
#define STR1AT10 "\x02\x40\x02\x77\x78\x40\x01\x73\x01\x40"
#define STR1AT10_LEN 10
#define STR1AT6_8_4 "\x40\x00\x00\x00\x20\x33\x32\x32\x30\x31\x32\x30\x31\x48\x30\x30\x30\x30\x31\x30\x31\x31\x31\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
#define STR1AT6_8_4_LEN 36
#define STR1AT6_16_3 "----- BEGIN RSA PUBLIC  KEY-----"
#define STR1AT6_16_3_LEN NDPI_STATICSTRING_LEN(STR1AT6_16_3)

#define STR2AT2_FIRST "\x0c\x01\xa4\x6f"
#define STR2AT2_FIRST_LEN 4
#define STR2AT8_FIRST "\xe0\xe7\x9f\x94\xe2\xe8\x02\xbe\xda\xb8\x94\x57\x28\xe5"
#define STR2AT8_FIRST_LEN 14


/*#define STR2AT2_FIRST "\x0c\x01\xb6\xc1\x01"
#define STR2AT8_FIRST "\xc3\x0a\x06\xe6\x1b\x61\x34\x63\x36\xbf\xb1\x4b\x10\x06\x30\x5b"

#define STR3AT6_SEC "\x82\xec\x42\xb0\x4d\x63\x34\xb1\xff\xff\xc8\x34\x80\xcb\xc7\xf1"
#define STR3AT4_8_6_SEC "\x76\x0b\xde\x3a\xb4\xe9\x6e\xae\x82\xe3\x11\x7d\x1c\x8b\xeb\x8f\xa2\x3a\x5a\x92\xd1\xf8\xe7\xa8\xcb\x9a\x9c\x20\x2e\x06\xf0\x6b\x68\x0b\x7b\x9b\xc9\x88\x5c\x56\x69\x31\xec\xd4\x88\x82\xd4\x7e"

#define STR1BEFORE16
*/

static void ndpi_int_aliwangwang_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					    struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ALIWANGWANG, NDPI_REAL_PROTOCOL);
}
/*
static char contains(const char *s, const char * find, int start, int max_cnt){
	int i;
	int len ;
	len = strlen(find);
	printf( "contains: find [%s] in [%s]\n",find,s);
	for(i=start;i<max_cnt;i++){
		if(*(s+i)==*find)
			if(memcmp(s, find, len)==0){
				printf("find!\n");
				return 0;
			}
	}
	printf("no find\n");
	return 1;
}
*/
	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_aliwangwang_tcp(struct ndpi_detection_module_struct
												  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "search for aliwangwang.\n");
	NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "payload len:%u.\n",packet->payload_packet_len);
	#ifdef DEBUG
	
#if 1
	if( // first open client
		(packet->payload_packet_len >=48)
			
		){
		if (   memcmp(packet->payload + 10, STR1AT10 ,10) == 0){
		
			NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "may aliwangwang1.\n");
			}
		else{
			int i,j;
			unsigned char buf [256] = STR1AT10;
			NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "07 LEN: %d\n",NDPI_STATICSTRING_LEN(STR1AT10));
			j = 10;
			for(i=j;i<NDPI_STATICSTRING_LEN(STR1AT10)+j;i++){
				NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "%2x",*(packet->payload+i));
			}

			NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "\n");
			for(i=j;i<NDPI_STATICSTRING_LEN(STR1AT10)+j;i++){
				NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "%c",*(packet->payload+i));
			}
			
			NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "\n");
			for(i=0;i<NDPI_STATICSTRING_LEN(STR1AT10);i++){
				NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "%2x",buf[i]);
			}
			NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "\n");
			for(i=0;i<NDPI_STATICSTRING_LEN(STR1AT10);i++){
				NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "%c",buf[i]);
			}
			NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "\n");
			for(i=0;i<NDPI_STATICSTRING_LEN(STR1AT10);i++){
				if(*(packet->payload+i+j) == buf[i]){
					NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "--");
				}else{
					NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "xx");
				}
			}
			NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "\n");
		}
	}

#endif
	#endif
	
	if(( // old version
			packet->payload_packet_len >= 24 
		&& (get_u_int32_t(packet->payload, 0) == htonl(0x88060000))
		&& (get_u_int16_t(packet->payload, 5) == htons( 0x0000))
		//&& packet->payload[7] == 0x00
		&& packet->payload[16]==0x01
		//&& packet->payload[18]==0x01	//may we can filter the pre 4 pkgs 
		&& (get_u_int16_t(packet->payload, 2*8+6) == htons(0x0000))
	)
 // new version
	|| ( // first open client or reconnect
		(packet->payload_packet_len >=20 )
			&& (
			ndpi_mem_cmp(packet->payload + 7, STR0AT7_9, 10) == 0
		 || ndpi_mem_cmp(packet->payload + 9, STR0AT7_9, 10) == 0)
		)
/*	//|| (contains(packet->payload,"\x40\x02\x77\x78\x40",0,17) == 0)
	|| ( //twice login first pkt
			packet->payload_packet_len >= 7*16
			&& packet->payload[0] == 0x26
			&& ndpi_mem_cmp(packet->payload + 2, STR2AT2_FIRST,STR2AT2_FIRST_LEN) == 0
			&& ndpi_mem_cmp(packet->payload + 8, STR2AT8_FIRST,STR2AT8_FIRST_LEN) == 0
		)
	|| ( //twice login sec pkt
			packet->payload_packet_len == 5*16+6
			&& packet->payload_packet_len < 128
			&& packet->payload_packet_len > 3*16
			&& packet->payload[0] == packet->payload_packet_len - 1
			&& get_u_int16_t(packet->payload, 2) == htonl(0x0100)
			//&& ndpi_mem_cmp(packet->payload + 6, STR3AT6_SEC,NDPI_STATICSTRING_LEN(STR3AT6_SEC )) == 0
			//&& ndpi_mem_cmp(packet->payload + (4*8+6), STR3AT4_8_6_SEC,NDPI_STATICSTRING_LEN(STR3AT4_8_6_SEC )+1) == 0
		)
	|| (
		   packet->payload_packet_len == (21*16+8+6) 
		&& (get_u_int16_t(packet->payload, 0) == htons( 0xdc02)) 
		&& (get_u_int16_t(packet->payload, 4) == htons( 0x0100)) 
		&& ndpi_mem_cmp(packet->payload + 10, STR1AT10,STR1AT10_LEN) == 0
		&& ndpi_mem_cmp(packet->payload + 6*8+4, STR1AT6_8_4, STR1AT6_8_4_LEN) == 0
		&& ndpi_mem_cmp(packet->payload + 6*16+3, STR1AT6_16_3, STR1AT6_16_3_LEN) == 0
		)*/
	){
	
		NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG,
									"found aliwangwang \n");
		ndpi_int_aliwangwang_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
		return;
	}

	NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG,
									"your aliwangwang_stage %u \n",flow->l4.tcp.aliwangwang_stage);
	if(   
		(packet->payload[0] == 0x37 
		&& packet->payload[3] == 0x01)
	|| ( packet->payload[2] == 0x0c
		&& packet->payload[3] == 0x01)
	)
		{
		flow->l4.tcp.aliwangwang_stage=4;
		NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG,
									"add aliwangwang_stage 3 \n");
		return;
	}
	if(flow->l4.tcp.aliwangwang_stage == 4){
		NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG,
									"check aliwangwang_stage 3 \n");
		if( (   packet->payload[0] == packet->payload_packet_len - 1
			&& packet->payload[3] == 0x0 
			&& packet->payload[4] == 0x0 
			&& memcmp(packet->payload + 7, "\x40\x02\x77\x78\x40", 5) == 0)
		  ||(
		  	 packet->payload[0] == packet->payload_packet_len - 1
		  	&& (packet->payload[2] & 0xf0)== 0x20
		  	&& packet->payload[3] == 0x01
		  	&& packet->payload[4] == 0x00
		  	)
		  ){
			flow->l4.tcp.aliwangwang_stage = 5;
		}else{
			flow->l4.tcp.aliwangwang_stage = 6;
			}
		
	}

	
	if(flow->l4.tcp.aliwangwang_stage == 5  ){
			ndpi_int_aliwangwang_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
	}
	
	flow->l4.tcp.aliwangwang_stage++;
	NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG,
									"adding aliwangwang_stage \n");
	if (flow->l4.tcp.aliwangwang_stage > 3){
		NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG,
									"exclude aliwangwang \n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ALIWANGWANG);
	}
	
}

void ndpi_search_aliwangwang(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_search_aliwangwang_tcp(ndpi_struct, flow);
	}
}

#endif

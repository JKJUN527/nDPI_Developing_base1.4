/*
 * http.c
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

#ifdef NDPI_PROTOCOL_HTTP

static void ndpi_int_http_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					 struct ndpi_flow_struct *flow,
					 u_int32_t protocol)
{
  

  if (protocol != NDPI_PROTOCOL_HTTP) {
    ndpi_int_add_connection(ndpi_struct, flow, protocol, NDPI_CORRELATED_PROTOCOL);
  } else {
    ndpi_int_reset_protocol(flow);
    ndpi_int_add_connection(ndpi_struct, flow, protocol, NDPI_REAL_PROTOCOL);
  }
  flow->http_detected = 1;
}

// this is in for of check_useragent_contains
// return bool (1)success or (0)fail
static char pt_str_search(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, const char *ptr, u_int16_t i ,u_int16_t max_len){

	if(ptr + i != NULL) {
		#ifdef NDPI_PROTOCOL_WECHAT
			if( NDPI_STATICSTRING_LEN("MicroMessenger") <= max_len -i 
				&& ndpi_mem_cmp(ptr + i, "MicroMessenger", NDPI_STATICSTRING_LEN("MicroMessenger")) == 0){
				NDPI_LOG(NDPI_PROTOCOL_WECHAT, ndpi_struct, NDPI_LOG_DEBUG, "wechat: wechat useragent detected.\n");
				ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WECHAT);
				return 0;
			}
		#endif

		#ifdef NDPI_PROTOCOL_THUNDER
			if( NDPI_STATICSTRING_LEN("Thunder") <= max_len -i 
				&& ndpi_mem_cmp(ptr + i, "Thunder", NDPI_STATICSTRING_LEN("Thunder")) == 0){
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder: thunder useragent detected.\n");
				ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_THUNDER);
				return 0;
			}
		#endif
		#ifdef NDPI_PROTOCOL_THUNDER
			if( NDPI_STATICSTRING_LEN("Bittorrent") <= max_len -i 
				&& ndpi_mem_cmp(ptr + i, "Bittorrent", NDPI_STATICSTRING_LEN("Bittorrent")) == 0){
				NDPI_LOG(NDPI_PROTOCOL_BITTORRENT, ndpi_struct, NDPI_LOG_DEBUG, "Bittorrent: Bittorrent useragent detected.\n");
				ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_BITTORRENT);
				return 0;
			}
		#endif
		#ifdef NDPI_PROTOCOL_WORLDOFWARCRAFT
			if((NDPI_STATICSTRING_LEN("Blizzard Web Client") <= max_len -i 
				&& ndpi_mem_cmp(ptr + i, "Blizzard Web Client", NDPI_STATICSTRING_LEN("Blizzard Web Client")) == 0)
			  ||(NDPI_STATICSTRING_LEN("Blizzard Downloader") <= max_len -i
				&& ndpi_mem_cmp(ptr + i, "Blizzard Downloader", NDPI_STATICSTRING_LEN("Blizzard Downloader")) == 0)
			){
			    NDPI_LOG(NDPI_PROTOCOL_WORLDOFWARCRAFT, ndpi_struct, NDPI_LOG_DEBUG, "WORLDOFWARCRAFT: WorldOfWarCraft useragent detected.\n");
				ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WORLDOFWARCRAFT);
				return 0;

			}
		#endif
	}
	return 1;
}

/*
somttimes useragent is not like UserAgent: xxx
check if the ua is in it 
*/
static u_int8_t check_useragent_contains(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	
	int i;
	struct ndpi_packet_struct *packet = &flow->packet;
	ndpi_parse_packet_line_info(ndpi_struct, flow);
	//NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "contains_http_useragent: packet->user_agent_line.len:%u, packet->user_agent_line.ptr:%s \n",packet->user_agent_line.len,packet->user_agent_line.ptr);
	
	if(packet->user_agent_line.ptr == NULL){
		NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,"none uaptr check skip\n");
		return 0;
	}
	
	for(i = 0; i< packet->user_agent_line.len ; i++){
		if(packet->user_agent_line.ptr + i != NULL){
			if(pt_str_search(ndpi_struct,flow, packet->user_agent_line.ptr, i, packet->user_agent_line.len) == 0){
				NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,"check success\n");
				return 1;
			}
			
		}
	}
	NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,"check fail\n");
	return 0;
}


#ifdef NDPI_PROTOCOL_THUNDER
static void thunder_check_http_payload(struct ndpi_detection_module_struct *ndpi_struct,struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	ndpi_parse_packet_line_info(ndpi_struct, flow);
	NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder: will HTTP packet detected in http.c. total lines:%u, len:%u\n",packet->parsed_lines, packet->payload_packet_len);
	//if (packet->host_line.ptr!=NULL &&packet->host_line.len>10 && (StringFind(packet->host_line.ptr,"sandai.net") != -1))
  	//{
    	//	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "thunder: hostline found.\n");
    //		ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_THUNDER);
    	//	return;
  	//}
//http download feature

	if(packet->payload_packet_len > 17 && ndpi_mem_cmp(packet->payload, "GET", 3) == 0 &&packet->parsed_lines > 5){
		ndpi_parse_packet_line_info(ndpi_struct, flow);
		NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "thunder: I COME IN 1\n");
		//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "line[1]:%s\n",packet->line[1].ptr);
		//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "line[2]:%s\n",packet->line[2].ptr);
		//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "line[3]:%s\n",packet->line[3].ptr);
		//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "line[4]:%s\n",packet->line[4].ptr);
		//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "line[5]:%s\n",packet->line[5].ptr);
		if (packet->line[1].len == 23
			&& ndpi_mem_cmp(packet->line[1].ptr, "Cache-Control: no-cache", 23) == 0
			&& packet->line[2].len == 22
			&& ndpi_mem_cmp(packet->line[2].ptr, "Connection: keep-alive", 22) == 0
			&& packet->line[3].len > 6
			&& ndpi_mem_cmp(packet->line[3].ptr, "Host: ", 6) == 0
			//&& packet->line[4].len > 13
			//&& ndpi_mem_cmp(packet->line[4].ptr, "Range: bytes=", 13) == 0 
			&& ( (packet->line[4].len > 11 && ndpi_mem_cmp(packet->line[4].ptr, "User-Agent:", 11) == 0)
				||(packet->line[4].len > 13 && ndpi_mem_cmp(packet->line[4].ptr, "Range: bytes=", 13) == 0)
				||(packet->line[4].len > 9 && ndpi_mem_cmp(packet->line[4].ptr, "Referer: ", 9) == 0)	
			)){
			NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
									"thunder HTTP download detected,(new one).\n");
			ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_THUNDER);
		}
	}

//before UDP download feature

	if (packet->payload_packet_len > 17 
				&& ndpi_mem_cmp(packet->payload, "POST / HTTP/1.1\r\n", 17) == 0 &&packet->parsed_lines > 5
			){
		ndpi_parse_packet_line_info(ndpi_struct, flow);
		NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder: HTTP packet detected. lines:%u \n",packet->parsed_lines);
		if (packet->line[1].len > 6
			&& ndpi_mem_cmp(packet->line[1].ptr, "Host: ", 6) == 0
			&& packet->line[2].len == 38
			&& ndpi_mem_cmp(packet->line[2].ptr, "Content-type: application/octet-stream", 38) == 0
			&& packet->line[3].len > 16
			&& ndpi_mem_cmp(packet->line[3].ptr, "Content-Length: ", 16) == 0
			//&& packet->line[4].len == 22
			&& (ndpi_mem_cmp(packet->line[4].ptr, "Connection: Keep-Alive", 22) == 0 ||ndpi_mem_cmp(packet->line[4].ptr, "Connection: Close", 17) == 0)
			 ){
			//NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG, "thunder: may thunder http header in http.c .\n");
		    
			//check media len and content-len
			//const char * media_ptr;
			//media_ptr = packet->line[6].ptr;
			// 0 88:58:03:26
			//if(packet->payload_packet_len > 80
			//&& ndpi_mem_cmp(media_ptr, "\x88\x58\x03\x26", 4) == 0
			//&& media_ptr[7] == 0x00
			//&& media_ptr[9] == 0x00
			//&& media_ptr[10] == 0x00
			//&& media_ptr[11] == 0x00
			//&& media_ptr[142] == 0x00
			//&& media_ptr[143] == 0x00

			//){
			
				NDPI_LOG(NDPI_PROTOCOL_THUNDER, ndpi_struct, NDPI_LOG_DEBUG,
									"thunder HTTP download detected, adding flow http.c.\n");
				ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_THUNDER);

			//}
			}

	}



}

#endif

#ifdef NDPI_PROTOCOL_DAHUAXIYOU2
static void check_dahuaxiyou2_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  if (packet->line[0].ptr!=NULL 
  	&& packet->line[0].len >= 83
  	&& memcmp(packet->line[0].ptr, "/services/ngxqrcodeauthstatus", NDPI_STATICSTRING_LEN("/services/ngxqrcodeauthstatus")) == 0
  	&& memcmp(packet->line[0].ptr + 72, "product=xy2", 11)
  	&& packet->host_line.ptr!=NULL 
  	&& packet->host_line.len > 13
  	&& memcmp(packet->host_line.ptr, "q.reg.163.com", 13)) {
    	NDPI_LOG(NDPI_PROTOCOL_DAHUAXIYOU2, ndpi_struct, NDPI_LOG_DEBUG, "dahuaxiyou: qrcode line found.\n");
    	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DAHUAXIYOU2);
    	return;
  }
}


#endif
#ifdef NDPI_PROTOCOL_TONGHUASHUN
static void check_tonghuashun_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search tonghuashun hostline.%s\n",packet->host_line.ptr);
  if (packet->host_line.ptr!=NULL && (StringFind(packet->host_line.ptr,"10jqka.com.cn") != -1 || StringFind(packet->host_line.ptr,"hexin") != -1) )
  	{
    	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "tonghuashun: hostline found.\n");
    	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TONGHUASHUN);
    	return;
  }
}

#endif
#ifdef NDPI_PROTOCOL_DAZHIHUI365
static void check_dazhihui_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search dazhihui hostline.%s\n",packet->host_line.ptr);
  if (packet->host_line.ptr!=NULL &&packet->host_line.len>9 && (StringFind(packet->host_line.ptr,"gw.com.cn") != -1) )
  	{
    	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "dazhihui: hostline found.\n");
    	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DAZHIHUI365);
    	return;
  }
}

#endif

#ifdef NDPI_PROTOCOL_HUARONG
static void check_huarong_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search huarong hostline.%s\n",packet->host_line.ptr);
  if (packet->host_line.ptr!=NULL &&packet->host_line.len>10 && (StringFind(packet->host_line.ptr,"hrsec.com.cn") != -1 || StringFind(packet->host_line.ptr,"tdx.com.cn") != -1) )
  	{
    	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "huarong: hostline found.\n");
    	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HUARONG);
    	return;
  }
}

#endif

#ifdef NDPI_PROTOCOL_QIANLONG
static void check_qianlong_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
 //NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search qianlong hostline.%s\n",packet->host_line.ptr);
  if (packet->host_line.ptr!=NULL &&packet->host_line.len>10 && (StringFind(packet->host_line.ptr,"ql18.com.cn") != -1) )
  	{
    	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "qianlong: hostline found.\n");
    	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QIANLONG);
    	return;
  }
}

#endif
#ifdef NDPI_PROTOCOL_PINGANZHENGQUAN
static void check_pinganzhengquan_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
//NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search pinganzhengquan hostline.%s\n",packet->host_line.ptr);
  if (packet->host_line.ptr!=NULL &&packet->host_line.len>15 && (StringFind(packet->host_line.ptr,"zxfile.tdx.com.cn") != -1 || StringFind(packet->host_line.ptr,"202.69.19.78") != -1 || StringFind(packet->host_line.ptr,"pingan.com") != -1))
  	{
    	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "pinganzhengquan: hostline found.\n");
    	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PINGANZHENGQUAN);
    	return;
  }
}

#endif
#ifdef NDPI_PROTOCOL_NIZHAN
static void check_nizhan_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search nizhan login.\n");
  if (packet->host_line.ptr!=NULL 
  	&& memcmp(packet->host_line.ptr, "ptlogin2.game.qq.com", NDPI_STATICSTRING_LEN("ptlogin2.game.qq.com")) == 0 
  	&& StringFind(packet->line[0].ptr,"service=nzclientpop") != -1)
  	{
    	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "nizhan: login found.\n");
    	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_NIZHAN);
    	return;
  }
}

#endif

/*  PT: add useragent*/

#ifdef NDPI_PROTOCOL_YIXIN
static void yixin_parse_packet_useragentline	(struct ndpi_detection_module_struct						
							*ndpi_struct, struct ndpi_flow_struct *flow)
	{  
	  struct ndpi_packet_struct *packet = &flow->packet;
	
	  if(packet->user_agent_line.len >= NDPI_STATICSTRING_LEN("NETEASE-YIXIN")
	  	&& memcmp(packet->user_agent_line.ptr, "NETEASE-YIXIN", NDPI_STATICSTRING_LEN("NETEASE-YIXIN")) == 0) {
		NDPI_LOG(NDPI_PROTOCOL_YIXIN, ndpi_struct, NDPI_LOG_DEBUG, "yixin: User Agent: NETEASE-YIXIN\n");
		ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_YIXIN);
	  }
	}
#endif
#ifdef NDPI_PROTOCOL_FETION
static void fetion_parse_packet_useragentline	(struct ndpi_detection_module_struct						
							*ndpi_struct, struct ndpi_flow_struct *flow)
	{  
	  struct ndpi_packet_struct *packet = &flow->packet;
	
	  if(packet->user_agent_line.len >= NDPI_STATICSTRING_LEN("IIC2.0/PC")
	  	&& memcmp(packet->user_agent_line.ptr, "IIC2.0/PC", NDPI_STATICSTRING_LEN("IIC2.0/PC")) == 0) {
		NDPI_LOG(NDPI_PROTOCOL_FETION, ndpi_struct, NDPI_LOG_DEBUG, "fetion: User Agent: IIC2.0/PC\n");
		ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FETION);
	  }
	}
#endif

#ifdef NDPI_PROTOCOL_DAHUAXIYOU2
static void dahuaxiyou2_parse_packet_useragentline	(struct ndpi_detection_module_struct						
							*ndpi_struct, struct ndpi_flow_struct *flow)
	{  
	  struct ndpi_packet_struct *packet = &flow->packet;
	
	  if(packet->user_agent_line.len >= NDPI_STATICSTRING_LEN("XYUpdate")
	  	&& memcmp(packet->user_agent_line.ptr, "XYUpdate", NDPI_STATICSTRING_LEN("XYUpdate")) == 0) {
		NDPI_LOG(NDPI_PROTOCOL_DAHUAXIYOU2, ndpi_struct, NDPI_LOG_DEBUG, "dahuaxiyou2: User Agent: XYUpdate\n");
		ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DAHUAXIYOU2);
	  }
	}
#endif

#ifdef NDPI_PROTOCOL_BITTORRENT
static void bittorrent_parse_packet_useragentline	(struct ndpi_detection_module_struct						
							*ndpi_struct, struct ndpi_flow_struct *flow)
	{ 
	/*This is from bittorrent.c, check useragent there cant check*/
	  struct ndpi_packet_struct *packet = &flow->packet;
	
	  if(
	  		(packet->user_agent_line.len >= NDPI_STATICSTRING_LEN("Bittorrent")
		  	&& ( memcmp(packet->user_agent_line.ptr, "Bittorrent", NDPI_STATICSTRING_LEN("Bittorrent")) == 0
		  	  || memcmp(packet->user_agent_line.ptr, "BitTorrent", NDPI_STATICSTRING_LEN("BitTorrent")) == 0 ))
		||
	  		(packet->user_agent_line.len >= NDPI_STATICSTRING_LEN("Azureus")
		  	&&  memcmp(packet->user_agent_line.ptr, "Azureus", NDPI_STATICSTRING_LEN("Azureus")) == 0)
		||
	  		(packet->user_agent_line.len >= NDPI_STATICSTRING_LEN("BTWebClient")
		  	&&  memcmp(packet->user_agent_line.ptr, "BTWebClient", NDPI_STATICSTRING_LEN("BTWebClient")) == 0)
		){
		NDPI_LOG(NDPI_PROTOCOL_DAHUAXIYOU2, ndpi_struct, NDPI_LOG_DEBUG, "Bittorrent: User Agent: Bittorrent/BTWebClient/Azureus\n");
		ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_BITTORRENT);
	  }
	}
#endif
/*
#ifdef NDPI_PROTOCOL_PPLIVE
static void pplive_parse_packet_useragentline	(struct ndpi_detection_module_struct						
							*ndpi_struct, struct ndpi_flow_struct *flow)
	{ 
	//This is from bittorrent.c, check useragent there cant check
	  struct ndpi_packet_struct *packet = &flow->packet;
		NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search pplive useragentline.%s\n",packet->user_agent_line.ptr);
  	if (packet->user_agent_line.ptr!=NULL &&packet->user_agent_line.len>=NDPI_STATICSTRING_LEN(" UPnP/1.0 DLNADOC/1.50 PPTV") && StringFind(packet->user_agent_line.ptr,"PPTV") != -1)
  	{
    	NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE: User Agent: UPnP/1.0 DLNADOC/1.50 PPTV/1.0.4.11\n");
	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PPLIVE);
    	return;
  }
	}
#endif
*/

/*  PT: add useragent end*/
static void parseHttpSubprotocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  // int i = 0;
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->iph /* IPv4 only */) {
    /* 
       Twitter Inc. TWITTER-NETWORK (NET-199-59-148-0-1) 199.59.148.0 - 199.59.151.255
       199.59.148.0/22
    */
    if(((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC73B9400 /* 199.59.148.0 */)
       || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC73B9400 /* 199.59.148.0 */)) {
      packet->detected_protocol_stack[0] = NDPI_PROTOCOL_TWITTER;
      return;
    }

    /* 
       CIDR:           69.53.224.0/19
       OriginAS:       AS2906
       NetName:        NETFLIX-INC
    
    */
  }
    
  if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP) {
    /* Try matching subprotocols */
    // ndpi_match_string_subprotocol(ndpi_struct, flow, (char*)packet->host_line.ptr, packet->host_line.len);
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ndpi_match_string_subprotocol start\n");
    ndpi_match_string_subprotocol(ndpi_struct, flow, flow->host_server_name, strlen(flow->host_server_name));
	NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ndpi_match_string_subprotocol end\n");
  }else{
	NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ndpi_match_string_subprotocol skip\n");
  }
}


static void check_custom_headers(struct ndpi_detection_module_struct
						   *ndpi_struct, struct ndpi_flow_struct *flow){
#if  defined(NDPI_PROTOCOL_PPLIVE) || defined(NDPI_PROTOCOL_YIXIN) || defined(NDPI_PROTOCOL_QQLIVE) || defined(NDPI_PROTOCOL_SOHU) || defined(NDPI_PROTOCOL_PPSTREAM)



	  struct ndpi_packet_struct *packet = &flow->packet;
	  u_int8_t a ;
	  for (a = 0; a < packet->parsed_lines; a++) {
		/*------wanglei---YIXIN-----*/
		#ifdef NDPI_PROTOCOL_YIXIN
			if (( packet->line[a].len>10 && memcmp(packet->line[a].ptr,"YX-PN: yxmc",11) == 0) ){
		  NDPI_LOG(NDPI_PROTOCOL_YIXIN, ndpi_struct, NDPI_LOG_DEBUG, "YIXIN: YX-PN found.\n");
		  ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_YIXIN);
		  return;
		}
		#endif
		/*------wanglei---SOHU-----*/
		#ifdef NDPI_PROTOCOL_SOHU
			if (( packet->line[a].len>= 10 && memcmp(packet->line[a].ptr,"GET /sohu/",10) == 0 && strstr(packet->line[a].ptr,"mp4") ) 
			    ||( packet->line[a].len>= 50 && memcmp(packet->line[a].ptr,"GET /p2p",8) == 0 
		    		&& strstr(packet->line[a].ptr,"mp4") 
				&& strstr(packet->line[a].ptr,"u HTTP")) 
			   || (packet->line[a].len >= 50 && memcmp(packet->line[a].ptr,"GET /p2p?=new",13)==0 && strstr(packet->line[a].ptr,"mp4"))
			   || (packet->line[a].len >= 50 && memcmp(packet->line[a].ptr,"GET /sohu/p2p",13)==0 )
			){
		     NDPI_LOG(NDPI_PROTOCOL_SOHU, ndpi_struct, NDPI_LOG_DEBUG, "SOHU: sohu found.\n");
		     ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SOHU);
		     return;
		  }
		#endif
		/*------wanglei---YOUKU-----*/
		#ifdef NDPI_PROTOCOL_YOUKU
			if ( (packet->line[a].len>= 12 && ( (memcmp(packet->line[a].ptr,"GET /youku",10) == 0
								&& strstr(packet->line[a].ptr,"flv"))
							    //memcmp(packet->line[a].ptr,"GET /ikupv",10) == 0 
            							//|| memcmp(packet->line[a].ptr,"GET /itudou",11) == 0 
            						   ||(memcmp(packet->line[a].ptr,"GET /player",11) == 0
            								&& strstr(packet->line[a].ptr,"/mp4/"))))
			|| (packet->line[a].len>= 27 && (memcmp(packet->line[a].ptr,"User-Agent: youku-tudou IKU",27) == 0))
	//							|| (memcmp(packet->line[a].ptr,"User-Agent:",11) == 0 && strstr(packet->line[a].ptr,"youku"))))
			|| (packet->line[a].len>= 22 && memcmp(packet->line[a].ptr,"Cookie: campKeys=ZH4sI",22) == 0 )
			|| (packet->line[a].len>= 30 && memcmp(packet->line[a].ptr,"GET /",5) == 0
				&&(strstr(packet->line[a].ptr,"flv")||strstr(packet->line[a].ptr,"mp4"))
				&&strstr(packet->line[a].ptr,"expire")
				&&strstr(packet->line[a].ptr,"ups_client_netip")
				&&strstr(packet->line[a].ptr,"ups_ts"))
			|| (packet->line[a].len>= 70 && memcmp(packet->line[a].ptr,"Referer:",8) == 0 &&strstr(packet->line[a].ptr,"upsplayer")
				&&strstr(packet->line[a].ptr,"youku"))
		
		     ){
		     NDPI_LOG(NDPI_PROTOCOL_YOUKU, ndpi_struct, NDPI_LOG_DEBUG, "YOUKU: youku found.\n");
		     ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_YOUKU);
		     return;
		  }
		#endif
		/*------wanglei---KU6-----*/
		#ifdef NDPI_PROTOCOL_KU6
			if ((packet->line[0].len >= 10 
				&& memcmp(packet->line[0].ptr,"GET /",5) == 0 
                        	&& strstr(packet->line[0].ptr,"mp4") 
				&& packet->line[a].len >= 13
                        	&& strstr(packet->line[a].ptr,"rbv01.ku6.com"))
			   ||(packet->line[1].len >=13
				&&strstr(packet->line[1].ptr,"rbv01.ku6.com")
				&&packet->line[a].len >= 12
				&&memcmp(packet->line[a].ptr,"Cookie: KUID",12) == 0)
			){
		     NDPI_LOG(NDPI_PROTOCOL_KU6, ndpi_struct, NDPI_LOG_DEBUG, "KU6: ku6 found.\n");
		     ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_KU6);
		     return;
		  }
		#endif
		/*------wanglei---funshion-----*/
		#ifdef NDPI_PROTOCOL_FUNSHION
			if (//(packet->line[a].len>= 20 && memcmp(packet->line[a].ptr,"User-Agent: Funshion",20) == 0)
                           (packet->line[a].len>= 26 && memcmp(packet->line[a].ptr,"Referer: http://vas.fun.tv",26) == 0) 
                           || (packet->line[a].len>= 35 && memcmp(packet->line[a].ptr,"Referer: http://static.funshion.com",35) == 0) 
                           || (packet->line[a].len>= 10 && memcmp(packet->line[a].ptr,"GET /",5) == 0
                           	&& strstr(packet->line[a].ptr+5,"mp4") && strstr(packet->line[a].ptr+5,"fun")) 
                           || (packet->line[a].len>= 10 && packet->line[0].len>= 10 && memcmp(packet->line[0].ptr,"GET /",5) == 0
                           	&& strstr(packet->line[0].ptr+5,"mp4") && strstr(packet->line[a].ptr,"funshion")) 
			   ){
		     NDPI_LOG(NDPI_PROTOCOL_FUNSHION, ndpi_struct, NDPI_LOG_DEBUG, "Funshion User-Agent found.\n");
		     ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FUNSHION);
		     return;
		  }
		#endif
		/*------wanglei---LETV-----*/
		#ifdef NDPI_PROTOCOL_LETV
			if ( (packet->line[a].len>=34 && memcmp(packet->line[a].ptr,"Referer: http://player.letvcdn.com",34) == 0)
			   || (packet->line[0].len>=20 && memcmp(packet->line[0].ptr,"GET /",5) == 0 
					&& (strstr(packet->line[0].ptr,"leju-client")
			   		|| (strstr(packet->line[0].ptr,"letv") 
			   			&&  strstr(packet->line[0].ptr,"mp4"))))
			   //||(packet->line[a].len>=32 && memcmp(packet->line[a].ptr,"Referer: http://client.pc.le.com",32)==0 )
                           || (packet->line[a].len>=20 && (memcmp(packet->line[a].ptr,"Set-Cookie: uid=JG7f",20)==0 
			   	||(memcmp(packet->line[a].ptr,"Set-Cookie:",11) == 0 
			   		&& strstr(packet->line[a].ptr,"letv.com"))))
  			){
		     NDPI_LOG(NDPI_PROTOCOL_LETV, ndpi_struct, NDPI_LOG_DEBUG, "LETV: letv found.\n");
		     ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_LETV);
		     return;
		  }
		#endif
		/*------wanglei---QQLIVE-----*/
		#ifdef NDPI_PROTOCOL_QQLIVE
			if (( packet->line[a].len>= 23 && (memcmp(packet->line[a].ptr,"GET /qqlive",11) == 0 
			   	|| memcmp(packet->line[a].ptr,"GET /VuZyqq",11) == 0 
			   	|| (memcmp(packet->line[a].ptr,"GET /d?dn",9) == 0 && strstr(packet->line[a].ptr,"qq.com")))) 
			   || (packet->line[a].len>= 22 && memcmp(packet->line[a].ptr,"GET /moviets.tc.qq.com",22) == 0 )
			   || (packet->line[a].len>= 18 && memcmp(packet->line[a].ptr,"User-Agent: QQLive",18) == 0 )
			   || (packet->line[a].len>= 18 && memcmp(packet->line[a].ptr,"GET /vhot2.qqvideo",18) == 0 )
			   || (packet->line[a].len>= 20 && memcmp(packet->line[a].ptr,"GET /",5) == 0 
				&& strstr(packet->line[a].ptr,"qq.com") 
				&& strstr(packet->line[a].ptr,"mp4"))
			   || (packet->line[a].len>= 20 && memcmp(packet->line[a].ptr,"GET /video",10) == 0 
				&& strstr(packet->line[a].ptr,"qq.com") 
				&& strstr(packet->line[a].ptr,"mp4"))
               		   || (packet->line[a].len>= 14 && ( memcmp(packet->line[a].ptr,"Cookie: QQLive",14) == 0 
               			|| (memcmp(packet->line[a].ptr,"GET /kvcollect",14) == 0 && strstr(packet->line[a].ptr,"qq="))))
			){
		     NDPI_LOG(NDPI_PROTOCOL_QQLIVE, ndpi_struct, NDPI_LOG_DEBUG, "QQLIVE: qqlive found.\n");
		     ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QQLIVE);
		     return;
		  }
		#endif
		/*------wanglei---PPSTREAM-----*/
		#ifdef NDPI_PROTOCOL_PPSTREAM
			if ( (packet->line[a].len> 50 
				&& memcmp(packet->line[a].ptr,"GET /videos/",12) == 0
			  	&& strstr(packet->line[a].ptr,"f4v") 
			 	&& strstr(packet->line[a].ptr,"iqiyi"))
			    || (packet->line[a].len>= 20 
					&& memcmp(packet->line[a].ptr,"Referer:",8) == 0 
					&&strstr(packet->line[a].ptr,"iqiyi.com")
					&&strstr(packet->line[a].ptr,"flashplayer"))
			    || (packet->line[a].len>= 30 && memcmp(packet->line[a].ptr,"GET /videos",11) == 0
				&&(strstr(packet->line[a].ptr,"f4v")||strstr(packet->line[a].ptr,"mp4"))
				&&strstr(packet->line[a].ptr,"dis_dz")
				&&strstr(packet->line[a].ptr,"src=iqiyi.com"))
		
		 ){
		     NDPI_LOG(NDPI_PROTOCOL_PPSTREAM, ndpi_struct, NDPI_LOG_DEBUG, "PPSTREAM: iqiyi found.\n");
		     ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PPSTREAM);
		     return;
		  }
		#endif
		/*------wanglei---PPLIVE-----*/
Referer: http://player.pplive.cn/ikan/3.4.2.27/player4player2.swf
		#ifdef NDPI_PROTOCOL_PPLIVE
			if ((packet->line[a].len > 20&& memcmp(packet->line[a].ptr,"Pragma: Client=PPLive",21) == 0 )
			    ||( packet->line[a].len > 37 && memcmp(packet->line[a].ptr,"Referer:",8)==0 && strstr(packet->line[a].ptr+8,"player.pplive.cn")) 
			    ||( packet->line[a].len > 50 && memcmp(packet->line[a].ptr,"GET /",5)==0 && strstr(packet->line[a].ptr+5,"agent=ppap"))
			 ){ 
		       NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE feature found.\n");
		       //NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE [%s].\n",packet->line[a].ptr);
		       ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PPLIVE);
		       return;
		}
		#endif
		/*PT 20161229*/

		#ifdef NDPI_PROTOCOL_ALIWANGWANG
		if (packet->line[a].len >= NDPI_STATICSTRING_LEN("Cookie: cna=/")
		 && memcmp(packet->line[a].ptr,"Cookie: cna=/",NDPI_STATICSTRING_LEN("Cookie: cna=/")) == 0
		){
		  NDPI_LOG(NDPI_PROTOCOL_ALIWANGWANG, ndpi_struct, NDPI_LOG_DEBUG, "aliwangwang: Cookie: cna=/ found.\n");
		  ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ALIWANGWANG);
		  return;
		}
		
		#endif

		/*PT 20161229 end*/
		#ifdef NDPI_PROTOCOL_TIANXIA3
		if ((packet->line[a].len>=NDPI_STATICSTRING_LEN("GET /tx2fix")
			&&memcmp(packet->line[a].ptr,"GET /tx2fix",11)==0)
		    ||(packet->line[a].len>=NDPI_STATICSTRING_LEN("HEAD /tx2fix")
			&&memcmp(packet->line[a].ptr,"HEAD /tx2fix",12)==0)
		    ||(packet->line[a].len>=NDPI_STATICSTRING_LEN("Server: WS CDN Server")
			&&memcmp(packet->line[a].ptr,"Server: WS CDN Server",21)==0)
		){
		  NDPI_LOG(NDPI_PROTOCOL_TIANXIA3, ndpi_struct, NDPI_LOG_DEBUG, "tianxia3:'tx2fix' found.\n");
		  ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TIANXIA3);
		  return;
		}
		
		#endif
		/*jkjun 2017-08-11 */
		#ifdef NDPI_PROTOCOL_GAME_DNF
		if (packet->line[a].len >= NDPI_STATICSTRING_LEN("GET /outer/ad_log_report")
		    &&memcmp(packet->line[a].ptr,"GET /",5)==0 
		    &&strstr(packet->line[a].ptr+5,"dnf")
		){
		  NDPI_LOG(NDPI_PROTOCOL_GAME_DNF, ndpi_struct, NDPI_LOG_DEBUG, "DNF login / found.\n");
		  ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GAME_DNF);
		  return;
		}
		
		#endif
		/*jkjun end*/

        /*ltk start*/
#ifdef NDPI_PROTOCOL_JINWANWEI
        char static const *jinwanwei_strs[] = {
            "GET /client_login.php?user_name=",
            "GET /checkGroupType.php?userName=",
            "GET /client_getTimes.php?userName=",
            "GET /client_getIP.php? HTTP/1.1",
            "POST /client_saveDomainList.php HTTP/1.1",
            "GET /gnapi/GetServiceProvider.php?ProductName=",

            NULL,
        };
        char const **jinwanwei_ptr;
        for (jinwanwei_ptr = jinwanwei_strs; *jinwanwei_ptr != NULL; jinwanwei_ptr++) {
            char const *str = *jinwanwei_ptr;
            int len = strlen(str);
            if (packet->line[a].len >= len && strncmp(packet->line[a].ptr, str, len) == 0) {
                ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_JINWANWEI);
                NDPI_LOG(NDPI_PROTOCOL_JINWANWEI, ndpi_struct, NDPI_LOG_DEBUG, "JinWanWei: Found via %s\n", str);
                return;
            }
        }
#endif /* NDPI_PROTOCOL_JINWANWEI */
#ifdef NDPI_PROTOCOL_QQ_TX
        NDPI_LOG(NDPI_PROTOCOL_QQ_TX, ndpi_struct, NDPI_LOG_DEBUG, "Into QQ transfer file.\n");
        static char const *qqtx_strs[] = {
            "GET /ftn_handler",
            "POST /ftn_handler",

            NULL,
        };
        const **qqtx_ptr;
        for (qqtx_ptr = qqtx_strs; *qqtx_ptr != NULL; qqtx_ptr++) {
            char const *str = *qqtx_ptr;
            int len = strlen(str);
            if (packet->line[a].len >= len && strncmp(packet->line[a].ptr, str, len) == 0) {
                ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QQ_TX);
                NDPI_LOG(NDPI_PROTOCOL_QQ_TX, ndpi_struct, NDPI_LOG_DEBUG, "QQ_TX: Found via %s\n", str);
                return;
            }
        }
#endif /* NDPI_PROTOCOL_QQ_TX */
        /*ltk start*/
      }
#endif

}

static void check_content_line(struct ndpi_detection_module_struct
						   *ndpi_struct, struct ndpi_flow_struct *flow){
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->content_line.ptr != NULL && packet->content_line.len != 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Content Type Line found %.*s\n",
	    packet->content_line.len, packet->content_line.ptr);
	
  }

}

static void check_useragent_line(struct ndpi_detection_module_struct
						   *ndpi_struct, struct ndpi_flow_struct *flow){
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len != 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "User Agent Type Line found %.*s\n",
	    packet->user_agent_line.len, packet->user_agent_line.ptr);		
#ifdef NDPI_PROTOCOL_FETION
				 if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_FETION) != 0)
				  fetion_parse_packet_useragentline(ndpi_struct, flow);
#endif		
#ifdef NDPI_PROTOCOL_YIXIN
				 if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_YIXIN) != 0)
				  yixin_parse_packet_useragentline(ndpi_struct, flow);
#endif		
#ifdef NDPI_PROTOCOL_DAHUAXIYOU2
				 if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_DAHUAXIYOU2) != 0)
				  dahuaxiyou2_parse_packet_useragentline(ndpi_struct, flow);
#endif		
#ifdef NDPI_PROTOCOL_BITTORRENT
				 if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_BITTORRENT) != 0)
				  bittorrent_parse_packet_useragentline(ndpi_struct, flow);
#endif
/*
#ifdef NDPI_PROTOCOL_PPLIVE
				 if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_PPLIVE) != 0)
				  pplive_parse_packet_useragentline(ndpi_struct, flow);
#endif		
*/
			check_useragent_contains(ndpi_struct,flow);


  }
}


static void check_host_line(struct ndpi_detection_module_struct
						   *ndpi_struct, struct ndpi_flow_struct *flow){
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->host_line.ptr != NULL) {
    u_int len;

#ifdef NDPI_PROTOCOL_THUNDER
	  if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_THUNDER) != 0){
	  	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "thunder: bitmask add ok\n");
			thunder_check_http_payload(ndpi_struct, flow);
	  	}
#endif

#ifdef NDPI_PROTOCOL_DAHUAXIYOU2
	  	if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_DAHUAXIYOU2) != 0){
	  	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "dahuaxiyou: bitmask add ok\n");
			check_dahuaxiyou2_payload(ndpi_struct, flow);
	  	}

#endif
#ifdef NDPI_PROTOCOL_TONGHUASHUN
	  	if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_TONGHUASHUN) != 0){
	  	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "tonghuashun: bitmask add ok\n");
			check_tonghuashun_payload(ndpi_struct, flow);
	  	}
#endif
#ifdef NDPI_PROTOCOL_DAZHIHUI365
	  	if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_DAZHIHUI365) != 0){
	  	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "dazhihui: bitmask add ok\n");
			check_dazhihui_payload(ndpi_struct, flow);
	  	}
#endif
#ifdef NDPI_PROTOCOL_HUARONG
		if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_HUARONG) != 0){
		NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "huarong: bitmask add ok\n");
			check_huarong_payload(ndpi_struct, flow);
		}
#endif
#ifdef NDPI_PROTOCOL_QIANLONG
		if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_QIANLONG) != 0){
		NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "qianlong: bitmask add ok\n");	
			check_qianlong_payload(ndpi_struct, flow);
		}
#endif
#ifdef NDPI_PROTOCOL_PINGANZHENGQUAN
		if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_PINGANZHENGQUAN) != 0){
		NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "pinganzhengquan: bitmask add ok\n");
		check_pinganzhengquan_payload(ndpi_struct, flow);
		}
#endif
#ifdef NDPI_PROTOCOL_NIZHAN
		if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_NIZHAN) != 0){
		NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "nizhan: bitmask add ok\n");			
                check_nizhan_payload(ndpi_struct, flow);
		}
#endif


    /* Copy result for nDPI apps */
    len = ndpi_min(packet->host_line.len, sizeof(flow->host_server_name)-1);
    strncpy((char*)flow->host_server_name, (char*)packet->host_line.ptr, len);
    flow->host_server_name[len] = '\0';

    parseHttpSubprotocol(ndpi_struct, flow);
    
    if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
      ndpi_int_http_add_connection(ndpi_struct, flow, packet->detected_protocol_stack[0]);
      return; /* We have identified a sub-protocol so we're done */
    }
  }
}

static void check_accept_line(struct ndpi_detection_module_struct
						   *ndpi_struct, struct ndpi_flow_struct *flow){
     struct ndpi_packet_struct *packet = &flow->packet;
	 if (packet->accept_line.ptr != NULL) {
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Accept Line found");
   // NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Accept Line found %.*s\n",packet->accept_line.len, packet->accept_line.ptr);
  }
}

static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct
						   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  /*check content line */
  check_content_line(ndpi_struct, flow);

  /* check for user agent here too */
  check_useragent_line(ndpi_struct,flow);
  
  /* check for host line */
  check_host_line(ndpi_struct,flow);
   
  /* check for accept line */
  check_accept_line(ndpi_struct, flow);

  /* check custom headers*/
  check_custom_headers(ndpi_struct, flow); 
}

static void check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "called check_http_payload.\n");

}

/**
 * this functions checks whether the packet begins with a valid http request
 * @param ndpi_struct
 * @returnvalue 0 if no valid request has been found
 * @returnvalue >0 indicates start of filename but not necessarily in packet limit
 */
static u_int16_t http_request_url_offset(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  /* FIRST PAYLOAD PACKET FROM CLIENT */
  /* check if the packet starts with POST or GET */
  if (packet->payload_packet_len >= 4 && memcmp(packet->payload, "GET ", 4) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: GET FOUND\n");
    return 4;
  } else if (packet->payload_packet_len >= 5 && memcmp(packet->payload, "POST ", 5) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: POST FOUND\n");
    return 5;
  } else if (packet->payload_packet_len >= 8 && memcmp(packet->payload, "OPTIONS ", 8) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: OPTIONS FOUND\n");
    return 8;
  } else if (packet->payload_packet_len >= 5 && memcmp(packet->payload, "HEAD ", 5) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: HEAD FOUND\n");
    return 5;
  } else if (packet->payload_packet_len >= 4 && memcmp(packet->payload, "PUT ", 4) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: PUT FOUND\n");
    return 4;
  } else if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "DELETE ", 7) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: DELETE FOUND\n");
    return 7;
  } else if (packet->payload_packet_len >= 8 && memcmp(packet->payload, "CONNECT ", 8) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: CONNECT FOUND\n");
    return 8;
  } else if (packet->payload_packet_len >= 9 && memcmp(packet->payload, "PROPFIND ", 9) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: PROFIND FOUND\n");
    return 9;
  } else if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "REPORT ", 7) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: REPORT FOUND\n");
    return 7;
  }

  return 0;
}

static void http_bitmask_exclude(struct ndpi_flow_struct *flow)
{
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HTTP);
}

void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  u_int16_t filename_start;

  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search http\n");

  /* set client-server_direction */
  if (flow->l4.tcp.http_setup_dir == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "initializes http to stage: 1 \n");
    flow->l4.tcp.http_setup_dir = 1 + packet->packet_direction;
  }

  if (NDPI_COMPARE_PROTOCOL_TO_BITMASK
      (ndpi_struct->generic_http_packet_bitmask, packet->detected_protocol_stack[0]) != 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	    "protocol might be detected earlier as http jump to payload type detection\n");
    goto http_parse_detection;
  }

  if (flow->l4.tcp.http_setup_dir == 1 + packet->packet_direction) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "http stage: 1\n");

    if (flow->l4.tcp.http_wait_for_retransmission) {
      if (!packet->tcp_retransmission) {
	if (flow->packet_counter <= 5) {
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "still waiting for retransmission\n");
	  return;
	} else {
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "retransmission not found, exclude\n");
	  http_bitmask_exclude(flow);
	  return;
	}
      }
    }

    if (flow->l4.tcp.http_stage == 0) {
      filename_start = http_request_url_offset(ndpi_struct, flow);
      if (filename_start == 0) {
	if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "HTTP/1.", 7) == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP response found (truncated flow ?)\n");
	  ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
	  return;
	}

	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "filename not found, exclude\n");
	http_bitmask_exclude(flow);
	return;
      }
      // parse packet
      ndpi_parse_packet_line_info(ndpi_struct, flow);

      if (packet->parsed_lines <= 1) {
	/* parse one more packet .. */
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "just one line, search next packet\n");

	packet->http_method.ptr = packet->line[0].ptr;
        packet->http_method.len = filename_start - 1;
	flow->l4.tcp.http_stage = 1;
	return;
      }
      // parsed_lines > 1 here
      if (packet->line[0].len >= (9 + filename_start)
	  && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
	packet->http_url_name.ptr = &packet->payload[filename_start];
	packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

	packet->http_method.ptr = packet->line[0].ptr;
	packet->http_method.len = filename_start - 1;

	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "http structure detected, adding\n");

	ndpi_int_http_add_connection(ndpi_struct, flow, (filename_start == 8) ? NDPI_PROTOCOL_HTTP_CONNECT : NDPI_PROTOCOL_HTTP);
	check_content_type_and_change_protocol(ndpi_struct, flow);
	/* HTTP found, look for host... */
	if (packet->host_line.ptr != NULL) {
	  /* aaahh, skip this direction and wait for a server reply here */
	  flow->l4.tcp.http_stage = 2;
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP START HOST found\n");
	  return;
	}
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP START HOST found\n");

	/* host not found, check in next packet after */
	flow->l4.tcp.http_stage = 1;
	return;
      }
    } else if (flow->l4.tcp.http_stage == 1) {
      /* SECOND PAYLOAD TRAFFIC FROM CLIENT, FIRST PACKET MIGHT HAVE BEEN HTTP... */
      /* UNKNOWN TRAFFIC, HERE FOR HTTP again.. */
      // parse packet
      ndpi_parse_packet_line_info(ndpi_struct, flow);

      if (packet->parsed_lines <= 1) {
	/* wait some packets in case request is split over more than 2 packets */
	if (flow->packet_counter < 5) {
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		  "line still not finished, search next packet\n");
	  return;
	} else {
	  /* stop parsing here */
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		  "HTTP: PACKET DOES NOT HAVE A LINE STRUCTURE\n");
	  http_bitmask_exclude(flow);
	  return;
	}
      }

      if (packet->line[0].len >= 9 && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
	check_content_type_and_change_protocol(ndpi_struct, flow);
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		"HTTP START HTTP found in 2. packet, check host here...\n");
	/* HTTP found, look for host... */
	flow->l4.tcp.http_stage = 2;

	return;
      }
    }
  } else {
    /* We have received a response for a previously identified partial HTTP request */
    
    if((packet->parsed_lines == 1) && (packet->packet_direction == 1 /* server -> client */)) {
      /* 
	 In apache if you do "GET /\n\n" the response comes without any header so we can assume that
	 this can be the case
      */
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
      return;
    }
  }

  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: REQUEST NOT HTTP CONFORM\n");
  http_bitmask_exclude(flow);
  return;

 http_parse_detection:
  if (flow->l4.tcp.http_setup_dir == 1 + packet->packet_direction) {
    /* we have something like http here, so check for host and content type if possible */
    if (flow->l4.tcp.http_stage == 0 || flow->l4.tcp.http_stage == 3) {
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP RUN MAYBE NEXT GET/POST...\n");
      // parse packet
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      /* check for url here */
      filename_start = http_request_url_offset(ndpi_struct, flow);
      if (filename_start != 0 && packet->parsed_lines > 1 && packet->line[0].len >= (9 + filename_start)
	  && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
	packet->http_url_name.ptr = &packet->payload[filename_start];
	packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

	packet->http_method.ptr = packet->line[0].ptr;
	packet->http_method.len = filename_start - 1;

	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "next http action, "
		"resetting to http and search for other protocols later.\n");
	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
      }
      check_content_type_and_change_protocol(ndpi_struct, flow);
      /* HTTP found, look for host... */
      if (packet->host_line.ptr != NULL) {
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		"HTTP RUN MAYBE NEXT HOST found, skipping all packets from this direction\n");
	/* aaahh, skip this direction and wait for a server reply here */
	flow->l4.tcp.http_stage = 2;
	return;
      }
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	      "HTTP RUN MAYBE NEXT HOST NOT found, scanning one more packet from this direction\n");
      flow->l4.tcp.http_stage = 1;
    } else if (flow->l4.tcp.http_stage == 1) {
      // parse packet and maybe find a packet info with host ptr,...
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      check_content_type_and_change_protocol(ndpi_struct, flow);
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP RUN second packet scanned\n");
      /* HTTP found, look for host... */
      flow->l4.tcp.http_stage = 2;
    }
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	    "HTTP skipping client packets after second packet\n");
    return;
  }
  /* server response */
  if (flow->l4.tcp.http_stage > 0) {
    /* first packet from server direction, might have a content line */
    ndpi_parse_packet_line_info(ndpi_struct, flow);
    check_content_type_and_change_protocol(ndpi_struct, flow);


    if (packet->empty_line_position_set != 0 || flow->l4.tcp.http_empty_line_seen == 1) {
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "empty line. check_http_payload.\n");
      check_http_payload(ndpi_struct, flow);
    }
    if (flow->l4.tcp.http_stage == 2) {
      flow->l4.tcp.http_stage = 3;
    } else {
      flow->l4.tcp.http_stage = 0;
    }
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	    "HTTP response first or second packet scanned,new stage is: %u\n", flow->l4.tcp.http_stage);
    return;
  } else {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP response next packet skipped\n");
  }
}
#endif



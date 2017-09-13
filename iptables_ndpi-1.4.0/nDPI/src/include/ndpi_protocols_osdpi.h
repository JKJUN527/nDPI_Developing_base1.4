/*
 * ndpi_protocols_osdpi.h
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


#ifndef __NDPI_API_INCLUDE_FILE__

#endif

#ifndef __NDPI_PROTOCOLS_DEFAULT_H__
#define __NDPI_PROTOCOLS_DEFAULT_H__

#ifdef __cplusplus
extern "C" {
#endif

#define NDPI_DETECTION_SUPPORT_IPV6
#define NDPI_PROTOCOL_HISTORY_SIZE              3

#define NDPI_PROTOCOL_UNKNOWN                   0
#define NDPI_PROTOCOL_FTP_CONTROL               1
#define NDPI_PROTOCOL_MAIL_POP                  2
#define NDPI_PROTOCOL_MAIL_SMTP                 3
#define NDPI_PROTOCOL_MAIL_IMAP                 4
#define NDPI_PROTOCOL_DNS                       5
#define NDPI_PROTOCOL_IPP                       6
#define NDPI_PROTOCOL_HTTP                      7
#define NDPI_PROTOCOL_MDNS                      8
#define NDPI_PROTOCOL_NTP                       9
#define NDPI_PROTOCOL_NETBIOS                   10
#define NDPI_PROTOCOL_NFS                       11
#define NDPI_PROTOCOL_SSDP                      12
#define NDPI_PROTOCOL_BGP                       13
#define NDPI_PROTOCOL_SNMP                      14
#define NDPI_PROTOCOL_SMB                       15
#define NDPI_PROTOCOL_SYSLOG                    16
#define NDPI_PROTOCOL_DHCP                      17
#define NDPI_PROTOCOL_POSTGRES                  18
#define NDPI_PROTOCOL_MYSQL                     19
#define NDPI_PROTOCOL_TDS                       20

#define NDPI_PROTOCOL_MAIL_POPS                 21
#define NDPI_PROTOCOL_MAIL_SMTPS                22
#define NDPI_PROTOCOL_EDONKEY                   23
#define NDPI_PROTOCOL_BITTORRENT                24

#define NDPI_PROTOCOL_QQ                        25
#define NDPI_PROTOCOL_MAIL_IMAPS                26
#define NDPI_PROTOCOL_PPLIVE                    27
#define NDPI_PROTOCOL_PPSTREAM                  28
#define NDPI_PROTOCOL_QQLIVE                    29
#define NDPI_PROTOCOL_THUNDER                   30

#define NDPI_PROTOCOL_SSL_NO_CERT               31 /* SSL without certificate (Skype, Ultrasurf?) - ntop.org */
#define NDPI_PROTOCOL_VRRP                      32
#define NDPI_PROTOCOL_WORLDOFWARCRAFT           33
#define NDPI_PROTOCOL_TELNET                    34

#define NDPI_PROTOCOL_IPSEC                     35
#define NDPI_PROTOCOL_ICMP                      36
#define NDPI_PROTOCOL_IGMP                      37
#define NDPI_PROTOCOL_SCTP                      38
#define NDPI_PROTOCOL_OSPF                      39
#define NDPI_PROTOCOL_RTP                       40
#define NDPI_PROTOCOL_RDP                       41
#define NDPI_PROTOCOL_SSL                       42
#define NDPI_PROTOCOL_SSH                       43
#define NDPI_PROTOCOL_MGCP                      44
#define NDPI_PROTOCOL_TFTP                      45
#define NDPI_PROTOCOL_LDAP                      46

#define NDPI_PROTOCOL_MSSQL                     47
#define NDPI_PROTOCOL_PPTP                      48
#define NDPI_PROTOCOL_FACEBOOK                  49
#define NDPI_PROTOCOL_TWITTER                   50
#define NDPI_PROTOCOL_DCERPC                    51
#define NDPI_PROTOCOL_RADIUS                    52
#define NDPI_PROTOCOL_LLMNR                     53
#define NDPI_PROTOCOL_HTTP_CONNECT              54
#define NDPI_PROTOCOL_FTP_DATA                  55
/* UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE */

/*Add custom define here FROM 225 ,and set NDPI_LAST_IMPLEMENTED_PROTOCOL to your last protocol -- PT */

#define NDPI_PROTOCOL_WECHAT                            60
#define NDPI_PROTOCOL_ALIWANGWANG                       61
#define NDPI_PROTOCOL_SINAWEIBO                         62
#define NDPI_PROTOCOL_TENCENTWEIBO                      63
#define NDPI_PROTOCOL_WEBQQ                             64
#define NDPI_PROTOCOL_DINGTALK                          65
#define NDPI_PROTOCOL_YOUDAONOTE                        66
#define NDPI_PROTOCOL_LETV                              67
#define NDPI_PROTOCOL_FUNSHION                          68
#define NDPI_PROTOCOL_KU6                               69
#define NDPI_PROTOCOL_SOHU                              70
#define NDPI_PROTOCOL_YOUKU                             72
#define NDPI_PROTOCOL_BAIDUHI                           73

#define NDPI_PROTOCOL_YIXIN                             74
#define NDPI_PROTOCOL_YY                                75
#define NDPI_PROTOCOL_RIP                               76
#define NDPI_PROTOCOL_L2TP                              77
#define NDPI_PROTOCOL_FTPS                              78
#define NDPI_PROTOCOL_NNTP                              79
#define NDPI_PROTOCOL_DAYTIME                           80

/**********************JK start******************************/
#define NDPI_PROTOCOL_TONGHUASHUN                       81
#define NDPI_PROTOCOL_QIANLONG                          82
#define NDPI_PROTOCOL_DAZHIHUI365                       83
#define NDPI_PROTOCOL_ZHINANZHEN                        84
#define NDPI_PROTOCOL_HUARONG                           85
#define NDPI_PROTOCOL_PINGANZHENGQUAN                   86
#define NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN                87
#define NDPI_PROTOCOL_TONGDAXIN                         88

/**********************JK end***************************/
#define NDPI_PROTOCOL_FETION                            89

#define NDPI_PROTOCOL_LOL                               90
#define NDPI_PROTOCOL_NIZHAN                            91
#define NDPI_PROTOCOL_DRAGONOATH                        92
#define NDPI_PROTOCOL_WENDAO                            93
#define NDPI_PROTOCOL_LIANZHONG                         94
#define NDPI_PROTOCOL_POPKART                           95
#define NDPI_PROTOCOL_MENGHUANXIYOU                     96
#define NDPI_PROTOCOL_TIANXIA3                          97
#define NDPI_PROTOCOL_HAOFANG                           98
#define NDPI_PROTOCOL_DAHUAXIYOU2                       99

/*zl start*/
#define NDPI_PROTOCOL_GAME_CF                           100
#define NDPI_PROTOCOL_GAME_ZHENTU                       101
#define NDPI_PROTOCOL_GAME_ZHENGFU                      102
#define NDPI_PROTOCOL_GAME_JINWUTUAN                    103
#define NDPI_PROTOCOL_GAME_DOTA2                        104
#define NDPI_PROTOCOL_GAME_JIZHAN                       105
/*zl end*/

/*jkjun games start*/
#define NDPI_PROTOCOL_GAME_QQSPEED                      106
#define NDPI_PROTOCOL_GAME_DNF                          107
#define NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP             108
#define NDPI_PROTOCOL_BAIDUPAN                          109
#define NDPI_PROTOCOL_GAME_EUDEMONS                     110
#define NDPI_PROTOCOL_GAME_JX3                          111
/*jkjun games end*/
#define NDPI_PROTOCOL_HUASHENGKE                        112
#define NDPI_PROTOCOL_JINWANWEI                         113
#define NDPI_PROTOCOL_WECHAT_TX                         114
#define NDPI_PROTOCOL_QQ_TX                             115
#define NDPI_PROTOCOL_QQMUSIC                           116
#define NDPI_PROTOCOL_GAME_QIANNYH                      117

#define NDPI_LAST_IMPLEMENTED_PROTOCOL                 NDPI_PROTOCOL_GAME_QIANNYH


#define NDPI_MAX_SUPPORTED_PROTOCOLS (NDPI_LAST_IMPLEMENTED_PROTOCOL + 1)
#define NDPI_MAX_NUM_CUSTOM_PROTOCOLS                           128
#ifdef __cplusplus
}
#endif
#endif

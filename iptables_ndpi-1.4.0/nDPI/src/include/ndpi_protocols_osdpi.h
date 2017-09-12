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
#define NDPI_PROTOCOL_HISTORY_SIZE				3

#define NDPI_PROTOCOL_UNKNOWN					0
#define NDPI_PROTOCOL_FTP_CONTROL						1
#define NDPI_PROTOCOL_MAIL_POP					2
#define NDPI_PROTOCOL_MAIL_SMTP					3
#define NDPI_PROTOCOL_MAIL_IMAP					4
#define NDPI_PROTOCOL_DNS              			5
#define NDPI_PROTOCOL_IPP						6
#define NDPI_PROTOCOL_HTTP						7
#define NDPI_PROTOCOL_MDNS						8
#define NDPI_PROTOCOL_NTP						9
#define NDPI_PROTOCOL_NETBIOS					10
#define NDPI_PROTOCOL_NFS						11
#define NDPI_PROTOCOL_SSDP						12
#define NDPI_PROTOCOL_BGP						13
#define NDPI_PROTOCOL_SNMP						14
#define NDPI_PROTOCOL_SMB						15
#define NDPI_PROTOCOL_SYSLOG					16
#define NDPI_PROTOCOL_DHCP						17
#define NDPI_PROTOCOL_POSTGRES					18
#define NDPI_PROTOCOL_MYSQL						19
#define NDPI_PROTOCOL_TDS						20

#define NDPI_PROTOCOL_MAIL_POPS					21
#define NDPI_PROTOCOL_MAIL_SMTPS				22
#define NDPI_PROTOCOL_EDONKEY					23
#define NDPI_PROTOCOL_BITTORRENT				24

#define	NDPI_PROTOCOL_QQ						25
#define NDPI_PROTOCOL_MAIL_IMAPS				26
#define NDPI_PROTOCOL_PPLIVE					27
#define NDPI_PROTOCOL_PPSTREAM					28
#define NDPI_PROTOCOL_QQLIVE					29
#define NDPI_PROTOCOL_THUNDER					30

#define NDPI_PROTOCOL_SSL_NO_CERT			    31 /* SSL without certificate (Skype, Ultrasurf?) - ntop.org */
#define NDPI_PROTOCOL_VRRP 				        32
#define NDPI_PROTOCOL_WORLDOFWARCRAFT			33
#define NDPI_PROTOCOL_TELNET					34

#define NDPI_PROTOCOL_IPSEC						35
#define NDPI_PROTOCOL_ICMP						36
#define NDPI_PROTOCOL_IGMP						37
#define NDPI_PROTOCOL_SCTP						38
#define NDPI_PROTOCOL_OSPF						39
#define	NDPI_PROTOCOL_RTP						40
#define NDPI_PROTOCOL_RDP						41
#define NDPI_PROTOCOL_SSL						42
#define NDPI_PROTOCOL_SSH						43
#define NDPI_PROTOCOL_MGCP						44
#define NDPI_PROTOCOL_TFTP						45
#define NDPI_PROTOCOL_LDAP						46

#define NDPI_PROTOCOL_MSSQL						47
#define NDPI_PROTOCOL_PPTP						48
#define NDPI_PROTOCOL_FACEBOOK                  49
#define NDPI_PROTOCOL_TWITTER                   50
#define NDPI_PROTOCOL_DCERPC                    51
#define NDPI_PROTOCOL_RADIUS                    52
#define NDPI_PROTOCOL_LLMNR                     53
#define NDPI_PROTOCOL_HTTP_CONNECT              54
#define NDPI_PROTOCOL_FTP_DATA                  55
#define NDPI_PROTOCOL_HUASHENGKE                56
#define NDPI_PROTOCOL_JINWANWEI                 57
/* UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE */

/*Add custom define here FROM 225 ,and set NDPI_LAST_IMPLEMENTED_PROTOCOL to your last protocol -- PT */

#define NDPI_PROTOCOL_WECHAT							60
#define NDPI_PROTOCOL_ALIWANGWANG						61
#define NDPI_PROTOCOL_SINAWEIBO							62
#define NDPI_PROTOCOL_TENCENTWEIBO						63
#define NDPI_PROTOCOL_WEBQQ								64
#define NDPI_PROTOCOL_DINGTALK							65
#define NDPI_PROTOCOL_YOUDAONOTE						66
#define NDPI_PROTOCOL_LETV								67
#define NDPI_PROTOCOL_FUNSHION							68
#define NDPI_PROTOCOL_KU6								69
#define NDPI_PROTOCOL_SOHU								70
//#define NDPI_PROTOCOL_TUDOU								71
#define NDPI_PROTOCOL_YOUKU								72
#define NDPI_PROTOCOL_BAIDUHI							73

#define NDPI_PROTOCOL_YIXIN								74
#define NDPI_PROTOCOL_YY								75
#define NDPI_PROTOCOL_RIP								76
#define NDPI_PROTOCOL_L2TP								77
#define NDPI_PROTOCOL_FTPS                              78
#define NDPI_PROTOCOL_NNTP                              79
#define NDPI_PROTOCOL_DAYTIME                           80

/**********************JK start******************************/
#define NDPI_PROTOCOL_TONGHUASHUN						81
#define NDPI_PROTOCOL_QIANLONG							82
#define NDPI_PROTOCOL_DAZHIHUI365                       83
#define NDPI_PROTOCOL_ZHINANZHEN                        84
#define NDPI_PROTOCOL_HUARONG							85
#define NDPI_PROTOCOL_PINGANZHENGQUAN                   86
#define NDPI_PROTOCOL_ZHAOSHANGZHENGQUAN                87
#define NDPI_PROTOCOL_TONGDAXIN                         88

/**********************JK end***************************/
#define NDPI_PROTOCOL_FETION							89

#define NDPI_PROTOCOL_LOL								90
#define NDPI_PROTOCOL_NIZHAN							91
#define NDPI_PROTOCOL_DRAGONOATH						92
#define NDPI_PROTOCOL_WENDAO							93
#define NDPI_PROTOCOL_LIANZHONG							94
#define NDPI_PROTOCOL_POPKART							95
#define NDPI_PROTOCOL_MENGHUANXIYOU						96
#define NDPI_PROTOCOL_TIANXIA3							97
#define NDPI_PROTOCOL_HAOFANG							98
#define NDPI_PROTOCOL_DAHUAXIYOU2						99

/*zl start*/
#define NDPI_PROTOCOL_GAME_CF							100
#define NDPI_PROTOCOL_GAME_ZHENTU						101				
#define NDPI_PROTOCOL_GAME_ZHENGFU						102
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

#define NDPI_LAST_IMPLEMENTED_PROTOCOL                       NDPI_PROTOCOL_GAME_JX3 



#define NDPI_MAX_SUPPORTED_PROTOCOLS (NDPI_LAST_IMPLEMENTED_PROTOCOL + 1)
#define NDPI_MAX_NUM_CUSTOM_PROTOCOLS                           128
#ifdef __cplusplus
}
#endif
#endif

//  #define NDPI_ENABLE_DEBUG_MESSAGES
//#define NDPI_PROTOCOL_XDMCP					15
//#define NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK			22
//#define NDPI_PROTOCOL_I23V5					23

//#define NDPI_PROTOCOL_APPLEJUICE				24
//#define NDPI_PROTOCOL_DIRECTCONNECT				25
//#define NDPI_PROTOCOL_SOCRATES					26
//#define NDPI_PROTOCOL_WINMX					27
//#define NDPI_PROTOCOL_VMWARE					28
  //#define NDPI_PROTOCOL_PANDO					29

//#define NDPI_PROTOCOL_FILETOPIA					30
//#define NDPI_PROTOCOL_IMESH					31
//#define NDPI_PROTOCOL_KONTIKI					32
//#define NDPI_PROTOCOL_OPENFT					33
//#define NDPI_PROTOCOL_FASTTRACK					34
//#define NDPI_PROTOCOL_GNUTELLA					35
//#define NDPI_PROTOCOL_OFF					38
//#define NDPI_PROTOCOL_AVI					39
//#define NDPI_PROTOCOL_FLASH					40
//#define NDPI_PROTOCOL_OGG					41
//#define	NDPI_PROTOCOL_MPEG					42
//#define	NDPI_PROTOCOL_QUICKTIME					43
//#define	NDPI_PROTOCOL_REALMEDIA					44
//#define	NDPI_PROTOCOL_WINDOWSMEDIA				45
//#define	NDPI_PROTOCOL_MMS					46
//#define	NDPI_PROTOCOL_XBOX					47

//#define	NDPI_PROTOCOL_MOVE					49
//#define	NDPI_PROTOCOL_RTSP					50
//#define NDPI_PROTOCOL_FEIDIAN					51
//#define NDPI_PROTOCOL_ICECAST					52
//#define NDPI_PROTOCOL_ZATTOO					55
//#define NDPI_PROTOCOL_SHOUTCAST					56
//#define NDPI_PROTOCOL_SOPCAST					57
//#define NDPI_PROTOCOL_TVANTS					58
//#define NDPI_PROTOCOL_TVUPLAYER					59
//#define NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV 			60
//#define NDPI_PROTOCOL_SOULSEEK					63
//#define NDPI_PROTOCOL_IRC					65
//#define NDPI_PROTOCOL_POPO					66
//#define NDPI_PROTOCOL_UNENCRYPED_JABBER				67
//#define NDPI_PROTOCOL_MSN					68
//#define NDPI_PROTOCOL_OSCAR					69
//#define NDPI_PROTOCOL_YAHOO					70
//#define NDPI_PROTOCOL_BATTLEFIELD				71
//#define NDPI_PROTOCOL_QUAKE					72
//#define NDPI_PROTOCOL_STEAM					74
//#define NDPI_PROTOCOL_HALFLIFE2					75
//#define NDPI_PROTOCOL_STUN					78
//#define NDPI_PROTOCOL_GRE					80
//#define NDPI_PROTOCOL_EGP					83
//#define NDPI_PROTOCOL_IP_IN_IP					86
//#define NDPI_PROTOCOL_VNC					89
//#define NDPI_PROTOCOL_PCANYWHERE				90
//#define NDPI_PROTOCOL_USENET					93
//#define NDPI_PROTOCOL_IAX					95
//#define NDPI_PROTOCOL_AFP					97
//#define NDPI_PROTOCOL_STEALTHNET				98
//#define NDPI_PROTOCOL_AIMINI					99
//#define NDPI_PROTOCOL_SIP					100
//#define NDPI_PROTOCOL_TRUPHONE					101
//#define NDPI_PROTOCOL_ICMPV6					102
//#define NDPI_PROTOCOL_DHCPV6					103
//#define NDPI_PROTOCOL_ARMAGETRON				104
//#define NDPI_PROTOCOL_CROSSFIRE					105
//#define NDPI_PROTOCOL_DOFUS					106
//#define NDPI_PROTOCOL_FIESTA					107
//#define NDPI_PROTOCOL_FLORENSIA					108
//#define NDPI_PROTOCOL_GUILDWARS					109
//#define NDPI_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC		110
//#define NDPI_PROTOCOL_KERBEROS					111
//#define NDPI_PROTOCOL_MAPLESTORY				113
//#define NDPI_PROTOCOL_WARCRAFT3					116
//#define NDPI_PROTOCOL_WORLD_OF_KUNG_FU				117
//#define NDPI_PROTOCOL_MEEBO					118
//#define NDPI_PROTOCOL_DROPBOX                                   121
//#define NDPI_PROTOCOL_GMAIL                                     122
//#define NDPI_PROTOCOL_GOOGLE_MAPS                               123

//#define NDPI_PROTOCOL_SKYPE                                     125
//#define NDPI_PROTOCOL_GOOGLE                                    126

//#define NDPI_PROTOCOL_NETFLOW                                   128
//#define NDPI_PROTOCOL_SFLOW                                     129
//#define NDPI_PROTOCOL_HTTP_CONNECT                              130
//#define NDPI_PROTOCOL_HTTP_PROXY                                131
//#define NDPI_PROTOCOL_CITRIX                                    132
//#define NDPI_PROTOCOL_NETFLIX                                   133
//#define NDPI_PROTOCOL_LASTFM                                    134
//#define NDPI_PROTOCOL_GROOVESHARK                               135
//#define NDPI_PROTOCOL_SKYFILE_PREPAID                           136
//#define NDPI_PROTOCOL_SKYFILE_RUDICS                            137
//#define NDPI_PROTOCOL_SKYFILE_POSTPAID                          138
//#define NDPI_PROTOCOL_CITRIX_ONLINE                             139
//#define NDPI_PROTOCOL_APPLE                                     140
//#define NDPI_PROTOCOL_WEBEX                                     141
//#define NDPI_PROTOCOL_WHATSAPP                                  142
//#define NDPI_PROTOCOL_APPLE_ICLOUD                              143
//#define NDPI_PROTOCOL_VIBER                                     144
//#define NDPI_PROTOCOL_APPLE_ITUNES                              145
//#define NDPI_PROTOCOL_WINDOWS_UPDATE                            147 /* Thierry Laurion */
//#define NDPI_PROTOCOL_TEAMVIEWER                                148 /* xplico.org */
//#define NDPI_PROTOCOL_TUENTI                                    149
//#define NDPI_PROTOCOL_LOTUS_NOTES                               150
//#define NDPI_PROTOCOL_SAP                                       151
//#define NDPI_PROTOCOL_GTP                                       152
//#define NDPI_PROTOCOL_UPNP                                      153
//#define NDPI_PROTOCOL_REMOTE_SCAN                               155
//#define NDPI_PROTOCOL_SPOTIFY                                   156
//#define NDPI_PROTOCOL_WEBM                                      157
//#define NDPI_PROTOCOL_H323                                      158 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_OPENVPN                                   159 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_NOE                                       160 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_CISCOVPN                                  161 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_TEAMSPEAK                                 162 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_TOR                                       163 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_SKINNY                                    164 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_RTCP                                      165 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_RSYNC                                     166 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_ORACLE                                    167 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_CORBA                                     168 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_UBUNTUONE                                 169 /* Remy Mudingay <mudingay@ill.fr> */
//#define NDPI_PROTOCOL_WHOIS_DAS                                 170
//#define NDPI_PROTOCOL_LOFTER									176
//#define NDPI_PROTOCOL_WEBMOMO									178
//#define NDPI_PROTOCOL_YOUDAODICT								181
//#define NDPI_PROTOCOL_PIPI										182
//#define NDPI_PROTOCOL_MICHAT									185
//#define NDPI_PROTOCOL_PPMATE									186
//#define NDPI_PROTOCOL_SINATV									187
//#define NDPI_PROTOCOL_EAGLEGET									188
//#define NDPI_PROTOCOL_BOBO										189
//#define NDPI_PROTOCOL_QVOD										190
//#define NDPI_PROTOCOL_6ROOMS									191
//#define NDPI_PROTOCOL_BAOFENG									192
//#define NDPI_PROTOCOL_XLLIVE									193
//#define NDPI_PROTOCOL_VOOLE										194
//#define NDPI_PROTOCOL_MANGO										197
//#define NDPI_PROTOCOL_KUGOU										198
//#define NDPI_PROTOCOL_QQMUSIC									202
//#define NDPI_PROTOCOL_SEE5										204
//#define NDPI_PROTOCOL_GAME5211									205
//#define NDPI_PROTOCOL_BAITUZHIBO								206
//#define NDPI_PROTOCOL_KUKUXIU									207
//#define NDPI_PROTOCOL_9158ZHIBO									208
//#define NDPI_PROTOCOL_AIM										209
//#define NDPI_PROTOCOL_DIANSHIZHIBOWANG							210
//#define NDPI_PROTOCOL_HUAJIAOZHIBO								211
//#define NDPI_PROTOCOL_MOP										212
//#define NDPI_PROTOCOL_ZHIBOBA									213
//#define NDPI_PROTOCOL_MAXTV										214
//#define NDPI_PROTOCOL_DIYISHIPIN								215
//#define NDPI_PROTOCOL_YIZHIBO									216
//#define NDPI_PROTOCOL_WOLEWANG									217
//#define NDPI_PROTOCOL_HUPO										218
//#define NDPI_PROTOCOL_BANLIAO									219
//#define NDPI_PROTOCOL_DOC360									220
//#define NDPI_PROTOCOL_HOOLO										221
//#define NDPI_PROTOCOL_BAOMIHUA									222
//#define NDPI_PROTOCOL_LAIFENGZHIBO								223
//#define NDPI_PROTOCOL_QYULE										224
//#define NDPI_PROTOCOL_JIDONGWANG								225
//#define NDPI_PROTOCOL_PHONE80S									226
//#define NDPI_PROTOCOL_QQZHIBO									227
//#define NDPI_PROTOCOL_MOFANG									228
//#define NDPI_PROTOCOL_BAMUDIANYIN								229
//#define NDPI_PROTOCOL_XFPLAY									230
//#define NDPI_PROTOCOL_RENZIXIN									232
//#define NDPI_PROTOCOL_WANGYIZHIBO								233
//#define NDPI_PROTOCOL_PANDA										234
//#define NDPI_PROTOCOL_XIAMI										235
//#define NDPI_PROTOCOL_WANGYIMUSIC								236
//#define NDPI_PROTOCOL_KUWO										237
//#define NDPI_PROTOCOL_9XIU										238
//#define NDPI_PROTOCOL_5TTK										239
//#define NDPI_PROTOCOL_SANGUOSHA									240 
//#define NDPI_PROTOCOL_JEBOO										241
//#define NDPI_PROTOCOL_KKZHIBO									242
//#define NDPI_PROTOCOL_LONGZHU									243
//#define NDPI_PROTOCOL_HUYA										244
//#define NDPI_PROTOCOL_ZHANQI									245
//#define NDPI_PROTOCOL_DEMAXIYA									246
//#define NDPI_PROTOCOL_FENGYUNZHIBO								247
//#define NDPI_PROTOCOL_XINTIYUWANG								248
//#define NDPI_PROTOCOL_HUNANWEISHI								249
//#define NDPI_PROTOCOL_HAOTV8									250
//#define NDPI_PROTOCOL_TVMAO										251
//#define NDPI_PROTOCOL_CIETV										252
//#define NDPI_PROTOCOL_TIANTIANZHIBO								253
//#define NDPI_PROTOCOL_AZHIBO									254
//#define NDPI_PROTOCOL_QUANMINTV									255
//#define NDPI_PROTOCOL_MEME										256
//#define NDPI_PROTOCOL_SINAZHIBO									257
//#define NDPI_PROTOCOL_FENGHUANG									258
//#define NDPI_PROTOCOL_24ZHIBOWANG								259
//#define NDPI_PROTOCOL_ISZHIBO									260
//#define NDPI_PROTOCOL_360BO										261
//#define NDPI_PROTOCOL_360ZHIBO									262
//#define NDPI_PROTOCOL_YANGSHI									263
//#define NDPI_PROTOCOL_1905DIANYIN								264
//#define NDPI_PROTOCOL_EVPLAYER									265
//#define NDPI_PROTOCOL_QIANQIAN									266
//#define NDPI_PROTOCOL_BAIDUMUSIC								267
//#define NDPI_PROTOCOL_LEWO										268
//#define NDPI_PROTOCOL_XIGUA										269
//#define NDPI_PROTOCOL_JINGOAL									272
//#define NDPI_PROTOCOL_YINXIANGNOTE								273
//#define NDPI_PROTOCOL_COMPRESS								    276
//#define NDPI_PROTOCOL_EXE								        277
//#define NDPI_PROTOCOL_TEXT	     							    278
//#define NDPI_PROTOCOL_TEREDO                                    279
//#define NDPI_PROTOCOL_FRESHDOWNLOAD                             280
//#define NDPI_PROTOCOL_HTTPS                                     282
//#define NDPI_PROTOCOL_WINBOX                                    285
//#define NDPI_PROTOCOL_YOUDAOCIDIAN								286

//#define NDPI_PROTOCOL_ZHENGQUANZHIXING							361

//#define NDPI_PROTOCOL_ALITONG									363
//#define NDPI_PROTOCOL_WANGYICC									364
//#define NDPI_PROTOCOL_QQDOWNLOAD								366
//#define NDPI_PROTOCOL_GAME_DNF 									379


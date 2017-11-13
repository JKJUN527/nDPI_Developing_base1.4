/*
 * ndpi_structs.h
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


#ifndef __NDPI_STRUCTS_INCLUDE_FILE__
#define __NDPI_STRUCTS_INCLUDE_FILE__

#include "ndpi_credis.h"
#include "linux_compat.h"
#include "ndpi_define.h"

#ifdef NDPI_DETECTION_SUPPORT_IPV6
struct ndpi_ip6_addr {
  union {
    u_int8_t u6_addr8[16];
    u_int16_t u6_addr16[8];
    u_int32_t u6_addr32[4];
    u_int64_t u6_addr64[2];
  } ndpi_v6_u;

#define ndpi_v6_addr		ndpi_v6_u.u6_addr8
#define ndpi_v6_addr16		ndpi_v6_u.u6_addr16
#define ndpi_v6_addr32		ndpi_v6_u.u6_addr32
#define ndpi_v6_addr64		ndpi_v6_u.u6_addr64
};

struct ndpi_ipv6hdr {
  /* use userspace and kernelspace compatible compile parameters */
#if defined(__LITTLE_ENDIAN__)
  u_int8_t priority:4, version:4;
#elif defined(__BIG_ENDIAN__)
  u_int8_t version:4, priority:4;
#else
# error "Byte order must be defined"
#endif

  u_int8_t flow_lbl[3];

  u_int16_t payload_len;
  u_int8_t nexthdr;
  u_int8_t hop_limit;

  struct ndpi_ip6_addr saddr;
  struct ndpi_ip6_addr daddr;
};
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

struct pro_node {
    int pro;                    /* just store protocol */
    struct pro_node *next;
};

/* hash table */
typedef struct ndpi_hash_t {
    int hash_size;
    u_int32_t (*hash_fn)(u_int8_t const *key, int len);
    struct pro_node * table[1];
} ndpi_hash_t;

typedef union {
  u_int32_t ipv4;
  u_int8_t ipv4_u_int8_t[4];
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  struct ndpi_ip6_addr ipv6;
#endif
} ndpi_ip_addr_t;


# define MAX_PACKET_COUNTER 65000

typedef struct ndpi_id_struct {
  /* detected_protocol_bitmask:
   * access this bitmask to find out whether an id has used skype or not
   * if a flag is set here, it will not be resetted
   * to compare this, use:
   * if (NDPI_BITMASK_COMPARE(id->detected_protocol_bitmask,
   *                            NDPI_PROTOCOL_BITMASK_XXX) != 0)
   * {
   *      // protocol XXX detected on this id
   * }
   */
  NDPI_PROTOCOL_BITMASK detected_protocol_bitmask;
#ifdef NDPI_PROTOCOL_FTP
  ndpi_ip_addr_t ftp_ip;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
  u_int32_t pplive_last_packet_time;
#endif
#ifdef NDPI_PROTOCOL_FTP
  u_int32_t ftp_timer;
#endif
#ifdef NDPI_PROTOCOL_THUNDER
  u_int32_t thunder_ts;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
  u_int16_t pplive_vod_cli_port;
#endif
#ifdef NDPI_PROTOCOL_FTP
  u_int32_t ftp_timer_set:1;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
  u_int32_t pplive_last_packet_time_set:1;
#endif
} ndpi_id_struct;

/* ************************************************** */ 

struct ndpi_flow_tcp_struct {
#ifdef NDPI_PROTOCOL_MAIL_SMTP
  u_int16_t smtp_command_bitmask;
#endif
#ifdef NDPI_PROTOCOL_MAIL_POP
  u_int16_t pop_command_bitmask;
#endif
#ifdef NDPI_PROTOCOL_QQ
  u_int16_t qq_nxt_len;
#endif
#ifdef NDPI_PROTOCOL_TDS
  u_int8_t tds_login_version;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
  u_int8_t pplive_next_packet_size[2];
#endif
#ifdef NDPI_PROTOCOL_EDONKEY
  u_int32_t edk_ext:1;
#endif
#ifdef NDPI_PROTOCOL_TDS
  u_int32_t tds_stage:3;
#endif
#ifdef NDPI_PROTOCOL_FTP
  u_int32_t ftp_codes_seen:5;
  u_int32_t ftp_client_direction:1;
#endif
#ifdef NDPI_PROTOCOL_HTTP
  u_int32_t http_setup_dir:2;
  u_int32_t http_stage:2;
  u_int32_t http_empty_line_seen:1;
  u_int32_t http_wait_for_retransmission:1;
#endif							// NDPI_PROTOCOL_HTTP
#ifdef NDPI_PROTOCOL_SSH
  u_int32_t ssh_stage:3;
#endif
#ifdef NDPI_PROTOCOL_TELNET
  u_int32_t telnet_stage:2;			// 0 - 2
#endif
#ifdef NDPI_PROTOCOL_SSL
  u_int32_t ssl_stage:2, ssl_seen_client_cert:1, ssl_seen_server_cert:1; // 0 - 5
#endif
#ifdef NDPI_PROTOCOL_POSTGRES
  u_int32_t postgres_stage:3;
#endif
  u_int32_t seen_syn:1;
  u_int32_t seen_syn_ack:1;
  u_int32_t seen_ack:1;
#ifdef NDPI_PROTOCOL_WORLDOFWARCRAFT
  u_int32_t wow_stage:2;
#endif
#ifdef NDPI_PROTOCOL_MAIL_POP
  u_int32_t mail_pop_stage:2;
#endif
#ifdef NDPI_PROTOCOL_MAIL_IMAP
  u_int32_t mail_imap_stage:3;
#endif
#ifdef NDPI_PROTOCOL_ALIWANGWANG 
  u_int8_t aliwangwang_stage; // pengtian
#endif


}

/* ************************************************** */ 

#if !defined(WIN32)
  __attribute__ ((__packed__))
#endif
  ;

#if defined(WIN32)
#define pthread_t              HANDLE
#define pthread_mutex_t        HANDLE
#define pthread_rwlock_t       pthread_mutex_t
#endif

struct ndpi_flow_udp_struct {

#ifdef NDPI_PROTOCOL_SNMP
  u_int32_t snmp_msg_id;
#endif
#ifdef NDPI_PROTOCOL_SNMP
  u_int32_t snmp_stage:2;
#endif
#ifdef NDPI_PROTOCOL_PPSTREAM
  u_int32_t ppstream_stage:3;		// 0-7
#endif
#ifdef NDPI_PROTOCOL_TFTP
  u_int32_t tftp_stage:1;
#endif
}

/* ************************************************** */ 

#if !defined(WIN32)
  __attribute__ ((__packed__))
#endif
  ;

#if defined(WIN32)
#define pthread_t              HANDLE
#define pthread_mutex_t        HANDLE
#define pthread_rwlock_t       pthread_mutex_t

#define sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)

#define pthread_rwlock_init                     pthread_mutex_init
#define pthread_rwlock_wrlock                   pthread_mutex_lock
#define pthread_rwlock_rdlock                   pthread_mutex_lock
#define pthread_rwlock_unlock                   pthread_mutex_unlock
#define pthread_rwlock_destroy					pthread_mutex_destroy
#endif

typedef struct ndpi_int_one_line_struct {
  const u_int8_t *ptr;
  u_int16_t len;
} ndpi_int_one_line_struct_t;

typedef struct ndpi_packet_struct {
  const struct ndpi_iphdr *iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iphv6;
#endif
  const struct ndpi_tcphdr *tcp;
  const struct ndpi_udphdr *udp;
  const u_int8_t *generic_l4_ptr;	/* is set only for non tcp-udp traffic */
  const u_int8_t *payload;

  u_int32_t tick_timestamp;

  u_int16_t detected_protocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
  u_int8_t detected_subprotocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];

  /* this is for simple read-only access to the real protocol 
   * used for the main loop */
  u_int16_t real_protocol_read_only;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
#  if NDPI_PROTOCOL_HISTORY_SIZE > 5
#    error protocol stack size not supported
#  endif

  struct {
    u_int8_t entry_is_real_protocol:5;
    u_int8_t current_stack_size_minus_one:3;
  } 
#if !defined(WIN32)
    __attribute__ ((__packed__))
#endif
    protocol_stack_info;
#endif

  struct ndpi_int_one_line_struct line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  struct ndpi_int_one_line_struct unix_line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  struct ndpi_int_one_line_struct host_line;
  struct ndpi_int_one_line_struct referer_line;
  struct ndpi_int_one_line_struct content_line;
  struct ndpi_int_one_line_struct accept_line;
  struct ndpi_int_one_line_struct user_agent_line;
  struct ndpi_int_one_line_struct http_url_name;
  struct ndpi_int_one_line_struct http_encoding;
  struct ndpi_int_one_line_struct http_transfer_encoding;
  struct ndpi_int_one_line_struct http_contentlen;
  struct ndpi_int_one_line_struct http_cookie;
  struct ndpi_int_one_line_struct http_x_session_type;
  struct ndpi_int_one_line_struct server_line;
  struct ndpi_int_one_line_struct http_method;
  struct ndpi_int_one_line_struct http_response;
  struct ndpi_int_one_line_struct http_payload;


  u_int16_t l3_packet_len;
  u_int16_t l4_packet_len;
  u_int16_t payload_packet_len;
  u_int16_t actual_payload_len;
  u_int16_t num_retried_bytes;
  u_int16_t parsed_lines;
  u_int16_t parsed_unix_lines;
  u_int16_t empty_line_position;
  u_int8_t tcp_retransmission;
  u_int8_t l4_protocol;

  u_int8_t packet_lines_parsed_complete;
  u_int8_t packet_unix_lines_parsed_complete;
  u_int8_t empty_line_position_set;
  u_int8_t packet_direction:1;
  u_int8_t client2server:1;       /* 1: client -> server; 0: server -> client */
  u_int8_t ssl_certificate_detected:4, ssl_certificate_num_checks:4;
} ndpi_packet_struct_t;

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

typedef struct ndpi_call_function_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  u_int8_t detection_feature;
} ndpi_call_function_struct_t;

typedef struct ndpi_subprotocol_conf_struct {
  void (*func) (struct ndpi_detection_module_struct *, char *attr, char *value, int protocol_id);
} ndpi_subprotocol_conf_struct_t;

#define MAX_DEFAULT_PORTS        5

typedef struct {
  u_int16_t port_low, port_high;
} ndpi_port_range;

/* ntop extensions */
typedef struct ndpi_proto_defaults {
  char *protoName;
  u_int16_t protoId;
} ndpi_proto_defaults_t;

typedef struct ndpi_default_ports_tree_node {
  ndpi_proto_defaults_t *proto;
  u_int16_t default_port;
} ndpi_default_ports_tree_node_t;

typedef struct ndpi_detection_module_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK generic_http_packet_bitmask;
  
  u_int32_t current_ts;
  u_int32_t ticks_per_second;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  void *user_data;
#endif
  /* callback function buffer */
  //struct ndpi_call_function_struct callback_buffer[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  struct ndpi_call_function_struct *callback_buffer;
  u_int32_t callback_buffer_size;

  //struct ndpi_call_function_struct callback_buffer_tcp_no_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  struct ndpi_call_function_struct *callback_buffer_tcp_no_payload;
  u_int32_t callback_buffer_size_tcp_no_payload;

  //struct ndpi_call_function_struct callback_buffer_tcp_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  struct ndpi_call_function_struct *callback_buffer_tcp_payload;
  u_int32_t callback_buffer_size_tcp_payload;

  //struct ndpi_call_function_struct callback_buffer_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  struct ndpi_call_function_struct *callback_buffer_udp;
  u_int32_t callback_buffer_size_udp;

  //struct ndpi_call_function_struct callback_buffer_non_tcp_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  struct ndpi_call_function_struct *callback_buffer_non_tcp_udp;
  u_int32_t callback_buffer_size_non_tcp_udp;

  ndpi_default_ports_tree_node_t *tcpRoot, *udpRoot;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  /* debug callback, only set when debug is used */
  ndpi_debug_function_ptr ndpi_debug_printf;
  const char *ndpi_debug_print_file;
  const char *ndpi_debug_print_function;
  u_int32_t ndpi_debug_print_line;
#endif
  /* misc parameters */
  u_int32_t tcp_max_retransmission_window_size;

  u_int32_t edonkey_upper_ports_only:1;
  u_int32_t edonkey_safe_mode:1;
  u_int32_t directconnect_connection_ip_tick_timeout;

  /* subprotocol registration handler */
  struct ndpi_subprotocol_conf_struct subprotocol_conf[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];

  u_int ndpi_num_supported_protocols;
  u_int ndpi_num_custom_protocols;

  /* HTTP (and soon DNS) host matching */
  void *ac_automa; /* Real type is AC_AUTOMATA_t */
  u_int8_t ac_automa_finalized;

  /* pplive params */
  u_int32_t pplive_connection_timeout;
  /* ftp parameters */
  u_int32_t ftp_connection_timeout;
  /* irc parameters */
  u_int32_t irc_timeout;
  /* gnutella parameters */
  u_int32_t gnutella_timeout;
  /* battlefield parameters */
  u_int32_t battlefield_timeout;
  /* thunder parameters */
  u_int32_t thunder_timeout;
  /* SoulSeek parameters */
  u_int32_t soulseek_connection_ip_tick_timeout;
  /* rtsp parameters */
  u_int32_t rtsp_connection_timeout;
  /* tvants parameters */
  u_int32_t tvants_connection_timeout;
  u_int32_t orb_rstp_ts_timeout;
  /* yahoo */
  //      u_int32_t yahoo_http_filetransfer_timeout;
  u_int8_t yahoo_detect_http_connections;
  u_int32_t yahoo_lan_video_timeout;
  u_int32_t zattoo_connection_timeout;
  u_int32_t jabber_stun_timeout;
  u_int32_t jabber_file_transfer_timeout;
#define NDPI_IP_STRING_SIZE 40
  char ip_string[NDPI_IP_STRING_SIZE];
  u_int8_t ip_version_limit;

  /* Cache */
  NDPI_REDIS redis;
  ndpi_hash_t *meta2protocol;       /* for ftp_data and tftp, save 5-meta infomation mapping to protocol */

  /* Skype (we need a lock as this cache can be accessed concurrently) */
  struct ndpi_LruCache skypeCache;
#ifndef __KERNEL__
  pthread_mutex_t skypeCacheLock;
#else
  spinlock_t skypeCacheLock;
#endif

  /* ********************* */
  ndpi_proto_defaults_t proto_defaults[NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS];

  u_int8_t match_dns_host_names:1;
} ndpi_detection_module_struct_t;

typedef struct ndpi_flow_struct {
  u_int16_t detected_protocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
#if NDPI_PROTOCOL_HISTORY_SIZE > 1
#  if NDPI_PROTOCOL_HISTORY_SIZE > 5
#    error protocol stack size not supported
#  endif
  
  struct {
    u_int8_t entry_is_real_protocol:5;
    u_int8_t current_stack_size_minus_one:3;
  } 
    
#if !defined(WIN32)
    __attribute__ ((__packed__))
#endif
    protocol_stack_info;
#endif  
  
  /* init parameter, internal used to set up timestamp,... */
  u_int8_t init_finished:1;
  u_int8_t setup_packet_direction:1;
  /* tcp sequence number connection tracking */
  u_int32_t next_tcp_seq_nr[2];

  /* the tcp / udp / other l4 value union
   * this is used to reduce the number of bytes for tcp or udp protocol states
   * */
  union {
    struct ndpi_flow_tcp_struct tcp;
    struct ndpi_flow_udp_struct udp;
  } l4;
  union{
    struct {
      char client_certificate[48], server_certificate[48];
    } ssl;
  } protos;
  u_char host_server_name[256]; /* HTTP host or DNS query */

  /* ALL protocol specific 64 bit variables here */

  /* protocols which have marked a connection as this connection cannot be protocol XXX, multiple u_int64_t */
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;

  u_int16_t packet_counter;			// can be 0-65000, it only count packets with payload?
  u_int16_t packet_direction_counter[2];
  u_int16_t byte_counter[2];

#ifdef NDPI_PROTOCOL_BITTORRENT
  u_int8_t bittorrent_stage;		// can be 0-255
#endif
#ifdef NDPI_PROTOCOL_EDONKEY
  u_int32_t edk_stage:5;			// 0-17
#endif
#ifdef NDPI_PROTOCOL_HTTP
  u_int32_t http_detected:1;
#endif							// NDPI_PROTOCOL_HTTP
#ifdef NDPI_PROTOCOL_PPLIVE
  u_int32_t pplive_stage:3;			// 0-7
#endif
/*
#ifdef NDPI_PROTOCOL_BAOFENG
  u_int32_t baofeng_stage:4;		// 0-15
  u_int32_t baofeng_count:4;            //0-15
  
#endif
*/
#ifdef NDPI_PROTOCOL_QQ
  u_int32_t qq_stage:3;
#endif
#ifdef NDPI_PROTOCOL_WEBQQ
  u_int32_t webqq_direction:1;
#endif
#ifdef NDPI_PROTOCOL_LOL
  u_int32_t lol_stage:3;
#endif
#ifdef NDPI_PROTOCOL_NIZHAN
  u_int32_t nizhan_stage:3;
#endif
#ifdef NDPI_PROTOCOL_WENDAO
  u_int32_t wendao_stage:3;
#endif
#ifdef NDPI_PROTOCOL_TIANXIA3
  u_int32_t tianxia3_stage:3;
#endif

#ifdef NDPI_PROTOCOL_GAME_ZHENTU
  u_int32_t zhentu_stage:4;
#endif

#ifdef NDPI_PROTOCOL_THUNDER
  u_int32_t thunder_stage:3;		// 0-7
  u_int32_t thunder_count:3;		// 0-7
#endif
#ifdef NDPI_PROTOCOL_DAZHIHUI365
  u_int32_t dazhihui_stage:3; //0-7
#endif
#ifdef NDPI_PROTOCOL_HUARONG
  u_int32_t huarong_stage:3; //0-7
#endif
#ifdef NDPI_PROTOCOL_QIANLONG
  u_int32_t qianlong_stage:3; //0-7
#endif
#ifdef NDPI_PROTOCOL_PINGANZHENGQUAN
  u_int32_t pinganzhengquan_stage:3; //0-7
#endif
#ifdef NDPI_PROTOCOL_ZHINANZHEN
  u_int32_t zhinanzhen_stage:3; //0-7
#endif
#ifdef NDPI_PROTOCOL_FTP_CONTROL
  u_int32_t ftp_control_stage:2;
#endif
#ifdef NDPI_PROTOCOL_GAME_QQSPEED
  u_int32_t qqspeed_stage:2;
#endif
#ifdef NDPI_PROTOCOL_GAME_DNF
  u_int32_t dnf_stage:2;
#endif
#ifdef NDPI_PROTOCOL_GAME_WORLD_OF_WARSHIP
  u_int32_t worldofwarship_stage:2;
  u_int32_t worldofwarship_count:2;
#endif
#ifdef NDPI_PROTOCOL_GAME_JX3
  u_int32_t jx3_stage:2;
#endif
#ifdef NDPI_PROTOCOL_GAME_EUDEMONS
	u_int32_t eudemons_stage:2;
#endif
#ifdef NDPI_PROTOCOL_GAME_QIANNYH
    u_int32_t qiannyh_stage:2;
#endif
#ifdef NDPI_PROTOCOL_GAME_CSGO
    u_int32_t csgo_stage:2;
#endif
#ifdef NDPI_PROTOCOL_MINECRAFT
    u_int32_t minecraft_compressed:1;
#endif
#ifdef NDPI_PROTOCOL_YY
    u_int32_t yy_stage:1;
#endif
#ifdef NDPI_PROTOCOL_KUGOUMUSIC
    u_int32_t kugou_music_type:2;   /* 0, uninit; 1, nornaml; 2, udp; 3, http+类似udp协议 */
    u_int32_t kugou_music_stage:2;
#endif

#ifdef NDPI_PROTOCOL_KUGOUMUSIC
    u_int32_t kugou_music_hash;      /* store hash */
    u_int8_t kugou_music_udp_seq;    /* guess it is a sequence. */
#endif
#ifdef NDPI_PROTOCOL_HUASHENGKE
    u_int8_t huashengke_stage;  /* for version 2 */
    u_int8_t huashengke3_stage; /* for version 3 */
#endif
#ifdef NDPI_PROTOCOL_WECHAT_TX
    u_int32_t wechat_tx_authkeyhash;
#endif
#ifdef NDPI_PROTOCOL_RTP
    u_int32_t rtp_ssrc;
    u_int16_t rtp_seq;
#endif

  /* internal structures to save functions calls */
  struct ndpi_packet_struct packet;
  struct ndpi_flow_struct *flow;
  struct ndpi_id_struct *src;
  struct ndpi_id_struct *dst;
} ndpi_flow_struct_t;

#endif							/* __NDPI_STRUCTS_INCLUDE_FILE__ */

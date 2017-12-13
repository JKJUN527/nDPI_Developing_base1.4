/*
 *	xt_ndpi - Netfilter module to match nDPI-detected sessions
 *
 *	(C) 2013 Luca Deri <deri@ntop.org>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/time.h>

#ifdef __i386__
#define LruKey u_int32_t
#error "not support __i386__"
#else
#define LruKey u_int64_t
#endif

//#define CACHE_SIZE  (32768)
#define CACHE_SIZE  (128)

#define MAX_MATCH_ABOVE_POOL 4
struct LruCacheEntryValue {
	u_int32_t	num_packets_processed;      /* this count includes SYN/ACK packets for TCP protocl */
	u_int8_t	protocol_detected, host_name_checked;
	/* nDPI */
	u_int16_t		ndpi_proto;
	struct ndpi_flow_struct *flow;
	struct ndpi_id_struct	*src, *dst;

	/* Linux */
	struct nf_conn	*ct;
	/* Cache */
	const struct sk_buff *last_processed_skb;
	int64_t last_stamp; 
	u_int32_t	src_ip, dst_ip;
	u_int16_t	sport, dport;
	int16_t 	above[MAX_MATCH_ABOVE_POOL+1];
	u_int8_t	proto;
};

struct LruCacheEntry {
	LruKey				key;
	struct LruCacheEntryValue	value;
};

struct LruCacheNode {
	struct LruCacheEntry node;
	struct {
		struct LruCacheNode *next;              /* Hash collision list */
	} hash;

	struct {
		struct LruCacheNode *prev, *next;       /* LRU */
	} lru_list;
};

struct LruCacheUnit {
	u_int32_t		max_lru_size, hash_size, current_size;
	struct LruCacheNode	**hash;
	struct LruCacheNode	*list_head, *list_tail;
};

/*
 * #define NUM_LRU_CACHE_UNITS        64
 * #define NUM_LRU_CACHE_UNITS        256 //PT
 */
//#define NUM_LRU_CACHE_UNITS        1024
#define NUM_LRU_CACHE_UNITS        (128)

struct LruCache {
	struct LruCacheUnit units[NUM_LRU_CACHE_UNITS];
};

/* ************************************ */

extern struct LruCache *lru_cache;

/* ************************************ */

void init_lru_cache( struct LruCache *cache, u_int32_t max_size );


void free_LruCacheEntryValue( struct LruCacheEntryValue *entry );


void free_lru_cache( struct LruCache *cache );


struct LruCacheNode* add_to_lru_cache( struct LruCache *cache, LruKey key );


struct LruCacheEntryValue* find_lru_cache( struct LruCache *cache, LruKey key );


void delete_node_from_lru_list( struct LruCacheUnit *cache_unit, struct LruCacheNode *node );


int init_lru_engine( void );


void term_lru_engine( void );



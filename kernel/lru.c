/*
 *	xt_ndpi - Netfilter module to match nDPI-detected sessions
 *
 *	(C) 2013 Luca Deri <deri@ntop.org>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/jiffies.h>

#include "ndpi.h"
#include "lru.h"

/* Least recently used cache */

/* ************************************ */

static u_int8_t traceLRU;
struct LruCache *lru_cache;

/* ************************************ */

void init_lru_cache_unit( struct LruCacheUnit *cache_unit, u_int32_t max_size )
{
	u_int size;

	if ( unlikely( traceLRU ) )
		pr_info( "[NDPI] %s()", __FUNCTION__ );

	cache_unit->max_lru_size = max_size, cache_unit->hash_size = 4 * max_size, cache_unit->current_size = 0;

	size = cache_unit->hash_size * sizeof(struct LruCacheNode*);
	if ( (cache_unit->hash = (struct LruCacheNode * *) kmalloc( size, GFP_ATOMIC ) ) == NULL )
	{
		pr_info( "[NDPI ERROR] Not enough memory?" );
		return;
	} else
		memset( cache_unit->hash, 0, size );

	cache_unit->list_head = cache_unit->list_tail = NULL;
}


/* ************************************ */

void init_lru_cache( struct LruCache *cache, u_int32_t max_size )
{
	int i, sz = max_size / NUM_LRU_CACHE_UNITS;

	for ( i = 0; i < NUM_LRU_CACHE_UNITS; i++ )
		init_lru_cache_unit( &cache->units[i], sz );
}


/* ************************************ */

void free_LruCacheEntryValue( struct LruCacheEntryValue *entry )
{
	/*PT test lock*/
	if ( entry->src )
	{
		kfree( entry->src ); entry->src = NULL;
	}
	if ( entry->dst )
	{
		kfree( entry->dst ); entry->dst = NULL;
	}
	if ( entry->flow )
	{
		kfree( entry->flow ); entry->flow = NULL;
	}
}


/* ************************************ */

void free_lru_cache_unit( struct LruCacheUnit *cache_unit )
{
	struct LruCacheNode *head = cache_unit->list_head;

	if ( unlikely( traceLRU ) )
		pr_info( "[NDPI] %s()", __FUNCTION__ );

	while ( head != NULL )
	{
		struct LruCacheNode *next = head->lru_list.next;

		free_LruCacheEntryValue( &head->node.value );

		kfree( head );
		head = next;
	}

	kfree( cache_unit->hash );
    cache_unit->hash = NULL;
}


/* ************************************ */

void free_lru_cache( struct LruCache *cache )
{
	int i;

	for ( i = 0; i < NUM_LRU_CACHE_UNITS; i++ )
		free_lru_cache_unit( &cache->units[i] );
}


/* ************************************ */

static int delete_oldest_lru_cache_unit( struct LruCacheUnit *cache_unit )
{
	struct LruCacheNode	*node = cache_unit->list_tail;
	u_int32_t		hash_id;
	struct LruCacheNode	*head, *prev = NULL;
	//static u_int32_t usenum;

	if ( unlikely( traceLRU ) )
		pr_info( "[NDPI] %s()", __FUNCTION__ );

	/* [1] Remove the last list element */
	if ( cache_unit->list_tail == NULL )
	{
		pr_crit( "[NDPI ERROR] Internal error (NULL tail)" );
		return -1;
	} else {
		cache_unit->list_tail = (cache_unit->list_tail)->lru_list.prev;

		if ( cache_unit->list_tail == NULL ) {
			pr_crit( "[NDPI ERROR] Internal error (NULL prev tail)" );
			return -1;
		}
        cache_unit->list_tail->lru_list.next = NULL;
    }

	hash_id = node->node.key % cache_unit->hash_size;
	head    = cache_unit->hash[hash_id];

	/* [2] Remove the node from the hash */
	while ( head != NULL ) {
		//if ( head->node.key == node->node.key )
		if (head == node) {
			/* node found */
			if ( prev == NULL )
				cache_unit->hash[hash_id] = node->hash.next;
			else {
				prev->hash.next = node->hash.next;
			}

			break;
		} else {
			prev = head;
			head = head->hash.next;
		}
	}

	/* [3] Free the memory */
	//usenum++;
	//pr_info( "delete_oldest_lru_cache_unit USE NUM IS:%u \n",usenum);
	
	free_LruCacheEntryValue( &node->node.value );
	kfree( node );
    node = NULL;
	cache_unit->current_size--;
	return 0;
}


/* ************************************ */

void delete_node_from_lru_list( struct LruCacheUnit *cache_unit, struct LruCacheNode *node )
{
	if ( node->lru_list.prev != NULL )
	{
		(node->lru_list.prev)->lru_list.next = node->lru_list.next;

		if ( node->lru_list.next != NULL )
			(node->lru_list.next)->lru_list.prev = node->lru_list.prev;
	} else {
		cache_unit->list_head = node->lru_list.next;
		if ( cache_unit->list_head )
			cache_unit->list_head->lru_list.prev = NULL;
	}

	if ( cache_unit->list_tail == node )
	{
		struct LruCacheNode *new_tail = (cache_unit->list_tail)->lru_list.prev;

		if ( new_tail == NULL )
			pr_info( "[NDPI ERROR] Internal error (NULL new_tail)" );
		else
            new_tail->lru_list.next = NULL;

        cache_unit->list_tail = new_tail;
	}
}


/* ************************************ */

static void add_node_to_lru_list( struct LruCacheUnit *cache_unit,
				  struct LruCacheNode *node )
{
	if ( cache_unit->list_head != NULL )
	{
		node->lru_list.next = cache_unit->list_head;
        node->lru_list.prev = NULL;
		(cache_unit->list_head)->lru_list.prev = node;
	} else {
		/*
		 * The list is empty so our node is going
		 * to be the oldest one in the LRU
		 */

		cache_unit->list_tail = node;
        node->lru_list.next	= NULL;
        node->lru_list.prev = NULL;
	}

	cache_unit->list_head = node; /* Add as head */

	if ( cache_unit->current_size > cache_unit->max_lru_size )
		delete_oldest_lru_cache_unit( cache_unit );
}


/* ************************************ */

static struct LruCacheNode* allocCacheNode( LruKey key )
{
	struct LruCacheNode *node = (struct LruCacheNode *) kmalloc( sizeof(struct LruCacheNode), GFP_ATOMIC );

	if (!node) {
		pr_info( "[NDPI ERROR] Not enough memory?" );
		return NULL;
    }

	if ( unlikely( traceLRU ) )
		pr_info( "[NDPI] %s(key=%lu)", __FUNCTION__, (long unsigned int) key );

    memset( node, 0, sizeof(struct LruCacheNode) );
    node->node.key = key;

	return(node);
}


/* ************************************ */

static struct LruCacheNode* add_to_lru_cache_unit( struct LruCacheUnit *cache_unit, LruKey key )
{
	u_int32_t		hash_id			= key % cache_unit->hash_size;
	struct LruCacheNode	*node			= NULL;
	u_int8_t		node_already_existing	= 0;

	if ( unlikely( traceLRU ) )
		pr_info( "[NDPI] %s(key=%lu)", __FUNCTION__, (unsigned long int) key );

	/* [1] Add to hash */
	if ( cache_unit->hash[hash_id] == NULL )
	{
		if ( (node = allocCacheNode( key ) ) == NULL )
		{
			goto ret_add_to_lru_cache;
		}

        node->hash.next = NULL;
		cache_unit->hash[hash_id] = node;
		cache_unit->current_size++;
		add_node_to_lru_list( cache_unit, node );
	} else {
		/* Check if the element exists */
		struct LruCacheNode *head = cache_unit->hash[hash_id];

		while ( head != NULL )
		{
			if ( head->node.key == key ) {
				/* key found */
				node = head;
				node_already_existing	= 1;
				break;
			}

            head = head->hash.next;
		}

		if ( !node_already_existing ) {
			if ( (node = allocCacheNode( key ) ) == NULL )
				goto ret_add_to_lru_cache;

			node->hash.next = cache_unit->hash[hash_id];
			cache_unit->hash[hash_id] = node;
			cache_unit->current_size++;
			add_node_to_lru_list( cache_unit, node );
		}
	}

ret_add_to_lru_cache:
	return node;
}


/* ************************************ */

/* Add if not existing or return existing otherwise */
struct LruCacheNode* add_to_lru_cache( struct LruCache *cache, LruKey key )
{
	return(add_to_lru_cache_unit( &cache->units[key % NUM_LRU_CACHE_UNITS], key ) );
}


/* ************************************ */

static struct LruCacheEntryValue* find_lru_cache_unit( struct LruCacheUnit *cache_unit, LruKey key )
{
	u_int32_t			hash_id		= key % cache_unit->hash_size;
	struct LruCacheNode		*head		= cache_unit->hash[hash_id];
	struct LruCacheEntryValue	* ret_val	= NULL;

	if ( unlikely( traceLRU ) )
		pr_info( "[NDPI] %s(%lu)", __FUNCTION__, (long unsigned int) key );

	while ( head != NULL )
	{
		if ( head->node.key == key )
		{
			ret_val = &head->node.value;
			break;
		} else {
			head = head->hash.next;
		}
	}

	return(ret_val);
}


/* ************************************ */

struct LruCacheEntryValue* find_lru_cache( struct LruCache *cache, LruKey key )
{
	return(find_lru_cache_unit( &cache->units[key % NUM_LRU_CACHE_UNITS], key ) );
}


/* ************************************ */

int init_lru_engine( void )
{
	traceLRU = 0;

	lru_cache = kmalloc( sizeof(struct LruCache), GFP_KERNEL );
	if ( lru_cache == NULL )
	{
		pr_info( "[NDPI] ERROR: Null cache" );
		return(-1);
	}

	init_lru_cache( lru_cache, CACHE_SIZE);
	return(0);
}


/* ************************************ */

void term_lru_engine( void )
{
	if ( lru_cache )
	{
		free_lru_cache( lru_cache );
		kfree( lru_cache );
        lru_cache = NULL;
	}
}



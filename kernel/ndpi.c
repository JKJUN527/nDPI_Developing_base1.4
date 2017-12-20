/*
 *	xt_ndpi - Netfilter module to match nDPI-detected sessions
 *
 *	(C) 2013 Luca Deri <deri@ntop.org>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include "ndpi.h"
#include "lru.h"

/* ************************************* */
struct ndpi_detection_module_struct *ndpi_struct;
u_int32_t ndpi_detection_tick_resolution;
u_int32_t ndpi_proto_size, ndpi_flow_struct_size;
/* define and init ndpi_lock */
DEFINE_SPINLOCK( ndpi_lock );
/* ************************************* */

static void debug_printf( u_int32_t protocol, void *id_struct,
			  ndpi_log_level_t log_level, const char *format, ... )
{
	/* do nothing */

	va_list args;
	va_start( args, format );
	switch ( log_level )
	{
	case NDPI_LOG_ERROR:
		vprintk( format, args );
		break;
	case NDPI_LOG_TRACE:
		vprintk( format, args );
		break;

	case NDPI_LOG_DEBUG:
		vprintk( format, args );
		break;
	}

	va_end( args );
}


static void *malloc_wrapper( unsigned long size )
{
	return(kmalloc( size, GFP_ATOMIC ) );
}


static void free_wrapper( void *freeable )
{
	kfree( freeable );
}


/* ********************************** */

int init_ndpi_engine( void )
{
	NDPI_PROTOCOL_BITMASK all;

	ndpi_detection_tick_resolution	= 1000;
	ndpi_struct			= ndpi_init_detection_module( ndpi_detection_tick_resolution,
								      malloc_wrapper, free_wrapper, debug_printf );
	if ( ndpi_struct == NULL )
	{
		pr_err( "[NDPI] global structure initialization failed.\n" );
		free_lru_cache( lru_cache );
		kfree( lru_cache );
		return(ENOMEM);
	}

	NDPI_BITMASK_SET_ALL( all );
	ndpi_set_protocol_detection_bitmask2( ndpi_struct, &all );
	ndpi_proto_size		= ndpi_detection_get_sizeof_ndpi_id_struct();
	ndpi_flow_struct_size	= ndpi_detection_get_sizeof_ndpi_flow_struct();

	pr_info( "[NDPI] nDPI initialized [ndpi_proto_size: %u][ndpi_flow_struct_size: %u]\n",
		 ndpi_proto_size, ndpi_flow_struct_size );

	return(0);
}


/* ********************************** */

void term_ndpi_engine( void )
{
	ndpi_exit_detection_module( ndpi_struct, free_wrapper );
}



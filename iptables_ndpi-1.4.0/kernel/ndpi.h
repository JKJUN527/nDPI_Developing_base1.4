/*
 *	xt_ndpi - Netfilter module to match nDPI-detected sessions
 *
 *	(C) 2013 Luca Deri <deri@ntop.org>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include "ndpi_main.h"

#ifdef __KERNEL__

/* Globals */
extern spinlock_t				ndpi_lock;      /*flow lock*/
extern spinlock_t				ipq_lock;       /*detect lock*/
extern u_int32_t				ndpi_proto_size, ndpi_flow_struct_size;
extern struct ndpi_detection_module_struct	*ndpi_struct;
extern u_int32_t				ndpi_detection_tick_resolution;

/* ********************************** */

int init_ndpi_engine( void );

void term_ndpi_engine( void );

#endif

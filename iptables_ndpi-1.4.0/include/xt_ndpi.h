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

struct xt_ndpi_protocols {
  NDPI_PROTOCOL_BITMASK protocols;
  int16_t match_above;
  int16_t pool;
  u_int16_t invflags;
};
struct xt_ndpi_tginfo {
	#ifdef ADVANCE_Q3_NDPI
       __u32 mark, mask;
       __u16 p_proto_id:1,m_proto_id:1,any_proto_id,t_accept:1,t_mark:1,t_clsf:1;
	#endif
};
#define NOT_YET_PROTOCOL   NDPI_LAST_IMPLEMENTED_PROTOCOL+1

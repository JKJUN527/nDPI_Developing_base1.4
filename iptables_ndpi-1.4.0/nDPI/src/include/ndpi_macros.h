/*
 * ndpi_macros.h
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


#ifndef __NDPI_MACROS_H__
#define __NDPI_MACROS_H__

#ifdef __cplusplus
extern "C" {
#endif


/* NDPI_MASK_SIZE */
typedef u_int64_t ndpi_ndpi_mask;

#define NDPI_NUM_BITS              256	// PT: the number of max protocol in ndpi
#define NDPI_BITS /* 64 */ (sizeof(ndpi_ndpi_mask) * 8 /* number of bits in a byte */)        /* bits per mask */
#define howmanybits(x, y)   (((x)+((y)-1))/(y))
#define NDPI_NUM_FDS_BITS     howmanybits(NDPI_NUM_BITS, NDPI_BITS)


typedef struct ndpi_protocol_bitmask_struct {
	ndpi_ndpi_mask bitmask[NDPI_NUM_FDS_BITS];
} ndpi_protocol_bitmask_struct_t;
#define NDPI_PROTOCOL_BITMASK struct ndpi_protocol_bitmask_struct
  
/*#define NDPI_SAVE_AS_BITMASK(bmask,value)           \
  {                   \
  (bmask).bitmask[0] = 0;               \
  (bmask).bitmask[1] = 0;               \
  (bmask).bitmask[2] = 0;               \
  (bmask).bitmask[(value) >> 6] = (((u_int64_t)1)<<((value) & 0x3F));     \
}*/
#define NDPI_SAVE_AS_BITMASK(bmask,value)  { NDPI_ZERO(&bmask) ; NDPI_ADD_PROTOCOL_TO_BITMASK(bmask, value); }



#define NDPI_SET(p, n)    ((p)->bitmask[(n)/NDPI_BITS] |= (1l << (((u_int64_t)n) % NDPI_BITS)))
#define NDPI_CLR(p, n)    ((p)->bitmask[(n)/NDPI_BITS] &= ~(1l << (((u_int64_t)n) % NDPI_BITS)))
#define NDPI_ISSET(p, n)  ((p)->bitmask[(n)/NDPI_BITS] & (1l << (((u_int64_t)n) % NDPI_BITS)))
#define NDPI_ZERO(p)      memset((char *)(p), 0, sizeof(*(p)))
#define NDPI_ONE(p)       memset((char *)(p), 0xFF, sizeof(*(p)))



//#define NDPI_BITMASK_COMPARE(a,b) (((a).bitmask[0]) & ((b).bitmask[0]) || ((a).bitmask[1]) & ((b).bitmask[1]) || ((a).bitmask[2]) & ((b).bitmask[2]))

//#ifndef __NDPI_BITMASK_COMPARE_PT
//#define __NDPI_BITMASK_COMPARE_PT
static char inline NDPI_BITMASK_COMPARE(NDPI_PROTOCOL_BITMASK left, NDPI_PROTOCOL_BITMASK right){
	u_int64_t i;
	for(i=0; i<NDPI_NUM_FDS_BITS;i++){
		if(((left).bitmask[i]) & ((right).bitmask[i]))
			return 1;
	}
	return 0;
}
//#endif


//#define NDPI_BITMASK_COMPARE(a,b) _NDPI_BITMASK_COMPARE(a,b)


//#define NDPI_BITMASK_MATCH(a,b)   (((a).bitmask[0]) == ((b).bitmask[0]) && ((a).bitmask[1]) == ((b).bitmask[1]) && ((a).bitmask[2]) == ((b).bitmask[2]))

// all protocols in b are also in a
//#define NDPI_BITMASK_CONTAINS_BITMASK(a,b)  ((((a).bitmask[0] & (b).bitmask[0]) == (b).bitmask[0]) && (((a).bitmask[1] & (b).bitmask[1]) == (b).bitmask[1]) && (((a).bitmask[2] & (b).bitmask[2]) == (b).bitmask[2]))

//#define NDPI_BITMASK_ADD(a,b)   {(a).bitmask[0] |= (b).bitmask[0]; (a).bitmask[1] |= (b).bitmask[1]; (a).bitmask[2] |= (b).bitmask[2];}
////#define NDPI_BITMASK_AND(a,b)   {(a).bitmask[0] &= (b).bitmask[0]; (a).bitmask[1] &= (b).bitmask[1]; (a).bitmask[2] &= (b).bitmask[2];}
//#define NDPI_BITMASK_DEL(a,b)   {(a).bitmask[0] = (a).bitmask[0] & (~((b).bitmask[0])); (a).bitmask[1] = (a).bitmask[1] & ( ~((b).bitmask[1])); (a).bitmask[0] = (a).bitmask[0] & (~((b).bitmask[0]));}
//#define NDPI_BITMASK_SET(a,b)   {(a).bitmask[0] = ((b).bitmask[0]); (a).bitmask[1] = (b).bitmask[1]; (a).bitmask[2] = (b).bitmask[2];}
//#define NDPI_BITMASK_RESET(a)   {((a).bitmask[0]) = 0; ((a).bitmask[1]) = 0; ((a).bitmask[2]) = 0;}
//#define NDPI_BITMASK_SET_ALL(a)   {((a).bitmask[0]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[1]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[2]) = 0xFFFFFFFFFFFFFFFFULL; }
////#define NDPI_BITMASK_IS_EMPTY(a) { if(((a).bitmask[0] == 0) && ((a).bitmask[1] == 0) && ((a).bitmask[2] == 0)) return(1); else return(0); }
 //#define NDPI_BITMASK_ADD(a,b)     NDPI_SET(&a,b)
 //#define NDPI_BITMASK_DEL(a,b)     NDPI_CLR(&a,b)
#define NDPI_BITMASK_RESET(a)     NDPI_ZERO(&a)
#define NDPI_BITMASK_SET_ALL(a)   NDPI_ONE(&a)
#define NDPI_BITMASK_SET(a, b)    { memcpy(&a, &b, sizeof(NDPI_PROTOCOL_BITMASK)); }

/* this is a very very tricky macro *g*,
  * the compiler will remove all shifts here if the protocol is static...
 */
/*#define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value)	\
  { if(((value) >> 6) < 3) (bmask).bitmask[(value) >> 6] |= (((u_int64_t)1)<<((value) & 0x3F));} \

#define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value)               \
  { if(((value) >> 6) < 3) (bmask).bitmask[(value) >> 6] = (bmask).bitmask[(value) >> 6] & (~(((u_int64_t)1)<<((value) & 0x3F)));}  \

#define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value)         \
  ((((value) >> 6) < 3) &&(bmask).bitmask[(value) >> 6] & (((u_int64_t)1)<<((value) & 0x3F))) \
*/
/* this is a very very tricky macro *g*,
 * the compiler will remove all shifts here if the protocol is static...
 */
#define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value)     NDPI_SET(&bmask,value)
#define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value)   NDPI_CLR(&bmask,value)
#define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value) NDPI_ISSET(&bmask,value)




#define NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_STRING  "%llu , %llu , %llu"
#define NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(bm) (bm).bitmask[0] , (bm).bitmask[1] , (bm).bitmask[2]
////#define NDPI_BITMASK_IS_ZERO(a) ( (a).bitmask[0] == 0 && (a).bitmask[1] == 0 && (a).bitmask[2] == 0)
////#define NDPI_BITMASK_CONTAINS_NEGATED_BITMASK(a,b) ((((a).bitmask[0] & ~(b).bitmask[0]) == ~(b).bitmask[0]) && (((a).bitmask[1] & ~(b).bitmask[1]) == ~(b).bitmask[1]) && (((a).bitmask[2] & ~(b).bitmask[2]) == ~(b).bitmask[2]))

#define ndpi_min(a,b)   ((a < b) ? a : b)
#define ndpi_max(a,b)   ((a > b) ? a : b)

#define NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct,flow,packet)		\
                        if (packet->packet_lines_parsed_complete != 1) {        \
			  ndpi_parse_packet_line_info(ndpi_struct,flow);	\
                        }                                                       \

#ifdef __cplusplus
}
#endif
#endif

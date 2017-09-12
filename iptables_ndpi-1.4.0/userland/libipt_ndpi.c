/* 
 * libipt_ndpi.c
 * Copyright (C) 2013 Luca Deri <deri@ntop.org>
 * 
 * This is a user-space library used by the netfilter kernel component
 * for setting the configuration of the kernel module
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
  Writing Netfilter modules

  http://inai.de/documents/Netfilter_Modules.pdf
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <xtables.h>
#include <stdlib.h>
#include <linux/version.h>

#include "xt_ndpi.h"

#define O_PROTO 0
#define MAX_PROTOS_NUM 256

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

/* ******************************************* */

#define ND_FLAG_PROTO 0x01
#define ND_FLAG_ABOVE 0x02
#define ND_FLAG_ABOVE_POOL 0x04
#define ND_FLAG_INV_PROTO 0x08


static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static int num_supported_protocols = 0;
static struct option ndpi_cli_opts[MAX_PROTOS_NUM /* Max number of protocols */];

/* ******************************************* */

static void debug_printf(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...) { }
static void *malloc_wrapper(unsigned long size) { return malloc(size); }
static void free_wrapper(void *freeable)        { free(freeable);      }

/* ******************************************* */

static int _isalpha(char c){
	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <='Z'));
}


static void setup_nDPI(void) {
  NDPI_PROTOCOL_BITMASK all;

  if(ndpi_struct != NULL) return;

  // init global detection structure
  ndpi_struct = ndpi_init_detection_module(1000 /* detection_tick_resolution */, malloc_wrapper, free_wrapper, debug_printf);
  if (ndpi_struct == NULL) {
    printf("ERROR: global structure initialization failed\n");
    exit(-1);
  }
  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  num_supported_protocols = ndpi_get_num_supported_protocols(ndpi_struct)+1 /* NOT_YET protocol */;
}

/* ******************************************* */

/* Dump configuration ane restore it later on */
static void  ndpi_save(const void *entry, const struct xt_entry_match *match) {
  const struct xt_ndpi_protocols *info = (const void *)match->data;
  int i;
  char flag;
  int show_flag ;
  flag = 0;
  if (info->invflags & ND_FLAG_INV_PROTO)
	printf("! ");
  for (i = 0; i < num_supported_protocols; i++){
    show_flag =(NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->protocols, i) != 0 ) ^ !!(info->invflags & ND_FLAG_INV_PROTO);
    if (show_flag){
		char *name = ndpi_get_proto_by_id(ndpi_struct, i);
		if (!name)
			continue;	
		if(flag == 1){
			printf(",%s", 
					(i == NOT_YET_PROTOCOL) ? "NOT_YET" : name);
		}else{
			printf("--protos %s", 
					(i == NOT_YET_PROTOCOL) ? "NOT_YET" :  name);
			flag = 1;
		}
		// printf("(%d,%d)",(NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->protocols, i) != 0 ), (info->invflags & ND_FLAG_INV_PROTO));
     
    }
  }
  printf(" ");
  if (info->match_above > 0){
	printf("--match-above %d ", info->match_above);
	if (!!(info->invflags & ND_FLAG_ABOVE_POOL))
		printf(" --pool %d ", info->pool);
  }
}

/* ******************************************* */

/* Print configuration on screen */
static void ndpi_print(const void *entry, const struct xt_entry_match *match, int numeric) {
  const struct xt_ndpi_protocols *info = (const void *)match->data;
  int i, num=0;
  int show_flag;
  if (!!(info->invflags & ND_FLAG_INV_PROTO))
	printf("! ");
  for (i = 0; i < num_supported_protocols; i++){
    show_flag =(NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->protocols, i) != 0 ) ^ !!(info->invflags & ND_FLAG_INV_PROTO);
    if (show_flag){
      
      printf("%s%s", (num == 0) ? "" : ",", 
	     (i == NOT_YET_PROTOCOL) ? "NOT_YET" : ndpi_get_proto_by_id(ndpi_struct, i));
      num++;
    }
  }

  printf(" ");
  if (info->match_above > 0){
	printf("--match-above %d ", info->match_above);
	printf("--pool %d ", info->pool);
  }

}


static int
parse_proto(const char *name, size_t len, NDPI_PROTOCOL_BITMASK *mask, bool reverse)
{
	int i;
	/*if (reverse)
		printf("\treverse:\n");*/
	for (i = 0; i < num_supported_protocols; i++){
		// printf("\tfind %d for_%s_",i, name);
		if( ndpi_cli_opts[i].name == NULL || strlen(ndpi_cli_opts[i].name) != len)
			continue;
		if (strncasecmp(name, ndpi_cli_opts[i].name, len) == 0) {
			/* build up bitmask for kernel module */
			if(reverse)
				NDPI_DEL_PROTOCOL_FROM_BITMASK(*mask, i);
			else
				NDPI_ADD_PROTOCOL_TO_BITMASK(*mask, i);
			// printf("\t setting %s\n", ndpi_cli_opts[i].name);
			return 1;
		}
	}
	return 0;
}


static void parse_protos(const char *arg, NDPI_PROTOCOL_BITMASK *mask, bool reverse)
{
	const char *comma;
	if(!arg || !_isalpha(arg[0]))
		return;

	//printf("\tadding ndpi proto..(total:%d)\n",num_supported_protocols);
	//printf("\t\targ:%s strlen(arg):%d\n",arg,strlen(arg));
	while ((comma = strchr(arg, ',')) != NULL) {
		//printf("\twhile handling %d, comma:%s...",cnt++, comma);
		
		if ( !parse_proto(arg, comma-arg, mask, reverse))
			xtables_error(PARAMETER_PROBLEM,
			           "ndpi: bad proto `%s'", arg);
		arg = comma + 1;
	}
	//printf("\tout handling %d ...",cnt++);
	
	if (strlen(arg) == 0 ||!parse_proto(arg, strlen(arg), mask, reverse))
		xtables_error(PARAMETER_PROBLEM, "ndpi: bad proto \"%s\"", arg);
	
}


/* Parse configuration passed from CLI to this library */
static int ndpi_parse(int c, char **argv, int invert, unsigned int *flags,
		      const void *entry, struct xt_entry_match **match) {
  struct xt_ndpi_protocols *info = (void *)(*match)->data;
  int16_t i16tmp;
  switch(c){
	  case 'P': /*--protos xxx,xxx*/
		if (*flags & ND_FLAG_PROTO)
			xtables_error(PARAMETER_PROBLEM,
				"--protos may be given only once");
		xtables_check_inverse(optarg, &invert, NULL, 0, argv);
		if ( invert){
			*flags |= ND_FLAG_INV_PROTO;
			info->invflags |= ND_FLAG_INV_PROTO;
		}
		*flags |= ND_FLAG_PROTO;
		//printf("ndpi_parseing args:%s",optarg);
		if (info->invflags & ND_FLAG_INV_PROTO)
			NDPI_BITMASK_SET_ALL(info->protocols);
		parse_protos(optarg, &info->protocols, info->invflags & ND_FLAG_INV_PROTO);
		break;
	  case 'M': /*--match-above*/
		if (*flags & ND_FLAG_ABOVE)
			xtables_error(PARAMETER_PROBLEM,
				"--match-above may be given only once");
		if (xtables_check_inverse(optarg, &invert, NULL, 0, argv))
			xtables_error(PARAMETER_PROBLEM,
				"Unexpected `!' after --match-above");

		i16tmp = atoi(optarg);
		if (i16tmp <= 0 || i16tmp >= 32767){
			xtables_error(PARAMETER_PROBLEM,
				"Unexpected value for --match-above <1~32766>");
		}
		*flags |= ND_FLAG_ABOVE;
		info->match_above = i16tmp;
		break;
	
	  case 'I': /*--pool*/
		if (*flags & ND_FLAG_ABOVE_POOL)
			xtables_error(PARAMETER_PROBLEM,
				"--pool may be given only once");
		if (xtables_check_inverse(optarg, &invert, NULL, 0, argv))
			xtables_error(PARAMETER_PROBLEM,
				"Unexpected `!' after --pool");

		i16tmp = atoi(optarg);
		/*This macro defined from lru.h*/
		#define MAX_MATCH_ABOVE_POOL 4
		if (i16tmp <= 0 || i16tmp > MAX_MATCH_ABOVE_POOL){
			xtables_error(PARAMETER_PROBLEM,
				"Unexpected value for --match-above <0~%d>",MAX_MATCH_ABOVE_POOL);
		}
		info->invflags |= ND_FLAG_ABOVE_POOL;
		*flags |= ND_FLAG_ABOVE_POOL;
		info->pool = i16tmp;
		break;	
	  default:
		return 0;
  	}
  return 1; /* ate a option */
}

/* ******************************************* */

static void ndpi_check(unsigned int flags) {
  if((flags & ND_FLAG_ABOVE) && !(flags & ND_FLAG_PROTO))
    xtables_error(PARAMETER_PROBLEM, "libipt_ndpi: You must use --match-above with --protos ");
  if((flags & ND_FLAG_ABOVE_POOL) && !(flags & ND_FLAG_ABOVE))
    xtables_error(PARAMETER_PROBLEM, "libipt_ndpi: You must use --pool with --match-above ");
  

  if(!(flags & ND_FLAG_PROTO)) {
    xtables_error(PARAMETER_PROBLEM, "libipt_ndpi: You need to specify at least one protocol");
  }
}

/* ******************************************* */

/* Print help */
static void ndpi_help(void) {
  int i;

  printf("[PT] nDPI supported match options:\n");

  for (i = 0; i < num_supported_protocols; i++){
    char *name = ndpi_get_proto_by_id(ndpi_struct, i);

    if(name == NULL) continue;

    if(i == NOT_YET_PROTOCOL)
      printf(" [!] --protos %s Match whenever the detection process is not yet completed\n", "NOT_YET");
    else
      printf(" [!] --protos %s Match %s protocol packets\n", name, name);
  }
  printf(" --match-above <num> : the count of a protocol detected times ( need --protos )\n");
  printf(" --pool <num> : the pool id default 0 ( need --match-above)\n");
}

/* ******************************************* */

static void ndpi_init (struct xt_entry_match *match) {
  struct xt_ndpi_protocols *info = (void *)match->data;
  /*set default above value*/
  info->match_above = -1;
  info->pool = 0;
  setup_nDPI();
}

/* ******************************************* */




static const struct option ndpi_opts[] = {
	{"protos", 1, NULL, 'P'},
	{"match-above", 1, NULL, 'M'},
	{"pool", 1, NULL, 'I'},
	{.name=NULL}
};

static struct xtables_match
ndpi_reg = {
  .version = XTABLES_VERSION,
  .name = "ndpi",
  .revision = 0,
  .family = NFPROTO_IPV4,
  .size = XT_ALIGN(sizeof(struct xt_ndpi_protocols)),
  .userspacesize = XT_ALIGN(sizeof(struct xt_ndpi_protocols)),
  .help = ndpi_help,
  .init = ndpi_init,
  .parse = ndpi_parse,
  .final_check = ndpi_check,
  .print = ndpi_print,
  .save = ndpi_save,
  .extra_opts = ndpi_opts,
};

/* tg */

static void NDPI_help(void)
{
        printf("NDPI: Just use NDPI to check all packets(for update appid)\n");
}

/*
static void NDPI_print_v0(const void *ip,
                          const struct xt_entry_target *target, int numeric)
{
    const struct xt_ndpi_tginfo *info = (const struct xt_ndpi_tginfo *)target->data;
	char buf[128];
	int l;
	l += snprintf(&buf[l],sizeof(buf)-l-1,"NDPI");
	printf(buf);
}
*/
static void NDPI_save_v0(const void *ip, const struct xt_entry_target *target)
{
	/*
    const struct xt_ndpi_tginfo *info = (const struct xt_ndpi_tginfo *)target->data;
	char buf[128];
	int l = 0;
	printf(buf);
	*/
}

static int NDPI_parse(int c, char **argv, int invert, unsigned int *flags,
              const void *entry, struct xt_entry_target **target)
{
    	// const struct xt_ndpi_tginfo *info = (const struct xt_ndpi_tginfo *)(*target)->data;
	return 0;
}


static struct xtables_target ndpi_tg_reg[] = {
        {
                .family        = NFPROTO_UNSPEC,
                .name          = "NDPI",
                .version       = XTABLES_VERSION,
                .revision      = 0,
                .size          = XT_ALIGN(0),
                .userspacesize = XT_ALIGN(0),
                .help          = NDPI_help,
				.parse		   = NDPI_parse,
				.save 		   = NDPI_save_v0
        },
};


/*tg end*/

/* ******************************************* */

void _init(void) {  
  int i = 0;

  setup_nDPI();

  for(i=0; i < num_supported_protocols; i++){
    if(i == NOT_YET_PROTOCOL)
      ndpi_cli_opts[i].name = "NOT_YET";
    else
      ndpi_cli_opts[i].name = ndpi_get_proto_by_id(ndpi_struct, i);
    ndpi_cli_opts[i].has_arg = false;
    ndpi_cli_opts[i].val = i;
  }

  ndpi_cli_opts[i].name = NULL;
  ndpi_cli_opts[i].flag = NULL;
  ndpi_cli_opts[i].has_arg = 0;
  ndpi_cli_opts[i].val = 0;
  
  xtables_register_match(&ndpi_reg);
  xtables_register_targets(ndpi_tg_reg,ARRAY_SIZE(ndpi_tg_reg));
}

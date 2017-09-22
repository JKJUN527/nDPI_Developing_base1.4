#ifndef _FLOWMETERUTIL_H_
#define _FLOWMETERUTIL_H_

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif


#include "ndpi_main.h"
#include <math.h>
#include <json/json.h>
#include <iLOG3/LOG.h>
#include <signal.h>
#include <pthread.h> 

/*60times*5s = 5min*/

extern u_int32_t  COUNT_TIMES ;
#define HOT_DELTA_SEC (COUNT_TIMES*5)
#define HOT_DELTA_LONG_PARA 2
/*This is to set ip load counter, like user set 1.1.1.1/1, will cause ip load too slow, 65 is slow about 8s*/
#define IP_LOAD_MAX_COUNT (1024*65)
#define MAX_CONF_LINES  20
#define MAX_KEY_LEN 48
#define MAX_VALUE_LEN 512
#define HASHTABLE_SIZE 5000
#define HASHTABLE_SIZE_ACTUALLY (HASHTABLE_SIZE + 1)
#define CONFIG0 0X0
#define CONFIG1 0X1
#define CONFIG2 0X2
#define CONFIG3 0X3
#define CONFIG4 0X4
#define CONFIG5 0X5

#define IP_FILE     		CONFIG0
#define IP_FILE_DEFAULT     	"/var/efw/flowmeter/all_ip.txt"
#define DATA_PATH     		CONFIG1
#define DATA_PATH_DEFAULT     		"/var/log/flowmeter/data_log"
#define DATA_PATH_RT     		CONFIG2
#define DATA_PATH_RT_DEFAULT     	"/var/log/flowmeter/data_log_rt"
#define LOG_SIZE_FM     		CONFIG3
#define LOG_SIZE_FM_DEFAULT     	"5248800"
#define MAX_USER_COUNT			CONFIG4
#define MAX_USER_COUNT_DEFAULT		"1024"

#define ADD_CONF(x,y) {x,NULL,y}
#define ADD_CONF_END() {NULL,NULL}

#define ISHTTP(X) (X == NDPI_PROTOCOL_HTTP)
// #define BUG(format, args...) printf("BUG:"#format"\n" , args)
#define BUG(format, args...)  ;
/*for log*/
#define LOG_FM(format, args...) InfoLog(g, __FILE__, __LINE__, format, args )
#define LOG_FM_RT(format, args...) InfoLog(g_rt, __FILE__, __LINE__, format, args )
#define LOG_STYLES_FM LOG_STYLE_FORMAT



typedef struct BinaryTree{
    int number;
    struct BinaryTree* left;
    struct BinaryTree* right;
}BinaryTree_t;


typedef struct ip_info{
	time_t tick;
	u_int32_t localIP;      //32bit ip
	u_int64_t fiveSecBytes;   //for output per 5s when needed
    u_int64_t tenMinBytes;    //for output per 10min
	u_int32_t fiveSecCount;
    u_int64_t tenMinCount;    //for output per 10min
	//pthread_mutex_t mutex;  //mutex need to init
}ip_info_t;

typedef struct ip_info_lit{
	time_t tick;
	u_int32_t localIP;      //32bit ip
	u_int64_t fiveSecBytes;   //for output per 5s when needed
    u_int64_t tenMinBytes;    //for output per 10min
	//pthread_mutex_t mutex;  //mutex need to init
}ip_info_lit_t;

/* tick set on first element*/
typedef struct app_info{
	time_t tick;
	pthread_mutex_t mutex;
    NDPI_PROTOCOL_BITMASK app_bitmask;
    struct ip_info_lit ip_infos[NDPI_MAX_SUPPORTED_PROTOCOLS];
	
}app_info_t;


/* tick set on first element*/
typedef struct HashEle{
	time_t tick;
	pthread_mutex_t mutex;
	int num;  //记录当前位置
	int url_id;  //记录url的hash值
	char *url;  //记录url
	struct HashEle *next;
	struct HashEle *next100;
	struct HashEle *sub_ele;
	// struct ip_info ip_infos[MAX_USER_COUNT];
	struct ip_info *ip_infos;
}HashEle_t;

/*1,暴力,描述,system,路径*/
typedef struct url_conf_row        // 记录url的类型，名称，介绍之类的
{
	int  id;
	char isSystem;
	char *dir;
	//pedef struct config_row *next;
	//typedef struct config_row *next100;           如果需要时，可以用
}url_conf_row_t;

   
typedef struct conf_row{
	char *key, *value;//初始化为空 
	char index;    
}conf_row_t;

typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol;
  struct ndpi_flow_struct *ndpi_flow;
  u_int32_t url_hash_idx; 
  u_int16_t packets, bytes;
  // result only, not used for flow identification
  u_int32_t detected_protocol;
  void *src_id, *dst_id;
} ndpi_flow_t;

extern char *config_file_path;
extern conf_row_t GLOBAL_CONF[MAX_CONF_LINES];
extern struct in_addr *all_ip;
extern u_int32_t all_ip_cnt;
extern HashEle_t *hashtable; //url hash hashtable
extern app_info_t *app_struct;
extern LOG *g;
extern LOG *g_rt;
extern u_int32_t max_user_count;
extern u_int32_t want_5s_flag;

void initLogHandler(void);
void destoryLogHandler(void);
int8_t initFlowmeterStruct(HashEle_t **out_hashtable, app_info_t **_app_struct);
u_int8_t initAppStruct(app_info_t **_app_struct,int size);
void dump_config(conf_row_t *global_conf);
void set_config_default(conf_row_t *global_conf);
void read_config(char *filename, conf_row_t *global_conf);
conf_row_t *get_conf_by_key(char *key, conf_row_t *global_conf);

u_int8_t isValidIP();
u_int8_t initUrlHashtable(HashEle_t *head, u_int32_t hash_size);
void quick_sort(struct in_addr arr[], int start, int end);
struct in_addr *load_all_ip_file(char *path, u_int32_t *total);
void dumpIP(u_int32_t ip);
void dumpIPS(struct in_addr *ip, u_int32_t total);
void dumpHashEle(HashEle_t *hash_ele, u_int32_t num, u_int32_t sub_num,  u_int32_t flag,  u_int32_t flag2);
void dumpIPInfoLit(ip_info_lit_t * info);
int btree2InAddr(struct BinaryTree *node, struct in_addr *arr, int index);
inline u_int8_t isHotInfo(time_t* tick);
inline u_int8_t isHotInfo2(time_t* tick, u_int32_t i);
void dumpAppStruct(app_info_t *app_struct);
int daemon_fm();
#endif 

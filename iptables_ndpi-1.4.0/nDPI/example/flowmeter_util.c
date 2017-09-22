/*
this is for flowmeter functions
*/

#include "flowmeter_util.h"

/*global vars*/
//conf_row_t *GLOBAL_CONF;

conf_row_t GLOBAL_CONF[] = {
	ADD_CONF("IP_FILE", IP_FILE),
	ADD_CONF("DATA_PATH", DATA_PATH),
	ADD_CONF("DATA_PATH_RT", DATA_PATH_RT),
	ADD_CONF("LOG_SIZE_FM", LOG_SIZE_FM),
	ADD_CONF("MAX_USER_COUNT", MAX_USER_COUNT),
	ADD_CONF_END()
};

struct in_addr *all_ip;
u_int32_t all_ip_cnt;
HashEle_t *hashtable = NULL;
app_info_t *app_struct = NULL;
char data_path[MAX_VALUE_LEN] =  "/var/log/flowmeter/data_log";
LOG * g = NULL;
LOG * g_rt = NULL;
char *config_file_path = NULL;
u_int32_t COUNT_TIMES = 12; /*12times*5s=1min*/
u_int32_t max_user_count = 1024;
u_int32_t want_5s_flag = 5;
/*global vars end*/

u_int64_t timeFix = 0 ;


// static char clearCmdBuf[1024] = {0};

void resetOneIpStruct(ip_info_t *ip)
{
	memset(ip, 0, sizeof(ip_info_t));
	//TODO may need to reset mutex
}

void resetIpStruct(ip_info_t *ip){};

void initIpStruct(ip_info_t **ip)
{
	*ip = (ip_info_t *)malloc(sizeof(ip_info_t));
	memset(*ip, 0, sizeof(ip_info_t));
	if (*ip)
		resetIpStruct(*ip);
}

/*
 * dump a ip 
 * @ip: host seq ip
 */
void dumpIP(u_int32_t i_ip)
{
	char show_buf[512];
	struct in_addr ip_buf;
	ip_buf.s_addr = htonl(i_ip);
	inet_ntop(AF_INET, (void *)&ip_buf, show_buf, 16);
	printf(" %s", show_buf);
}
void dumpIP2Str(u_int32_t i_ip, char* show_buf)
{
	struct in_addr ip_buf;
	ip_buf.s_addr = htonl(i_ip);
	inet_ntop(AF_INET, (void *)&ip_buf, show_buf, 16);
}
void dumpIPS(struct in_addr *ips, u_int32_t cnt)
{
	u_int32_t i = 0;
	printf("Dump ips:\n");
	for (; i < cnt; i++)
	{
		printf("\t %u) %x=>",i , ntohl(ips[i].s_addr));
		dumpIP(ntohl(ips[i].s_addr));
		printf("\n");
	}
}

/* convert bttree to inaddr
@node: start node
@arr: inaddr arr
@index: start index
@return: next index(all count)
 * */

int btree2InAddr(struct BinaryTree *node, struct in_addr *arr, int index) //bt为根节点，把树中的ip读入a中，从小到大，i为0；  //遍历二叉树，得到ip   返回的值为ip个数
{
	if (node == NULL)
 	{	
		return 0;
	}

	if (index >= max_user_count - 1)
		return index;

	if (node->left != NULL)
	{
		index = btree2InAddr(node->left, arr, index);
	}

	arr[index++].s_addr = htonl(node->number);

	if (node->right != 0)
	{
    		index = btree2InAddr(node->right, arr, index);
  	}
	return index;
}

#define IP_IS_NET(x) ((x << 24) == 0)

/*insert a ip into a btree
@root : btree root 
@n: ip host seq
*/
int insertIP2BTree(struct BinaryTree* root, u_int32_t ip)       
{
	struct BinaryTree *temp =0;
	struct BinaryTree *t; 
	static int counter = 0;
	counter++;
        temp = root;
	/*valid ip is just ip, not net*/
	if (IP_IS_NET(ip) ){
		#ifdef DUMP_IPS
		printf("should skip ip net!\n");
		#endif
		return 0 ;
	}
	if (counter > IP_LOAD_MAX_COUNT){
		printf("!!!!!!!!!!Too large ip counter, skip remain all!!!!!!!!!!\n");
		return -1;
	}
        t = (struct BinaryTree*)malloc(sizeof(struct BinaryTree));
        t->number = ip;
        t->left =0;
        t->right =0;
	#ifdef DUMP_IPS
	printf("\t node %u=>",ntohl(temp->number));
	dumpIP(ntohl(temp->number));
	printf("\n");

	printf("\t insert %u=>",ip);
	dumpIP(ip);
	printf("\n");
	#endif 
	if(temp -> number == 0)
	{
		temp -> number = ip;
		return 0;
	}
        while(temp != NULL)
        {
		if(t->number == temp -> number)
		{
			#ifdef DEBUG_IPS
			/*same node*/
			printf("same node, will free\n");
			#endif
			free(t);
			t = NULL;
			return 0;
		}
       		else if(t->number > temp->number)
            	{
                	if(temp->right ==0)
	                {
        	 		temp->right = t;
		               	break;
                	}
        	        else
	                {
                    		temp = temp->right;
                	}
            	}
            	else
            	{
                	if(temp->left ==0)
                	{
                 		temp->left = t;
		                break;
                	}
               		else 
	                {
        	            temp = temp->left;
                	}
 	         }            
        }
	return 0;
}


void convertSegment(const char *left_ip, const char *right_ip, u_int64_t *low, u_int64_t *high, int af)
{
	struct in_addr addr_low, addr_high;
	if (inet_pton(af, left_ip, (void *)&addr_low) < 0)
	{
		printf("WARNING !! WRONG LOW IP %s\n", left_ip);
		*low = 0;
		*high = 0;
		return;
	}
	if (inet_pton(af, right_ip, (void *)&addr_high) < 0)
	{
		printf("WARNING !! WRONG HIGH IP %s\n", right_ip);
		*low = 0;
		*high = 0;
		return;
	}
	*low = ntohl(addr_low.s_addr);
	*high = ntohl(addr_high.s_addr);
	// printf("low(at):0x%lx\thigh(at+1):0x%lx\n", *low, *high);
}

//PT:convert 192.168.1.1/24 or 192.168.11.1 -> int64
void convertCidr(const char *ip, int cidr, u_int64_t *low, u_int64_t *high, int af)
{
	int max_cidr = 32;
	struct in_addr addr_low;
	if (af == AF_INET)
		max_cidr = 32;
	else if (af == AF_INET6)
		max_cidr = 128;

	*low = 0;
	*high = 0;

	if (inet_pton(af, ip, (void *)&addr_low) < 0)
	{
		printf("WARNING !! WRONG IP %s\n", ip);
		return;
	}
	if (cidr != 0 && cidr > 0 && cidr <= max_cidr)
	{
		//printf("cidr:%d\th:0x%x\tn:0x%x\n",cidr, ntohl(addr_low.s_addr),addr_low.s_addr);
		*low = ((ntohl(addr_low.s_addr) >> (max_cidr - cidr)) << (max_cidr - cidr));
		*high = (ntohl(addr_low.s_addr) | ((int)(pow(2, (max_cidr - cidr)) - 1))); //PS if raise error of pow ,use gcc -lm
																				   //printf("(int)(pow(2,(max_cidr - cidr) )- 1):0x%x\n",(int)(pow(2,(max_cidr - cidr) )- 1));
	}
	else
	{
		*low = ntohl(addr_low.s_addr);
		*high = 0;
	}
	//printf("inet_pton: 0x%x\n", s.s_addr);
}

//PT:handle ip line
void handle_ip_line(const char *line, u_int64_t *at)
{
	char linebuf[512];
	char *left, *right;
	char *buf;
	short cidr;
	memcpy(linebuf, line, sizeof(linebuf));
	buf = strrchr(linebuf, '-');
	if (buf == NULL)
	{
		//get cidr
		buf = strrchr(linebuf, '/');
		if (buf != NULL)
		{
			cidr = atoi(buf + 1);
			*buf = '\0';
		}else{
			cidr = 32;
		}
		//just ip or ip/cidr
		left = linebuf;
		convertCidr(left, cidr, at, at + 1, AF_INET);
		return;
	}
	else
	{
		//ip-ip
		right = buf + 1;
		*buf = '\0';
		left = linebuf;
		convertSegment(left, right, at, at + 1, AF_INET);
		return;
	}
}

/*PT:
handle the all user file ,return array is all_ip[MAX_USER_COUNT] 
total is ptr to set all the ip cnt
*/
struct in_addr *load_all_ip_file(char *path, u_int32_t *total)
{
	static u_int32_t cnt = 0;
	FILE *fd;
	int i;
	u_int64_t i_ip;
	struct BinaryTree btree;
	//struct in_addr all_ip[MAX_USER_COUNT]={0};
	struct in_addr *all_ip = ndpi_malloc(sizeof(struct in_addr) * max_user_count);
	u_int64_t at[2] = {0};
	memset(all_ip, 0, sizeof(struct in_addr) * max_user_count);
	memset(&btree, 0, sizeof(struct BinaryTree));
	(*total) = 0;
	// printf("*total:%d\n", *total);
	fd = fopen(path, "r");
	if (fd == NULL)
	{
		printf("Unable to open ip file %s \n", path);
		return NULL;
	}
	// printf("cnt:%u\n", cnt);
	while (fd)
	{
		char buffer[512], *line;

		if (!(line = fgets(buffer, sizeof(buffer), fd)))
			break;

		if (((i = strlen(line)) <= 1) || (line[0] == '#'))
			continue;
		else
			line[i - 1] = '\0';

		handle_ip_line(line, at);
		//printf("after handle one line at:0x%x at+1:0x%x\n",at[0], at[1]);
		if (at[0] != 0)
		{
			// printf("#0\n");
			//valid ip
			if (at[1] != 0)
			{
				//ip-ip or ip/cidr
				//printf("0x%x~0x%x ,adding..\n",at[0], at[1]);

				i_ip = at[0];
				/*
				if ((i_ip <= at[1]) && (cnt < max_user_count))
					printf("it should go in for!\n");
				else
					printf("wont go in for-> i_ip <= at[1] && cnt < max_user_count <=>0x%lx <= 0x%lx && %u < %u \n", i_ip, at[1], cnt, max_user_count);
				printf("i_ip-at[1]<%lu\tcnt-max_user_count:%d\n", i_ip - at[1], cnt - max_user_count);
 * 				if ((i_ip <= at[1]))
					printf("(i_ip <= at[1]) ok\n");
				if ((cnt < max_user_count))
					printf("(cnt < max_user_count ok\n");
				printf("#1\n");
				*/

				// for (i_ip = at[0]; (i_ip <= at[1]) && (cnt < max_user_count); i_ip++, cnt++)
				for (i_ip = at[0]; (i_ip <= at[1]) ; i_ip++, cnt++)
				{
					//add ip
					#ifdef DUMP_IPS
					printf("%d)Detected one ip:0x%lx", cnt, i_ip);
					dumpIP(i_ip);
					printf("\n");
					#endif
					if (insertIP2BTree(&btree,i_ip)== -1) break;
					// all_ip[cnt].s_addr = htonl(i_ip);
					// (*total)++;
				}
				/*
				printf("#2\n");
				if (cnt >= max_user_count)
				{
					printf("WARNING! YOUR ALL USER IP IS TOO MUCH(LARGER THAN %d IPS), DROPED OTHERS!\n", max_user_count);
					break;
				}
				printf("#3\n");
				*/
			}
			else
			{	
				#ifdef DUMP_IPS
				printf("%d)Detected one ip:0x%lx", cnt, i_ip);
                                dumpIP(i_ip);
                                printf("\n");
				#endif
				if (insertIP2BTree(&btree,i_ip)== -1) break;
				/*
				printf("#4\n");
				if (cnt >= max_user_count)
				{
					printf("WARNING! YOUR ALL USER IP IS TOO MUCH(LARGER THAN %d IPS), DROPED OTHERS!\n", max_user_count);
					break;
				}
				all_ip[cnt].s_addr = htonl(i_ip);
				(*total)++;
				dumpIP(i_ip);
				printf("#5\n");
				*/
			}
		}
	}
	/*load all_ip from tree*/
	cnt = 0;	
	*total = btree2InAddr(&btree, all_ip, 0);	
	printf("Load ip file over, total:%d\n", *total);
	return all_ip;
}

/*sort ip*/
int partition(struct in_addr *arr, u_int32_t low, u_int32_t high)
{
	u_int64_t key;
	// printf("partition low:%u high:%u\n",low,high);
	key = arr[low].s_addr;
	while (low < high)
	{
		while (low < high && ntohl(arr[high].s_addr) >= ntohl(key))
			high--;
		if (low < high)
		{
			arr[low].s_addr = arr[high].s_addr;
			/*
 			printf("\t%x ",ntohl(arr[low].s_addr));
			dumpIP(ntohl(arr[low].s_addr));
			printf("\t%x ",ntohl(arr[high].s_addr));
			dumpIP(ntohl(arr[high].s_addr));
			*/
			low++;
		}
		while (low < high && ntohl(arr[low].s_addr) <= ntohl(key))
			low++;
		if (low < high)
		{
			arr[high].s_addr = arr[low].s_addr;
			/*
 			printf("\t%x ",ntohl(arr[low].s_addr));
			dumpIP(ntohl(arr[low].s_addr));
			printf("\t%x ",ntohl(arr[high].s_addr));
			dumpIP(ntohl(arr[low].s_addr));
			*/
			high--;
		}
	}
	arr[low].s_addr = key;
	return low;
}
void quick_sort(struct in_addr *arr, int start, int end)
{
	int pos;
	// printf("quick sort start:%d end:%d\n",start,end);
	if (start < end)
	{
		pos = partition(arr, start, end);
		quick_sort(arr, start, pos - 1);
		quick_sort(arr, pos + 1, end);
	}
	return; // ip排序 ip_reset初始化
}
/*sort ip end*/

/*hash for string and int*/
u_int32_t hash_string(const char *str) //   BKDRHash 算法    字符串url的hash值
{
	u_int32_t seed = 131; // 31 131 1313 13131 131313 etc..
	u_int32_t hash = 0;
	while (*str)
	{
		hash = hash * seed + (*str++);
	}
	return (hash & 0x7FFFFFFF);
}

u_int32_t hash_int(u_int32_t i) //url_num的hash值
{
	u_int32_t hash_k = i;
	i %= HASHTABLE_SIZE;
	return i;
}
/*hash end*/

/*
find the position of key in arr
@arr: int arr
@total: the length for arr
@key: the int key you want to find postion
@return: -1 or correct index
*/
int find_index_by_value(int arr[], int total, int key)
{
	//        二分查找，用于找到ip的代号,如果找到了，返回在数组中的位置，即代号，否则返回-1。
	int low = 0;
	int high = total - 1;
	while (low <= high)
	{
		int mid = (low + high) / 2;
		int midVal = arr[mid];
		if (midVal < key)
			low = mid + 1;
		else if (midVal > key)
			high = mid - 1;
		else
			return mid;
	}
	return -1;
}

#define FIND_IP(x) find_index_by_ip_int(all_ip, all_ip_cnt, x)
/*
find index from all_ip struct
@all_ip: struct in_addr * 
@all_ip_cnt: max count to find
@ip: host seq ip number
@index: out index
*/
int64_t find_index_by_ip_int(struct in_addr *all_ip, u_int32_t all_ip_cnt, u_int32_t ip)
{
	int32_t low = 0;
	int32_t high = all_ip_cnt;
	struct in_addr *midVal;
	// printf("will find ip:%u all_ip_cnt:%u\n", ip, all_ip_cnt);
	while (low <= high && low >= 0 && high>=0)
	{
		int mid = (low + high) / 2;
		// printf("low:%d high:%d mid: %d\n",low, high,mid);
		midVal = &all_ip[mid];
		if (ntohl(midVal->s_addr) < ip)
			low = mid + 1;
		else if (ntohl(midVal->s_addr) > ip)
			high = mid - 1;
		else{
			#if 1
			if ( ip != ntohl(midVal->s_addr))
				printf("[ERROR] found this ip error: %u s_addr:%u index:%u \n",ip, ntohl(midVal->s_addr), mid );
			#endif 
			return mid;
		}
	}
	// printf("not found this ip\n");
	return -1;
}


/*find_index_by_XXX end*/

/*
get hash element by index, like a array
@head: hashtable index
@index: the index of hash
@return: the element when found or NULL when not found
*/
HashEle_t *find_hash_by_index(HashEle_t *head, int index) //找到hash值对应的结点 ,并返回所对应的位置
{
	HashEle_t *q = head;
	u_int32_t k = index / 100;
	u_int32_t l = index % 100;
	if (index >= HASHTABLE_SIZE_ACTUALLY)
		return NULL;
	while (k--)
	{
		q = q->next100;
	}
	while (l--)
	{
		q = q->next;
	}
	q = q->next; //当n=0时，实际上对应的为head.next的结点
	return q;
}


HashEle_t *setUrlIntoHashtableById(HashEle_t *hashtable, u_int32_t url_hash_idx) //     两个参数，第一个是HashEle_t的头结点指针，第二个是要设置的
{
	int ret;
	u_int32_t hash_idx;
	HashEle_t *hash_ele;
	HashEle_t *hash_tmp;
	// get hash index
	if (url_hash_idx == 0x7FFFFFFF || url_hash_idx == 0)
		return NULL;
	/*calc mod*/
	hash_idx = hash_int(url_hash_idx);
	/*get ele by mod*/
	hash_ele = find_hash_by_index(hashtable, hash_idx);
	/*mod may same, find until */
	if (hash_ele->url != NULL)
	{
		// printf("confilict or same url idx(%u, %u): %s\n",url_hash_idx, hash_idx, in_url);
		while (hash_ele != NULL)
		{
			/*compare url hash id (fast than strcmp)*/
			/*same url*/
			if (hash_ele->url_id == url_hash_idx)
			{
				// printf("same url\n");
				//found
				return hash_ele;
			}
			#if 1
			else if (!isHotInfo2( &hash_ele->tick, HOT_DELTA_LONG_PARA )){ /*expire url, reuse it */
				/*lock to reset it */
				ret = pthread_mutex_trylock( &hash_ele->mutex ); 
				if (ret != 0 ){
					/*cant get this mutex lock,skip it */
					printf("  init new mutex fail\n");
					goto last;
				}
				/* reset the ele, MUST SAVE subele*/
				if (hash_ele->url != NULL){
					/*reset last unused url str*/
					free(hash_ele->url);
					hash_ele->url = NULL;
				}
				// memset(hash_ele->ip_infos, 0, sizeof(ip_info_t)*all_ip_cnt);
				pthread_mutex_unlock( &hash_ele->mutex );
				break;
			}
			#endif
			else
			{
				// printf("not same url %s<=>%s, search next\n", hash_ele->url, in_url);
				//  not found, find sub ele until no any sub
last:
				hash_tmp = hash_ele;
				hash_ele = hash_ele->sub_ele;
			}
		} /*end while*/
		/*sub ele is null, get a new ele*/
		if (hash_ele == NULL)
		{
			int ret ;
			printf("not found , malloc a new\n");
			hash_ele = (HashEle_t *)malloc(sizeof(HashEle_t));
			if (hash_ele == NULL)
			{	
				printf("malloc fail\n");return NULL;
			}
			memset(hash_ele, 0, sizeof(HashEle_t));
			ret = pthread_mutex_init( &hash_ele->mutex, 0);  
			if (ret != 0){
				printf("mutex init fail\n");
				free(hash_ele);
				hash_ele = NULL;
			}
			else{
				// printf("mutex success %p\n", &hash_ele->mutex);
			}
			hash_ele->ip_infos = (ip_info_t *)malloc(sizeof(ip_info_t)*all_ip_cnt);
			if (hash_ele->ip_infos == NULL )
			{	printf("malloc fail\n");return NULL;};
			memset(hash_ele->ip_infos, 0, sizeof(ip_info_t)*all_ip_cnt);
			hash_tmp->sub_ele = hash_ele;
		} /* end if*/
	} /* end if */
	/*set new hash attr*/

	hash_ele->num = hash_idx;
	// printf("set url over: %s\n", hash_ele->url);
	return hash_ele;
}

/*set url, and get its hashelement, also "get hash element by url"*/
HashEle_t *setUrlIntoHashtable(HashEle_t *hashtable, const char *in_url) //     两个参数，第一个是HashEle_t的头结点指针，第二个是要设置的
{

	HashEle_t *hash_ele;
	/*calc big hash*/
	u_int32_t url_hash_idx;
	url_hash_idx = hash_string((const char*)in_url);
	hash_ele = setUrlIntoHashtableById(hashtable, url_hash_idx);
	/*set into hashtable success*/
	if (hash_ele != NULL){
		hash_ele->url_id = url_hash_idx;
		/*when reuse or exists, we dont need to reset the url str*/
		if (hash_ele->url == NULL){
			hash_ele->url = ndpi_strdup(in_url);
		}
	}
	return hash_ele;
}

u_int8_t initIPArr(ip_info_t *infos)
{
	//TODO: if has pointer in ip_info, need init ip arr infos by global ip arr
	return 0;
}

/*format bytes
 * @bytes: sizeof
 * @return: formated bytes(will larger than real) */
char * formatBytes(u_int32_t bytes, char *buf){
	int bs = 0;
	char c = ' ';
	u_int32_t tmp = 0;
	// printf("bytes: %u\n",bytes);
	while((tmp = bytes >> (bs*10)) > 0){

		// printf("bs:%d %d %u\n", bs, bytes>>(bs*10), tmp);
		bs++;
		if (bs >= 4)
			break;
	}
	if (bytes) bs--;
	if (bs==3)	c = 'G';
	else if (bs == 2) c='M';
	else if (bs == 1) c = 'K';
	// printf("bs: %d %u %cB\n",bs ,bytes>>(bs*10)+1, c);
	sprintf(buf,"%u %cB", bytes>>(bs*10)+1, c);
	return buf;
}

/*
init hash table
@head: hashtable head pointer
@hash_size: hashtable sizeof
@return: 0->success -1->fail
*/
u_int8_t initUrlHashtable(HashEle_t *head, u_int32_t hash_size)
{ //初始化url_node ，n为初始化结点个数，拟定5000
	int i;
	HashEle_t *tmp;
	HashEle_t *p = head; //记录头结点，头结点为不存数据
	HashEle_t *t = head;
	char buf[48] = {0};
	int ret ;
	for (i = 0; i < hash_size; i++)
	{
		if ((i % 100) == 0 && i != 0)
		{
			t->next100 = p; //记录接下来第一百结点个的位置
			t = t->next100;
		}
		tmp = (HashEle_t *)malloc(sizeof(HashEle_t));
		if (tmp == NULL)
			return -1;

                // printf("node address is :%p\n", tmp);

		memset(tmp, 0, sizeof(HashEle_t));
		ret = pthread_mutex_init( &tmp->mutex, 0 );  /*init mutex*/
                if (ret != 0){
                     perror("mutex init fail\n");
                }
                else{
		     // printf("mutex success %p\n", &tmp->mutex);
                }

		tmp->ip_infos = (ip_info_t *)malloc(sizeof(ip_info_t)*all_ip_cnt);
		// printf("ip_infos %p\n", tmp->ip_infos);
		if (tmp->ip_infos == NULL)
			return -2;
	    memset(tmp->ip_infos, 0, sizeof(ip_info_t)*all_ip_cnt);
		tmp->num = i;
		initIPArr(tmp->ip_infos); //初始化url_node中的ip记录
		p->next = tmp;
		p = tmp;
	}
	printf("\tmalloc hashtable success, size: %s\n", formatBytes( sizeof(HashEle_t)*hash_size + sizeof(ip_info_t)*all_ip_cnt*hash_size, buf));
	return 0;
}

u_int8_t isValiadIP()
{
	return true;
}

/*get conf_row by conf_key*/
conf_row_t *get_conf_by_key(char *key, conf_row_t *global_conf) //判断读取到的数据是不是在固定数据中，并返回数据，无则返回-1
{
	int i;
	if (key == NULL)
		return NULL;
	for (i = 0; i < MAX_CONF_LINES && global_conf[i].key != NULL; i++)
	{
		if (global_conf[i].key != NULL && strlen(global_conf[i].key) == strlen(key) && memcmp(key, global_conf[i].key, strlen(key)) == 0)
		{
			// printf("found key(%s) in conf\t\t", key);
			return &global_conf[i];
		}
	}
	return NULL;
}

/*
handle KEY=VALUE format file
@filename: filename 
@dst: conf
*/
void read_config(char *filename, conf_row_t *global_conf)
{
	//读取配置文件
	char c;
	char t[MAX_KEY_LEN] = {0}; //用于存放已读取的字符串
	int i = 0;
	FILE *f;
	conf_row_t *temp_conf_row;
	if (filename == NULL)
		return;
	f = fopen(filename, "r");
	/*TODO: handle error when read */
	printf("read_config from %s\n", filename);
	if (f == NULL)
	{
		printf("error when read %s", filename);
		return;
	}
	c = getc(f);
	while (c != EOF)
	{
		if (c == '\n' || (c == '\r')) //读到\n，continue
		{
			/*read next line*/
			c = getc(f);
			continue;
		}
		i = 0;
		// printf("READ AND SET KEY\n");
		/*has handled \r \n*/
		if (c == '=')
		{
			/*next new line*/
			do
			{
				c = getc(f);
			} while (c != '\n' && c != '\r' && c != EOF);
			continue;
		}
		while (c != EOF)
		{

			if (c == '=' || c == '\n' || c == '\r')
			{
				if (c == '=')
				{
					/*FOUND KEY*/
					goto found_key;
				}
				else
				{
					/*next new line*/
					do
					{
						c = getc(f);
					} while (c != '\n' && c != '\r' && c != EOF);
					continue;
				}
			}
			else
			{
				/*correct key, continue set key*/
				t[i++] = c;
			}
			c = getc(f);
		}
		continue;
	found_key:
		c = getc(f);
		t[i] = '\0'; //    数组不满的时候
		if (c == '\n' || c == '\r' || c == EOF)
		{
			printf("continue\n");
			continue; //数据只有前一半的时候，做continue处理  而不再固定数据中进行查找
		}
		temp_conf_row = get_conf_by_key(t, global_conf);
		if (temp_conf_row == NULL)
		{
			/*not found valid key*/
			printf("\tSkip Support Key:%s\n", t);
			/*read until next new line*/
			do
			{
				c = getc(f);
			} while (c != '\n' && c != '\r' && c != EOF);
			if (c == EOF)
				return; //读到文件末尾，return
			continue;   //读到下一行，继续循环读数据
		}
		else
		{
			//found valid key, set it's value
			int value_idx = 0;
			char temp_v[MAX_VALUE_LEN] = {0};
			while (c != '\n' && c != '\r' && c != EOF)
			{
				if (value_idx >= MAX_VALUE_LEN)
				{
					printf("\tERROR, UNSUPPORT VALUES LEN, MAX VALUE LEN IS %d\n", MAX_VALUE_LEN);
					exit(-1);
				}
				temp_v[value_idx++] = c;
				c = getc(f);
			}
			temp_conf_row->value = ndpi_strdup(temp_v);
			// printf("value: %s\n", temp_v);
		}
		/*set key value ok*/
	}
	// printf("read success!\n");
}

funcBeforeRotateFile BeforeRotateFile ;
int BeforeRotateFile( LOG *g , char *rotate_log_pathfilename )
{
	strcat( rotate_log_pathfilename , ".gz" );
	return 0;
}


funcAfterRotateFile AfterRotateFile ;
int AfterRotateFile( LOG *g , char *rotate_log_pathfilename )
{
	char	cmd[ 256 + 1 ] ;
	
	memset( cmd , 0x00 , sizeof(cmd) );
	SNPRINTF( cmd , sizeof(cmd)-1 , "gzip %s" , rotate_log_pathfilename );
	system( cmd );
	
	return 0;
}

void initLogHandler()
{
	g = CreateLogHandle();
	g_rt = CreateLogHandle();
	if (g== NULL|| g_rt == NULL){
		printf("Init log handler fail !\n");
		exit(-1);
	}
	SetLogOutput(g, LOG_OUTPUT_FILE, GLOBAL_CONF[DATA_PATH].value, LOG_NO_OUTPUTFUNC);
	SetLogLevel( g , LOG_LEVEL_INFO );
	SetLogStyles( g , LOG_STYLES_FM , LOG_NO_STYLEFUNC );
	SetLogRotateMode(g, LOG_ROTATEMODE_SIZE );
	SetLogRotateSize(g, atoi(GLOBAL_CONF[LOG_SIZE_FM].value) );
	SetBeforeRotateFileFunc( g, & BeforeRotateFile );
	SetAfterRotateFileFunc( g, & AfterRotateFile );
	SetLogOutput(g_rt, LOG_OUTPUT_FILE, GLOBAL_CONF[DATA_PATH_RT].value, LOG_NO_OUTPUTFUNC);
	SetLogLevel( g_rt , LOG_LEVEL_INFO );
	SetLogStyles( g_rt , LOG_STYLES_FM , LOG_NO_STYLEFUNC );
	SetLogRotateMode(g_rt, LOG_ROTATEMODE_SIZE );
	SetLogRotateSize(g_rt, atoi(GLOBAL_CONF[LOG_SIZE_FM].value));
	SetBeforeRotateFileFunc( g_rt, & BeforeRotateFile );
	SetAfterRotateFileFunc( g_rt, & AfterRotateFile );
}
void destoryLogHandler(){
	DestroyLogHandle( g );
	DestroyLogHandle( g_rt );
}

void set_config_default(conf_row_t *global_conf)
{
	int i;
	if (global_conf == NULL)
	{
		printf("global conf is NULL!\n");
	}
	/*set default*/
	global_conf[DATA_PATH].value = global_conf[DATA_PATH].value != NULL ? global_conf[DATA_PATH].value : DATA_PATH_DEFAULT;
	global_conf[DATA_PATH_RT].value = global_conf[DATA_PATH_RT].value != NULL ? global_conf[DATA_PATH_RT].value : DATA_PATH_RT_DEFAULT;
	global_conf[LOG_SIZE_FM].value = global_conf[LOG_SIZE_FM].value != NULL ? global_conf[LOG_SIZE_FM].value : LOG_SIZE_FM_DEFAULT;
	global_conf[MAX_USER_COUNT].value = global_conf[MAX_USER_COUNT].value != NULL ? global_conf[MAX_USER_COUNT].value : MAX_USER_COUNT_DEFAULT;
	max_user_count = atoi(global_conf[MAX_USER_COUNT].value);
	// sprintf(clearCmdBuf,"cat /dev/null > %s", GLOBAL_CONF[DATA_PATH_RT].value);
	// printf("settig clearCmdBuf: %s\n", clearCmdBuf);
	for (i = 0; global_conf[i].key != NULL; i++)
	{	
		printf("\t%d %s=%s\n",global_conf[i].index , global_conf[i].key, global_conf[i].value);
	}
}

u_int64_t getTimeFix(){
	time_t t;
	t = time(0);
	return ((u_int64_t )t)/want_5s_flag;
}

/*dump conf to console*/
void dump_config(conf_row_t *global_conf)
{
	int i;
	if (global_conf == NULL)
	{
		printf("global conf is NULL!\n");
	}
	for (i = 0; global_conf[i].key != NULL; i++)
	{
		printf("\t%d %s=%s\n",global_conf[i].index , global_conf[i].key, global_conf[i].value);
	}
}

/*@size: user count*/
u_int8_t initAppStruct(app_info_t **_app_struct, int size)
{
	char buf[48] = {0};
	*_app_struct = (app_info_t *)malloc(sizeof(app_info_t) * size);
 	if (*_app_struct != NULL)
	{
		
		printf("\tmalloc appstruct success, size: %s \n",formatBytes(sizeof(app_info_t)*size, buf));
		memset(*_app_struct, 0 , sizeof(app_info_t)*size);
		return 0;
	}else
		return -1;
}

int8_t initFlowmeterStruct(HashEle_t **out_hashtable, app_info_t **_app_struct)
{
	/*init url struct*/
	/*init head*/
	printf("------------%s-----------\n",__FUNCTION__);
	*out_hashtable = (HashEle_t *)malloc(sizeof(HashEle_t));
	memset(*out_hashtable, 0, sizeof(HashEle_t));
	if (0 != pthread_mutex_init( &(*out_hashtable)->mutex, 0 )){
		printf("Init hashtable head lock fail, exit\n");
		exit(1);
	}
	(*out_hashtable)->ip_infos = (ip_info_t *)malloc(sizeof(ip_info_t)*all_ip_cnt);
	memset((*out_hashtable)->ip_infos, 0, sizeof(ip_info_t)*all_ip_cnt);
	if (initUrlHashtable(*out_hashtable, HASHTABLE_SIZE) != 0)
	{
		printf("\tinitUrlHashtable fail\n");
		return -1;
	}
	else
	{
		printf("\tinitUrlHashtable success %p\n", *out_hashtable);
	}
	/*init app struct*/
	if (initAppStruct(_app_struct, all_ip_cnt) != 0)
	{
		printf("\tinitAppStruct fail\n");
		return -2;
	}
	else
	{
		printf("\tinitAppStruct success\n");
	}
	return 0;
}

/*
 * @
 * @
 * @
 * @ appid
 * @ ip_index */
void updateAppData(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow *flow, app_info_t *_app_struct, u_int64_t appid, u_int64_t ip_index)
{

		if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(_app_struct->app_bitmask, appid) == 0) NDPI_ADD_PROTOCOL_TO_BITMASK(_app_struct->app_bitmask, appid);
		_app_struct->tick = _app_struct->ip_infos[appid].tick  = time(NULL);
		_app_struct->ip_infos[appid].localIP = ntohl(all_ip[ip_index].s_addr);
		_app_struct->ip_infos[appid].fiveSecBytes += flow->bytes; //5s bytes will add to 10min every 10min bytes and set to 0
		// dumpIPInfoLit(&_app_struct->ip_infos[index]);
}

void updateUrlData(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow *flow, HashEle_t *hash_ele, int64_t index)
{
		hash_ele->tick = hash_ele->ip_infos[index].tick  = time(NULL);
		hash_ele->ip_infos[index].localIP = ntohl(all_ip[index].s_addr);
		hash_ele->ip_infos[index].fiveSecBytes += flow->bytes    ; //5s bytes will add to 10min every 10min bytes and set to 0
		hash_ele->ip_infos[index].fiveSecCount += 1; 
		// printf("url in update: %s\n",hash_ele->url);
		// dumpHashEle(hash_ele, 0, 0, 0, 0);
}

/*static void printFlow(struct ndpi_flow *flow) {
  char buf1[32], buf2[32];

  printf("\t%s %s:%u > %s:%u [proto: %u/%s][%u pkts/%u bytes]\n",
	 ipProto2Name(flow->protocol),
	 intoaV4(ntohl(flow->lower_ip), buf1, sizeof(buf1)),
	 ntohs(flow->lower_port),
	 intoaV4(ntohl(flow->upper_ip), buf2, sizeof(buf2)),
	 ntohs(flow->upper_port),
	 flow->detected_protocol,
	 ndpi_get_proto_name(ndpi_struct, flow->detected_protocol),
	 flow->packets, flow->bytes);
}
*/

void updateFlowData(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow *flow, HashEle_t *_hashtable, app_info_t *_app_struct)
{
	int64_t index = -1;
/*	
	printf("in updateFlowData\n");
	printf("lower_ip:%u upper_ip:%u\n",ntohl(flow->lower_ip), ntohl(flow->upper_ip));
	printf("lower_ip:");
	dumpIP(ntohl(flow->lower_ip));
	printf(" upper_ip:");
	dumpIP(ntohl(flow->upper_ip));
	printf("\n");
*/
	/*validate ip : if used bpf , this can be ignored*/
	// if((index = FIND_IP(ntohl(flow->lower_ip))) != -1 || (index = FIND_IP(ntohl(flow->upper_ip)) != -1))

#define JUDGE_AND_UPDATE  { 								\
		/* printf("Found valid ip:");*/					\
		/* dumpIP(ntohl(all_ip[index].s_addr)); */ 				\
		/* printf("\n"); */							\
		if (ISHTTP(flow->detected_protocol)) 					\
		{									\
			/*1. get hash ele by url*/					\
			HashEle_t *hash_ele = NULL;					\
			/* printf("will setUrlIntoHashtable\n"); */			\
			if (flow->ndpi_flow == NULL){				\
				hash_ele =  setUrlIntoHashtableById(_hashtable, flow->url_hash_idx);		\
			}else{								\
				if ( flow->ndpi_flow->host_server_name != NULL && strlen(flow->ndpi_flow->host_server_name) > 0) {	\
					hash_ele = setUrlIntoHashtable(_hashtable, flow->ndpi_flow->host_server_name);	\
					if (hash_ele != NULL){					\
						flow->url_hash_idx = hash_ele->url_id;		\
					}						\
				}else{							\
					/* host server is empty*/			\
				}							\
			}								\
			/*2. update data*/						\
			if (hash_ele != NULL)						\
			{								\
				pthread_mutex_lock( &hash_ele->mutex );		\
				/* printf("will update url: %s\n", hash_ele->url);*/	\
				/* printf("[URL] updateUrlData\n"); */			\
				updateUrlData(ndpi_struct, flow, hash_ele, index);	\
				pthread_mutex_unlock( &hash_ele->mutex );		\
				/* printf("[URL] updateUrlData over\n"); */		\
			}								\
			else								\
			{								\
				/* BUG("hash_ele is null url");*/	\
			}								\
		}									\
		else									\
		{									\
			/* TODO: shield Unknown data*/					\
			/* printf("will update app data\n");*/				\
			/* printf("[APP] updateAppData\n"); */			\
			updateAppData(ndpi_struct, flow, &_app_struct[index], flow->detected_protocol, index);	\
			/* printf("[APP] updateAppData over\n"); */			\
		}									\
	}
	if((index = FIND_IP(ntohl(flow->lower_ip))) != -1 ){
		JUDGE_AND_UPDATE;
	}
	if ((index = FIND_IP(ntohl(flow->upper_ip))) != -1){
		JUDGE_AND_UPDATE;
	}
		
	/* printf("update over\n");*/
}

void accuUrlData(HashEle_t *hash_ele, u_int32_t num, u_int32_t sub_num, u_int32_t ten_min_flag, u_int32_t rt_flag){
	u_int32_t i = 0;
	// static u_int32_t cnt = 0;
	// printf("%u)will accuUrl %u-%u data ten_min_flag:%u rt_flag:%u\n",cnt++,num,sub_num, ten_min_flag, rt_flag);
	#if 0
	if (!isHotInfo2(&(hash_ele->tick), HOT_DELTA_LONG_PARA) && hash_ele->tick != 0){
		printf("[URL] time tick:%u - now:%u = %d\n",hash_ele->tick, time(NULL), time(NULL) - hash_ele->tick);
	}
	#endif
	if ( hash_ele == NULL || !isHotInfo2(&(hash_ele->tick), HOT_DELTA_LONG_PARA))
		return;
	for(;i < all_ip_cnt; i++){
		/*rt data*/
		// if (isHotInfo((time_t*) &hash_ele->ip_infos[i]))
		//	printf("%s is hot\n", hash_ele->url);
		//else
		//	printf("%s is not hot tick:%u now:%u\n", hash_ele->url, hash_ele->ip_infos[i].tick, time(NULL));
		if ( !isHotInfo2(&(hash_ele->ip_infos[i].tick), HOT_DELTA_LONG_PARA)) /*this para is 2, when it is 1 it will be reset to 0*/
		{
			// hash_ele->ip_infos[i].tenMinBytes = hash_ele->ip_infos[i].fiveSecBytes = hash_ele->ip_infos[i].tenMinCount = hash_ele->ip_infos[i].fiveSecCount = 0;
			continue;
		}else{
			// printf("[URL] common data, will detect\n");
		}
		if (rt_flag && isHotInfo((time_t*) &hash_ele->ip_infos[i].tick) && hash_ele->ip_infos[i].fiveSecBytes)
		{
			// printf("[URL] logging url 5s !\n");	
			/*U: www.baidu.com,ip,fiveSecBytes,fiveSecCount*/
			LOG_FM_RT("T:%11ld U: %s,%u,%u,%u\n", timeFix, hash_ele->url, ntohl(all_ip[i].s_addr), hash_ele->ip_infos[i].fiveSecBytes, hash_ele->ip_infos[i].fiveSecCount);
		}
		/*accu 5s data*/
		if (hash_ele->ip_infos[i].fiveSecBytes)
		{
			hash_ele->ip_infos[i].tenMinBytes += hash_ele->ip_infos[i].fiveSecBytes ;
			hash_ele->ip_infos[i].fiveSecBytes = 0;
			hash_ele->ip_infos[i].tenMinCount += hash_ele->ip_infos[i].fiveSecCount ;
			hash_ele->ip_infos[i].fiveSecCount = 0;
		}
		/*U: www.baidu.com,ip,fiveSecBytes,fiveSecCount*/
		if (ten_min_flag && hash_ele->ip_infos[i].tenMinBytes){
			// printf("[URL] logging url 10min!\n");

			LOG_FM("U: %s,%u,%u,%u\n", hash_ele->url, ntohl(all_ip[i].s_addr), hash_ele->ip_infos[i].tenMinBytes, hash_ele->ip_infos[i].tenMinCount);  
			hash_ele->ip_infos[i].tenMinBytes = 0;	
			hash_ele->ip_infos[i].tenMinCount = 0;	
		}
	}
	// printf("[URL] accu over\n");
}

void writeAppData(ip_info_lit_t *info){
	/*write data to log*/
}

void accuAppData(app_info_t *_app_struct, u_int32_t ten_min_flag, u_int32_t rt_flag)
{
	u_int32_t i_user = 0, bytes = 0;
	/*rt data*/
	char ip_buf[128];
	char id_buf[128];
	// printf("will accuApp\n");
	for(i_user = 0; i_user < all_ip_cnt; i_user++){
		u_int32_t appid = 0;
		u_int32_t temp_ip = 0 ;
		json_object *jObj = NULL;
		json_object *jobj_one_ip_app_infos = NULL;

		if (rt_flag){
			// printf("rt_flag in accuAppData!\n");
			jObj=json_object_new_object();
			jobj_one_ip_app_infos = json_object_new_array();
			if(jobj_one_ip_app_infos==NULL || jObj ==NULL){
				if (jobj_one_ip_app_infos) json_object_put(jobj_one_ip_app_infos);
				if (jObj) json_object_put(jObj);
				printf("jobj_one_ip_app_infos or jObj is NULL skip..\n");
				continue;
			}
		}
		// printf("[APP] dump---------------\n");
		// dumpAppStruct(&_app_struct[i_user]);
		for(; appid < NDPI_MAX_SUPPORTED_PROTOCOLS ;appid++){
			if (temp_ip == 0 && _app_struct[i_user].ip_infos[appid].localIP != 0) {

				temp_ip = _app_struct[i_user].ip_infos[appid].localIP;
				snprintf(ip_buf,sizeof(ip_buf),"%u",temp_ip);
				// printf("setting localIP:%u temp_ip:%u s_addr:%u ntohl(s_addr):%u\n", _app_struct[i_user].ip_infos[appid].localIP, temp_ip ,all_ip[i_user].s_addr ,ntohl(all_ip[i_user].s_addr));
			}
			if(ISHTTP(appid) || appid == 0)
				continue;
			if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(/*bitmask*/_app_struct[i_user].app_bitmask, appid) == 0 || (_app_struct[i_user].ip_infos[appid].fiveSecBytes == 0 && _app_struct[i_user].ip_infos[appid].tenMinBytes == 0 )){
				continue; 
			}
			/*else{
				printf("\t5s bytes:%u\n", _app_struct[i_user].ip_infos[appid].fiveSecBytes);
			}*/
			// if (isHotInfo(&_app_struct[i_user].ip_infos[appid].tick)){
			if (_app_struct[i_user].ip_infos[appid].fiveSecBytes){
				if (rt_flag){
					// printf("#2 rt_flag in accuAppData!\n");
					json_object * json_one_app_obj;
					json_one_app_obj = json_object_new_object();

					bytes = _app_struct[i_user].ip_infos[appid].fiveSecBytes;
					memset(id_buf,0, sizeof(id_buf));
					snprintf(id_buf,sizeof(id_buf),"%u",appid);
					// printf("\t5s bytes:%lu bytes:%lu\n", _app_struct[i_user].ip_infos[appid].fiveSecBytes, bytes);	
					json_object_object_add(json_one_app_obj,  id_buf, json_object_new_int64(bytes)); 
					json_object_array_add(jobj_one_ip_app_infos, json_one_app_obj);
				}
				
	   			/*accu 5s*/
				_app_struct[i_user].ip_infos[appid].tenMinBytes += _app_struct[i_user].ip_infos[appid].fiveSecBytes ;
				_app_struct[i_user].ip_infos[appid].fiveSecBytes = 0;
			}
			 if (ten_min_flag)
				// printf("should 10min app data; 5sbytes:%u 10minbytes:%u\n",_app_struct[i_user].ip_infos[appid].fiveSecBytes,_app_struct[i_user].ip_infos[appid].tenMinBytes);
			if (ten_min_flag &&  temp_ip && _app_struct[i_user].ip_infos[appid].tenMinBytes){
				/*ten min data: A: appid,ip,tenMinBytes*/
				#if 0
				printf("[APP] logging app 10min!\n");
				printf("A: %u,%u,%u\n", appid, ntohl(all_ip[i_user].s_addr), _app_struct[i_user].ip_infos[appid].tenMinBytes);  
				#endif
				LOG_FM("A: %u,%u,%u\n", appid, ntohl(all_ip[i_user].s_addr), _app_struct[i_user].ip_infos[appid].tenMinBytes); 
				NDPI_DEL_PROTOCOL_FROM_BITMASK( _app_struct[i_user].app_bitmask, appid); 
				_app_struct[i_user].ip_infos[appid].tenMinBytes = 0;
			}
		}/*for appid*/
		if (rt_flag){
			// printf("#3rt_flag in accuAppData! temp_ip:%u\n",temp_ip);
			if(temp_ip != 0 && json_object_array_length(jobj_one_ip_app_infos) != 0){
					if (strlen(id_buf) == 0)
						printf("EMpty id_buf!! temp_ip:%u\n",temp_ip);
					// printf("#3.success rt_flag in accuAppData!\n");	
					json_object_object_add(jObj,ip_buf,jobj_one_ip_app_infos);
					// printf("(ip_buf:%s<->ip:%u(0x%x))buf:%s\n",ip_buf,_app_struct->ip_infos[i_user].localIP,_app_struct->ip_infos[i_user].localIP,json_object_to_json_string(jObj));
					#if 0
					printf("[APP] logging app 5s!\n");
					printf("T:%11ld A: %s\n", timeFix,json_object_to_json_string(jObj));
					# endif
					LOG_FM_RT("T:%11ld A: %s\n", timeFix,json_object_to_json_string(jObj));
					// printf("RT_DATA: %s\n",json_object_to_json_string(jObj));
					temp_ip = 0;
			}else{
	
					// printf("#3.fail rt_flag in accuAppData!\n");	
					json_object_put(jobj_one_ip_app_infos);
			}
			//dispose
			memset(ip_buf,0,sizeof(ip_buf));
			// printf("disposing..\n");
			json_object_put(jObj);
	   	}/*rt data end*/	   
	}/*for i_user*/

}


void walkUrlHashtable(HashEle_t *hashtable, void (*cb)(HashEle_t *hash_ele, u_int32_t _num, u_int32_t _sub_num, u_int32_t _flag, u_int32_t _flag2 ),u_int32_t write_flag, u_int32_t rt_flag)
{
	/*TODO walk all hash table and call cb function */
	/*1. walk hash, can get url*/
	/*2. find a ip*/
	/*cb(url,ip)*/
	// static u_int32_t debug = 0;
	u_int32_t num=0, sub_num=0 ;
	HashEle_t *p = hashtable; //记录当前要释放的节点
	HashEle_t *p1 = NULL;			  //记录要释放节点的下个节点
	// HashEle_t *q1; //记录要释放支链节点的下个节点
	// pthread_mutex_t *mutex1, *mutex2;
	while (p!=NULL)
	{
		// mutex1 = mutex2 = &p->mutex;
		// printf("will get mutex %p %p %p\n", p, p->ip_infos, &p->mutex);
		// pthread_mutex_lock(mutex2);
		p1 = p->next;
		if (p->url == NULL)
		{
			// pthread_mutex_unlock(mutex2);
			p = p1;
			continue;
		}
		// printf("[debug:%u]-------num %u.%u\n",debug,num, sub_num);
		num = num +1 ;
		while (p!=NULL)
		{
			// printf("will get mutex inner\n");
			// printf("[debug:%u]-----------cb %u\n",debug,sub_num);
			pthread_mutex_lock(&p->mutex);
			cb(p,num,sub_num,write_flag,rt_flag);
			pthread_mutex_unlock(&p->mutex);
			if (p->sub_ele == NULL) break;
			p = p->sub_ele;
			sub_num++;
		}
		// pthread_mutex_unlock(mutex2);
		p = p1;
	}
	// debug++;
	printf("\ttotal HASHTABLE_SIZE:%u num: %u sub_num: %u\n", HASHTABLE_SIZE, num - 1, sub_num );
	return;
}

void freeHashEle(HashEle_t *hash_ele, u_int32_t num, u_int32_t sub_num, u_int32_t flag, u_int32_t flag2)
{
	if (hash_ele != NULL)
	{
		if (hash_ele->url != NULL)
			free(hash_ele->url);
		free(hash_ele);
	}
}

void freeHashtable(HashEle_t *hashtable)
{
	walkUrlHashtable(hashtable, freeHashEle, 0, 0);
}

inline u_int8_t isHotInfo(time_t* tick)
{
	return ( (*tick) + HOT_DELTA_SEC) > time(NULL);
}

inline u_int8_t isHotInfo2(time_t* tick, u_int32_t i)
{
	return ( (*tick) + i * HOT_DELTA_SEC) > time(NULL);
}

void dumpIPInfo(ip_info_t * info){
	char buf[256];
	if(isHotInfo((time_t*)info)){
		dumpIP2Str(info->localIP, buf);
		printf("\t tick:%u \tIP:%s\t count(5s):%lu\t bytes(5s):%lu\t\t count(10min):%lu\t bytes(10min):%lu\n"
			, info->tick, buf, info->fiveSecCount, info->fiveSecBytes, info->tenMinCount, info->tenMinBytes);
	}
}
int test = 0;
void dumpIPInfoLit(ip_info_lit_t * info){
	char buf[256];
	if(isHotInfo2((time_t*)info,2)){
		printf("\t app:%u",test);
		dumpIP2Str(info->localIP, buf);
		printf("\t\tIP:%s\t bytes(5s):%lu\t\t bytes(10min):%lu\n"
			, buf, info->fiveSecBytes, info->tenMinBytes);
	}
}

void dumpAppStruct(app_info_t *app_struct){
	u_int32_t i = 0;
	for(; i < NDPI_MAX_SUPPORTED_PROTOCOLS; i++){
		test = i;
		dumpIPInfoLit(&app_struct->ip_infos[i]);
	}
}

void dumpHashEle(HashEle_t *hash_ele, u_int32_t num, u_int32_t sub_num,  u_int32_t flag,  u_int32_t flag2){
	char buf[256];
	u_int32_t i = 0;
	printf("-%u.%u: ",num,sub_num);
	if(hash_ele== NULL){
		printf("empty element!\n");
		return;
	}
	printf("\t url:%s-------------\n", hash_ele->url);
	for (; i< all_ip_cnt; i++){

		dumpIPInfo(&hash_ele->ip_infos[i]);
	}
}

void dumpHashtable(HashEle_t *hashtable)
{
	walkUrlHashtable(hashtable,dumpHashEle, 0, 0);
}

/*
void clearOldRtData(){
	printf("will clear old rt data");
	system(clearCmdBuf);	
}
*/

/*execute every 5s, when write_flag set, write 10min data*/
void calcFlowThread(HashEle_t *_hashtable, app_info_t *_app_struct, u_int32_t write_flag, u_int32_t rt_flag, u_int8_t keep_data_rt){
	u_int32_t i = 0 ;
	#if 1
	// static u_int32_t debug = 0;
	// debug++;
	if (rt_flag)
		printf("[CALC] rt_data!!!!!\n");
	if (write_flag)
		printf("[CALC] 10 min data!!!\n");
	// printf("walkUrlHashtable %u\n",debug);	
	#endif
	printf("[URL] will walk UrlHashtable\n");
	// if (! keep_data_rt)
	//	clearOldRtData();
	// update time fix
	timeFix = getTimeFix();
	walkUrlHashtable(_hashtable,accuUrlData, write_flag, rt_flag);
	printf("[URL] walkUrlHashtable end\n");
	// printf("accuAppData %u\n",debug);
	printf("[APP]will accuAppData\n");
	accuAppData(_app_struct, write_flag, rt_flag);
	printf("[APP] accuAppData end \n");
	
}


int daemon_fm()
{
    int exit_val = 0;
    pid_t cpid;
    int i;

    printf("Initializing daemon mode\n");

    /* Don't daemonize if we've already daemonized */
    if(getppid() != 1)
    {
        /* now fork the child */
        printf("Spawning daemon child...\n");
        cpid = fork();

        if(cpid > 0)
        {
            /* Parent */
            printf("Daemon child %d lives...\n", cpid);

            printf("Daemon parent exiting (%d)\n", exit_val);

            exit(exit_val);                /* parent */
        }

        if(cpid < 0)
        {
            /* Daemonizing failed... */
            perror("fork");
            exit(1);
        }
    }
    /* Child */
    setsid();

    close(0);
    close(1);
    close(2);
    /* redirect stdin/stdout/stderr to /dev/null */
    i = open("/dev/null", O_RDWR);  /* stdin, fd 0 */
    dup(i);
    dup(i);
}

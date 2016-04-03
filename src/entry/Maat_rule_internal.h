#ifndef H_MAAT_RULE_INTERNAL_H_INCLUDE
#define H_MAAT_RULE_INTERNAL_H_INCLUDE

#include "Maat_rule.h"

#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/field_stat2.h>
#include "dynamic_array.h"
#include "UniversalBoolMatch.h"
#include "rulescan.h"

#include "mesa_fuzzy.h"
#include "great_index_engine.h"

#include <pthread.h>
#include <iconv.h>

extern const char *maat_module;


#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 411)
#define atomic_inc(x) __sync_add_and_fetch((x),1)
#define atomic_dec(x) __sync_sub_and_fetch((x),1)
#define atomic_add(x,y) __sync_add_and_fetch((x),(y))
#define atomic_sub(x,y) __sync_sub_and_fetch((x),(y))
typedef int atomic_t;
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) __sync_add_and_fetch((x),0)
#define atomic_set(x,y) __sync_lock_test_and_set((x),y)
#else 
#include <alsa/iatomic.h>
#endif 
#define	CPU_CACHE_ALIGMENT	64
#define	TRUE	1
#define	FALSE	0

#define	MAX_TABLE_NUM			256
#define	MAX_CHARSET_NUM			16
#define	MAX_TABLE_NAME_LEN		256
#define	MAX_TABLE_LINE_SIZE		(1024*4)
#define	MAX_EXPR_KEYLEN			1024
#define	MAX_DISTRICT_LEN			64
#define	MAX_PLUGING_NUM			32

#define	MAX_SCANNER_HIT_NUM		64

#define	MAX_GROUP_CACHE		128

#define	MAX_FAILED_NUM		128

#define	MAX_MAAT_STAT_NUM	64
#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			 \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

typedef	void*	rule_scanner_t;
enum MAAT_TABLE_TYPE
{	
	TABLE_TYPE_EXPR=0,
	TABLE_TYPE_IP,
	TABLE_TYPE_COMPILE,
	TABLE_TYPE_PLUGIN,
	TABLE_TYPE_INTVAL,
	TABLE_TYPE_DIGEST,
	TABLE_TYPE_EXPR_PLUS,
	TABLE_TYPE_GROUP

};
enum MAAT_EXPR_TYPE
{	
	EXPR_TYPE_STRING=0,
	EXPR_TYPE_AND,
	EXPR_TYPE_REGEX,
	EXPR_TYPE_OFFSET
};
enum MAAT_MATCH_METHOD
{	
	MATCH_METHOD_SUB=0,
	MATCH_METHOD_RIGHT,
	MATCH_METHOD_LEFT,
	MATCH_METHOD_FULL
};

struct db_str_rule_t
{
	int region_id;
	int group_id;
	char keywords[MAX_EXPR_KEYLEN];
	char district[MAX_DISTRICT_LEN];
	enum MAAT_EXPR_TYPE expr_type;
	enum MAAT_MATCH_METHOD match_method;
	int is_hexbin;
	int is_case_sensitive;
	int is_valid;

};
struct db_ip_rule_t
{
	int region_id;
	int group_id;
	int addr_type;
	union
	{
		//ip address use network order
		//port use host order
		ipv4_rule_t ipv4_rule;
		ipv6_rule_t ipv6_rule;
	};
	int is_valid;
};
struct db_intval_rule_t
{
	int region_id;
	int group_id;
	interval_rule_t intval;
	int is_valid;
};
struct db_digest_rule_t
{
	int region_id;
	int group_id;
	unsigned long long orgin_len;
	const char* digest_string;
	short confidence_degree;
	int is_valid;
};
struct _head_Maat_rule_t
{
	int 	config_id;
	int		service_id;
	char 	do_log;
	char 	do_blacklist;
	char	action;
	char	resevered;
	int		serv_def_len;
};
struct db_compile_rule_t
{
//	Maat_rule_t m_rule_head;
	struct _head_Maat_rule_t m_rule_head;// fix len of Maat_rule_t
	char* service_defined;
	long long effective_range;
	int is_valid;
	int declare_grp_num;
};
struct db_group_rule_t
{
	int group_id;
	int compile_id;
	int is_valid;
};
struct op_expr_t
{
	boolean_expr_t* p_expr;
	scan_rule_t* p_rules[MAAT_MAX_EXPR_ITEM_NUM];
};

struct _Maat_region_rule_t
{
	int region_id;
	int expr_id;
	int district_id;
	enum MAAT_TABLE_TYPE region_type;
};
struct _Maat_group_rule_t
{
	int group_id;
	int region_boundary;
	int region_cnt;
	int ref_cnt;
	dynamic_array_t *region_rules;
	void* compile_shortcut;
	pthread_mutex_t mutex;
};
struct _Maat_compile_rule_t
{
	struct db_compile_rule_t *db_c_rule;
	dynamic_array_t *groups;
	int group_cnt;
	int compile_id;//equal to db_c_rule->m_rule.config_id
	pthread_rwlock_t rwlock;//reading compile rule is safe in update thread, rwlock lock called when delete or scan thread read
};
struct _compile_result_t
{
	int compile_id;
	universal_bool_expr_t group_set;
};
struct _callback_plugin
{
	Maat_start_callback_t 	*start;
	Maat_update_callback_t	*update;
	Maat_finish_callback_t	*finish;
	void* u_para;
};

struct _plugin_table_info
{
	int cb_plug_cnt;
	struct _callback_plugin  cb_plug[MAX_PLUGING_NUM];
	dynamic_array_t *cache_lines;
	int line_num;
	long cache_size;
	pthread_mutex_t plugin_mutex;
};
struct _Maat_table_info_t
{
	unsigned short table_id;
	char table_name[MAX_TABLE_NAME_LEN];
	enum MAAT_TABLE_TYPE table_type;
	enum MAAT_CHARSET src_charset;
	enum MAAT_CHARSET dst_charset[MAX_CHARSET_NUM];
	int src_charset_in_dst;
	int do_charset_merge;
	int cfg_num;
	int cross_cache_size;
	union
	{
		int expr_rule_cnt;	//expr_type=0,1,3
		int ipv4_rule_cnt;
	};
	union
	{
		int regex_rule_cnt;	//expr_type=2
		int ipv6_rule_cnt;
	};
	struct _plugin_table_info *cb_info;
//for stat>>>>>>>>
	int stat_line_id;
	long long scan_cnt;
	long long scan_cpu_time;	//nano
	long long input_bytes;
	long long stream_num;
	long long hit_cnt;
};

struct _INNER_scan_status_t
{
	int thread_num;
	int cur_hit_cnt;
	int hit_group_cnt;
	int hit_group_size;
	unsigned int cur_hit_id[MAX_SCANNER_HIT_NUM];
	unsigned int *hitted_group_id;
};
struct _OUTER_scan_status_t
{
	struct _Maat_feather_t* feather;
	int is_set_district;
	int district_id;
	struct _INNER_scan_status_t* inner;
};
enum maat_garbage_type
{
	GARBAGE_SCANNER=0,
	GARBAGE_GROUP_RULE,
	GARBAGE_COMPILE_RULE,
	GARBAGE_BOOL_MATCHER
};
struct iconv_handle_t
{
	int is_initialized;
	iconv_t cd;
};
struct _stream_para_t
{
	struct _Maat_feather_t* feather;
	int version;
	int thread_num;
	int max_cross_size;
	int caching_size;
	unsigned short table_id;
	char do_merge;
	char do_expr:4;
	char do_regex:4;
	char* last_cache;
	char* scan_buff;
	void* rs_stream_para;
	long acc_scan_len;
	unsigned long long total_len;
	fuzzy_handle_t *fuzzy_hash_handle;
	pthread_mutex_t fuzzy_mutex;
	unsigned char query_point[8];
};
struct _Maat_scanner_t
{
	int version;
	time_t last_update_time;
	long long *ref_cnt;	//optimized for cache_alignment 64
	rule_scanner_t region;
	pthread_rwlock_t digest_rwlock[MAX_TABLE_NUM];
	GIE_handle_t*	digest_handle[MAX_TABLE_NUM];
	MESA_htable_handle region_hash;
	MESA_htable_handle group_hash;
	MESA_htable_handle compile_hash;
	MESA_htable_handle district_map;
	unsigned int district_num;
	unsigned int cfg_num;
	unsigned int exprid_generator;
	MESA_lqueue_head region_update_q;
	MESA_lqueue_head digest_update_q[MAX_TABLE_NUM];
	void * expr_compiler;
	scan_result_t *region_rslt_buff;
	MESA_lqueue_head tomb_ref;//reference of feather->garbage_q
	int max_thread_num;
	iconv_t iconv_handle[MAX_CHARSET_NUM][MAX_CHARSET_NUM];//iconv_handle[to][from]
};
struct _Maat_feather_t
{
	struct _Maat_scanner_t *scanner;
	struct _Maat_scanner_t *update_tmp_scanner;
	MESA_lqueue_head garbage_q;
	int table_cnt;
	int GROUP_MODE_ON;
	int still_working;
	int scan_interval_ms;
	int effect_interval_ms;
	int stat_on;
	int perf_on;
	struct _Maat_table_info_t *p_table_info[MAX_TABLE_NUM];
	MESA_htable_handle map_tablename2id;
	void* logger;
	int maat_version;
	int scan_thread_num;
	int rule_scan_type;
	char inc_dir[MAX_TABLE_NAME_LEN];
	char full_dir[MAX_TABLE_NAME_LEN];
	char stat_file[MAX_TABLE_NAME_LEN];
//for stat>>>>
	screen_stat_handle_t stat_handle;
	int total_stat_id;
	int fs_status_id[MAX_MAAT_STAT_NUM];
	int fs_column_id[MAX_MAAT_STAT_NUM];
	long long outer_mid_cnt;
	long long inner_mid_cnt;
	long long hit_cnt;
	long long *thread_call_cnt;//size indicate by scan_thread_num, 
};
struct _maat_garbage_t
{
	enum maat_garbage_type type;
	time_t create_time;
	int ok_times;
	union
	{
		struct _Maat_scanner_t* scanner;
		struct _Maat_group_rule_t* group_rule;
		struct _Maat_compile_rule_t* compile_rule;
		void* bool_matcher;
		void * raw;
	};
};
void garbage_bagging(enum maat_garbage_type type,void *p,MESA_lqueue_head garbage_q);
void garbage_bury(MESA_lqueue_head garbage_q,void *logger);
void make_group_set(const struct _Maat_compile_rule_t* compile_rule,universal_bool_expr_t* a_set);
int read_table_info(struct _Maat_table_info_t** p_table_info,int num,const char* table_info_path,void*logger);
void maat_start_cb(unsigned int new_version,int update_type,void*u_para);
void maat_update_cb(const char* table_name,const char* line,void *u_para);
void maat_finish_cb(void* u_para);
void *thread_rule_monitor(void *arg);
unsigned int make_sub_type(unsigned short table_id,enum MAAT_CHARSET charset,int do_charset_merge);
inline void ipv6_ntoh(unsigned int *v6_addr)
{
	unsigned int i=0;
	for(i=0;i<4;i++)
	{
		v6_addr[i]=ntohl(v6_addr[i]);
	}
	return;
}
void maat_stat_init(struct _Maat_feather_t* feather);
void maat_stat_table(struct _Maat_table_info_t* p_table,int scan_len,struct timespec* start, struct timespec* end);
void maat_stat_output(struct _Maat_feather_t* feather);



#endif


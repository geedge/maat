#ifndef H_MAAT_RULE_INTERNAL_H_INCLUDE
#define H_MAAT_RULE_INTERNAL_H_INCLUDE

#include "Maat_rule.h"
#include "Maat_command.h"

#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/field_stat2.h>
#include "dynamic_array.h"
#include "UniversalBoolMatch.h"
#include "rulescan.h"
#include "hiredis.h"

#include "stream_fuzzy_hash.h"
#include "gram_index_engine.h"
#include "aligment_int64.h"
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
#define	TRUE	1
#define	FALSE	0

#define	MAX_TABLE_NUM			256
#define	MAX_CONJUNCTION_TABLE_NUM	8
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
	TABLE_TYPE_INTERVAL,
	TABLE_TYPE_DIGEST,
	TABLE_TYPE_EXPR_PLUS,
	TABLE_TYPE_SIMILARITY,
	TABLE_TYPE_GROUP,
	TABLE_TYPE_COMPILE,
	TABLE_TYPE_PLUGIN

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
	char* digest_string;
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
	int convert_failed;
	int no_effect_convert_cnt;
	int table_id;
	int rule_type;
};

struct _Maat_region_inner_t
{
	int region_id;
	int district_id;
	int table_id;
	int expr_id_cnt;
	int expr_id_lb;
	int expr_id_ub;
	enum MAAT_TABLE_TYPE table_type;
};
struct _Maat_group_inner_t
{
	int group_id;
	int table_id;
	int region_boundary;
	int region_cnt;
	int ref_cnt;
	char* group_name;
	dynamic_array_t *regions;
	void* compile_shortcut;
	pthread_mutex_t mutex;
};
struct _Maat_compile_inner_t
{
	struct db_compile_rule_t *db_c_rule;
	dynamic_array_t *groups;
	int compile_id;//equal to db_c_rule->m_rule.config_id
	int table_id;
	int group_boundary;
	int group_cnt;
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
	int cache_line_num;
	int acc_line_num;
	int update_type;
	long cache_size;
};
struct _region_stat_t
{
	int cfg_num;
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
};
struct _Maat_table_info_t
{
	unsigned short table_id;
	unsigned short conj_cnt;
	unsigned short updating_name;
	char table_name[MAX_CONJUNCTION_TABLE_NUM][MAX_TABLE_NAME_LEN];
	enum MAAT_TABLE_TYPE table_type;
	enum MAAT_CHARSET src_charset;
	enum MAAT_CHARSET dst_charset[MAX_CHARSET_NUM];
	int src_charset_in_dst;
	int do_charset_merge;
	int cfg_num;
	int cross_cache_size;
	int quick_expr_switch;
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
	int valid_flag_column;
//for stat>>>>>>>>
	unsigned long long udpate_err_cnt;
	unsigned long long iconv_err_cnt;
	int stat_line_id;
	mcore_long_t	scan_cnt;
	mcore_long_t	scan_cpu_time;	//nano
	mcore_long_t	input_bytes;
	mcore_long_t	stream_num;
	mcore_long_t	hit_cnt;
};

struct _INNER_scan_status_t
{
	int cur_hit_cnt;
	int hit_group_cnt;
	int hit_group_size;
	unsigned int cur_hit_id[MAX_SCANNER_HIT_NUM];
	unsigned int *hitted_group_id;
};
struct _OUTER_scan_status_t
{
	struct _Maat_feather_t* feather;
	unsigned short thread_num;
	unsigned char is_set_district;
	unsigned char is_last_region;
	int district_id;
	struct _INNER_scan_status_t* inner;
};
enum maat_garbage_type
{
	GARBAGE_SCANNER=0,
	GARBAGE_GROUP_RULE,
	GARBAGE_COMPILE_RULE,
	GARBAGE_BOOL_MATCHER,
	GARBAGE_MAP_STR2INT
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
	long process_offset;
	unsigned long long total_len;
	sfh_instance_t *fuzzy_hash_handle;
	pthread_mutex_t fuzzy_mutex;
	unsigned char query_point[8];
};
struct GIE_aux_t
{
	enum MAAT_TABLE_TYPE table_type;
	GIE_handle_t*	gie_handle;
	MESA_lqueue_head update_q;
};
struct _Maat_scanner_t
{
	int version;
	time_t last_update_time;
	long long *ref_cnt;	//optimized for cache_alignment 64
	rule_scanner_t region;
	long gie_total_q_size;
	struct GIE_aux_t gie_aux[MAX_TABLE_NUM];
	MESA_htable_handle region_hash;
	MESA_htable_handle group_hash;
	MESA_htable_handle compile_hash;
	MESA_htable_handle district_map;
	MESA_htable_handle tmp_district_map;
	unsigned int district_num;
	unsigned int cfg_num;
	unsigned int exprid_generator;
	unsigned int dedup_expr_num;
	MESA_lqueue_head region_update_q;
	void * expr_compiler;
	scan_result_t *region_rslt_buff;
	MESA_lqueue_head tomb_ref;//reference of feather->garbage_q
	struct _region_stat_t region_counter[MAX_TABLE_NUM];
	int max_thread_num;
	iconv_t iconv_handle[MAX_CHARSET_NUM][MAX_CHARSET_NUM];//iconv_handle[to][from]
};
struct _Maat_feather_t
{
	struct _Maat_scanner_t *scanner;
	struct _Maat_scanner_t *update_tmp_scanner;
	MESA_lqueue_head garbage_q;
	int table_cnt;
	int DEFERRED_LOAD_ON;
	int GROUP_MODE_ON;
	int REDIS_MODE_ON;
	int still_working;
	int scan_interval_ms;
	int effect_interval_ms;
	int stat_on;
	int perf_on;
	struct _Maat_table_info_t *p_table_info[MAX_TABLE_NUM];
	MESA_htable_handle map_tablename2id;
	void* logger;
	int maat_version;
	int last_full_version;
	int scan_thread_num;
	int rule_scan_type;
	char inc_dir[MAX_TABLE_NAME_LEN];
	char full_dir[MAX_TABLE_NAME_LEN];
	char stat_file[MAX_TABLE_NAME_LEN];
	char instance_name[MAX_TABLE_NAME_LEN];
	char table_info_fn[MAX_TABLE_NAME_LEN];
	char compile_tn[MAX_TABLE_NAME_LEN];
	char group_tn[MAX_TABLE_NAME_LEN];
	pthread_mutex_t plugin_table_reg_mutex;
	unsigned char decrypt_key[MAX_TABLE_NAME_LEN];
	
	char redis_ip[MAX_TABLE_NAME_LEN];
	int redis_port;
	int redis_index;
	int AUTO_NUMBERING_ON;
	struct timeval connect_timeout;
	redisContext *redis_read_ctx;
	redisContext *redis_write_ctx;	// not thread safe.
	int on_redis_writing;
	int cmd_q_cnt;
	struct _Maat_cmd_inner_t* cmd_qhead, *cmd_qtail;
	pthread_mutex_t redis_write_lock; //protect redis_write_ctx
	long long base_rgn_seq,base_grp_seq,server_time;
//for stat>>>>
	screen_stat_handle_t stat_handle;
	int total_stat_id;
	int fs_status_id[MAX_MAAT_STAT_NUM];
	int fs_column_id[MAX_MAAT_STAT_NUM];
	mcore_long_t outer_mid_cnt;
	mcore_long_t inner_mid_cnt;
	mcore_long_t hit_cnt;
	mcore_long_t thread_call_cnt;//size indicate by scan_thread_num, 
	mcore_long_t orphan_group_saving;
	mcore_long_t last_region_saving;
	long long total_scan_bytes;
	long long total_scan_cnt;
	long long update_err_cnt;//sum of the same name variable in each table
	long long iconv_err_cnt;//sum of the same name variable in each table
	long long scan_err_cnt;	
	long long zombie_rs_stream;
	long long postpone_q_size;
	long long compile_rule_num;
	long long cmd_acc_num;
};
struct _maat_garbage_t
{
	enum maat_garbage_type type;
	time_t create_time;
	int ok_times;
	union
	{
		struct _Maat_scanner_t* scanner;
		struct _Maat_group_inner_t* group_rule;
		struct _Maat_compile_inner_t* compile_rule;
		void* bool_matcher;
		void * raw;
		MESA_htable_handle str2int_map;
	};
};
struct serial_rule_t		//rm= Redis Maat
{
	enum MAAT_OPERATION op;//0: delete, 1: add.
	int rule_id;
	int label_id;
	long long timeout;			// absolute unix time.
	char table_name[256];
	char* table_line;
};
void garbage_bagging(enum maat_garbage_type type,void *p,MESA_lqueue_head garbage_q);
void garbage_bury(MESA_lqueue_head garbage_q,void *logger);
void make_group_set(const struct _Maat_compile_inner_t* compile_rule,universal_bool_expr_t* a_set);
int read_table_info(struct _Maat_table_info_t** p_table_info,int num,const char* table_info_path,int max_thread_num,void* logger);
void maat_start_cb(unsigned int new_version,int update_type,void*u_para);
int maat_update_cb(const char* table_name,const char* line,void *u_para);
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
void * HASH_fetch_by_id(MESA_htable_handle hash,int id);
int HASH_add_by_id(MESA_htable_handle hash,int id,void*data);
int HASH_delete_by_id(MESA_htable_handle hash,int id);
void maat_read_full_config(_Maat_feather_t* _feather);
void maat_stat_init(struct _Maat_feather_t* feather);
void maat_stat_table(struct _Maat_table_info_t* p_table,int scan_len,struct timespec* start, struct timespec* end,int thread_num);
void maat_stat_output(struct _Maat_feather_t* feather);
char* _maat_strdup(const char* s);
char* str_unescape(char* s);
redisReply *_wrap_redisCommand(redisContext *c, const char *format, ...);
int get_rm_key_list(unsigned int version,redisContext *c,struct serial_rule_t** list,void* logger, unsigned int* new_version,int *update_type);
int get_maat_redis_value(redisContext *c,struct serial_rule_t* rule_list,int rule_num,void* logger,int print_process);
void empty_serial_rules(struct serial_rule_t* rule);
void redis_monitor_traverse(unsigned int version,redisContext *c,
							void (*start)(unsigned int ,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
							int (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
							void (*finish)(void*),//u_para
							void* u_para,
							const unsigned char* dec_key,
							_Maat_feather_t* feather);
const char*	module_name_str(const char*name);
#define maat_module	(module_name_str("MAAT_Frame"))


#endif


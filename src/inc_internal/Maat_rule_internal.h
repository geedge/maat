#ifndef H_MAAT_RULE_INTERNAL_H_INCLUDE
#define H_MAAT_RULE_INTERNAL_H_INCLUDE

#include "Maat_rule.h"
#include "Maat_command.h"
#include "Maat_table_description.h"

#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/field_stat2.h>
#include <MESA/rulescan.h>
#include "dynamic_array.h"
#include "bool_matcher.h"
#include "hiredis.h"

#include "stream_fuzzy_hash.h"
#include "gram_index_engine.h"
#include "alignment_int64.h"
#include <pthread.h>
#include <iconv.h>
#include <openssl/md5.h>

extern const char *maat_module;




#define	MAX_TABLE_NUM			256
#define	MAX_TABLE_LINE_SIZE		(1024*16)
#define	MAX_EXPR_KEYLEN			1024
#define	MAX_DISTRICT_LEN			64

#define	MAX_SCANNER_HIT_NUM			64
#define	MAX_GROUP_CACHE		128

#define	MAX_FAILED_NUM		128

#define	MAX_MAAT_STAT_NUM	64


typedef	void*	rule_scanner_t;



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
	int not_flag;
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
struct Maat_group_inner_t
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
struct Maat_compile_inner_t
{
	struct db_compile_rule_t *db_c_rule;
	dynamic_array_t *groups;	//element is struct Maat_group_inner_t*
	char not_flag[MAX_ITEMS_PER_BOOL_EXPR];
	char is_valid;
	int compile_id;//equal to db_c_rule->m_rule.config_id
	const struct Maat_table_desc* ref_table;
	int group_boundary;
	int group_cnt;
 	int not_group_cnt;
	MAAT_RULE_EX_DATA* ads;
	pthread_rwlock_t rwlock;//reading compile rule is safe in update thread, rwlock lock called when delete or scan thread read
};
struct _compile_result_t
{
	int compile_id;
	struct bool_expr group_set;
};
struct _INNER_scan_status_t
{
	size_t cur_hit_cnt;
	size_t hit_group_cnt;
	size_t hit_group_size;
	unsigned long long cur_hit_id[MAX_SCANNER_HIT_NUM];
	unsigned long long *hitted_group_id;
	char not_grp_compile_hitted_flag;
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
	GARBAGE_MAP_STR2INT,
	GARBAGE_FOREIGN_FILE
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
struct similar_runtime
{
	GIE_handle_t*	gie_handle;
	MESA_lqueue_head update_q;
};
struct plugin_runtime
{
	dynamic_array_t *cache_lines;
	long long cache_line_num;
	long long acc_line_num;
	long long cache_size;
	pthread_rwlock_t rwlock;
	MESA_htable_handle key2ex_hash;
};
struct expr_runtime
{
	long long expr_rule_cnt;	//expr_type=0,1,3
	long long regex_rule_cnt;	//expr_type=2
};
struct ip_runtime
{
	long long ipv4_rule_cnt;
	long long ipv6_rule_cnt;

};
struct group_runtime
{
	long long not_flag_group;
};
struct Maat_table_runtime
{
	enum MAAT_TABLE_TYPE table_type;
	long origin_rule_num;
	union
	{	
		struct similar_runtime similar;	//for digest and similarity
		struct plugin_runtime plugin;		
		struct expr_runtime expr;
		struct ip_runtime ip;
		struct group_runtime group;
		void * other;
	};
	mcore_long_t	scan_cnt;
	mcore_long_t	scan_cpu_time;	//nano
	mcore_long_t	input_bytes;
	mcore_long_t	stream_num;
	mcore_long_t	hit_cnt;
};
struct rule_tag
{
	char* tag_name;
	char* tag_val;
};
struct Maat_scanner_t
{
	long long version;
	time_t last_update_time;
	mcore_long_t ref_cnt;
	rule_scanner_t region;
	long gie_total_q_size;
	
	struct Maat_table_runtime* table_rt[MAX_TABLE_NUM];

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
	struct bool_matcher * bool_matcher_expr_compiler;
	scan_result_t *region_rslt_buff;
	MESA_lqueue_head tomb_ref;//reference of g_feather->garbage_q

	int max_thread_num;
	iconv_t iconv_handle[MAX_CHARSET_NUM][MAX_CHARSET_NUM];//iconv_handle[to][from]
};
enum data_source
{
	SOURCE_NONE=0,
	SOURCE_REDIS,
	SOURCE_IRIS_FILE,
	SOURCE_JSON_FILE
};
struct source_iris_ctx
{
	char inc_dir[MAX_TABLE_NAME_LEN];
	char full_dir[MAX_TABLE_NAME_LEN];
};
struct source_json_ctx
{
	char json_file[MAX_TABLE_NAME_LEN];
	char iris_file[MAX_TABLE_NAME_LEN];
	char effective_json_md5[MD5_DIGEST_LENGTH*2+1];
	time_t last_md5_time;
};
struct source_redis_ctx
{
	redisContext *read_ctx;
	redisContext *write_ctx;
	char redis_ip[64];
	int redis_port;
	int redis_db;
	time_t last_reconnect_time;
};
struct _Maat_feather_t
{
	struct Maat_scanner_t *scanner;
	struct Maat_scanner_t *update_tmp_scanner;
	MESA_lqueue_head garbage_q;
	int table_cnt;
	int DEFERRED_LOAD_ON;
	int GROUP_MODE_ON;
	int REDIS_MODE_ON;
	enum data_source input_mode;
	union
	{
		struct source_iris_ctx iris_ctx;
		struct source_json_ctx json_ctx;
		struct source_redis_ctx mr_ctx;
	};
	int still_working;
	int scan_interval_ms;
	int effect_interval_ms;
	int cumulative_update_off;
	int stat_on;
	int perf_on;
	struct Maat_table_desc *p_table_info[MAX_TABLE_NUM];
	MESA_htable_handle map_tablename2id;
	void* logger;
	long long maat_version;
	long long last_full_version;
	int scan_thread_num;
	int rule_scan_type;

	char stat_file[MAX_TABLE_NAME_LEN];
	char instance_name[MAX_TABLE_NAME_LEN];
	char table_info_fn[MAX_TABLE_NAME_LEN];
	char compile_tn[MAX_TABLE_NAME_LEN];
	char group_tn[MAX_TABLE_NAME_LEN];
	pthread_mutex_t background_update_mutex;
	unsigned char decrypt_key[MAX_TABLE_NAME_LEN];
	pthread_t cfg_mon_t;

	int AUTO_NUMBERING_ON;

//	redisContext *redis_write_ctx;	// not thread safe.

	int cmd_q_cnt;
	struct _Maat_cmd_inner_t* cmd_qhead, *cmd_qtail;
	long long base_rgn_seq,base_grp_seq,server_time;
	long long load_version_from;

	char* accept_tags_raw;
	struct rule_tag *accept_tags;
	int n_tags;
	
	char foreign_cont_dir[MAX_TABLE_NAME_LEN];
	int foreign_cont_linger;
//internal states
	long long new_version;
	int active_plugin_table_num;
	int is_last_plugin_table_updating;

//for scanner independent stat>>>>
	int backgroud_update_enabled;
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
	long long line_cmd_acc_num;
};
struct _maat_garbage_t
{
	enum maat_garbage_type type;
	time_t create_time;
	int expire_after;
	int ok_times;
	union
	{
		struct Maat_scanner_t* scanner;
		struct Maat_group_inner_t* group_rule;
		struct Maat_compile_inner_t* compile_rule;
		struct bool_matcher* bool_matcher;
		void * raw;
		MESA_htable_handle str2int_map;
		char* filename;
	};
};
struct foreign_key
{
	int column;
	int is_existed;
	char* key;
	char* filename;
};
struct serial_rule_t		//rm= Redis Maat
{
	enum MAAT_OPERATION op;//0: delete, 1: add.
	long rule_id;
	int label_id;
	char with_error;
	long long timeout;			// absolute unix time.
	char table_name[256];
	char* table_line;
	int n_foreign;
	struct foreign_key* f_keys;
};
int parse_accept_tag(const char* value, struct rule_tag** result, void* logger);
void garbage_bagging(enum maat_garbage_type type,void *p,MESA_lqueue_head garbage_q);
void garbage_bagging_with_timeout(enum maat_garbage_type type,void *p, int timeout, MESA_lqueue_head garbage_q);
void garbage_bury(MESA_lqueue_head garbage_q,void *logger);
void make_group_set(struct Maat_compile_inner_t* compile_rule, struct bool_expr* a_set, unsigned char *has_not);
int read_table_description(struct Maat_table_desc** p_table_info,int num,const char* table_info_path,int max_thread_num,void* logger);
void maat_start_cb(long long new_version,int update_type,void*u_para);
int maat_update_cb(const char* table_name,const char* line,void *u_para);
void maat_finish_cb(void* u_para);
void *thread_rule_monitor(void *arg);
unsigned int make_sub_type(unsigned short table_id,enum MAAT_CHARSET charset,int do_charset_merge);

void * HASH_fetch_by_id(MESA_htable_handle hash,int id);
int HASH_add_by_id(MESA_htable_handle hash,int id,void*data);
int HASH_delete_by_id(MESA_htable_handle hash,int id);
void maat_read_full_config(_Maat_feather_t* _feather);
void maat_stat_init(struct _Maat_feather_t* feather);
void maat_stat_table(struct Maat_table_runtime* p,int scan_len,struct timespec* start, struct timespec* end,int thread_num);
void maat_stat_output(struct _Maat_feather_t* feather);

redisReply *_wrap_redisCommand(redisContext *c, const char *format, ...);
int get_rm_key_list(redisContext *c, long long instance_version, long long desired_version, long long* new_version, struct serial_rule_t** list,int *update_type, void* logger, int cumulative_off);
int get_maat_redis_value(redisContext *c,struct serial_rule_t* rule_list,int rule_num,void* logger,int print_process);
int get_foreign_keys_by_prefix(redisContext *ctx, struct serial_rule_t* rule_list, int rule_num, const char* dir,void *logger);
void get_foreign_conts(redisContext *ctx, struct serial_rule_t* rule_list, int rule_num, int print_fn, void *logger);
void rewrite_table_line_with_foreign(struct serial_rule_t*p);

void fill_maat_rule(struct Maat_rule_t *rule, const struct _head_Maat_rule_t* rule_head, const char* srv_def, int srv_def_len);
MAAT_RULE_EX_DATA rule_ex_data_new(const struct _head_Maat_rule_t * rule_head, const char* srv_def, const struct compile_ex_data_idx* ex_desc);
void rule_ex_data_free(const struct _head_Maat_rule_t * rule_head, const char* srv_def, MAAT_RULE_EX_DATA *ad, const struct compile_ex_data_idx* ex_desc);
MESA_htable_handle wrap_plugin_EX_hash_new(long long estimate_size, Maat_plugin_EX_key2index_func_t * key2index);
int plugin_EX_data_new(const struct Maat_table_desc* plugin_table, const char* line, MESA_htable_handle key2ex_hash, void *logger);
int plugin_EX_data_free(const struct Maat_table_desc* plugin_table, const char* line, MESA_htable_handle key2ex_hash, void *logger);


void set_serial_rule(struct serial_rule_t* rule,enum MAAT_OPERATION op,int rule_id,int label_id,const char* table_name,const char* line, long long timeout);
void empty_serial_rules(struct serial_rule_t* rule);
int exec_serial_rule(redisContext* ctx,struct serial_rule_t* s_rule,unsigned int serial_rule_num, long long server_time, void* logger);
long long redis_server_time(redisContext* ctx);
redisContext * connect_redis(const char*redis_ip, int redis_port, int redis_db, void* logger);
char* md5_file(const char* filename, char* md5string);

void redis_monitor_traverse(long        long version, struct source_redis_ctx* mr_ctx,
		void (*start)(long long,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
		int (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
		void (*finish)(void*),//u_para
		void* u_para,
		const unsigned char* dec_key,
		_Maat_feather_t* feather);



#endif


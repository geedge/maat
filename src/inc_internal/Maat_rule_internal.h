#pragma once

#include "Maat_rule.h"
#include "Maat_command.h"
#include "Maat_limits.h"
#include "Maat_table.h"
#include "Maat_table_runtime.h"

#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/field_stat2.h>
#include <MESA/rulescan.h>
#include "dynamic_array.h"
#include "hiredis.h"
#include "IPMatcher.h"
#include "stream_fuzzy_hash.h"
#include "gram_index_engine.h"
#include "alignment_int64.h"
#include <pthread.h>
#include <iconv.h>
#include <openssl/md5.h>
#include <sys/queue.h>



#define mr_region_id_var	"SEQUENCE_REGION"
#define mr_group_id_var		"SEQUENCE_GROUP"





typedef	void*	rule_scanner_t;



struct db_str_rule_t
{
	int region_id;
	int group_id;
	char keywords[MAX_EXPR_KEYLEN+1];
	char district[MAX_DISTRICT_LEN+1];
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
struct db_intval_rule
{
	int region_id;
	int group_id;
	interval_rule_t intval;
	int is_valid;
};
struct db_digest_rule
{
	int region_id;
	int group_id;
	unsigned long long orgin_len;
	char* digest_string;
	short confidence_degree;
	int is_valid;
};
struct Maat_rule_head
{
	int 	config_id;
	int		service_id;
	char 	do_log;
	char 	do_blacklist;
	char	action;
	char	resevered;
	int		serv_def_len;
};

#define	COMPILE_RULE_MAGIC	0x1a2b3c4d
struct Maat_compile_rule
{
	long long magic_num;
	struct Maat_rule_head head;// fix len of Maat_rule_t
	char* service_defined;
	int is_valid;
	int declared_clause_num;
	double evaluation_order;
	const struct Maat_table_schema* ref_table;
	MAAT_RULE_EX_DATA* ads;
	int compile_id;
	pthread_rwlock_t rwlock;
};
struct db_group2group_rule
{
	int group_id;
	int superior_group_id;
	int is_valid;
};
struct db_group2compile_rule
{
	int group_id;
	int compile_id;
	int is_valid;
	int not_flag;
	int virtual_table_id;
	int clause_index;
};
struct db_group_rule_t
{
	int group_id;
	int parent_id;
	int is_valid;
	int not_flag;
	int parent_type;	//PARENT_TYPE_**, 0:compile, 1: group.
	int virtual_table_id;
	int clause_id;
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

struct Maat_region_inner
{
	int region_id;
	int group_id;
	int district_id;
	int table_id;
	int expr_id_cnt;
	int expr_id_lb;
	int expr_id_ub;
	enum MAAT_TABLE_TYPE table_type;
};


struct _OUTER_scan_status_t
{
	struct _Maat_feather_t* feather;
	unsigned short thread_num;
	unsigned char is_set_district;
	unsigned char is_last_region;
	int district_id;
	int scan_cnt;
	struct Maat_hierarchy_compile_mid* compile_mid;
};

struct iconv_handle_t
{
	int is_initialized;
	iconv_t cd;
};
struct _stream_para_t
{
	struct _Maat_feather_t* feather;
	const struct Maat_table_schema* p_real_table;
	int virtual_table_id;
	int version;
	int thread_num;
	int max_cross_size;
	int caching_size;
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

struct rule_tag
{
	char* tag_name;
	char* tag_val;
};
struct Maat_scanner
{
	long long version;
	time_t last_update_time;
	mcore_long_t ref_cnt;
	rule_scanner_t region;
	size_t gie_update_q_size;
	size_t to_update_group_cnt;
	size_t to_update_compile_cnt;

	struct Maat_table_runtime_manager*  table_rt_mgr;
	size_t max_table_num;

	struct Maat_hierarchy * hier;
	struct Maat_garbage_bin* ref_garbage_bin;


	MESA_htable_handle district_map;
	MESA_htable_handle tmp_district_map;


	int most_popular_sub_group;
	unsigned long long max_presented_top_group_cnt;
	
	unsigned int district_num;
	unsigned int cfg_num;
	unsigned int exprid_generator;
	unsigned int dedup_expr_num;
	MESA_lqueue_head region_update_q;

	scan_result_t *region_rslt_buff;
	GIE_result_t* gie_rslt_buff;
	void* logger_ref;

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
	struct timespec last_md5_time;
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
	struct Maat_scanner *scanner;
	struct Maat_scanner *update_tmp_scanner;
	struct Maat_garbage_bin * garbage_bin;
	struct Maat_table_manager* table_mgr;
	
	int DEFERRED_LOAD_ON;
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
	
	void* logger;
	long long maat_version;
	long long last_full_version;
	int scan_thread_num;
	int rule_scan_type;

	char stat_file[MAX_TABLE_NAME_LEN];
	char instance_name[MAX_TABLE_NAME_LEN];
	char table_info_fn[MAX_TABLE_NAME_LEN];
	char compile_tn[MAX_TABLE_NAME_LEN];
	char group2compile_tn[MAX_TABLE_NAME_LEN];
	char group2group_tn[MAX_TABLE_NAME_LEN];
	char group_tn[MAX_TABLE_NAME_LEN];
	pthread_mutex_t background_update_mutex;
	char decrypt_key[MAX_TABLE_NAME_LEN];
	char decrypt_algo[MAX_TABLE_NAME_LEN];
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
//internal states
	long long new_version;

//for scanner independent stat>>>>
	int backgroud_update_enabled;
	screen_stat_handle_t stat_handle;
	int total_stat_id;
	int fs_status_id[MAX_MAAT_STAT_NUM];
	int fs_column_id[MAX_MAAT_STAT_NUM];
	mcore_long_t outer_mid_cnt;
	mcore_long_t  compile_mid_cnt;
	mcore_long_t hit_cnt;
	mcore_long_t thread_call_cnt;//size indicate by scan_thread_num, 
	mcore_long_t not_grp_hit_cnt;
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

struct foreign_key
{
	int column;
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
	TAILQ_ENTRY(serial_rule_t) entries;
};
int parse_accept_tag(const char* value, struct rule_tag** result, void* logger);

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

void fill_maat_rule(struct Maat_rule_t *rule, const struct Maat_rule_head* rule_head, const char* srv_def, int srv_def_len);
MAAT_RULE_EX_DATA rule_ex_data_new(const struct Maat_rule_head * rule_head, const char* srv_def, const struct compile_ex_data_idx* ex_desc);
void rule_ex_data_free(const struct Maat_rule_head * rule_head, const char* srv_def, MAAT_RULE_EX_DATA *ad, const struct compile_ex_data_idx* ex_desc);


void set_serial_rule(struct serial_rule_t* rule,enum MAAT_OPERATION op,int rule_id,int label_id,const char* table_name,const char* line, long long timeout);
void empty_serial_rules(struct serial_rule_t* rule);
int exec_serial_rule(redisContext* ctx,struct serial_rule_t* s_rule,unsigned int serial_rule_num, long long server_time, void* logger);
long long redis_server_time(redisContext* ctx);
redisContext * connect_redis(const char*redis_ip, int redis_port, int redis_db, void* logger);

int load_maat_json_file(_Maat_feather_t* feather, const char* maat_json_fn, char* err_str, size_t err_str_sz);
void redis_monitor_traverse(long        long version, struct source_redis_ctx* mr_ctx,
		void (*start)(long long,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
		int (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
		void (*finish)(void*),//u_para
		void* u_para,
		const char* dec_key,
		_Maat_feather_t* feather);



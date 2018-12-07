#pragma once
#include "Maat_rule.h"
#define	MAX_COMPILE_EX_DATA_NUM		2
#define	MAX_FOREIGN_CLMN_NUM		8
#define	MAX_PLUGIN_PER_TABLE		32
#define	MAX_CHARSET_NUM				16
#define	MAX_CONJUNCTION_TABLE_NUM	8
#define	MAX_TABLE_NAME_LEN			256	

enum USER_REGION_ENCODE
{
	USER_REGION_ENCODE_NONE=0,
	USER_REGION_ENCODE_ESCAPE,
	USER_REGION_ENCODE_BASE64
};

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

struct compile_ex_data_idx
{
	Maat_rule_EX_new_func_t *new_func;
	Maat_rule_EX_free_func_t* free_func;
	Maat_rule_EX_dup_func_t* dup_func;
	long argl;
	void *argp;
	int idx;
	int table_id;
};
struct compile_table_desc
{
	enum USER_REGION_ENCODE user_region_encoding;
	int ex_data_num;
	struct compile_ex_data_idx ex_desc[MAX_COMPILE_EX_DATA_NUM];
};

struct plugin_table_callback_desc
{
	Maat_start_callback_t 	*start;
	Maat_update_callback_t	*update;
	Maat_finish_callback_t	*finish;
	void* u_para;
};
struct plugin_table_ex_data_desc
{
	Maat_plugin_EX_new_func_t* new_func;
	Maat_plugin_EX_free_func_t* free_func;
	Maat_plugin_EX_dup_func_t* dup_func;
	Maat_plugin_EX_key2index_func_t* key2index_func;
	long argl;
	void *argp;
};
struct plugin_table_desc
{
	int key_column;
	int valid_flag_column;
	int rule_tag_column;
	int n_foreign;
	int foreign_columns[MAX_FOREIGN_CLMN_NUM];
	int cb_plug_cnt;
	int have_exdata;
	long long estimate_size;
	struct plugin_table_callback_desc cb_plug[MAX_PLUGIN_PER_TABLE];	
	struct plugin_table_ex_data_desc ex_desc;
};
struct expr_table_desc
{
	enum MAAT_CHARSET src_charset;
	enum MAAT_CHARSET dst_charset[MAX_CHARSET_NUM];
	int src_charset_in_dst;
	int do_charset_merge;
	int cross_cache_size;
	int quick_expr_switch;
	long long iconv_err_cnt;
};
struct ip_table_desc
{
	int ipv4_rule_cnt;
	int ipv6_rule_cnt;
};

struct Maat_table_desc
{
	int table_id;
	int conj_cnt;
	int updating_name;
	char table_name[MAX_CONJUNCTION_TABLE_NUM][MAX_TABLE_NAME_LEN];
	enum MAAT_TABLE_TYPE table_type;
	union
	{
		struct compile_table_desc compile;		
		struct expr_table_desc expr;
		struct ip_table_desc ip;		
		struct plugin_table_desc plugin;
		void* others;//group, interval and digest don't have sperate description info.
	};	
//for stat>>>>>>>>
	unsigned long long udpate_err_cnt;
	unsigned long long unmatch_tag_cnt;
	int stat_line_id;
};


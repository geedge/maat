#pragma once
#include <MESA/MESA_htable.h>
#include "Maat_rule.h"
#include "Maat_limits.h"

#define	MAX_COMPILE_EX_DATA_NUM		2
#define	MAX_FOREIGN_CLMN_NUM		8
#define	MAX_PLUGIN_PER_TABLE		32
#define	MAX_CHARSET_NUM				__CHARSET_MAX
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
	TABLE_TYPE_INVALID=-1,
	TABLE_TYPE_EXPR=0,
	TABLE_TYPE_IP,
	TABLE_TYPE_IP_PLUS,
	TABLE_TYPE_INTERVAL,
	TABLE_TYPE_DIGEST,
	TABLE_TYPE_EXPR_PLUS,
	TABLE_TYPE_SIMILARITY,
	TABLE_TYPE_VIRTUAL,
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

struct expr_table_desc
{
	enum MAAT_CHARSET src_charset;
	enum MAAT_CHARSET dst_charset[MAX_CHARSET_NUM];
	int src_charset_in_dst;
	int do_charset_merge;
	int cross_cache_size;
	int quick_expr_switch;//obsolete since 20190401
	long long iconv_err_cnt;
};
struct virtual_table_desc
{
	int real_table_id;
	char real_table_name[MAX_TABLE_NAME_LEN];
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
		struct plugin_table_desc plugin;		
		struct virtual_table_desc virtual_table;;
		void* others;//group, ip, interval and digest don't have sperate description info.
	};	
//for stat>>>>>>>>
	unsigned long long udpate_err_cnt;
	unsigned long long unmatch_tag_cnt;
	int stat_line_id;
};
struct Maat_table_manager;
struct Maat_table_manager* Maat_table_manager_create(const char* table_info_path, void* logger);
void Maat_table_manager_destroy(struct Maat_table_manager* table_mgr);
size_t Maat_table_manager_get_size(struct Maat_table_manager* table_mgr);
size_t Maat_table_manager_get_count(struct Maat_table_manager* table_mgr);

struct Maat_table_desc * Maat_table_get_by_id(struct Maat_table_manager* table_mgr, int table_id, enum MAAT_TABLE_TYPE expect_type, int* virutal_table_id);
struct Maat_table_desc * Maat_table_get_by_id_raw(struct Maat_table_manager* table_mgr, int table_id);

int Maat_table_get_id_by_name(struct Maat_table_manager* table_mgr, const char* table_name);
int Maat_table_add_callback_func(struct Maat_table_manager* table_mgr,
									int table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para);
int Maat_table_get_compile_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz);
int Maat_table_get_group_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz);
const char* Maat_table_get_name_by_id(struct Maat_table_manager* table_mgr, int table_id);
enum MAAT_TABLE_TYPE Maat_table_get_type_by_id(struct Maat_table_manager* table_mgr, int table_id);

int Maat_table_new_compile_rule_ex_index(struct Maat_table_manager* table_mgr, const char* compile_table_name,
										 Maat_rule_EX_new_func_t *new_func,
										 Maat_rule_EX_free_func_t* free_func,
										 Maat_rule_EX_dup_func_t* dup_func,
										 long argl, void *argp);
struct compile_ex_data_idx* Maat_table_get_compile_rule_ex_desc(struct Maat_table_manager* table_mgr, const char* compile_table_name, int idx);
int Maat_table_plugin_new_ex_index(struct Maat_table_manager* table_mgr, int table_id,
										Maat_plugin_EX_new_func_t* new_func,
										Maat_plugin_EX_free_func_t* free_func,
										Maat_plugin_EX_dup_func_t* dup_func,
										Maat_plugin_EX_key2index_func_t* key2index_func,
										long argl, void *argp);
void Maat_table_manager_all_plugin_cb_start(struct Maat_table_manager* table_mgr, int update_type);
void Maat_table_manager_all_plugin_cb_finish(struct Maat_table_manager* table_mgr);

int Maat_table_manager_is_last_plugin_table_updating(struct Maat_table_manager* table_mgr);
struct Maat_table_desc* Maat_table_get_desc_by_name(struct Maat_table_manager* table_mgr, const char* table_name);
void Maat_table_set_updating_name(struct Maat_table_desc* p_table, const char* table_name);


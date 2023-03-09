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
enum MAAT_SCAN_TYPE
{
	SCAN_TYPE_INVALID=-1,
	SCAN_TYPE_NONE=0,
	SCAN_TYPE_PLUGIN,
	SCAN_TYPE_IP_PLUGIN,
	SCAN_TYPE_FQDN_PLUGIN,
	SCAN_TYPE_BOOL_PLUGIN,
	SCAN_TYPE_IP,
	SCAN_TYPE_INTERVAL,
	SCAN_TYPE_STRING,
    SCAN_TYPE_FLAG,
	__SCAN_TYPE_MAX
};

enum MAAT_TABLE_COMPONENT_TYPE
{	
	COMPONENT_TABLE_TYPE_NONE=-1,
	COMPONENT_TABLE_TYPE_SOURCE_IP=0,
	COMPONENT_TABLE_TYPE_DESTINATION_IP,
	COMPONENT_TABLE_TYPE_SESSION,
	__COMPONENT_TABLE_TYPE_MAX
};


enum MAAT_TABLE_TYPE
{	
	TABLE_TYPE_INVALID=-1,
    TABLE_TYPE_FLAG=0,
	TABLE_TYPE_EXPR,
	TABLE_TYPE_IP,
	TABLE_TYPE_IP_PLUS,
	TABLE_TYPE_INTERVAL,
	TABLE_TYPE_DIGEST,
	TABLE_TYPE_EXPR_PLUS,
	TABLE_TYPE_SIMILARITY,
	TABLE_TYPE_INTERVAL_PLUS,
	//Above are physical table for scan
	TABLE_TYPE_VIRTUAL,
	TABLE_TYPE_COMPOSITION,
	TABLE_TYPE_GROUP2GROUP,
	TABLE_TYPE_GROUP2COMPILE,
	TABLE_TYPE_GROUP,
	TABLE_TYPE_COMPILE,
	TABLE_TYPE_PLUGIN,
	TABLE_TYPE_IP_PLUGIN,
	TABLE_TYPE_FQDN_PLUGIN,
	TABLE_TYPE_BOOL_PLUGIN
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
struct compile_table_schema
{
	enum USER_REGION_ENCODE user_region_encoding;
	int ex_data_num;
	struct compile_ex_data_idx ex_desc[MAX_COMPILE_EX_DATA_NUM];
};

struct expr_table_schema
{
	enum MAAT_CHARSET src_charset;
	enum MAAT_CHARSET dst_charset[MAX_CHARSET_NUM];
	int src_charset_in_dst;
	int do_charset_merge;
	int cross_cache_size;
	int quick_expr_switch;//obsolete since 20190401
	long long iconv_err_cnt;
};
struct virtual_table_schema
{
	int physical_table_id[__SCAN_TYPE_MAX];
};
struct composition_table_schema
{	
	int component_table_id[__COMPONENT_TABLE_TYPE_MAX];
};
struct plugin_table_callback_schema
{
	Maat_start_callback_t 	*start;
	Maat_update_callback_t	*update;
	Maat_finish_callback_t	*finish;
	void* u_para;
};
struct EX_data_schema
{
	Maat_plugin_EX_new_func_t* new_func;
	Maat_plugin_EX_free_func_t* free_func;
	Maat_plugin_EX_dup_func_t* dup_func;
	Maat_plugin_EX_key2index_func_t* key2index_func;
	long argl;
	void *argp;
	int set_flag;
};
struct plugin_table_schema
{
	int key_column;
	int valid_flag_column;
	int rule_tag_column;
	int n_foreign;
	int foreign_columns[MAX_FOREIGN_CLMN_NUM];
	int cb_plug_cnt;
	struct plugin_table_callback_schema cb_plug[MAX_PLUGIN_PER_TABLE];	
	struct EX_data_schema ex_schema;
};
struct ip_plugin_table_schema
{
	int row_id_column;
	int ip_type_column;
	int start_ip_column;
	int end_ip_column;
	int valid_flag_column;
	int rule_tag_column;
	int have_exdata;
	struct EX_data_schema ex_schema;
};
struct fqdn_plugin_table_schema
{

	int row_id_column;
	int is_suffix_flag_column;	
	int fqdn_column;
	int valid_flag_column;
	int rule_tag_column;
	int have_exdata;
	struct EX_data_schema ex_schema;
};
struct bool_plugin_table_schema
{
	int row_id_column;
	int bool_expr_column;
	int rule_tag_column;
	int valid_flag_column;
	int have_exdata;
	struct EX_data_schema ex_schema;

};
struct Maat_table_schema
{
	int table_id;
	int conj_cnt;
	int updating_name;
	char table_name[MAX_CONJUNCTION_TABLE_NUM][MAX_TABLE_NAME_LEN];
	enum MAAT_TABLE_TYPE table_type;
	union
	{
		struct compile_table_schema compile;		
		struct expr_table_schema expr;
		struct plugin_table_schema plugin;		
		struct ip_plugin_table_schema ip_plugin;
		struct fqdn_plugin_table_schema fqdn_plugin;
		struct bool_plugin_table_schema bool_plugin;
		struct virtual_table_schema virtual_table;
		struct composition_table_schema composition;
		void* others;//group, ip, interval and digest don't have any special schema.
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

struct Maat_table_schema * Maat_table_manager_get_scan_by_id(struct Maat_table_manager* table_mgr, int table_id, enum MAAT_SCAN_TYPE scan_type, int* virutal_table_id);
struct Maat_table_schema * Maat_table_manager_get_by_id_raw(struct Maat_table_manager* table_mgr, int table_id);
enum MAAT_SCAN_TYPE Maat_table_get_scan_type(enum MAAT_TABLE_TYPE table_type);

int Maat_table_manager_get_id_by_name(struct Maat_table_manager* table_mgr, const char* table_name);
int Maat_table_manager_add_callback_func(struct Maat_table_manager* table_mgr,
									int table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para);
int Maat_table_manager_get_compile_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz);
int Maat_table_manager_get_group2compile_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz);
int Maat_table_manager_get_group2group_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz);

const char* Maat_table_manager_get_name_by_id(struct Maat_table_manager* table_mgr, int table_id);
enum MAAT_TABLE_TYPE Maat_table_manager_get_type_by_id(struct Maat_table_manager* table_mgr, int table_id);

int Maat_table_manager_new_compile_rule_ex_index(struct Maat_table_manager* table_mgr, const char* compile_table_name,
										 Maat_rule_EX_new_func_t *new_func,
										 Maat_rule_EX_free_func_t* free_func,
										 Maat_rule_EX_dup_func_t* dup_func,
										 long argl, void *argp);
struct compile_ex_data_idx* Maat_table_manager_get_compile_rule_ex_desc(struct Maat_table_manager* table_mgr, const char* compile_table_name, int idx);
int Maat_table_schema_set_EX_data_schema(struct Maat_table_schema *table_schema,
										Maat_plugin_EX_new_func_t* new_func,
										Maat_plugin_EX_free_func_t* free_func,
										Maat_plugin_EX_dup_func_t* dup_func,
										Maat_plugin_EX_key2index_func_t* key2index_func,
										long argl, void *argp,
										void* logger);
struct EX_data_schema *Maat_table_schema_get_EX_data_schema(struct Maat_table_schema *table_schema);


void Maat_table_manager_all_plugin_cb_start(struct Maat_table_manager* table_mgr, int update_type);
void Maat_table_manager_all_plugin_cb_finish(struct Maat_table_manager* table_mgr);

int Maat_table_manager_is_last_plugin_table_updating(struct Maat_table_manager* table_mgr);
struct Maat_table_schema* Maat_table_manager_get_desc_by_name(struct Maat_table_manager* table_mgr, const char* table_name);
void Maat_table_schema_set_updating_name(struct Maat_table_schema* p_table, const char* table_name);

int Maat_table_manager_get_child_id(struct Maat_table_manager* table_mgr, int parent_table_id, enum MAAT_TABLE_COMPONENT_TYPE type);
int Maat_table_schema_get_valid_flag_column(struct Maat_table_schema* p_table);


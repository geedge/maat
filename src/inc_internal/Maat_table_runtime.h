#pragma once

#include "Maat_table_schema.h"
#include "Maat_ex_data.h"

#include "IPMatcher.h"
#include "gram_index_engine.h"
#include "bool_matcher.h"
#include "flag_matcher.h"
#include "FQDN_engine.h"
#include "alignment_int64.h"
#include "rcu_hash.h"
#include <MESA/MESA_list_queue.h>

struct flag_runtime
{
    struct flag_matcher *matcher;
    struct rcu_hash_table *htable;
};
struct similar_runtime
{
	GIE_handle_t*	gie_handle;
	MESA_lqueue_head update_q;
};
struct fqdn_plugin_runtime
{
	struct FQDN_engine* fqdn_engine;
	struct EX_data_rt* ex_data_rt;
	int changed_flag;
};
struct bool_plugin_runtime
{
	struct bool_matcher *matcher;
	struct EX_data_rt* ex_data_rt;
	int changed_flag;
};
struct plugin_runtime
{
	struct EX_data_rt* ex_data_rt;
	long long acc_line_num;
};

struct ip_plugin_runtime
{
	struct EX_data_rt* ex_data_rt;
	struct ip_matcher* ip_matcher;
	size_t mem_use_by_ip_matcher;
	int changed_flag;
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
struct group2compile_runtime
{
	long long not_flag_group;
};
struct Maat_table_runtime
{
	enum MAAT_TABLE_TYPE table_type;
	long origin_rule_num;
	union
	{	
        struct flag_runtime flag;
		struct similar_runtime similar;	//for digest and similarity
		struct fqdn_plugin_runtime fqdn_plugin;//for fqdn_plugin and fqdn_plugin
		struct bool_plugin_runtime bool_plugin;
		struct plugin_runtime plugin;		
		struct ip_plugin_runtime ip_plugin;
		struct expr_runtime expr;
		struct ip_runtime ip;
		struct group2compile_runtime group2compile;		
		void * other;
	};
	mcore_long_t	scan_cnt;
	mcore_long_t	scan_cpu_time;	//nano
	mcore_long_t	input_bytes;
	mcore_long_t	stream_num;
	mcore_long_t	hit_cnt;
	struct Maat_garbage_bin* ref_garbage_bin;
};


struct Maat_table_runtime_manager;
struct Maat_table_runtime_manager* Maat_table_runtime_manager_create(struct Maat_table_manager* table_manager, int max_thread_num, struct Maat_garbage_bin* bin);
void Maat_table_rt_manager_destroy(struct Maat_table_runtime_manager* table_rt_mgr);
struct Maat_table_runtime* Maat_table_runtime_get(struct Maat_table_runtime_manager* table_rt_mgr, int table_id);
void Maat_table_runtime_perf_stat(struct Maat_table_runtime* p, int scan_len, struct timespec* start, struct timespec* end,int thread_num);
enum MAAT_TABLE_TYPE Maat_table_runtime_get_type(struct Maat_table_runtime* table_rt);

size_t Maat_table_runtime_plugin_cached_row_count(struct Maat_table_runtime* table_rt);
const char* Maat_table_runtime_plugin_get_cached_row(struct Maat_table_runtime* table_rt, size_t Nth_row);

int Maat_table_runtime_commit_EX_data_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger);
void Maat_table_runtime_digest_add(struct Maat_table_runtime* table_rt, int expr_id, const char* digest, short confidence_degree, void* tag);
void Maat_table_runtime_digest_del(struct Maat_table_runtime* table_rt, int expr_id);
int Maat_table_runtime_digest_batch_udpate(struct Maat_table_runtime* table_rt);

void Maat_table_runtime_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);
void Maat_table_runtime_plugin_commit_update(struct Maat_table_runtime* table_rt);
MAAT_PLUGIN_EX_DATA Maat_table_runtime_plugin_get_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_desc, const char* key);

void Maat_table_runtime_ip_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);
int Maat_table_runtime_ip_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const struct ip_data* ip, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size);
int Maat_table_runtime_ip_plugin_commit_update(struct Maat_table_runtime* table_rt);

void Maat_table_runtime_fqdn_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);
int Maat_table_runtime_fqdn_plugin_commit_update(struct Maat_table_runtime* table_rt);
int Maat_table_runtime_fqdn_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* query_fqdn, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size);

void Maat_table_runtime_bool_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);
int Maat_table_runtime_bool_plugin_commit_update(struct Maat_table_runtime* table_rt);
int Maat_table_runtime_bool_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, unsigned long long item_ids[], size_t n_item, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size);

void Maat_table_runtime_flag_add(struct Maat_table_runtime *table_rt, int expr_id, uint64_t flag, uint64_t mask, void *tag);
void Maat_table_runtime_flag_del(struct Maat_table_runtime *table_rt, int expr_id);
int Maat_table_runtime_flag_commit_update(struct Maat_table_runtime* table_rt, void *logger);

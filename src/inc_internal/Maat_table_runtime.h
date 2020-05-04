#include "Maat_table.h"
#include "Maat_ex_data.h"
#include "IPMatcher.h"
#include "gram_index_engine.h"
#include "alignment_int64.h"
#include "dynamic_array.h"
#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>

struct similar_runtime
{
	GIE_handle_t*	gie_handle;
	MESA_lqueue_head update_q;
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
	struct ip_matcher* old_ip_matcher;
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
		struct ip_plugin_runtime ip_plugin;
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
struct Maat_table_runtime_manager;
struct Maat_table_runtime_manager* Maat_table_runtime_manager_create(struct Maat_table_manager* table_manager, int max_thread_num);
void Maat_table_rt_manager_destroy(struct Maat_table_runtime_manager* table_rt_mgr);
struct Maat_table_runtime* Maat_table_runtime_get(struct Maat_table_runtime_manager* table_rt_mgr, int table_id);
long long Maat_table_runtime_plugin_cached_line_count(struct Maat_table_runtime* table_rt);
const char* Maat_table_runtime_plugin_get_cached_line(struct Maat_table_runtime* table_rt, long long Nth_line);

int Maat_table_runtime_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_desc, void* logger);
MAAT_PLUGIN_EX_DATA Maat_table_runtime_plugin_get_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_desc, const char* key);
void Maat_table_runtime_digest_add(struct Maat_table_runtime* table_rt, int expr_id, const char* digest, short confidence_degree, void* tag);
void Maat_table_runtime_digest_del(struct Maat_table_runtime* table_rt, int expr_id);
int Maat_table_runtime_digest_batch_udpate(struct Maat_table_runtime* table_rt);

void Maat_table_runtime_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);
void Maat_table_runtime_ip_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);

int Maat_table_runtime_ip_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger);
int Maat_table_runtime_ip_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const struct ip_data* ip, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size);
int Maat_table_runtime_ip_plugin_rebuild_ip_matcher(struct Maat_table_runtime* table_rt);
struct ip_matcher* Maat_table_runtime_dettach_old_ip_matcher(struct Maat_table_runtime* table_rt);



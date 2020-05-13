
#include "dynamic_array.h"
#include "Maat_rule.h"
#include <MESA/MESA_htable.h>

#include <sys/queue.h>

struct EX_data_rt
{
	dynamic_array_t *cache_rows;
	long long cache_row_num;
	long long cache_size;
	MESA_htable_handle key2ex_hash;
	const struct EX_data_schema* ex_schema;
	int table_id;
	void (* user_data_free)(void *user_data);
};
struct EX_data_container
{
	MAAT_RULE_EX_DATA ex_data;
	const struct EX_data_rt* rt;
	void* user_data;
	TAILQ_ENTRY(EX_data_container) entries;
};

TAILQ_HEAD(EX_data_container_q,      EX_data_container);
struct EX_data_rt* EX_data_rt_new(int table_id, long long estimate_size, Maat_plugin_EX_key2index_func_t * key2index, void (* user_data_free)(void *user_data));
void EX_data_rt_free(struct EX_data_rt* p);
void EX_data_rt_set_schema(struct EX_data_rt* p, const struct EX_data_schema* schema);
void EX_data_rt_cache_row(struct EX_data_rt* p, const char* row);

const char* EX_data_rt_get_cached_row(struct EX_data_rt* p, int i);

void EX_data_rt_clear_row_cache(struct EX_data_rt* p);
int EX_data_rt_get_row_num(struct EX_data_rt* p);

struct EX_data_container* EX_data_rt_row2EX_data(struct EX_data_rt* ex_rt, 
											const char* row, const char* key, size_t key_len,
											void* user_data, void* logger);

int EX_data_rt_delete_by_row(struct EX_data_rt* ex_rt, const char* row, const char* key, size_t key_len,	void *logger);
MAAT_RULE_EX_DATA  EX_data_rt_get_EX_data_by_key(struct EX_data_rt* ex_rt, const char* key, size_t key_len);
MAAT_RULE_EX_DATA  EX_data_rt_get_EX_data_by_container(struct EX_data_rt* ex_rt, struct EX_data_container* container);
size_t EX_data_rt_list_all(struct EX_data_rt* ex_rt, EX_data_container_q* listed);


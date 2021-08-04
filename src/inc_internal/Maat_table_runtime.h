#include "Maat_table.h"
#include "Maat_ex_data.h"



struct Maat_table_runtime_manager;
struct Maat_table_runtime;
struct Maat_table_runtime_manager* Maat_table_runtime_manager_create(struct Maat_table_manager* table_manager, int max_thread_num, struct Maat_garbage_bin* bin);
void Maat_table_rt_manager_destroy(struct Maat_table_runtime_manager* table_rt_mgr);
struct Maat_table_runtime* Maat_table_runtime_get(struct Maat_table_runtime_manager* table_rt_mgr, int table_id);

size_t Maat_table_runtime_plugin_cached_row_count(struct Maat_table_runtime* table_rt);
const char* Maat_table_runtime_plugin_get_cached_row(struct Maat_table_runtime* table_rt, size_t Nth_row);

int Maat_table_runtime_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_desc, void* logger);
MAAT_PLUGIN_EX_DATA Maat_table_runtime_plugin_get_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_desc, const char* key);
void Maat_table_runtime_digest_add(struct Maat_table_runtime* table_rt, int expr_id, const char* digest, short confidence_degree, void* tag);
void Maat_table_runtime_digest_del(struct Maat_table_runtime* table_rt, int expr_id);
int Maat_table_runtime_digest_batch_udpate(struct Maat_table_runtime* table_rt);

void Maat_table_runtime_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);

void Maat_table_runtime_ip_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);

int Maat_table_runtime_ip_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger);
int Maat_table_runtime_ip_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const struct ip_data* ip, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size);
int Maat_table_runtime_ip_plugin_build_new_ip_matcher(struct Maat_table_runtime* table_rt);
struct ip_matcher* Maat_table_runtime_apply_new_ip_matcher(struct Maat_table_runtime* table_rt);

int Maat_table_runtime_fqdn_plugin_build_new_fqdn_engine(struct Maat_table_runtime* table_rt);

void Maat_table_runtime_fqdn_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger);
int Maat_table_runtime_fqdn_plugin_build_new_fqdn_engine(struct Maat_table_runtime* table_rt);
struct FQDN_engine* Maat_table_runtime_apply_new_fqdn_engine(struct Maat_table_runtime* table_rt);
int Maat_table_runtime_fqdn_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger);
int Maat_table_runtime_fqdn_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* query_fqdn, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size);



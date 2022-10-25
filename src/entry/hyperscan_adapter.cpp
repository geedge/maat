#include <hs_compile.h>
#include <hs_runtime.h>
struct hs_adapter
{
	hs_database_t *hs_pure_literal_db;
	hs_database_t *hs_regex_db;
	struct bool_matcher *logical_matcher;
	int mode;
	int n_thread;
	hs_scratch_t *scratchs[];
};

struct hs_adapter *hs_adapter_new(struct hs_expression ** exprs, size_t n_expr, int scan_mode, int n_thread)
{
}
void hs_adpter_free(struct hs_adapter *adapter)
{

}
int hs_adapter_scan(struct hs_adapter *adapter, int thread_id, const char* data, unsigned int length, void **matched_tags, size_t n_tag)
{
}

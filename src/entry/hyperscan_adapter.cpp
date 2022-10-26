#include <hs_compile.h>
#include <hs_runtime.h>
#include <Maat_utils.h>
struct hs_adapter
{
	hs_database_t *hs_pure_literal_db;
	hs_database_t *hs_regex_db;
	struct bool_matcher *logical_matcher;
	int mode;
	int n_thread;
	size_t regex_cnt;
	size_t regex_sub_pattern_cnt;
	size_t pure_lit_cnt;
	size_t pure_lit_sub_pattern_cnt;
	void **user_tag_array;
	hs_scratch_t *scratchs[];
};
struct hs_adapter *hs_adapter_new(struct hs_expression ** exprs, size_t n_expr, int scan_mode, int n_thread)
{
	struct hs_adapter *hsa=ALLOC(struct hs_adapter, 1);
	size_t i=0, j=0;
	unsigned int *hs_ids=NULL;
	for(i=0; i<n_expr; i++)
	{
		if(exprs[i].is_regex)
		{
			hsa->regex_cnt++;
			hsa->regex_sub_pattern_cnt=exprs[i].n_sub_pattern;
		}
		else
		{
			hsa->pure_lit_cnt++;
			hsa->pure_lit_sub_pattern_cnt++;
		}
	}
	const char **regex_exprs=NULL, **pure_lit_exprs=NULL;
	if(hsa->regex_sub_pattern_cnt>0)
	{
		regex_exprs=ALLOC(char *, hsa->regex_sub_pattern_cnt);
	}
	if(hsa->pure_lit_sub_pattern_cnt>0)
	{
		pure_lit_exprs=ALLOC(char *, hsa->pure_lit_sub_pattern_cnt)
	}
	size_t sub_pure_lit_idx=0, sub_regex_idx=0;
	for(i=0; i<n_expr; i++)
	{
		for(j=0; j<exprs[i]->n_sub_pattern; j++)
		{
			regex_exprs[j]=exprs[i].
		}
		sub_pure_lit_idx

	}
	struct bool_expr *bool_exprs=ALLOC(struct bool_expr, 1);
}
void hs_adpter_free(struct hs_adapter *adapter)
{

}
int hs_adapter_scan(struct hs_adapter *adapter, int thread_id, const char* data, unsigned int length, void **matched_tags, size_t n_tag)
{
}
int hs_adapter_open_stream(struct hs_adapter *adapter, int thread_id)
{

}
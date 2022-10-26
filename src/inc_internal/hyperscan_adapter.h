#pragma once
#include <hs_runtime.h>
#ifdef __cplusplus
extern "C"
{
#endif

#define	HSA_MAX_SUB_STRING_NUM	8
struct hs_pattern
{
	char *pattern;
	size_t pattern_len;
	int start_offset;	//-1: not specified; -2: match is start at the begining of the input
	int end_offset;		//-1: not specified; -2; match is end at the end of the input
};

struct hs_expression
{
	void * user_tag;
	int is_regex;	//if is_regex==1, then n_sub_pattern must be 1
	size_t n_sub_pattern;	//must not exceed HSA_MAX_SUB_STRING_NUM
	struct hs_pattern sub_patterns[];
};

struct hs_adapter;
#define HSA_SCAN_MODE_BLOCK	0
#define	HSA_SCAN_MODE_STREAM 1
/**
 * @param scan_mode 
 * 			HSA_SCAN_MODE_BLOCK or HSA_SCAN_MODE_STREAM
 * @param exprs
 * 			Expressions to match, it's life time must be longger than the hs_adapter.
*/
struct hs_adapter *hs_adapter_new(const struct hs_expression ** exprs, size_t n_expr, int scan_mode, int n_thread);
void hs_adapter_free(struct hs_adapter *adapter);

int hs_adapter_scan(struct hs_adapter *adapter, int thread_id, const char* data, unsigned int length, void **matched_tags, size_t n_tag);

#ifdef __cplusplus
}
#endif


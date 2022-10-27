#pragma once

#include <stddef.h>

#include "../deps/uthash/uthash.h"

struct sub_string_pattern
{
	int is_regex;
	size_t len;
	char *pattern;
};
struct string_pattern
{
	unsigned int item_id;
	unsigned int group_id;
	char district[128];
	size_t n_sub_pattern;
	struct sub_string_pattern *sub_pattern;
	UT_hash_handle hh;
};
struct string_schema
{
	int item_id_column;
	int district_column;
	int pattern_column;
	int is_regex_column;
	int valid_flag_column;
	int rule_tag_column;
	int have_exdata;
	struct EX_data_schema ex_schema;
};
struct string_runtime
{
	struct hs_db_t *pure_literal_db;
	struct hs_db_t *regex_db;
	struct bool_matcher *bool_matcher;	
	struct string_pattern *hash_effect_item;
};

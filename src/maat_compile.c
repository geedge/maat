/*
**********************************************************************************************
*	File: maat_hierarchy.cpp
*   Description: 
*	Authors: Zheng Chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <pthread.h>
#include <linux/limits.h>

#include "maat_utils.h"
#include "log/log.h"
#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "bool_matcher.h"
#include "igraph/igraph.h"
#include "maat_compile.h"
#include "maat_garbage_collection.h"
#include "maat_group.h"
#include "rcu_hash.h"
#include "maat_table.h"

#define MODULE_COMPILE	 module_name_str("maat.compile")
#define MAX_TABLE_LINE_SIZE  (1024 * 16)
#define	MAX_COMPILE_EX_DATA_NUM		2

enum user_region_encode {
	USER_REGION_ENCODE_NONE = 0,
	USER_REGION_ENCODE_ESCAPE,
	USER_REGION_ENCODE_BASE64
};

struct compile_schema {
    int compile_id_column;
    int tags_column;
    int user_region_column;
    int declared_clause_num_column;
    int evaluation_order_column;
    enum user_region_encode user_region_encoding;
	size_t n_ex_schema;
	struct compile_ex_data_schema ex_schema[MAX_COMPILE_EX_DATA_NUM];
    int table_id; //ugly
    struct table_manager *ref_tbl_mgr;
    size_t unmatched_tag_cnt;
};

struct group2compile_schema {
    int group_id_column;
    int compile_id_column;
    int not_flag_column;
    int vtable_name_column;
    int clause_index_column;
    char associated_compile_table_id;
    int table_id;//ugly
    struct table_manager *ref_tbl_mgr;
};

struct compile_item {
    uint64_t compile_id;
    char user_region[MAX_TABLE_LINE_SIZE];
    int declared_clause_num;
    int evaluation_order;
};

struct group2compile_item {
    uint64_t group_id;
    uint64_t compile_id;
    int not_flag;
    int vtable_id;
    int clause_index;
    int associated_compile_table_id;
};

/* compile_runtime and group2compile_runtime share compile_hash_map */
struct compile_runtime {
	struct bool_matcher *bm;
    struct maat_compile *compile_hash; // <compile_id, struct maat_compile>
    unsigned long long clause_id_generator;

	uint32_t rule_num;
    uint32_t updating_rule_num;

    pthread_rwlock_t rwlock; /* TODO: replaced with mutex? */
    struct bool_expr_match *expr_match_buff;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

struct group2compile_runtime {
    long long not_flag_group;
    struct compile_runtime *ref_compile_rt;
    struct group2group_runtime *ref_g2g_rt;
};

struct maat_clause_state {
	unsigned long long clause_id;
	char not_flag;
	char in_use;
	UT_array *literal_ids;
};

struct maat_literal_id {
	uint64_t group_id;
	int vtable_id;
};

struct maat_clause {
	unsigned long long clause_id;
	size_t n_literal_id;
	struct maat_literal_id *literal_ids;
	UT_hash_handle hh;
};

struct compile_sort_para {
	double evaluation_order;
	int declared_clause_num;
	uint64_t compile_id;
	void *user;
};

#define MAAT_COMPILE_MAGIC	0x4a5b6c7d
struct maat_compile {
	unsigned int magic;
	uint64_t compile_id;
	int actual_clause_num;
	int declared_clause_num;
	int not_clause_cnt;
	void *user_data;
	void (*user_data_free)(void *);
	UT_hash_handle hh;
	struct maat_clause_state clause_states[MAX_ITEMS_PER_BOOL_EXPR];
};

struct maat_internal_hit_path {
	int Nth_scan;
	int Nth_hit_item;
	uint64_t item_id;
	uint64_t group_id;
	int vtable_id;
};

struct maat_compile_state {
	int thread_id;
	int Nth_scan;
	time_t hier_ver;
	size_t this_scan_hit_item_cnt;
	int	not_clause_hitted_flag;
	int is_no_count_scan;
	size_t hit_path_cnt;

	UT_array *internal_hit_paths;
	UT_array *all_hit_clauses;
	UT_array *this_scan_hit_clauses;
};

int compile_table_set_rule_ex_data_schema(struct compile_schema *compile_schema, 
                                          int table_id,
										  maat_rule_ex_new_func_t *new_func,
                                          maat_rule_ex_free_func_t *free_func,
                                          maat_rule_ex_dup_func_t *dup_func,
                                          long argl, void *argp,
                                          struct log_handle *logger)
{
	if (compile_schema->n_ex_schema == MAX_COMPILE_EX_DATA_NUM) {
        log_error(logger, MODULE_COMPILE, 
                  "compile ex schema num reach maxium, can't set anymore");
		return -1;
	}

	int idx = compile_schema->n_ex_schema;
	compile_schema->ex_schema[idx].idx = idx;
	compile_schema->ex_schema[idx].table_id = table_id;
	compile_schema->ex_schema[idx].argl = argl;
	compile_schema->ex_schema[idx].argp = argp;
	compile_schema->ex_schema[idx].new_func = new_func;
	compile_schema->ex_schema[idx].free_func = free_func;
	compile_schema->ex_schema[idx].dup_func = dup_func;
	compile_schema->n_ex_schema++;

	return idx;
}

void *compile_runtime_get_user_data(struct compile_runtime *compile_rt, uint64_t compile_id, int is_dettach)
{
    struct maat_compile *compile = NULL;
    void *ret = NULL;

    pthread_rwlock_rdlock(&compile_rt->rwlock);
    HASH_FIND(hh, compile_rt->compile_hash, &compile_id, sizeof(uint64_t), compile);
    if (compile != NULL) {
        ret = compile->user_data;
        if (is_dettach) {
            compile->user_data = NULL;
        }
    }
    pthread_rwlock_unlock(&compile_rt->rwlock);

    return ret;
}

void fill_maat_rule(struct maat_rule *rule, const struct maat_rule_head *rule_head,
                    const char *srv_def, int srv_def_len)
{
    memcpy(rule, rule_head, sizeof(struct maat_rule_head));
	memcpy(rule->service_defined, srv_def, MIN(srv_def_len, MAX_SERVICE_DEFINE_LEN));
}

void *rule_ex_data_new(const struct maat_rule_head *rule_head, const char *srv_def,
                       const struct compile_ex_data_schema *ex_schema)
{
	void *ex_data = NULL;
	struct maat_rule rule;

	fill_maat_rule(&rule, rule_head, srv_def, strlen(srv_def)+1);
	ex_schema->new_func(ex_schema->idx, &rule, srv_def, &ex_data, ex_schema->argl, ex_schema->argp);
	
    return ex_data;
}

void rule_ex_data_free(const struct maat_rule_head *rule_head, const char *srv_def, 
                       void *ex_data, const struct compile_ex_data_schema *ex_schema)
{
	struct maat_rule rule;

    memset(&rule, 0, sizeof(rule));
	fill_maat_rule(&rule, rule_head, srv_def, strlen(srv_def)+1);
	ex_schema->free_func(ex_schema->idx, &rule, srv_def, ex_data, 
                         ex_schema->argl, ex_schema->argp);
}

void rule_ex_data_new_cb(void *user_data, void *param)
{
	struct compile_ex_data_schema *ex_schema = (struct compile_ex_data_schema *)param;
	struct compile_rule *compile = (struct compile_rule *)user_data;
	
	// if(compile->ref_table->table_id!=ex_desc->table_id)
	// {
	// 	return;
	// }
    
	void *ad = rule_ex_data_new(&(compile->head), compile->service_defined, ex_schema);
	compile->ex_data[ex_schema->idx] = ad;
}

void compile_runtime_user_data_iterate(struct compile_runtime *compile_rt, 
                                       void (*callback)(void *user_data, void *param), 
                                       void *param)
{
    struct maat_compile *compile = NULL, *tmp_compile = NULL;

    pthread_rwlock_rdlock(&compile_rt->rwlock);
    HASH_ITER(hh, compile_rt->compile_hash, compile, tmp_compile) {
        if (compile->user_data) {
            callback(compile->user_data, param);
        }
    }
    pthread_rwlock_unlock(&compile_rt->rwlock);
}

void compile_table_rule_ex_data_iterate(struct compile_schema *compile_schema, int idx)
{
    if (NULL == compile_schema) {
		return;
	}

    if (idx >= compile_schema->n_ex_schema) {
        return;
    }

    struct compile_ex_data_schema *ex_schema = (compile_schema->ex_schema + idx);
    struct compile_runtime *compile_rt = NULL;
    compile_rt = (struct compile_runtime *)table_manager_get_runtime(compile_schema->ref_tbl_mgr,
                                                                     compile_schema->table_id);
    compile_runtime_user_data_iterate(compile_rt, rule_ex_data_new_cb, ex_schema);
}

void *compile_table_get_rule_ex_data(struct compile_schema *compile_schema, uint64_t compile_id, size_t idx)
{
	if (NULL == compile_schema) {
		return NULL;
	}

    struct compile_rule *compile_rule = NULL;
    struct compile_runtime *compile_rt = NULL;
    compile_rt = (struct compile_runtime *)table_manager_get_runtime(compile_schema->ref_tbl_mgr,
                                                                     compile_schema->table_id);
	
    compile_rule = (struct compile_rule *)compile_runtime_get_user_data(compile_rt, compile_id, 0);
    if (NULL == compile_rule) {
        return NULL;
    }

    void *ex_data = NULL;
    assert(idx < compile_schema->n_ex_schema);
    struct compile_ex_data_schema *ex_schema = &(compile_schema->ex_schema[idx]);
    ex_schema->dup_func(ex_schema->idx, &ex_data, compile_rule->ex_data + idx, ex_schema->argl, ex_schema->argp);

	return ex_data;
}

size_t compile_table_rule_ex_data_schema_count(struct compile_schema *compile_schema)
{
	if (NULL == compile_schema) {
		return 0;
	}

	return compile_schema->n_ex_schema;
}

UT_icd ut_literal_id_icd = {sizeof(struct maat_literal_id), NULL, NULL, NULL};
UT_icd ut_clause_id_icd = {sizeof(uint64_t), NULL, NULL, NULL};
UT_icd ut_hit_path_icd = {sizeof(struct maat_internal_hit_path), NULL, NULL, NULL};

void *compile_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name,
                         struct log_handle *logger)
{
    int read_cnt = 0;

	struct compile_schema *compile_schema = ALLOC(struct compile_schema, 1);

	cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        compile_schema->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "user_region_encoded");
    if (item != NULL && item->type == cJSON_String) {
        if (strcmp(item->valuestring, "escape") == 0) {
            compile_schema->user_region_encoding = USER_REGION_ENCODE_ESCAPE;
        } else if (strcmp(item->valuestring, "none") == 0) {
            compile_schema->user_region_encoding = USER_REGION_ENCODE_NONE;
        } else {
            log_error(logger, MODULE_COMPILE,
                      "table %s has no user_region_encoded column", table_name);
            goto error;
        }
        read_cnt++;
    }

   	item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_COMPILE, 
                  "table %s has no custom column", table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "compile_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        compile_schema->compile_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "tags");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        compile_schema->tags_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "user_region");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        compile_schema->user_region_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "clause_num");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        compile_schema->declared_clause_num_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "evaluation_order");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        compile_schema->evaluation_order_column = custom_item->valueint;
        read_cnt++;
    }

    compile_schema->ref_tbl_mgr = tbl_mgr;

    if (read_cnt < 7) {
		goto error;
    }

	return compile_schema;
error:
	FREE(compile_schema);
	return NULL;
}

void compile_schema_free(void *compile_schema)
{
	FREE(compile_schema);
}

void *group2compile_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                               const char *table_name, struct log_handle *logger)
{
    int read_cnt = 0;
	struct group2compile_schema *g2c_schema = ALLOC(struct group2compile_schema, 1);

	cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        g2c_schema->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "associated_compile_table_id");
    if (item != NULL && item->type == cJSON_Number) {
        g2c_schema->associated_compile_table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_COMPILE, "table %s has no custom column", table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->group_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "compile_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->compile_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "not_flag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->not_flag_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "virtual_table_name");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->vtable_name_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "clause_index");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->clause_index_column = custom_item->valueint;
        read_cnt++;
    }

    g2c_schema->ref_tbl_mgr = tbl_mgr;

    if (read_cnt < 7) {
		goto error;
    }

	return g2c_schema;
error:
	FREE(g2c_schema);
	return NULL;
}

void group2compile_schema_free(void *g2c_schema)
{
	FREE(g2c_schema);
}

int group2compile_associated_compile_table_id(void *g2c_schema)
{
    struct group2compile_schema *schema = (struct group2compile_schema *)g2c_schema;

    return schema->associated_compile_table_id;
}

struct compile_item *
compile_item_new(const char *line, struct compile_schema *compile_schema,
                 struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char tag_str[MAX_TABLE_LINE_SIZE] = {0};
    size_t n_accept_tag = 0;
    struct compile_item *compile_item = ALLOC(struct compile_item, 1);

    int ret = get_column_pos(line, compile_schema->compile_id_column, 
                             &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE, 
                  "compile table(table_id:%d) line:%s has no compile_id",
                  compile_schema->table_id, line);
        goto error;
    }
    compile_item->compile_id = atoll(line + column_offset);

    ret = get_column_pos(line, compile_schema->tags_column,
                         &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE, 
                  "compile table(table_id:%d) line:%s has no tags",
                  compile_schema->table_id, line);
        goto error;
    }
    
    memcpy(tag_str, (line + column_offset), column_len);
    n_accept_tag = table_manager_accept_tags_count(compile_schema->ref_tbl_mgr);

    if (n_accept_tag > 0 && strlen(tag_str) > 2) {
		str_unescape(tag_str);
        ret = table_manager_accept_tags_match(compile_schema->ref_tbl_mgr, tag_str);
		if (TAG_MATCH_ERR == ret) {
			log_error(logger, MODULE_COMPILE,
					  "compile table(table_id:%d) line:%s is invalid tag",
					  compile_schema->table_id, line);
			goto error;
		}

		if (TAG_MATCH_MATCHED == ret) { //not matched
			compile_schema->unmatched_tag_cnt++;
            goto error;
		}
	}

    ret = get_column_pos(line, compile_schema->user_region_column, 
                         &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "compile table(table_id:%d) line:%s has no user_region",
					  compile_schema->table_id, line);
		goto error;
    }

    if (column_len > MAX_TABLE_LINE_SIZE) {
        log_error(logger, MODULE_COMPILE,
				  "compile table(table_id:%d) line:%s user_region too long",
				  compile_schema->table_id, line);
		goto error;
    }
    
    memcpy(compile_item->user_region, (line + column_offset), column_len);

    switch (compile_schema->user_region_encoding) {
		case USER_REGION_ENCODE_ESCAPE:
			str_unescape(compile_item->user_region);
			break;
		default:
			break;
	}

    ret = get_column_pos(line, compile_schema->declared_clause_num_column, 
                         &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "compile table(table_id:%d) line:%s has no clause_num",
				  compile_schema->table_id, line);
		goto error;
    }
    compile_item->declared_clause_num = atoi(line + column_offset);

    ret = get_column_pos(line, compile_schema->evaluation_order_column, 
                         &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "compile table(table_id:%d) line:%s has no evaluation_order",
				  compile_schema->table_id, line);
		goto error;
    }
    compile_item->evaluation_order = atoi(line + column_offset);

    return compile_item;
error:
    FREE(compile_item);
    return NULL;
}

void compile_item_free(struct compile_item *compile_item)
{
    if (NULL == compile_item) {
        return;
    }

    FREE(compile_item);
}

void *compile_runtime_new(void *compile_schema, int max_thread_num, 
                          struct maat_garbage_bin *garbage_bin,
						  struct log_handle *logger)
{
	if (NULL == compile_schema) {
        return NULL;
    }

    struct compile_runtime *compile_rt = ALLOC(struct compile_runtime, 1);

    compile_rt->expr_match_buff = ALLOC(struct bool_expr_match, max_thread_num * MAX_SCANNER_HIT_COMPILE_NUM);
    compile_rt->logger = logger;
    compile_rt->ref_garbage_bin = garbage_bin;
    pthread_rwlock_init(&compile_rt->rwlock, NULL);

    return compile_rt;
}

void maat_compile_free(struct maat_compile *compile)
{
	struct maat_clause_state *clause_state = NULL;
	if (compile->user_data && compile->user_data_free) {
		compile->user_data_free(compile->user_data);
	}

	for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		clause_state = compile->clause_states + i;
		utarray_free(clause_state->literal_ids);
		clause_state->literal_ids = NULL;
		clause_state->in_use = 0;
	}
	compile->magic = 0;
	free(compile);
}

void maat_compile_hash_free(struct maat_compile **compile_hash)
{
	struct maat_compile *compile = NULL, *tmp_compile = NULL;

	HASH_ITER(hh, *compile_hash, compile, tmp_compile) {
		HASH_DEL(*compile_hash, compile);
		maat_compile_free(compile);
	}
	assert(*compile_hash == NULL);
}

void compile_runtime_free(void *compile_runtime)
{
    if (NULL == compile_runtime) {
        return;
    }

    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
    
    pthread_rwlock_wrlock(&compile_rt->rwlock);

    if (compile_rt->bm != NULL) {
        bool_matcher_free(compile_rt->bm);
    }

    if (compile_rt->compile_hash != NULL) {
        maat_compile_hash_free(&(compile_rt->compile_hash));
    }
    pthread_rwlock_unlock(&compile_rt->rwlock);

    if (compile_rt->expr_match_buff != NULL) {
        FREE(compile_rt->expr_match_buff);
    }

    FREE(compile_rt);
}

void *group2compile_runtime_new(void *g2c_schema, int max_thread_num, 
                                struct maat_garbage_bin *garbage_bin,
                                struct log_handle *logger)
{
    struct group2compile_runtime *g2c_rt = ALLOC(struct group2compile_runtime, 1);
    return g2c_rt;
}

void group2compile_runtime_init(void *g2c_runtime, void *compile_runtime, 
                                void *g2g_runtime)
{
    struct group2compile_runtime *g2c_rt = (struct group2compile_runtime *)g2c_runtime;

    g2c_rt->ref_compile_rt = (struct compile_runtime *)compile_runtime;
    g2c_rt->ref_g2g_rt = (struct group2group_runtime *)g2g_runtime;
}

void group2compile_runtime_free(void *g2c_runtime)
{
    if (NULL == g2c_runtime) {
        return;
    }

    FREE(g2c_runtime);
}

int is_valid_table_name(const char *str)
{
	size_t integer_cnt=0;
	for (size_t i = 0; i < strlen(str); i++) {
		if (str[i] >= '0' && str[i] <= '9') {
			integer_cnt++;
		}
	}

	if (strlen(str) == 0 || integer_cnt == strlen(str) || 
        0 == strcasecmp(str, "null")) {
		return 0;
	}

	return 1;
}

struct group2compile_item *
group2compile_item_new(const char *line, struct group2compile_schema *g2c_schema,
                       struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char vtable_name[NAME_MAX] = {0};
    struct group2compile_item *g2c_item = ALLOC(struct group2compile_item, 1);

    int ret = get_column_pos(line, g2c_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "group2compile table(table_id:%d) line:%s has no group_id",
				  g2c_schema->table_id, line);
		goto error;
    }
    g2c_item->group_id = atoll(line + column_offset);

    ret = get_column_pos(line, g2c_schema->compile_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "group2compile table(table_id:%d) line:%s has no compile_id",
				  g2c_schema->table_id, line);
		goto error;
    }
    g2c_item->compile_id = atoll(line + column_offset);

    ret = get_column_pos(line, g2c_schema->not_flag_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "group2compile table(table_id:%d) line:%s has no NOT_flag",
				  g2c_schema->table_id, line);
		goto error;
    }
    g2c_item->not_flag = atoi(line + column_offset);

    ret = get_column_pos(line, g2c_schema->vtable_name_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "group2compile table(table_id:%d) line:%s has no virtual_table_name",
				  g2c_schema->table_id, line);
		goto error;
    }

    if (column_len > NAME_MAX) {
        log_error(logger, MODULE_COMPILE, 
                  "group2compile table(table_id:%d) line:%s virtual_table_name length too long",
                  g2c_schema->table_id, line);
        goto error;
    }
    
    memcpy(vtable_name, (line + column_offset), column_len);
    
    if (is_valid_table_name(vtable_name)) {
        g2c_item->vtable_id = table_manager_get_table_id(g2c_schema->ref_tbl_mgr, vtable_name);
        if (g2c_item->vtable_id < 0) {
            log_error(logger, MODULE_COMPILE,
                      "group2compile table(table_id:%d) line:%s unknown virtual table:%s",
                      g2c_schema->table_id, line, vtable_name);
            goto error;
        }
    }
   
    ret = get_column_pos(line, g2c_schema->clause_index_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
                      "group2compile table(table_id:%d) line:%s has no clause_index",
                      g2c_schema->table_id, line);
        goto error;
    }

    g2c_item->clause_index = atoi(line + column_offset);

    return g2c_item;
error:
    FREE(g2c_item);
    return NULL;
}

void group2compile_item_free(struct group2compile_item *g2c_item)
{
    if (NULL == g2c_item) {
        return;
    }

    FREE(g2c_item);
}

#define MAAT_HIER_COMPILE_MAGIC	0x4a5b6c7d
struct maat_compile *maat_compile_new(uint64_t compile_id)
{
	struct maat_compile *compile = ALLOC(struct maat_compile, 1);

	compile->magic = MAAT_HIER_COMPILE_MAGIC;
	compile->compile_id = compile_id;

    for(int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {	
		utarray_new(compile->clause_states[i].literal_ids, &ut_literal_id_icd);
		compile->clause_states[i].in_use=0;
	}

	return compile;
}

int maat_compile_set(struct maat_compile *compile, int declared_clause_num, 
                     void *user_data, void (*user_data_free)(void *))
{
	if (user_data != NULL && NULL == user_data_free) {
		return -1;
	}

	compile->declared_clause_num = declared_clause_num;
	compile->user_data = user_data;
	compile->user_data_free = user_data_free;

	return 0;
}

int maat_compile_hash_add(struct maat_compile **compile_hash, uint64_t compile_id, 
                          struct maat_compile *compile)
{
	int ret = 0;

    assert(compile->declared_clause_num >= 0);
    HASH_ADD(hh, *compile_hash, compile_id, sizeof(uint64_t), compile);
	//TODO:mytest need to delete
#if 0
	size_t compile_cnt = HASH_COUNT(*compile_hash);
	struct maat_compile *compile1 = NULL, *tmp_compile1 = NULL;
	HASH_ITER (hh, *compile_hash, compile1, tmp_compile1) {
		printf("<maat_compile_hash_add> compile_id:%lu, compile_cnt:%zu\n", 
                compile1->compile_id, compile_cnt);
	}
#endif
	return ret;
}

void maat_compile_hash_set(struct maat_compile **compile_hash, uint64_t compile_id,
                          struct maat_compile *compile)
{
    struct maat_compile *tmp_compile = NULL;

    HASH_FIND(hh, *compile_hash, &compile_id, sizeof(uint64_t), tmp_compile);
    assert(tmp_compile != NULL);

    assert(tmp_compile->user_data == NULL);
    maat_compile_set(tmp_compile, compile->declared_clause_num,
                     compile->user_data, compile->user_data_free);
    
}

int maat_compile_hash_remove(struct maat_compile **compile_hash, struct maat_compile *compile,
                             struct maat_garbage_bin *garbage_bin)
{
	if (0 == compile->actual_clause_num) {
		 HASH_DEL(*compile_hash, compile);
		 maat_garbage_bagging(garbage_bin, compile, (void (*)(void *))maat_compile_free);
	}

	//TODO:mytest need to delete
#if 0
	size_t compile_cnt = HASH_COUNT(*compile_hash);
	struct maat_compile *compile1 = NULL, *tmp_compile1 = NULL;
	HASH_ITER (hh, *compile_hash, compile1, tmp_compile1) {
		printf("<maat_compile_hash_remove> compile_id:%lu, compile_cnt:%zu\n", 
                compile1->compile_id, compile_cnt);
	}
#endif
	return 0;
}

struct maat_compile *maat_compile_hash_find(struct maat_compile **compile_hash, uint64_t compile_id)
{
	struct maat_compile *compile = NULL;

	HASH_FIND(hh, *compile_hash, &compile_id, sizeof(compile_id), compile);

    return compile;
}

size_t maat_compile_in_use_count(struct maat_compile *compile_hash)
{
    struct maat_compile *compile = NULL, *tmp_compile = NULL;
    size_t in_use_compile_cnt = 0;
    struct maat_clause_state *clause_state = NULL;

    HASH_ITER(hh, compile_hash, compile, tmp_compile) {
        //find how much compile whose clause is in_use
		for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
			clause_state = compile->clause_states + i;
			if (clause_state->in_use) {
                in_use_compile_cnt++;
				break;
			}
		}
    }

	return in_use_compile_cnt;
}

int compare_literal_id(const void *pa, const void *pb)
{
	struct maat_literal_id *la = (struct maat_literal_id *)pa;
	struct maat_literal_id *lb = (struct maat_literal_id *)pb;

	int ret = la->vtable_id - lb->vtable_id;
	if (0 == ret) {
		ret = la->group_id - lb->group_id;
	}

	return ret;
}

int maat_compile_clause_add_literal(struct maat_compile *compile,
                                    struct maat_literal_id *literal_id,
									int clause_index, int clause_not_flag)
{
	struct maat_clause_state *clause_state = compile->clause_states + clause_index;

	clause_state->not_flag = clause_not_flag;
	if (!clause_state->in_use) {
		clause_state->in_use = 1;
		compile->actual_clause_num++;
	}

	struct maat_literal_id *tmp = NULL;
    tmp = (struct maat_literal_id *)utarray_find(clause_state->literal_ids,
                                                 literal_id, compare_literal_id);
	if (tmp) {
        assert(tmp->group_id == literal_id->group_id);
        assert(tmp->vtable_id == literal_id->vtable_id);
		return -1;
	} else {
		utarray_push_back(clause_state->literal_ids, literal_id);
		utarray_sort(clause_state->literal_ids, compare_literal_id);
	}

	return 0;
}

int maat_compile_clause_remove_literal(struct maat_compile *compile,
                                       struct maat_literal_id *literal_id,
                                       int clause_index)
{
    struct maat_clause_state* clause_state = compile->clause_states + clause_index;
	struct maat_literal_id *tmp = NULL;
    tmp = (struct maat_literal_id *)utarray_find(clause_state->literal_ids,
                                                 literal_id, compare_literal_id);
	if (tmp) {
		assert(*(unsigned long long*)tmp == *(unsigned long long*)(literal_id));
	} else {
		return -1;
	}

	size_t remove_idx = utarray_eltidx(clause_state->literal_ids, tmp);
	utarray_erase(clause_state->literal_ids, remove_idx, 1);

	if (0 == utarray_len(clause_state->literal_ids)) {
		clause_state->in_use=0;
		compile->actual_clause_num--;
	}

	return 0;
}

static const struct maat_clause *
maat_clause_hash_fetch_clause(struct maat_clause **clause_hash,
                              unsigned long long *clause_id_generator,
							  struct maat_literal_id *literal_ids, 
                              size_t n_literal_id)
{
	struct maat_clause *clause = NULL;

	HASH_FIND(hh, *clause_hash, literal_ids, n_literal_id * sizeof(struct maat_literal_id), clause);
	if (!clause) {
		clause = ALLOC(struct maat_clause, 1);
		clause->clause_id = *clause_id_generator;
		clause->n_literal_id = n_literal_id;
		clause->literal_ids = ALLOC(struct maat_literal_id, n_literal_id);
		memcpy(clause->literal_ids, literal_ids, n_literal_id * sizeof(struct maat_literal_id));
		
		(*clause_id_generator)++;
		HASH_ADD_KEYPTR(hh, *clause_hash, clause->literal_ids, 
                        n_literal_id * sizeof(struct maat_literal_id), clause);
	}

	return clause;
}

static void maat_clause_hash_free(struct maat_clause *clause_hash)
{
	struct maat_clause *clause = NULL, *tmp_clause = NULL;

	HASH_ITER (hh, clause_hash, clause, tmp_clause) {
		HASH_DELETE(hh, clause_hash, clause);
		free(clause->literal_ids);
		clause->n_literal_id = 0;
		free(clause);
	}
}

struct bool_matcher *
maat_compile_bool_matcher_new(struct maat_compile *compile_hash, 
                              unsigned long long *clause_id_generator,
                              struct log_handle *logger)
{
	if (NULL == compile_hash || NULL == logger) {
		return NULL;
	}

    size_t i = 0, j = 0;
    int has_clause_num = 0;
	struct bool_matcher *bm = NULL;
	struct maat_clause_state *clause_state = NULL;
	const struct maat_clause *clause = NULL;
	struct maat_clause *clause_hash = NULL; // <literal_id, struct maat_clause>
    
	//STEP 1, update clause_id of each compile and literal
	struct maat_compile *compile = NULL, *tmp_compile = NULL;
	struct maat_literal_id *literal_ids = NULL;
	size_t n_literal_id = 0;
	HASH_ITER(hh, compile_hash, compile, tmp_compile) {
		has_clause_num = 0;
		for (i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
			clause_state = compile->clause_states + i;
			clause_state->clause_id = 0;
			if (!clause_state->in_use) {
				continue;
			}
			
			has_clause_num++;
			literal_ids = (struct maat_literal_id *)utarray_eltptr(clause_state->literal_ids, 0);
			n_literal_id = utarray_len(clause_state->literal_ids);
			clause = maat_clause_hash_fetch_clause(&clause_hash, clause_id_generator, 
                                                    literal_ids, n_literal_id);
			clause_state->clause_id = clause->clause_id;
		}
		assert(has_clause_num == compile->actual_clause_num);
	}

    //STEP 2, serial compile clause states to a bool expression array
    size_t expr_cnt = 0;
	size_t compile_cnt = maat_compile_in_use_count(compile_hash);
    struct bool_expr *bool_expr_array = ALLOC(struct bool_expr, compile_cnt);
    HASH_ITER(hh, compile_hash, compile, tmp_compile) {
		for (i = 0, j = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
			if (compile->clause_states[i].in_use) {
				if (compile->clause_states[i].not_flag) {
					compile->not_clause_cnt++;
				}

				//TODO:mytest need to delete
				#if 0
				struct maat_literal_id *p = NULL;
				for(p = (struct maat_literal_id *)utarray_front(compile->clause_states[i].literal_ids); p!=NULL; p=(struct maat_literal_id *)utarray_next(compile->clause_states[i].literal_ids,p)) {
    				printf("compile_id:%lu, clause_id:%llu, literal{%lu: %d}\n", 
							compile->compile_id, compile->clause_states[i].clause_id, p->group_id, p->vtable_id);
  				}
				#endif
				bool_expr_array[expr_cnt].items[j].item_id = compile->clause_states[i].clause_id;
				bool_expr_array[expr_cnt].items[j].not_flag = compile->clause_states[i].not_flag;

				j++;
			}
		}

        // printf("bool_matcher_new compile_id:%lu j:%zu, compile->declared_clause_num:%d\n", 
        //         compile->compile_id, j, compile->declared_clause_num);
		//some compile may have zero groups, e.g. default policy.
		if (j == (size_t)compile->declared_clause_num && j > 0) {
			bool_expr_array[expr_cnt].expr_id = compile->compile_id;
			bool_expr_array[expr_cnt].user_tag = compile;
			bool_expr_array[expr_cnt].item_num = j;
			expr_cnt++;
		}
	}

	//size_t expr_index = 0, item_index = 0;

    // STEP 3, build bool matcher
    size_t mem_size = 0;
	if (0 == expr_cnt) {		
		log_error(logger, MODULE_COMPILE, "No bool expression to build bool matcher.");
		goto error;
	}

	//TODO:mytest need to delete
	#if 0
	printf("bool_matcher_new....................expr_cnt:%zu\n", expr_cnt);
	for (expr_index = 0; expr_index < expr_cnt; expr_index++) {
		printf("bool_expr_array[%zu].expr_id:%llu, item_num:%zu\n", expr_index, bool_expr_array[expr_index].expr_id,
																	bool_expr_array[expr_index].item_num);
		for (item_index = 0; item_index < bool_expr_array[expr_index].item_num; item_index++) {
			printf("bool_expr_array[%zu].items[%zu]:%llu, not_flag:%d\n", expr_index, item_index, 
					bool_expr_array[expr_index].items[item_index].item_id,
					bool_expr_array[expr_index].items[item_index].not_flag);
		}
		printf("\n");
	}
	#endif

	bm = bool_matcher_new(bool_expr_array, expr_cnt, &mem_size);
	if (bm != NULL) {
		log_info(logger, MODULE_COMPILE,
				"Build bool matcher of %zu expressions with %zu bytes memory.", expr_cnt, mem_size);
	} else {
		log_error(logger, MODULE_COMPILE, "Build bool matcher failed!");
	}

error:
	maat_clause_hash_free(clause_hash);
    FREE(bool_expr_array);

    return bm;
}

void maat_compile_bool_matcher_free(struct bool_matcher *bm)
{
    bool_matcher_free(bm);
}

size_t maat_compile_bool_matcher_match(struct bool_matcher *bm, int is_last_scan,
                                       struct maat_compile_state *compile_state,
                                       void **user_data_array, size_t ud_array_size)
{
	struct maat_compile *compile = NULL;
	struct bool_expr_match *expr_match = ALLOC(struct bool_expr_match, MAX_SCANNER_HIT_COMPILE_NUM);
	size_t ud_result_cnt = 0;

	//TODO:mytest need to delete
	#if 0
	unsigned long long *p;
    printf("utarray_len:%u\n", utarray_len(compile_state->all_hit_clauses));
	for (p = (unsigned long long *)utarray_front(compile_state->all_hit_clauses); p != NULL; p = (unsigned long long *)utarray_next(compile_state->all_hit_clauses, p))
	{
		printf("before bool_matcher_match compile_state clause_id:%llu\n",  *p);
	}
	#endif
	
	int bool_match_ret = bool_matcher_match(bm, (unsigned long long *)utarray_eltptr(compile_state->all_hit_clauses, 0),
											utarray_len(compile_state->all_hit_clauses), 
                                            expr_match, MAX_SCANNER_HIT_COMPILE_NUM);
	for (int i = 0; i < bool_match_ret && ud_result_cnt < ud_array_size; i++) {
		compile = (struct maat_compile *)expr_match[i].user_tag;
		assert(compile->magic == MAAT_COMPILE_MAGIC);
		assert((unsigned long long)compile->compile_id == expr_match[i].expr_id);
		if (0 == compile->actual_clause_num) {
			continue;
		}

        if ((compile->not_clause_cnt > 0) && (LAST_SCAN_UNSET == is_last_scan)) {
            compile_state->not_clause_hitted_flag = 1;
        }

		//TODO: not_clause
		if (compile->user_data) {
			user_data_array[ud_result_cnt] = compile->user_data;
			ud_result_cnt++;
		}
	}

    compile_state->this_scan_hit_item_cnt = 0;
	return ud_result_cnt;
}

int maat_add_group_to_compile(struct maat_compile **compile_hash, struct group2compile_item *g2c_item,
                              struct log_handle *logger)
{
	int ret = -1;
	struct maat_compile *compile = maat_compile_hash_find(compile_hash, g2c_item->compile_id);
	if (!compile) {
		compile = maat_compile_new(g2c_item->compile_id);
		ret = maat_compile_hash_add(compile_hash, g2c_item->compile_id, compile);
		if (ret < 0) {
			return -1;
		}
	}

	struct maat_literal_id literal_id = {g2c_item->group_id, g2c_item->vtable_id};
    
	ret = maat_compile_clause_add_literal(compile, &literal_id, g2c_item->clause_index, 
                                          g2c_item->not_flag);
	if (ret < 0) {
		log_error(logger, MODULE_COMPILE,
                  "add literal_id{group_id:%d, vtable_id:%d} to clause_index: %d of compile %d failed",
				  g2c_item->group_id, g2c_item->vtable_id, g2c_item->clause_index, 
                  g2c_item->compile_id);
		ret = -1;
	} else {
		ret = 0;
	}

    // printf("group2compile update compile_id:%lu, compile->declared_clause_num:%d\n",
    //         compile->compile_id, compile->declared_clause_num);
	return ret;
}

int maat_remove_group_from_compile(struct maat_compile **compile_hash,
                                   struct group2compile_item *g2c_item,
                                   struct maat_garbage_bin *garbage_bin, 
								   struct log_handle *logger)
{
	struct maat_compile *compile = NULL;
	HASH_FIND(hh, *compile_hash, &(g2c_item->compile_id), sizeof(g2c_item->compile_id), compile);
	if (!compile) {
		log_error(logger, MODULE_COMPILE,
                  "Remove group %d from compile %d failed, compile is not exisited.",
				  g2c_item->group_id, g2c_item->compile_id);
		return -1;	
	}

	struct maat_literal_id literal_id = {g2c_item->group_id, g2c_item->vtable_id};
	int ret = maat_compile_clause_remove_literal(compile, &literal_id, g2c_item->clause_index);
	if (ret < 0) {
		log_error(logger, MODULE_COMPILE,
				  "Remove group %d vtable_id %d from clause %d of compile %d failed, literal is not in compile.",
				   g2c_item->group_id, g2c_item->vtable_id, g2c_item->clause_index, g2c_item->compile_id);
		return -1;
	}

	if (0 == compile->actual_clause_num && NULL == compile->user_data) {		
		HASH_DEL(*compile_hash, compile);
		maat_garbage_bagging(garbage_bin, compile, (void (*)(void*))maat_compile_free);
	}
	
	return 0;
}

static inline int compare_clause_id(const void *a, const void *b)
{
	long long ret = *(const unsigned long long *)a - *(const unsigned long long *)b;

	if (0 == ret) {
		return 0;
	} else if(ret < 0) {
		return -1;
	} else {
		return 1;
	}
}

struct maat_compile_state *maat_compile_state_new(int thread_id)
{
    struct maat_compile_state *compile_state = ALLOC(struct maat_compile_state, 1);

	compile_state->thread_id = thread_id;
	//compile_state->hier_ver = hier->version;
	utarray_new(compile_state->internal_hit_paths, &ut_hit_path_icd);
	utarray_new(compile_state->all_hit_clauses, &ut_clause_id_icd);
	utarray_new(compile_state->this_scan_hit_clauses, &ut_clause_id_icd);

	return compile_state;
}

void maat_compile_state_free(struct maat_compile_state *compile_state)
{
    utarray_free(compile_state->internal_hit_paths);
	utarray_free(compile_state->all_hit_clauses);
	utarray_free(compile_state->this_scan_hit_clauses);
	free(compile_state);
}

static int maat_compile_hit_path_add(UT_array *hit_paths, uint64_t item_id, uint64_t group_id,
                                     int vtable_id, int Nth_scan, int Nth_item_result)
{
	struct maat_internal_hit_path new_path;

	new_path.item_id = item_id;
	new_path.Nth_hit_item = Nth_item_result;
	new_path.Nth_scan = Nth_scan;
	new_path.group_id = group_id;
	new_path.vtable_id = vtable_id;
	
	utarray_push_back(hit_paths, &new_path);

	return 1;
}

static int maat_compile_has_literal(struct maat_compile* compile,
                                    struct maat_literal_id *literal_id)
{
	int i = 0;
	struct maat_literal_id *tmp = NULL;
	struct maat_clause_state *clause_state = NULL;

	for (i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		clause_state = compile->clause_states+i;
		if(!clause_state->in_use) {
			continue;
		}

		tmp = (struct maat_literal_id*)utarray_find(clause_state->literal_ids,
                                                    literal_id, compare_literal_id);
		if (tmp) {
			assert(tmp->group_id == literal_id->group_id && 
                   tmp->vtable_id == literal_id->vtable_id);
			return 1;
		}
	}

	return 0;
}

static int maat_compile_is_hit_path_existed(const struct maat_hit_path *hit_paths,
                                            size_t n_path, const struct maat_hit_path *find)
{
	for (size_t i = 0; i < n_path; i++) {
		if (0 == memcmp(hit_paths + i, find, sizeof(*find))) {
			return 1;
		}
	}

	return 0;
}

size_t compile_runtime_get_hit_paths(struct compile_runtime *compile_rt,
                                     struct group2group_runtime *g2g_rt, 
									 struct maat_compile_state *compile_state, 
                                  	 struct maat_hit_path *hit_paths, 
                                     size_t hit_path_index, size_t hit_path_size)
{
	size_t i = 0, j = 0;
	struct maat_internal_hit_path *internal_path = NULL;
    size_t hit_path_cnt = hit_path_index;
    size_t new_hit_path_cnt = 0;

	for (i = 0; i < utarray_len(compile_state->internal_hit_paths); i++) {
		internal_path = (struct maat_internal_hit_path *)utarray_eltptr(compile_state->internal_hit_paths, i);
        /*
            NOTE: maybe one item has been deleted, but it's item_id still exist in internal_hit_paths
        */
        uint64_t top_group_ids[MAX_SCANNER_HIT_GROUP_NUM];
        memset(top_group_ids, 0, sizeof(top_group_ids));
        int top_group_cnt = group2group_runtime_get_top_groups(g2g_rt, &(internal_path->group_id),
                                                               1, top_group_ids);
        if (top_group_cnt <= 0) {
            /* 
                item->group_id has no top group, this group can only be referenced by compile
                ------------------------------------------------------------------------------
                for example: 
                    compile1 -> group1 -> group2 -> item1
                    group3 -> item2
                             
                    group1 and group3 has no top group
                    group1 is referenced by compile1, group3 is not referenced by any compile

                    NOTE: Add the hit path as long as the item is hit
                    
            */
            top_group_cnt = 1; //add one hit path which top_group_ids[0] = -1
        }

        for (int j = 0; j < top_group_cnt && hit_path_cnt < hit_path_size; j++, hit_path_cnt++) {
            hit_paths[hit_path_cnt].Nth_scan = internal_path->Nth_scan;
            hit_paths[hit_path_cnt].item_id = internal_path->item_id;
            hit_paths[hit_path_cnt].sub_group_id = internal_path->group_id;
            hit_paths[hit_path_cnt].top_group_id = top_group_ids[j]; //top_group_id may be -1
            hit_paths[hit_path_cnt].vtable_id = internal_path->vtable_id;
            hit_paths[hit_path_cnt].compile_id = -1;
        }
	}

    /* assign hit_paths[].compile_id */
    struct maat_compile *compile = NULL;
    struct maat_literal_id literal_id = {0, 0};
    struct maat_hit_path tmp_path;
    struct bool_expr_match *expr_match = compile_rt->expr_match_buff + compile_state->thread_id * MAX_SCANNER_HIT_COMPILE_NUM;
    int bool_match_ret = bool_matcher_match(compile_rt->bm, 
                                            (unsigned long long *)utarray_eltptr(compile_state->all_hit_clauses, 0),
											utarray_len(compile_state->all_hit_clauses), expr_match, 
                                            MAX_SCANNER_HIT_COMPILE_NUM);
	for (int idx = 0; idx < bool_match_ret; idx++) {
        compile = (struct maat_compile *)expr_match[idx].user_tag;
		assert(compile->magic == MAAT_COMPILE_MAGIC);
		assert((unsigned long long)compile->compile_id == expr_match[idx].expr_id);
		if (0 == compile->actual_clause_num) {
			continue;
		}

        for (j = 0; j < hit_path_cnt && (hit_path_cnt + new_hit_path_cnt) < hit_path_size; j++) {
			if (hit_paths[j].top_group_id < 0) {
				continue;
			}

			literal_id.group_id = hit_paths[j].top_group_id;
			literal_id.vtable_id = hit_paths[j].vtable_id;
			if (maat_compile_has_literal(compile, &literal_id)) {
				if (hit_paths[j].compile_id < 0) {
					hit_paths[j].compile_id = compile->compile_id;
				} else {
                    // means same literal_id hit more than one compile_id
					tmp_path = hit_paths[j];
					tmp_path.compile_id = compile->compile_id;
					if(maat_compile_is_hit_path_existed(hit_paths, hit_path_cnt + new_hit_path_cnt, &tmp_path)) {
						hit_paths[hit_path_cnt + new_hit_path_cnt] = tmp_path;
						new_hit_path_cnt++;
					}
				}
			}
		}
	}

    return hit_path_cnt + new_hit_path_cnt;
}

void maat_compile_state_update_hit_path(struct maat_compile_state *compile_state,
                                        uint64_t item_id, uint64_t group_id, int vtable_id, 
                                        int Nth_scan, int Nth_item_result)
{
	if (compile_state->Nth_scan != Nth_scan) {
		assert(compile_state->this_scan_hit_item_cnt == 0);
		compile_state->Nth_scan = Nth_scan;
		utarray_clear(compile_state->this_scan_hit_clauses);
	}

    maat_compile_hit_path_add(compile_state->internal_hit_paths, item_id, group_id, 
                              vtable_id, Nth_scan, Nth_item_result);

	compile_state->hit_path_cnt++;
	compile_state->this_scan_hit_item_cnt++;
}

void maat_compile_state_update_hit_clause(struct maat_compile_state *compile_state,
                                          void *compile_runtime, uint64_t group_id,
                                          int vtable_id)
{
    if (NULL == compile_state || NULL == compile_runtime) {
        return;
    }
    
	struct maat_compile *compile = NULL, *tmp_compile = NULL;
	struct maat_clause_state *clause_state = NULL;
	struct maat_literal_id literal_id = {group_id, vtable_id};
    struct maat_literal_id *tmp = NULL;
    unsigned long long *clause_id = 0;
    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
    
    pthread_rwlock_rdlock(&compile_rt->rwlock);
    assert(compile_rt->compile_hash != NULL);
    
	HASH_ITER(hh, compile_rt->compile_hash, compile, tmp_compile) {
		for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
			clause_state = compile->clause_states + i;
			if (!clause_state->in_use) {
				continue;
			}

            size_t new_clause_idx = utarray_len(compile_state->this_scan_hit_clauses);
			tmp = (struct maat_literal_id *)utarray_find(clause_state->literal_ids, 
                                                         &literal_id, compare_literal_id);
			if (tmp) {
				//Deduplication
				if (utarray_find(compile_state->all_hit_clauses, &(clause_state->clause_id), 
                                compare_clause_id)) {
					continue;
				}

                utarray_push_back(compile_state->this_scan_hit_clauses, &(clause_state->clause_id));
			}

            //means this scan hit new clause
            if ((utarray_len(compile_state->this_scan_hit_clauses) - new_clause_idx) > 0) {
                utarray_reserve(compile_state->all_hit_clauses, 
                                utarray_len(compile_state->this_scan_hit_clauses) - new_clause_idx);

                for (i = new_clause_idx; i < utarray_len(compile_state->this_scan_hit_clauses); i++) {
                    clause_id = (unsigned long long *)utarray_eltptr(compile_state->this_scan_hit_clauses, i);
                    utarray_push_back(compile_state->all_hit_clauses, clause_id);
                }
                utarray_sort(compile_state->all_hit_clauses, compare_clause_id);
            }
        }
	}
    pthread_rwlock_unlock(&compile_rt->rwlock);
}

int maat_compile_state_has_NOT_clause(struct maat_compile_state *compile_state)
{   
    return compile_state->not_clause_hitted_flag;
}

void compile_item_to_compile_rule(struct compile_item *compile_item,
                                  struct compile_schema *compile_schema,
                                  struct compile_rule *compile_rule)
{
    struct maat_rule_head rule_head;
    rule_head.config_id = compile_item->compile_id;
    
    compile_rule->magic_num = COMPILE_RULE_MAGIC;
    compile_rule->head = rule_head;
    compile_rule->declared_clause_num = compile_item->declared_clause_num;
    compile_rule->ex_data = ALLOC(void *, MAX_COMPILE_EX_DATA_NUM);

    compile_rule->ref_table = compile_schema;
    compile_rule->head.serv_def_len = strlen(compile_item->user_region);
    compile_rule->service_defined = ALLOC(char, compile_rule->head.serv_def_len);
    memcpy(compile_rule->service_defined, compile_item->user_region, 
           compile_rule->head.serv_def_len);
    compile_rule->evaluation_order = compile_item->evaluation_order;

    size_t n_rule_ex_schema =compile_schema->n_ex_schema;
    for (size_t i = 0; i < n_rule_ex_schema; i++) {
        struct compile_ex_data_schema *ex_schema = &(compile_schema->ex_schema[i]);
        compile_rule->ex_data[i] = rule_ex_data_new(&compile_rule->head, 
                                                    compile_rule->service_defined, ex_schema);
    }
    compile_rule->compile_id = compile_item->compile_id;
    pthread_rwlock_init(&compile_rule->rwlock, NULL);
}

void destroy_compile_rule(struct compile_rule *compile_rule)
{
	struct compile_schema *schema = compile_rule->ref_table;
	assert(compile_rule->magic_num==COMPILE_RULE_MAGIC);

    size_t n_rule_ex_schema = schema->n_ex_schema;
	for (size_t i = 0; i < n_rule_ex_schema; i++) {
        struct compile_ex_data_schema *ex_schema = &(schema->ex_schema[i]);
		rule_ex_data_free(&(compile_rule->head), compile_rule->service_defined, 
                          compile_rule->ex_data+i, ex_schema);
		compile_rule->ex_data[i] = NULL;
	}
	free(compile_rule->ex_data);
	compile_rule->declared_clause_num = -1;
	free(compile_rule->service_defined);
	compile_rule->service_defined = NULL;
	free(compile_rule);
}

int compile_runtime_update(void *compile_runtime, void *compile_schema, 
                           const char *line, int valid_column)
{
    if (NULL == compile_runtime || NULL == compile_schema ||
        NULL == line) {
        return -1;
    }

    int ret = -1;
    struct maat_compile *compile = NULL;
    struct compile_item *compile_item = NULL;
    struct compile_schema *schema = (struct compile_schema *)compile_schema;
    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    }

    long long compile_id = get_column_value(line, schema->compile_id_column);
    if (compile_id < 0) {
        return -1;
    }

    if (0 == is_valid) {
        //delete
        pthread_rwlock_wrlock(&compile_rt->rwlock);
        compile = maat_compile_hash_find(&(compile_rt->compile_hash), compile_id);
        if (NULL == compile) {
            pthread_rwlock_unlock(&compile_rt->rwlock);
            return -1;
        }

        ret = maat_compile_hash_remove(&(compile_rt->compile_hash), compile,
                                        compile_rt->ref_garbage_bin);
        pthread_rwlock_unlock(&compile_rt->rwlock);
        if (ret < 0) {
            log_error(compile_rt->logger, MODULE_COMPILE,
                      "remove compile table(table_id:%d) compile(compile_id:%lld) from compile_hash failed",
                      schema->table_id, compile_id);
            return -1;
        }
    } else {
        //add
        pthread_rwlock_wrlock(&compile_rt->rwlock);

        compile_item = compile_item_new(line, schema, compile_rt->logger);
        if (NULL == compile_item) {
            pthread_rwlock_unlock(&compile_rt->rwlock);
            return -1;
        }

        struct compile_rule *compile_rule = ALLOC(struct compile_rule, 1);
        compile_item_to_compile_rule(compile_item, schema, compile_rule);
        compile_item_free(compile_item);
        compile_item = NULL;

        compile = maat_compile_new(compile_rule->compile_id);
        if (NULL == compile) {
            destroy_compile_rule(compile_rule);
            pthread_rwlock_unlock(&compile_rt->rwlock);
            log_error(compile_rt->logger, MODULE_COMPILE,
                      "maat_compile_new failed, compile_table(table_id:%d) compile_id:%d", 
                      schema->table_id, compile_item->compile_id);
            return -1;
        }
        
        maat_compile_set(compile, compile_rule->declared_clause_num, compile_rule, 
                        (void (*)(void *))destroy_compile_rule);
        struct maat_compile *tmp_compile = maat_compile_hash_find(&(compile_rt->compile_hash), compile_id);
        if (tmp_compile != NULL) {
            maat_compile_hash_set(&(compile_rt->compile_hash), compile_id, compile);
        } else {
            maat_compile_hash_add(&(compile_rt->compile_hash), compile_id, compile);
        }
        // printf("compile_runtime_update compile_id:%lu, compile->declared_clause_num:%d\n",
        //         compile->compile_id, compile->declared_clause_num);

        pthread_rwlock_unlock(&compile_rt->rwlock);
    }

    return 0;
}

int group2compile_runtime_update(void *g2c_runtime, void *g2c_schema, 
                                 const char *line, int valid_column)
{
    if (NULL == g2c_runtime || NULL == g2c_schema || NULL == line) {
        return -1;
    }

    struct group2compile_schema *schema = (struct group2compile_schema *)g2c_schema;
    struct group2compile_runtime *g2c_rt = (struct group2compile_runtime *)g2c_runtime;
    struct compile_runtime *compile_rt = g2c_rt->ref_compile_rt;
    struct group2group_runtime *g2g_rt = g2c_rt->ref_g2g_rt;
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    } 
    
    int ret = -1;
    struct group2compile_item *g2c_item = group2compile_item_new(line, schema, compile_rt->logger);
    if (NULL == g2c_item) {
        return -1;
    }

     struct maat_group *group = NULL;
    if (0 == is_valid) {
        //delete
        group = group2group_runtime_find_group(g2g_rt, g2c_item->group_id);
        if (!group) {
            log_error(compile_rt->logger, MODULE_COMPILE,
                      "Remove group %d from compile %d failed, group is not exisited.",
                      g2c_item->group_id, g2c_item->compile_id);
            return -1;
        }

        pthread_rwlock_wrlock(&compile_rt->rwlock);
        ret = maat_remove_group_from_compile(&(compile_rt->compile_hash), g2c_item,
                                             compile_rt->ref_garbage_bin, compile_rt->logger);
        pthread_rwlock_unlock(&compile_rt->rwlock);
        if (0 == ret) {
            if (g2c_item->not_flag) {
                g2c_rt->not_flag_group--;
            }
            maat_group_ref_dec(group);
        }
    } else {
        //add
        group = group2group_runtime_find_group(g2g_rt, g2c_item->group_id);
	    if (!group) {
	 	    group = group2group_runtime_add_group(g2g_rt, g2c_item->group_id);
	    }

        pthread_rwlock_wrlock(&compile_rt->rwlock);
        ret = maat_add_group_to_compile(&(compile_rt->compile_hash), g2c_item, compile_rt->logger);
        pthread_rwlock_unlock(&compile_rt->rwlock);
        if (0 == ret) {
            if (g2c_item->not_flag) {
                g2c_rt->not_flag_group++;
            }
            maat_group_ref_inc(group);
        }
    }
    

    group2compile_item_free(g2c_item);
    return ret;
}

int compile_runtime_commit(void *compile_runtime, const char *table_name)
{
    if (NULL == compile_runtime) {
        return -1;
    }

    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
    //TODO: no need add rdlock?
    size_t compile_cnt = maat_compile_in_use_count(compile_rt->compile_hash);
    if (0 == compile_cnt) {
        return 0;
    }

    struct bool_matcher *old_bool_matcher = NULL;
    struct bool_matcher *new_bool_matcher = NULL;

    log_info(compile_rt->logger, MODULE_COMPILE,
             "table[%s] committing %zu compile rules for rebuilding compile bool_matcher engine",
             table_name, compile_cnt);
    
    int ret = 0;
    new_bool_matcher = maat_compile_bool_matcher_new(compile_rt->compile_hash, 
                                                     &compile_rt->clause_id_generator,
                                                     compile_rt->logger);
    if (NULL == new_bool_matcher) {
        log_error(compile_rt->logger, MODULE_COMPILE,
                  "table[%s] rebuild compile bool_matcher engine failed when update %zu compile rules", 
                  table_name, compile_cnt);
        ret = -1;
    }

    pthread_rwlock_wrlock(&compile_rt->rwlock);
    old_bool_matcher = compile_rt->bm;
    compile_rt->bm = new_bool_matcher;
    pthread_rwlock_unlock(&compile_rt->rwlock);

    maat_garbage_bagging(compile_rt->ref_garbage_bin, old_bool_matcher, 
                        (void (*)(void*))maat_compile_bool_matcher_free);
  
    compile_rt->rule_num = compile_cnt;

    return ret;
}

static int compile_sort_para_compare(const struct compile_sort_para *a,
                                     const struct compile_sort_para *b)
{
	//If both of compile rule's evaluation order are specified, compile rule with small evaluation order is priority.
	if (a->evaluation_order != 0 && b->evaluation_order != 0) {
		if (a->evaluation_order - b->evaluation_order < 0) {
			return -1;
		} else if(a->evaluation_order - b->evaluation_order > 0) {
			return 1;
		}
	} else if(a->evaluation_order + b->evaluation_order!= 0) {
        //If one of compile rule's evaluation order is zero, compile rule with big evaluation order is priority.
		return (a->evaluation_order - b->evaluation_order > 0) ? -1 : 1;
	}

	//If compile rule's execute sequences are not specified or equal.
	if (a->declared_clause_num != b->declared_clause_num) {
		return (a->declared_clause_num - b->declared_clause_num);
	} else {
		return (b->compile_id - a->compile_id);
	}
}

static void compile_sort_para_set(struct compile_sort_para *para, 
                                  const struct compile_rule *compile_relation,
                                  void *user)
{
	para->compile_id = compile_relation->compile_id;
	para->evaluation_order = compile_relation->evaluation_order;
	para->declared_clause_num = compile_relation->declared_clause_num;
	para->user = user;
}

static int compare_compile_rule(const void *a, const void *b)
{
	const struct compile_rule *ra = *(const struct compile_rule **)a;
	const struct compile_rule *rb = *(const struct compile_rule **)b;
	
	struct compile_sort_para sa, sb;
	compile_sort_para_set(&sa, ra, NULL);
	compile_sort_para_set(&sb, rb, NULL);

	return compile_sort_para_compare(&sa, &sb);
}

int compile_runtime_match(struct compile_runtime *compile_rt, 
                          uint64_t *compile_ids, size_t compile_ids_size, 
                          struct maat_state *state)
{
    struct maat_compile_state *compile_state = state->compile_state;
    int is_last_scan = state->is_last_scan;
    struct compile_rule *compile_rules[compile_ids_size];
    
    // all hit clause_id -> compile_id
    pthread_rwlock_rdlock(&compile_rt->rwlock);
    size_t bool_match_ret = maat_compile_bool_matcher_match(compile_rt->bm, 
                                                            is_last_scan, compile_state,
                                                            (void **)compile_rules,
                                                            compile_ids_size);
    pthread_rwlock_unlock(&compile_rt->rwlock);
    if (bool_match_ret > 0) {
        qsort(compile_rules, bool_match_ret, sizeof(struct compile_rule *), 
              compare_compile_rule);
    }
   
    for (size_t i = 0; i < bool_match_ret; i++) {
        compile_ids[i] = compile_rules[i]->compile_id;
	}
    
    return MIN(bool_match_ret, compile_ids_size);
}

int maat_compile_state_update(struct maat_item *item_hash, int vtable_id,
                              uint64_t *hit_item_ids, size_t hit_item_cnt,
                              size_t *n_hit_group_id, struct maat_state *state)
{
    struct maat_item *item = NULL;
    uint64_t hit_group_ids[MAX_SCANNER_HIT_GROUP_NUM];
    memset(hit_group_ids, 0, sizeof(hit_group_ids));
    size_t hit_group_cnt = 0;

    void *g2g_rt = table_manager_get_runtime(state->maat_instance->tbl_mgr,
                                             state->maat_instance->g2g_table_id);
    if (NULL == g2g_rt) {
        return -1;
    }

    for (size_t i = 0; i < hit_item_cnt; i++) {
        HASH_FIND(hh, item_hash, &(hit_item_ids[i]), sizeof(uint64_t), item);
        //assert(item != NULL);
        if (!item) {
            // item config has been deleted
            continue;
        }

        if (hit_group_cnt >= MAX_SCANNER_HIT_GROUP_NUM) {
            hit_group_cnt = MAX_SCANNER_HIT_GROUP_NUM;
            //Prevent group_id_array out of bounds
        } else {
            hit_group_ids[hit_group_cnt++] = item->group_id;
        }

        // update hit path
        maat_compile_state_update_hit_path(state->compile_state, hit_item_ids[i], 
                                           item->group_id, vtable_id, state->scan_cnt, i);
    }

    *n_hit_group_id = hit_group_cnt;

    /* update hit clause */
    int compile_table_ids[MAX_COMPILE_TABLE_NUM] = {0};
    size_t compile_table_cnt = 0;
    if (0 == state->n_compile_table) {
        compile_table_ids[0] = state->maat_instance->default_compile_table_id;
        compile_table_cnt = 1;
    } else {
        for (size_t i = 0; i < state->n_compile_table; i++) {
            compile_table_ids[i] = maat_table_get_id(state->maat_instance, state->compile_tables[i]);
        }
        compile_table_cnt = state->n_compile_table;
    }

    for (size_t idx = 0; idx < compile_table_cnt; idx++) {
        void *compile_rt = table_manager_get_runtime(state->maat_instance->tbl_mgr, 
                                                     compile_table_ids[idx]);
        for (size_t i = 0; i < hit_group_cnt; i++) {
            uint64_t top_group_ids[MAX_SCANNER_HIT_GROUP_NUM];
            memset(top_group_ids, 0, sizeof(top_group_ids));
            int top_group_cnt = group2group_runtime_get_top_groups(g2g_rt, &hit_group_ids[i],
                                                                   1, top_group_ids);
            for (int j = 0; j < top_group_cnt; j++) {
                maat_compile_state_update_hit_clause(state->compile_state, compile_rt,
                                                     top_group_ids[j], vtable_id);
            }
        }
    }

    return 0;
}
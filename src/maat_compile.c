/*
**********************************************************************************************
*	File: maat_compile.c
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <pthread.h>
#include <linux/limits.h>

#include "maat_utils.h"
#include "log/log.h"
#include "maat.h"
#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "bool_matcher.h"
#include "igraph/igraph.h"
#include "maat_compile.h"
#include "maat_garbage_collection.h"
#include "maat_group.h"
#include "maat_ex_data.h"
#include "maat_table.h"
#include "alignment.h"

#define MODULE_COMPILE	 module_name_str("maat.compile")

struct compile_schema {
    int compile_id_column;
    int rule_tag_column;
    int declared_clause_num_column;
    int set_flag;
    int gc_timeout_s;
    int table_id; //ugly
    struct ex_data_schema ex_schema;
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

struct group2compile_schema {
    int group_id_column;
    int compile_id_column;
    int not_flag_column;
    int vtable_name_column;
    int clause_index_column;
    int asso_compile_table_id; //asso is abbreviation for associated
    int table_id;//ugly
    struct table_manager *ref_tbl_mgr;
};

struct compile_item {
    long long compile_id;
    int declared_clause_num;
};

struct group2compile_item {
    long long group_id;
    long long compile_id;
    int not_flag;
    int vtable_id;
    int clause_index;
    int asso_compile_table_id;
};

struct maat_literal_id {
	long long group_id;
	long long vtable_id;
};

struct maat_clause {
	long long clause_id;
	size_t n_literal_id;
	struct maat_literal_id *literal_ids;
	UT_hash_handle hh;
};

struct literal_clause {
    struct maat_literal_id key;
    UT_array *clause_ids;
    UT_hash_handle hh;
};

struct compile_rule {
	uint32_t magic_num;
    int declared_clause_num;
    long long compile_id;
    char *table_line;
    size_t table_line_len;
	struct compile_schema *ref_schema;
	void **ex_data;
    char table_name[MAX_NAME_STR_LEN];
};

/* compile_runtime and group2compile_runtime share compile_hash_map */
struct compile_runtime {
	struct bool_matcher *bm;
    struct rcu_hash_table *cfg_hash; // <compile_id, struct maat_compile>
    struct maat_runtime *ref_maat_rt;
    time_t version;
    struct maat_clause *clause_by_literals_hash;
    struct literal_clause *literal2clause_hash;

    long long rule_num;
    long long update_err_cnt;
    struct bool_expr_match *expr_match_buff;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

struct group2compile_runtime {
    long long not_flag_group;
    long long rule_num;
    long long update_err_cnt;
    struct compile_runtime *ref_compile_rt;
};

struct maat_clause_state {
	long long clause_id;
	UT_array *ut_literal_ids;
	char not_flag; // 1 byte
	char in_use;   // 1 byte
    char pad[6];   // for 8 bytes alignment
};

struct compile_sort_para {
	int declared_clause_num;
	long long compile_id;
};

#define MAAT_COMPILE_MAGIC	0x4a5b6c7d
struct maat_compile {
	uint32_t magic_num;
    int actual_clause_num;
	int declared_clause_num;
    int not_clause_cnt;
	long long compile_id;
    char table_name[MAX_NAME_STR_LEN];
	void *user_data;
	void (*user_data_free)(void *);
	struct maat_clause_state clause_states[MAX_ITEMS_PER_BOOL_EXPR];
};

struct maat_internal_hit_path {
    long long item_id;
	long long group_id;
	int Nth_scan;
	int Nth_hit_item;
	int vtable_id;
};

struct maat_compile_state {
    uint8_t this_scan_hit_item_flag;
    uint8_t not_clause_hit_flag;
	int Nth_scan;
    time_t compile_rt_version;

	UT_array *internal_hit_paths;
	UT_array *all_hit_clauses;
	UT_array *this_scan_hit_clauses;
};

UT_icd ut_literal_id_icd = {sizeof(struct maat_literal_id), NULL, NULL, NULL};
UT_icd ut_clause_id_icd = {sizeof(long long), NULL, NULL, NULL};
UT_icd ut_hit_group_icd = {sizeof(struct maat_hit_group), NULL, NULL, NULL};
UT_icd ut_hit_path_icd = {sizeof(struct maat_internal_hit_path), NULL, NULL, NULL};

struct maat_compile *maat_compile_new(long long compile_id)
{
	struct maat_compile *compile = ALLOC(struct maat_compile, 1);

	compile->magic_num = MAAT_COMPILE_MAGIC;
	compile->compile_id = compile_id;

    for(int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {	
		utarray_new(compile->clause_states[i].ut_literal_ids, &ut_literal_id_icd);
		compile->clause_states[i].in_use=0;
        compile->clause_states[i].clause_id = -1;
	}

	return compile;
}

int maat_compile_set(struct maat_compile *compile, const char *table_name,
                     int declared_clause_num, void *user_data, 
                     void (*user_data_free)(void *))
{
	if (user_data != NULL && NULL == user_data_free) {
		return -1;
	}

    memset(compile->table_name, 0, sizeof(compile->table_name));
    memcpy(compile->table_name, table_name, sizeof(compile->table_name));
	compile->declared_clause_num = declared_clause_num;
	compile->user_data = user_data;
	compile->user_data_free = user_data_free;

	return 0;
}

void maat_compile_free(struct maat_compile *compile)
{
	struct maat_clause_state *clause_state = NULL;
	if (compile->user_data && compile->user_data_free) {
		compile->user_data_free(compile->user_data);
        compile->user_data = NULL;
	}

	for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		clause_state = compile->clause_states + i;

        if (clause_state->ut_literal_ids != NULL) {
            utarray_free(clause_state->ut_literal_ids);
		    clause_state->ut_literal_ids = NULL;
        }
		
		clause_state->in_use = 0;
	}
	compile->magic_num = 0;
	FREE(compile);
}

void rcu_compile_cfg_free(void *user_ctx, void *data)
{
    struct maat_compile *compile = (struct maat_compile *)data;
    maat_compile_free(compile);
}

int compile_table_set_ex_data_schema(struct compile_schema *compile_schema, int table_id,
									 maat_ex_new_func_t *new_func,
                                     maat_ex_free_func_t *free_func,
                                     maat_ex_dup_func_t *dup_func,
                                     long argl, void *argp)
{
	if (1 == compile_schema->set_flag) {
        log_error(compile_schema->logger, MODULE_COMPILE, 
                  "[%s:%d] compile table(table_id:%d)ex schema has been set already, can't set again",
                  __FUNCTION__, __LINE__, table_id);
		return -1;
	}

    compile_schema->ex_schema.new_func = new_func;
    compile_schema->ex_schema.free_func = free_func;
    compile_schema->ex_schema.dup_func = dup_func;
    compile_schema->ex_schema.argl = argl;
    compile_schema->ex_schema.argp = argp;
    compile_schema->set_flag = 1;
    
	return 0;
}

void *compile_runtime_get_user_data(struct compile_runtime *compile_rt, long long compile_id)
{
    struct maat_compile *compile = rcu_hash_find(compile_rt->cfg_hash,
                                                 (char *)&compile_id, sizeof(long long));
    void *ret = NULL;
    if (compile != NULL) {
        ret = compile->user_data;
    }

    return ret;
}

void *rule_ex_data_new(const char *table_name, int table_id, const char *table_line, 
                       struct ex_data_schema *ex_schema)
{
	void *ex_data = NULL;

	ex_schema->new_func(table_name, table_id, NULL, table_line, &ex_data, 
                        ex_schema->argl, ex_schema->argp);
    return ex_data;
}

void rule_ex_data_free(int table_id, void **ex_data, const struct ex_data_schema *ex_schema)
{
	ex_schema->free_func(table_id, ex_data, ex_schema->argl, ex_schema->argp);
}

void rule_ex_data_new_cb(void *user_data, void *param, const char *table_name, int table_id)
{
	struct ex_data_schema *ex_schema = (struct ex_data_schema *)param;
	struct compile_rule *compile = (struct compile_rule *)user_data;

	void *ad = rule_ex_data_new(table_name, table_id, compile->table_line, ex_schema);
	*compile->ex_data = ad;
}

void compile_runtime_user_data_iterate(struct compile_runtime *compile_rt, 
                                       void (*callback)(void *user_data, void *param, const char *table_name, int table_id), 
                                       void *param, int table_id)
{
    /* I'm in background_update_mutex, config update can't happen, so no need to lock cfg_hash */
    void **data_array = NULL;
    size_t data_cnt = rcu_hash_list(compile_rt->cfg_hash, &data_array);

    for (size_t i = 0; i < data_cnt; i++) {
        struct maat_compile *compile = (struct maat_compile *)data_array[i];
        if (compile->user_data) {
            callback(compile->user_data, param, compile->table_name, table_id);
        }
    }

    FREE(data_array);
}

void *compile_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name,
                         struct log_handle *logger)
{
	struct compile_schema *schema = ALLOC(struct compile_schema, 1);
    schema->logger = logger;

	cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no table_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

   	item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "compile_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->compile_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no compile_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "tags");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->rule_tag_column = custom_item->valueint;
    }

    custom_item = cJSON_GetObjectItem(item, "clause_num");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->declared_clause_num_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no clause_num column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    //gc_timeout_s is optional
    custom_item = cJSON_GetObjectItem(item, "gc_timeout_s");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->gc_timeout_s = custom_item->valueint;
    }

    schema->ref_tbl_mgr = tbl_mgr;
	return schema;
error:
	FREE(schema);
	return NULL;
}

void compile_schema_free(void *compile_schema)
{
	FREE(compile_schema);
}

void *group2compile_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                               const char *table_name, struct log_handle *logger)
{
	struct group2compile_schema *g2c_schema = ALLOC(struct group2compile_schema, 1);

	cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        g2c_schema->table_id = item->valueint;
    } else {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "associated_compile_table_id");
    if (item != NULL && item->type == cJSON_Number) {
        g2c_schema->asso_compile_table_id = item->valueint;
    } else {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no associated_compile_table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->group_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no group_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "compile_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->compile_id_column = custom_item->valueint;
    } else {
         log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no compile_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "not_flag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->not_flag_column = custom_item->valueint;
    } else {
         log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no not_flag column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "virtual_table_name");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->vtable_name_column = custom_item->valueint;
    } else {
         log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no virtual_table_name column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "clause_index");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->clause_index_column = custom_item->valueint;
    } else {
         log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no clause_index column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    g2c_schema->ref_tbl_mgr = tbl_mgr;
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

    return schema->asso_compile_table_id;
}

int compile_accept_tag_match(struct compile_schema *schema, const char *line,
                             const char *table_name, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    if (schema->rule_tag_column > 0 && n_tag > 0) {
        int ret = get_column_pos(line, schema->rule_tag_column, 
                                 &column_offset, &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_COMPILE,
                      "[%s:%d] table: <%s> has no rule_tag in line:%s",
                      __FUNCTION__, __LINE__, table_name, line);
            return TAG_MATCH_ERR;
        }

        if (column_len > 2) {
            char *tag_str = ALLOC(char, column_len + 1);
            memcpy(tag_str, (line + column_offset), column_len);
            ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag_str);
            FREE(tag_str);
            if (TAG_MATCH_ERR == ret) {
                log_error(logger, MODULE_COMPILE,
                          "[%s:%d] table: <%s> has invalid tag format in line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_ERR;
            }

            if (TAG_MATCH_UNMATCHED == ret) {
                log_error(logger, MODULE_COMPILE,
                          "[%s:%d] table: <%s> has unmatched tag in line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_UNMATCHED;
            }
        }
    }

    return TAG_MATCH_MATCHED;
}

struct compile_item *
compile_item_new(const char *line, struct compile_schema *compile_schema,
                 const char *table_name, struct log_handle *logger)
{
    int ret = compile_accept_tag_match(compile_schema, line, table_name, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    size_t column_offset = 0;
    size_t column_len = 0;
    struct compile_item *compile_item = ALLOC(struct compile_item, 1);

    ret = get_column_pos(line, compile_schema->compile_id_column, 
                             &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
                  "[%s:%d] table: <%s> has no compile_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    compile_item->compile_id = atoll(line + column_offset);

    ret = get_column_pos(line, compile_schema->declared_clause_num_column, 
                         &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
                  "[%s:%d] table: <%s> has no clause_num in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }
    compile_item->declared_clause_num = atoi(line + column_offset);

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

void *compile_runtime_new(void *compile_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin, 
                          struct log_handle *logger)
{
	if (NULL == compile_schema) {
        return NULL;
    }

    struct compile_schema *schema = (struct compile_schema *)compile_schema;
    struct compile_runtime *compile_rt = ALLOC(struct compile_runtime, 1);

    compile_rt->expr_match_buff = ALLOC(struct bool_expr_match, 
                                        max_thread_num * MAX_SCANNER_HIT_COMPILE_NUM);
    compile_rt->version = time(NULL);
    compile_rt->cfg_hash = rcu_hash_new(rcu_compile_cfg_free, NULL,
                                        schema->gc_timeout_s);
    compile_rt->clause_by_literals_hash = NULL;
    compile_rt->literal2clause_hash = NULL;
    compile_rt->logger = logger;
    compile_rt->ref_garbage_bin = garbage_bin;

    return compile_rt;
}

static void maat_clause_hash_free(struct maat_clause *clause_hash)
{
	struct maat_clause *clause = NULL, *tmp_clause = NULL;

	HASH_ITER (hh, clause_hash, clause, tmp_clause) {
		HASH_DEL(clause_hash, clause);
		FREE(clause->literal_ids);
		clause->n_literal_id = 0;
		FREE(clause);
	}
}

static void literal2clause_hash_free(struct literal_clause *hash)
{
    struct literal_clause *l2c_val = NULL, *tmp_l2c_val = NULL;

    HASH_ITER(hh, hash, l2c_val, tmp_l2c_val) {
        HASH_DEL(hash, l2c_val);
        if (l2c_val->clause_ids != NULL) {
            utarray_free(l2c_val->clause_ids);
            l2c_val->clause_ids = NULL;
        }
        
        FREE(l2c_val);
    }
    assert(hash == NULL);
}

void garbage_literal2clause_hash_free(void *l2c_hash, void *arg)
{
    literal2clause_hash_free((struct literal_clause *)l2c_hash);
}

void compile_runtime_free(void *compile_runtime)
{
    if (NULL == compile_runtime) {
        return;
    }

    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;

    if (compile_rt->bm != NULL) {
        bool_matcher_free(compile_rt->bm);
        compile_rt->bm = NULL;
    }

    if (compile_rt->cfg_hash != NULL) {
        rcu_hash_free(compile_rt->cfg_hash);
        compile_rt->cfg_hash = NULL;
    }
    
    if (compile_rt->literal2clause_hash != NULL) {
        literal2clause_hash_free(compile_rt->literal2clause_hash);
        compile_rt->literal2clause_hash = NULL;
    }

    if (compile_rt->clause_by_literals_hash != NULL) {
        maat_clause_hash_free(compile_rt->clause_by_literals_hash);
        compile_rt->clause_by_literals_hash = NULL;
    }

    if (compile_rt->expr_match_buff != NULL) {
        FREE(compile_rt->expr_match_buff);
    }

    FREE(compile_rt);
}

void compile_runtime_init(void *compile_runtime, struct maat_runtime *maat_rt)
{
    if (NULL == compile_runtime) {
        return;
    }

    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
    compile_rt->ref_maat_rt = maat_rt;
}

void *group2compile_runtime_new(void *g2c_schema, size_t max_thread_num,
                                struct maat_garbage_bin *garbage_bin, 
                                struct log_handle *logger)
{
    if (NULL == g2c_schema) {
        return NULL;
    }

    struct group2compile_runtime *g2c_rt = ALLOC(struct group2compile_runtime, 1);

    return g2c_rt;
}

void group2compile_runtime_init(void *g2c_runtime, void *compile_runtime)
{
    struct group2compile_runtime *g2c_rt = (struct group2compile_runtime *)g2c_runtime;

    g2c_rt->ref_compile_rt = (struct compile_runtime *)compile_runtime;
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
                       const char *table_name, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char vtable_name[MAX_NAME_STR_LEN] = {0};
    struct group2compile_item *g2c_item = ALLOC(struct group2compile_item, 1);

    int ret = get_column_pos(line, g2c_schema->group_id_column, &column_offset,
                             &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> has no group_id in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }
    g2c_item->group_id = atoll(line + column_offset);

    ret = get_column_pos(line, g2c_schema->compile_id_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> has no compile_id in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }
    g2c_item->compile_id = atoll(line + column_offset);

    ret = get_column_pos(line, g2c_schema->not_flag_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> has no NOT_flag in line:%s ",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }
    g2c_item->not_flag = atoi(line + column_offset);

    ret = get_column_pos(line, g2c_schema->vtable_name_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s>has no virtual_table_name in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }

    if (column_len > MAX_NAME_STR_LEN) {
        log_error(logger, MODULE_COMPILE, 
                  "[%s:%d] g2c table:<%s> virtual_table_name length exceed "
                  "maxium:%d in line:%s", __FUNCTION__, __LINE__, table_name,
                  MAX_NAME_STR_LEN, line);
        goto error;
    }
    
    memcpy(vtable_name, (line + column_offset), column_len);
    
    if (is_valid_table_name(vtable_name)) {
        g2c_item->vtable_id = table_manager_get_table_id(g2c_schema->ref_tbl_mgr,
                                                         vtable_name);
        if (g2c_item->vtable_id < 0) {
            log_error(logger, MODULE_COMPILE,
                      "[%s:%d] g2c table:<%s> has unknown virtual table:%s in line:%s",
                      __FUNCTION__, __LINE__, table_name, vtable_name, line);
            goto error;
        }
    }
   
    ret = get_column_pos(line, g2c_schema->clause_index_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_COMPILE,
                  "[%s:%d] g2c table:<%s> has no clause_index in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
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

int compare_literal_id(const void *pa, const void *pb)
{
	struct maat_literal_id *la = (struct maat_literal_id *)pa;
	struct maat_literal_id *lb = (struct maat_literal_id *)pb;

	long long ret = la->vtable_id - lb->vtable_id;
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
    tmp = (struct maat_literal_id *)utarray_find(clause_state->ut_literal_ids,
                                                 literal_id, compare_literal_id);
	if (tmp) {
        assert(tmp->group_id == literal_id->group_id);
        assert(tmp->vtable_id == literal_id->vtable_id);
		return -1;
	} else {
		utarray_push_back(clause_state->ut_literal_ids, literal_id);
		utarray_sort(clause_state->ut_literal_ids, compare_literal_id);
	}

	return 0;
}

int maat_compile_clause_remove_literal(struct maat_compile *compile,
                                       struct maat_literal_id *literal_id,
                                       int clause_index)
{
    struct maat_clause_state* clause_state = compile->clause_states + clause_index;
	struct maat_literal_id *tmp = NULL;
    tmp = (struct maat_literal_id *)utarray_find(clause_state->ut_literal_ids,
                                                 literal_id, compare_literal_id);
	if (tmp) {
		assert(*(unsigned long long*)tmp == *(unsigned long long*)(literal_id));
	} else {
		return -1;
	}

	size_t remove_idx = utarray_eltidx(clause_state->ut_literal_ids, tmp);
	utarray_erase(clause_state->ut_literal_ids, remove_idx, 1);

	if (0 == utarray_len(clause_state->ut_literal_ids)) {
		clause_state->in_use = 0;
		compile->actual_clause_num--;
	}

	return 0;
}

static const struct maat_clause *
maat_clause_hash_fetch_clause(struct compile_runtime *compile_rt,
							  struct maat_literal_id *literal_ids, 
                              size_t n_literal_id)
{
	struct maat_clause *clause = NULL;
    
	HASH_FIND(hh, compile_rt->clause_by_literals_hash, literal_ids, 
              n_literal_id * sizeof(struct maat_literal_id), clause);
	if (NULL == clause) {
		clause = ALLOC(struct maat_clause, 1);
		clause->clause_id = maat_runtime_get_sequence(compile_rt->ref_maat_rt, "clause_id");
		clause->n_literal_id = n_literal_id;
		clause->literal_ids = ALLOC(struct maat_literal_id, n_literal_id);
		memcpy(clause->literal_ids, literal_ids, n_literal_id * sizeof(struct maat_literal_id));
		
		HASH_ADD_KEYPTR(hh, compile_rt->clause_by_literals_hash, clause->literal_ids, 
                        n_literal_id * sizeof(struct maat_literal_id), clause);
	}

	return clause;
}

struct bool_matcher *
maat_compile_bool_matcher_new(struct compile_runtime *compile_rt, size_t *compile_cnt)
{
	if (NULL == compile_rt) {
        return NULL;
    }

    size_t i = 0, j = 0, idx = 0;
    int has_clause_num = 0;
    const struct maat_clause *clause = NULL;
    struct maat_literal_id *literal_ids = NULL;

    // STEP 1, update clause_id of each compile and literal
    void **data_array = NULL;
    struct maat_compile *iter_compile = NULL;
    size_t rule_cnt = rcu_updating_hash_list(compile_rt->cfg_hash, &data_array);
    *compile_cnt = rule_cnt;

    for (idx = 0; idx < rule_cnt; idx++) {
        iter_compile = (struct maat_compile *)data_array[idx];
        has_clause_num = 0;
        for (i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            struct maat_clause_state *clause_state = iter_compile->clause_states + i;
            if (!clause_state->in_use) {
                continue;
            }

            has_clause_num++;
            literal_ids = (struct maat_literal_id *)utarray_eltptr(clause_state->ut_literal_ids, 0);
            size_t n_literal_id = utarray_len(clause_state->ut_literal_ids);
            clause = maat_clause_hash_fetch_clause(compile_rt, literal_ids, n_literal_id);
            clause_state->clause_id = clause->clause_id;
        }
        assert(has_clause_num == iter_compile->actual_clause_num);
    }

    // STEP 2, serial compile clause states to a bool expression array
    size_t expr_cnt = 0;
    struct bool_expr *bool_expr_array = ALLOC(struct bool_expr, rule_cnt);

    for (idx = 0; idx < rule_cnt; idx++) {
        iter_compile = (struct maat_compile *)data_array[idx];
        for (i = 0, j = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            if (iter_compile->clause_states[i].in_use) {
                if (iter_compile->clause_states[i].not_flag) {
                    iter_compile->not_clause_cnt++;
                }
// TODO:mytest need to delete
#if 0
				struct maat_literal_id *p = NULL;
				for(p = (struct maat_literal_id *)utarray_front(iter_compile->clause_states[i].ut_literal_ids); p!=NULL; 
                    p = (struct maat_literal_id *)utarray_next(iter_compile->clause_states[i].ut_literal_ids, p)) {
    				printf("<before bool_matcher_new> compile_rt:%p compile_id:%lld, clause_id:%llu, literal{%lld: %lld}\n", 
							compile_rt, iter_compile->compile_id, iter_compile->clause_states[i].clause_id, p->group_id, p->vtable_id);
  				}
#endif
                bool_expr_array[expr_cnt].items[j].item_id = iter_compile->clause_states[i].clause_id;
                bool_expr_array[expr_cnt].items[j].not_flag = iter_compile->clause_states[i].not_flag;

                j++;
            }
        }

        // some compile may have zero groups, e.g. default policy.
        if (j == (size_t)iter_compile->declared_clause_num && j > 0) {
            bool_expr_array[expr_cnt].expr_id = iter_compile->compile_id;
            bool_expr_array[expr_cnt].user_tag = iter_compile;
            bool_expr_array[expr_cnt].item_num = j;
            expr_cnt++;
        }
    }

    FREE(data_array);

    // STEP 3, build bool matcher
    size_t mem_size = 0;
    if (0 == expr_cnt) {
        log_error(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] No bool expression to build bool matcher.",
                  __FUNCTION__, __LINE__);
        FREE(bool_expr_array);
        return NULL;
    }

    struct bool_matcher *bm = bool_matcher_new(bool_expr_array, expr_cnt, &mem_size);
    if (bm != NULL) {
        log_info(compile_rt->logger, MODULE_COMPILE,
                 "Build bool matcher of %zu expressions with %zu bytes memory.",
                 expr_cnt, mem_size);
    } else {
        log_error(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] Build bool matcher failed!", __FUNCTION__, __LINE__);
    }

    FREE(bool_expr_array);
    return bm;
}

static inline int compare_clause_id(const void *a, const void *b)
{
	long long ret = *(const long long *)a - *(const long long *)b;

	if (0 == ret) {
		return 0;
	} else if(ret < 0) {
		return -1;
	} else {
		return 1;
	}
}

static inline int compare_hit_group(const void *pa, const void *pb)
{
	struct maat_hit_group *la=(struct maat_hit_group *)pa;
	struct maat_hit_group *lb=(struct maat_hit_group *)pb;

	long long ret = la->group_id - lb->group_id;
	if (ret == 0) {
		ret = la->vtable_id - lb->vtable_id;
	}

	return ret;
}

struct literal_clause *
maat_compile_build_literal2clause_hash(struct compile_runtime *compile_rt)
{
    if (NULL == compile_rt) {
        return NULL;
    }

    void **data_array = NULL;
    struct maat_clause_state *clause_state = NULL;
    struct maat_literal_id *tmp_literal_id = NULL;
    struct literal_clause *l2c_value = NULL;
    struct literal_clause *literal2clause_hash = NULL;
    size_t compile_cnt = rcu_updating_hash_list(compile_rt->cfg_hash, &data_array);

    for (size_t idx = 0; idx < compile_cnt; idx++) {
        struct maat_compile *compile = (struct maat_compile *)data_array[idx];
        for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            clause_state = compile->clause_states + i;
            if (!clause_state->in_use) {
                continue;
            }

            for (size_t j = 0; j < utarray_len(clause_state->ut_literal_ids); j++) {
                tmp_literal_id = (struct maat_literal_id *)utarray_eltptr(clause_state->ut_literal_ids, j);
                HASH_FIND(hh, literal2clause_hash, tmp_literal_id, sizeof(struct maat_literal_id), l2c_value);
                if (NULL == l2c_value) {
                    l2c_value = ALLOC(struct literal_clause, 1);
                    l2c_value->key = *tmp_literal_id;
                    utarray_new(l2c_value->clause_ids, &ut_clause_id_icd);
                    HASH_ADD(hh, literal2clause_hash, key, sizeof(l2c_value->key), l2c_value);
                }

                if (utarray_find(l2c_value->clause_ids, &(clause_state->clause_id), compare_clause_id)) {
                    continue;
                }
                utarray_push_back(l2c_value->clause_ids, &(clause_state->clause_id));
                utarray_sort(l2c_value->clause_ids, compare_clause_id);
            }
        }
    }

    FREE(data_array);
    return literal2clause_hash;
}

static int maat_compile_has_clause(struct maat_compile *compile, long long clause_id)
{
	struct maat_clause_state *clause_state = NULL;

	for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		clause_state = compile->clause_states + i;
		if (!clause_state->in_use) {
			continue;
		}

		if (clause_state->clause_id == clause_id) {
			return 1;
		}
	}

	return 0;
}

static size_t compile_state_if_new_hit_compile(struct maat_compile_state *compile_state,
                                               struct maat_compile *compile)
{
	size_t r_in_c_cnt = 0;
	int ret = 0;

	long long new_hit_clause_id = 0;
	for (size_t i = 0; i < utarray_len(compile_state->this_scan_hit_clauses); i++) {
		new_hit_clause_id = *(long long*)utarray_eltptr(compile_state->this_scan_hit_clauses, i);
		ret = maat_compile_has_clause(compile, new_hit_clause_id);
		if (ret) {
			r_in_c_cnt++;
		}
	}

	return r_in_c_cnt;
}

size_t maat_compile_bool_matcher_match(struct compile_runtime *compile_rt, int is_last_scan,
                                       struct maat_compile_state *compile_state, int thread_id,
                                       void **user_data_array, size_t ud_array_size)
{
    size_t ud_result_cnt = 0;
	struct maat_compile *compile = NULL;
	struct bool_expr_match *expr_match = compile_rt->expr_match_buff +
                                         (thread_id * MAX_SCANNER_HIT_COMPILE_NUM);
    assert(thread_id >= 0);

    if (0 == compile_state->compile_rt_version) {
        compile_state->compile_rt_version = compile_rt->version;
    }

    if (NULL == compile_rt->bm || 0 == utarray_len(compile_state->all_hit_clauses)
        || compile_state->compile_rt_version != compile_rt->version) {
        compile_state->this_scan_hit_item_flag = 0;
        return 0;
    }

	//TODO:mytest need to delete
	#if 0
	unsigned long long *p = utarray_eltptr(compile_state->all_hit_clauses, 0);
	for (p = (unsigned long long *)utarray_front(compile_state->all_hit_clauses); p != NULL; 
         p = (unsigned long long *)utarray_next(compile_state->all_hit_clauses, p)) {
		printf("before bool_matcher_match compile_rt:%p compile_state clause_id:%llu\n",  compile_rt, *p);
	}
	#endif
	
	int bool_match_ret = bool_matcher_match(compile_rt->bm, 
                                            (unsigned long long *)utarray_eltptr(compile_state->all_hit_clauses, 0),
											utarray_len(compile_state->all_hit_clauses), 
                                            expr_match, MAX_SCANNER_HIT_COMPILE_NUM);
	for (int i = 0; i < bool_match_ret && ud_result_cnt < ud_array_size; i++) {
		compile = (struct maat_compile *)expr_match[i].user_tag;
		assert(compile->magic_num == MAAT_COMPILE_MAGIC);
		assert((unsigned long long)compile->compile_id == expr_match[i].expr_id);
		if (0 == compile->actual_clause_num) {
			continue;
		}

        size_t n_new_hit_compile = compile_state_if_new_hit_compile(compile_state, compile);
        int this_scan_hit_item_flag = compile_state->this_scan_hit_item_flag;
        if ((compile->not_clause_cnt > 0) && (LAST_SCAN_UNSET == is_last_scan)) {
            compile_state->not_clause_hit_flag = 1;
        } else if (compile->user_data) {
             if (n_new_hit_compile > 0 || 0 == this_scan_hit_item_flag) {
                /* compile hit because of new item or
                   hit a compile that refer a NOT-logic group in previous scan */
                user_data_array[ud_result_cnt] = compile->user_data;
			    ud_result_cnt++;
            }
        }
	}

    compile_state->this_scan_hit_item_flag = 0;

	return ud_result_cnt;
}

#define	COMPILE_RULE_MAGIC	0x1a2b3c4d
struct compile_rule *compile_rule_new(struct compile_item *compile_item,
                                      struct compile_schema *schema,
                                      const char *table_name,
                                      const char *table_line)
{
    struct compile_rule *compile_rule = ALLOC(struct compile_rule, 1);

    compile_rule->magic_num = COMPILE_RULE_MAGIC;
    compile_rule->declared_clause_num = compile_item->declared_clause_num;
    compile_rule->ref_schema = schema;
    compile_rule->ex_data = ALLOC(void *, 1);
    memcpy(compile_rule->table_name, table_name, sizeof(compile_rule->table_name));
    compile_rule->table_line_len = strlen(table_line) + 1;
    compile_rule->table_line = ALLOC(char, compile_rule->table_line_len);
    memcpy(compile_rule->table_line, table_line, compile_rule->table_line_len);

    if (1 == schema->set_flag)
    {
        *(compile_rule->ex_data) = rule_ex_data_new(table_name, schema->table_id,
                                                    compile_rule->table_line,
                                                    &(schema->ex_schema));
    }

    compile_rule->compile_id = compile_item->compile_id;

    return compile_rule;
}

struct compile_rule *compile_rule_clone(struct compile_rule *rule)
{
    struct compile_rule *new_rule = ALLOC(struct compile_rule, 1);

    new_rule->magic_num = rule->magic_num;
    new_rule->declared_clause_num = rule->declared_clause_num;
    new_rule->ref_schema = rule->ref_schema;
    new_rule->ex_data = ALLOC(void *, 1);
    memcpy(new_rule->table_name, rule->table_name, sizeof(new_rule->table_name));
    new_rule->table_line_len = rule->table_line_len;
    new_rule->table_line = ALLOC(char, new_rule->table_line_len);
    memcpy(new_rule->table_line, rule->table_line, new_rule->table_line_len);

    if (1 == rule->ref_schema->set_flag) {
        *(new_rule->ex_data) = rule_ex_data_new(rule->table_name, rule->ref_schema->table_id,
                                                rule->table_line, &(rule->ref_schema->ex_schema));
    }
    new_rule->compile_id = rule->compile_id;

    return new_rule;
}

void compile_rule_free(struct compile_rule *compile_rule)
{
    struct compile_schema *schema = compile_rule->ref_schema;
    assert(compile_rule->magic_num == COMPILE_RULE_MAGIC);

    if (1 == schema->set_flag) {
        rule_ex_data_free(schema->table_id, compile_rule->ex_data,
                          &(schema->ex_schema));
        *compile_rule->ex_data = NULL;
    }

    if (compile_rule->ex_data != NULL) {
        FREE(compile_rule->ex_data);
    }
    
    compile_rule->declared_clause_num = -1;

    if (compile_rule->table_line != NULL) {
        FREE(compile_rule->table_line);
    }
    
    FREE(compile_rule);
}

struct maat_compile *maat_compile_clone(struct maat_compile *compile, int deep_copy)
{
    struct maat_compile *new_compile = ALLOC(struct maat_compile, 1);

    new_compile->magic_num = compile->magic_num;
    new_compile->compile_id = compile->compile_id;
    new_compile->actual_clause_num = compile->actual_clause_num;
    new_compile->declared_clause_num = compile->declared_clause_num;
    memcpy(new_compile->table_name, compile->table_name, sizeof(new_compile->table_name));
    new_compile->not_clause_cnt = compile->not_clause_cnt;
    new_compile->user_data_free = compile->user_data_free;
    if (1 == deep_copy && compile->user_data != NULL) {
        new_compile->user_data = compile_rule_clone((struct compile_rule *)compile->user_data);
    }

    struct maat_literal_id *literal_id = NULL;
    for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
        new_compile->clause_states[i].clause_id = compile->clause_states[i].clause_id;
        new_compile->clause_states[i].in_use = compile->clause_states[i].in_use;
        new_compile->clause_states[i].not_flag = compile->clause_states[i].not_flag;
        utarray_new(new_compile->clause_states[i].ut_literal_ids, &ut_literal_id_icd);
        for (int j = 0; j < utarray_len(compile->clause_states[i].ut_literal_ids); j++) {
            literal_id = (struct maat_literal_id *)utarray_eltptr(compile->clause_states[i].ut_literal_ids, j);
            utarray_push_back(new_compile->clause_states[i].ut_literal_ids, literal_id);
        }

        for (int k = 0; k < utarray_len(new_compile->clause_states[i].ut_literal_ids); k++) {
            literal_id = (struct maat_literal_id *)utarray_eltptr(new_compile->clause_states[i].ut_literal_ids, k);
        }
    }

    return new_compile;
}

int maat_add_group_to_compile(struct rcu_hash_table *hash_tbl, struct group2compile_item *g2c_item,
                              struct log_handle *logger)
{
	int ret = -1;
    long long compile_id = g2c_item->compile_id;
    struct maat_compile *compile = NULL;
    struct maat_literal_id literal_id = {g2c_item->group_id, g2c_item->vtable_id};

    int updating_flag = rcu_hash_is_updating(hash_tbl);
    if (1 == updating_flag) {
        compile = rcu_updating_hash_find(hash_tbl, (char *)&compile_id, sizeof(long long));
        if (compile != NULL) {
            /* compile found in updating hash(added by compile runtime), it can be modified directly */
            ret = maat_compile_clause_add_literal(compile, &literal_id, g2c_item->clause_index,
                                                  g2c_item->not_flag);
            if (ret < 0) {
                log_error(logger, MODULE_COMPILE,
                          "[%s:%d] add literal_id{group_id:%lld, vtable_id:%d} to clause_index: %d"
                          " of compile %d failed", __FUNCTION__, __LINE__, g2c_item->group_id,
                          g2c_item->vtable_id, g2c_item->clause_index, compile_id);
            }
        } else {
            /* compile neither in effective hash nor in updating hash, so new one */
            compile = maat_compile_new(compile_id);
            assert(compile != NULL);
            ret = maat_compile_clause_add_literal(compile, &literal_id, g2c_item->clause_index,
                                                  g2c_item->not_flag);
            if (ret < 0) {
                log_error(logger, MODULE_COMPILE,
                          "[%s:%d] add literal_id{group_id:%lld, vtable_id:%d} to clause_index: %d"
                          " of compile %d failed", __FUNCTION__, __LINE__, g2c_item->group_id,
                          g2c_item->vtable_id, g2c_item->clause_index, compile_id);
            }
            rcu_hash_add(hash_tbl, (char *)&compile_id, sizeof(long long), compile);
        }
    } else {
        compile = rcu_hash_find(hash_tbl, (char *)&compile_id, sizeof(long long));
        if (compile != NULL) {
            /*******************************************************************
                compile found in effective hash(added by compile runtime), which means

                1. rcu_hash_add(hash_tbl, compile)  ==> finished
                2. rcu_hash_commit(hash_tbl)        ==> finished

                can only be deleted but not modified
                before delete it, we need to make a copy for further use
            *********************************************************************/
            struct maat_compile *copy_compile = maat_compile_clone(compile, 1);
            assert(copy_compile != NULL);

            /* delete compile from rcu hash */
            rcu_hash_del(hash_tbl, (char *)&compile_id, sizeof(long long));

            ret = maat_compile_clause_add_literal(copy_compile, &literal_id, g2c_item->clause_index,
                                                  g2c_item->not_flag);
            if (ret < 0) {
                log_error(logger, MODULE_COMPILE,
                          "[%s:%d] add literal_id{group_id:%lld, vtable_id:%d} to clause_index: %d"
                          " of compile %d failed", __FUNCTION__, __LINE__, g2c_item->group_id,
                          g2c_item->vtable_id, g2c_item->clause_index, compile_id);
            }

            rcu_hash_add(hash_tbl, (char *)&compile_id, sizeof(long long), copy_compile);
        } else {
            compile = maat_compile_new(compile_id);
            assert(compile != NULL);
            ret = maat_compile_clause_add_literal(compile, &literal_id, g2c_item->clause_index,
                                                  g2c_item->not_flag);
            if (ret < 0) {
                log_error(logger, MODULE_COMPILE,
                          "[%s:%d] add literal_id{group_id:%lld, vtable_id:%d} to clause_index: %d"
                          " of compile %d failed",  __FUNCTION__, __LINE__, g2c_item->group_id,
                          g2c_item->vtable_id, g2c_item->clause_index, compile_id);
            }
            rcu_hash_add(hash_tbl, (char *)&compile_id, sizeof(long long), compile);
        }
    }

    return ret;
}

int maat_remove_group_from_compile(struct rcu_hash_table *hash_tbl,
                                   struct group2compile_item *g2c_item,
                                   struct log_handle *logger)
{
	int ret = -1;
    long long compile_id = g2c_item->compile_id;
    struct maat_compile *compile = NULL;
    struct maat_literal_id literal_id = {g2c_item->group_id, g2c_item->vtable_id};

    int updating_flag = rcu_hash_is_updating(hash_tbl);
    if (1 == updating_flag) {
        compile = rcu_updating_hash_find(hash_tbl, (char *)&compile_id,
                                         sizeof(long long));
        if (NULL == compile) {
            log_error(logger, MODULE_COMPILE,
                      "[%s:%d] Remove group_id:%lld from compile_id:%lld failed, compile"
                      " is not exisited.", __FUNCTION__, __LINE__, g2c_item->group_id,
                      compile_id);
            return -1;
        } else {
            /* compile found in updating hash, it can be modified directly */
            ret = maat_compile_clause_remove_literal(compile, &literal_id,
                                                     g2c_item->clause_index);
            if (ret < 0) {
                log_error(logger, MODULE_COMPILE,
                          "[%s:%d] Remove group_id:%lld vtable_id %d from clause %d of "
                          "compile_id:%lld failed, literal is not in compile.", __FUNCTION__,
                          __LINE__, g2c_item->group_id, g2c_item->vtable_id,
                          g2c_item->clause_index, compile_id);
            }

            if (0 == compile->actual_clause_num && NULL == compile->user_data) {
                rcu_hash_del(hash_tbl, (char *)&compile_id, sizeof(long long));
            } 
        }
    } else {
        //find in effetive hash
        compile = rcu_hash_find(hash_tbl, (char *)&compile_id, sizeof(long long));
        if (compile != NULL) {
            /*******************************************************************
                compile found in effective hash, which means

                1. rcu_hash_add(hash_tbl, compile)  ==> finished
                2. rcu_hash_commit(hash_tbl)        ==> finished

                can only be deleted but not modified
                before delete it, we need to make a copy for further use
            *********************************************************************/
            struct maat_compile *copy_compile = maat_compile_clone(compile, 1);
            assert(copy_compile != NULL);

            /* delete compile from rcu hash */
            rcu_hash_del(hash_tbl, (char *)&compile_id, sizeof(long long));

            ret = maat_compile_clause_remove_literal(copy_compile, &literal_id,
                                                     g2c_item->clause_index);
            if (ret < 0) {
                log_error(logger, MODULE_COMPILE,
                          "[%s:%d] Remove group_id:%lld vtable_id %d from clause %d of compile_id:"
                          "%lld failed, literal is not in compile.", __FUNCTION__, __LINE__,
                          g2c_item->group_id, g2c_item->vtable_id, g2c_item->clause_index,
                          compile_id);
            }
            
            if (0 == copy_compile->actual_clause_num && NULL == copy_compile->user_data) {
                maat_compile_free(copy_compile);
            } else {
                rcu_hash_add(hash_tbl, (char *)&compile_id, sizeof(long long), copy_compile);
            }
        } else {
            log_error(logger, MODULE_COMPILE,
                      "[%s:%d] Remove group_id:%lld from compile_id:%lld failed, "
                      "compile is not exisited.", __FUNCTION__, __LINE__, 
                      g2c_item->group_id, compile_id);
            return -1;
        }
    }

    return ret;
}

struct maat_compile_state *maat_compile_state_new(void)
{
    struct maat_compile_state *compile_state = ALLOC(struct maat_compile_state, 1);

	utarray_new(compile_state->internal_hit_paths, &ut_hit_path_icd);
	utarray_new(compile_state->all_hit_clauses, &ut_clause_id_icd);
	utarray_new(compile_state->this_scan_hit_clauses, &ut_clause_id_icd);

	return compile_state;
}

void maat_compile_state_reset(struct maat_compile_state *compile_state)
{
    if (NULL == compile_state) {
        return;
    }

    compile_state->Nth_scan = 0;
    compile_state->compile_rt_version = 0;
    compile_state->this_scan_hit_item_flag = 0;
    compile_state->not_clause_hit_flag = 0;

    utarray_clear(compile_state->internal_hit_paths);
    utarray_clear(compile_state->all_hit_clauses);
    utarray_clear(compile_state->this_scan_hit_clauses);
}

void maat_compile_state_free(struct maat_compile_state *compile_state,
                             struct maat *maat_inst, int thread_id)
{
    if (NULL == compile_state) {
        return;
    }
    
    long long free_bytes = 0;
    if (compile_state->internal_hit_paths != NULL) {
        free_bytes += utarray_len(compile_state->internal_hit_paths) * sizeof(struct maat_internal_hit_path);
        utarray_free(compile_state->internal_hit_paths);
        compile_state->internal_hit_paths = NULL;
    }
    
    if (compile_state->all_hit_clauses != NULL) {
        free_bytes += utarray_len(compile_state->all_hit_clauses) * sizeof(long long);
        utarray_free(compile_state->all_hit_clauses);
        compile_state->all_hit_clauses = NULL;
    }
	
    if (compile_state->this_scan_hit_clauses != NULL) {
        free_bytes += utarray_len(compile_state->this_scan_hit_clauses) * sizeof(long long);
        utarray_free(compile_state->this_scan_hit_clauses);
        compile_state->this_scan_hit_clauses = NULL;
    }
	
	FREE(compile_state);

    free_bytes += sizeof(struct maat_compile_state);
    alignment_int64_array_add(maat_inst->stat->maat_state_free_bytes, thread_id, free_bytes);
}

static int maat_compile_hit_path_add(UT_array *hit_paths, long long item_id,
                                     long long group_id, int vtable_id, 
                                     int Nth_scan, int Nth_item_result)
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

static int maat_compile_has_literal(struct maat_compile *compile,
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

		tmp = (struct maat_literal_id*)utarray_find(clause_state->ut_literal_ids,
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

size_t compile_runtime_get_hit_paths(struct compile_runtime *compile_rt, int thread_id,
									 struct maat_compile_state *compile_state, 
                                  	 struct maat_hit_path *hit_path_array, 
                                     size_t array_size, size_t n_internal_hit_path)
{
    /* assign hit_path_array[].compile_id */
    size_t new_hit_path_cnt = 0;
    struct maat_compile *compile = NULL;
    struct maat_literal_id literal_id = {0, 0};
    struct bool_expr_match *expr_match = compile_rt->expr_match_buff + 
                                         (thread_id * MAX_SCANNER_HIT_COMPILE_NUM);
    assert(thread_id >= 0);

    if (compile_state->compile_rt_version != compile_rt->version) {
        return 0;
    }

    int bool_match_ret = bool_matcher_match(compile_rt->bm, 
                                            (unsigned long long *)utarray_eltptr(compile_state->all_hit_clauses, 0),
											utarray_len(compile_state->all_hit_clauses), expr_match, 
                                            MAX_SCANNER_HIT_COMPILE_NUM);
	for (int idx = 0; idx < bool_match_ret; idx++) {
        compile = (struct maat_compile *)expr_match[idx].user_tag;
		assert(compile->magic_num == MAAT_COMPILE_MAGIC);
		assert((unsigned long long)compile->compile_id == expr_match[idx].expr_id);
		if (0 == compile->actual_clause_num || NULL == compile->user_data) {
			continue;
		}

        for (size_t j = 0; j < n_internal_hit_path && (n_internal_hit_path + new_hit_path_cnt) < array_size; j++) {
			if (hit_path_array[j].top_group_id < 0) {
                literal_id.group_id = hit_path_array[j].sub_group_id;
			} else {
                literal_id.group_id = hit_path_array[j].top_group_id;
            }

			literal_id.vtable_id = hit_path_array[j].vtable_id;
			if (maat_compile_has_literal(compile, &literal_id)) {
                if (hit_path_array[j].top_group_id < 0) {
                    hit_path_array[j].top_group_id = hit_path_array[j].sub_group_id;
                }

				if (hit_path_array[j].compile_id < 0) {
					hit_path_array[j].compile_id = compile->compile_id;
				} else {
                    // means same literal_id hit more than one compile_id
					struct maat_hit_path tmp_path = hit_path_array[j];
					tmp_path.compile_id = compile->compile_id;
					if(maat_compile_is_hit_path_existed(hit_path_array, n_internal_hit_path + new_hit_path_cnt, &tmp_path)) {
						hit_path_array[n_internal_hit_path + new_hit_path_cnt] = tmp_path;
						new_hit_path_cnt++;
					}
				}
			}
		}
	}

    return (n_internal_hit_path + new_hit_path_cnt);
}

void maat_compile_state_update_hit_path(struct maat_compile_state *compile_state,
                                        long long item_id, long long group_id,
                                        int vtable_id, int Nth_scan, int Nth_item_result)
{
	if (compile_state->Nth_scan != Nth_scan) {
		assert(compile_state->this_scan_hit_item_flag == 0);
		compile_state->Nth_scan = Nth_scan;
		utarray_clear(compile_state->this_scan_hit_clauses);
	}

    maat_compile_hit_path_add(compile_state->internal_hit_paths, item_id, group_id, 
                              vtable_id, Nth_scan, Nth_item_result);

	compile_state->this_scan_hit_item_flag = 1;
}

void maat_compile_state_update_hit_clause(struct maat_compile_state *compile_state,
                                          struct compile_runtime *compile_rt,
                                          long long group_id, int vtable_id)
{
    if (NULL == compile_state || NULL == compile_rt) {
        return;
    }
    
	struct maat_literal_id literal_id = {group_id, vtable_id};
    struct literal_clause *l2c_val = NULL;
    
    HASH_FIND(hh, compile_rt->literal2clause_hash, &literal_id, sizeof(literal_id), l2c_val);
    if (!l2c_val) {
        return;
    }

    size_t i = 0;
    long long *clause_id = 0;
    size_t new_clause_idx = utarray_len(compile_state->this_scan_hit_clauses);
    for (i = 0; i < utarray_len(l2c_val->clause_ids); i++) {
        clause_id = (long long *)utarray_eltptr(l2c_val->clause_ids, i);
        if (utarray_find(compile_state->all_hit_clauses, clause_id, compare_clause_id)) {
            continue;
        }
        utarray_push_back(compile_state->this_scan_hit_clauses, clause_id);
    }

    if ((utarray_len(compile_state->this_scan_hit_clauses) - new_clause_idx) > 0) {
        utarray_reserve(compile_state->all_hit_clauses,
                        utarray_len(compile_state->this_scan_hit_clauses) - new_clause_idx);
        
        for (i = new_clause_idx; i < utarray_len(compile_state->this_scan_hit_clauses); i++) {
            clause_id = (long long *)utarray_eltptr(compile_state->this_scan_hit_clauses, i);
            utarray_push_back(compile_state->all_hit_clauses, clause_id);
        }
        utarray_sort(compile_state->all_hit_clauses, compare_clause_id);
    }
}

int maat_compile_state_has_NOT_clause(struct maat_compile_state *compile_state)
{   
    return compile_state->not_clause_hit_flag;
}

void compile_runtime_ex_data_iterate(struct compile_runtime *compile_rt,
                                     struct compile_schema *compile_schema)
{
    if (NULL == compile_rt || NULL == compile_schema ||
        (0 == compile_schema->set_flag)) {
		return;
	}

    compile_runtime_user_data_iterate(compile_rt, rule_ex_data_new_cb, 
                                      &(compile_schema->ex_schema),
                                      compile_schema->table_id);
}

void *compile_runtime_get_ex_data(struct compile_runtime *compile_rt, 
                                  struct compile_schema *compile_schema, 
                                  long long compile_id)
{
	if (NULL == compile_rt || NULL == compile_schema || compile_id < 0 ||
        (0 == compile_schema->set_flag)) {
		return NULL;
	}

    struct compile_rule *compile_rule = NULL;
    compile_rule = (struct compile_rule *)compile_runtime_get_user_data(compile_rt,
                                                                        compile_id);
    if (NULL == compile_rule) {
        return NULL;
    }
   
    void *ex_data = NULL;
    compile_schema->ex_schema.dup_func(compile_schema->table_id, &ex_data, 
                                       compile_rule->ex_data, 
                                       compile_schema->ex_schema.argl, 
                                       compile_schema->ex_schema.argp);
	return ex_data;
}

int compile_runtime_add_compile(struct compile_runtime *compile_rt, struct compile_schema *schema,
                                 long long compile_id, const char *table_name, const char *line)
{
    struct compile_item *compile_item = NULL;
    struct maat_compile *compile = NULL;

    compile_item = compile_item_new(line, schema, table_name, compile_rt->logger);
    if (NULL == compile_item) {
        return -1;
    }

    struct compile_rule *compile_rule = compile_rule_new(compile_item, schema, table_name, line);
    compile_item_free(compile_item);

    int updating_flag = rcu_hash_is_updating(compile_rt->cfg_hash);
    if (1 == updating_flag) {
        compile = rcu_updating_hash_find(compile_rt->cfg_hash, (char *)&compile_id,
                                         sizeof(long long));
        if (compile != NULL) {
            /****************************************************************
               compile found in updating hash(added by group2compile runtime), which means

               1. rcu_hash_add(htable, compile) ==> finished
               2. rcu_hash_commit(htable)       ==> undo
               because it's in updating hash, we can modify it directly
           ******************************************************************/

            /* compile has group2compile_table info, so set compile_table info */
            maat_compile_set(compile, table_name, compile_rule->declared_clause_num,
                             compile_rule, (void (*)(void *))compile_rule_free);
        } else {
            // compile neither in effective hash nor in updating hash
            compile = maat_compile_new(compile_rule->compile_id);
            assert(compile != NULL);
            maat_compile_set(compile, table_name, compile_rule->declared_clause_num,
                             compile_rule, (void (*)(void *))compile_rule_free);
            rcu_hash_add(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long), compile);
        }
    } else {
        compile = rcu_hash_find(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long));
        if (compile != NULL) {
            /********************************************************************************
               compile found in effective hash(added by group2compile runtime), which means

               1. rcu_hash_add(htable, compile)  ==> finished
               2. rcu_hash_commit(htable)        ==> finished

               can only be deleted but not modified
               before delete it, we need to make a copy for further use
           ***********************************************************************************/
            struct maat_compile *copy_compile = maat_compile_clone(compile, 0);
            assert(copy_compile != NULL);

            /* delete compile from rcu hash */
            rcu_hash_del(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long));

            /* copy_compile has group2compile_table info, so set compile_table info */
            maat_compile_set(copy_compile, table_name, compile_rule->declared_clause_num,
                             compile_rule, (void (*)(void *))compile_rule_free);
            /* add copy_compile to rcu hash */
            rcu_hash_add(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long), copy_compile);
        } else {
            compile = maat_compile_new(compile_rule->compile_id);
            assert(compile != NULL);
            maat_compile_set(compile, table_name, compile_rule->declared_clause_num,
                             compile_rule, (void (*)(void *))compile_rule_free);
            rcu_hash_add(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long), compile);
        }
    }

    return 0;
}

void compile_runtime_del_compile(struct compile_runtime *compile_rt, long long compile_id)
{
    struct maat_compile *compile = NULL;

    int updating_flag = rcu_hash_is_updating(compile_rt->cfg_hash);

    if (1 == updating_flag) {
        // find in updating hash
        compile = rcu_updating_hash_find(compile_rt->cfg_hash, (char *)&compile_id,
                                         sizeof(long long));
        if (compile != NULL) {
            /****************************************************************
                compile found in updating hash, which means

                1. rcu_hash_del(htable, compile) ==> finished
                2. rcu_hash_commit(htable)       ==> undo
                because it's in updating hash, we can modify it directly
            ******************************************************************/
            if (compile->user_data_free && compile->user_data) {
                compile->user_data_free(compile->user_data);
                compile->user_data = NULL;
            }

            if (0 == compile->actual_clause_num) {
                rcu_hash_del(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long));
            }
        }
    } else {
        // find in effective hash
        compile = rcu_hash_find(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long));
        if (compile != NULL) {
            /*******************************************************************
                compile found in effective hash, which means

                1. rcu_hash_add(htable, compile)  ==> finished
                2. rcu_hash_commit(htable)        ==> finished

                can only be deleted but not modified
                before delete it, we need to make a copy for further use
            *********************************************************************/
            struct maat_compile *copy_compile = maat_compile_clone(compile, 0);
            assert(copy_compile != NULL);

            /* delete compile from rcu hash */
            rcu_hash_del(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long));

            if (0 == copy_compile->actual_clause_num) {
                maat_compile_free(copy_compile);
            } else {
                rcu_hash_add(compile_rt->cfg_hash, (char *)&compile_id, 
                             sizeof(long long), copy_compile);
            }
        }
    }
}

int compile_runtime_update(void *compile_runtime, void *compile_schema, 
                           const char *table_name, const char *line, 
                           int valid_column)
{
    if (NULL == compile_runtime || NULL == compile_schema || NULL == line) {
        return -1;
    }

    struct compile_schema *schema = (struct compile_schema *)compile_schema;
    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        log_error(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] compile table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        compile_rt->update_err_cnt++;
        return -1;
    }

    long long compile_id = get_column_value(line, schema->compile_id_column);
    if (compile_id < 0) {
        log_error(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] compile table:<%s> has no compile_id(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  schema->compile_id_column, line);
        compile_rt->update_err_cnt++;
        return -1;
    }

    if (0 == is_valid) {
        // delete
        compile_runtime_del_compile(compile_rt, compile_id);
    } else {
        // add
        int ret = compile_runtime_add_compile(compile_rt, schema, compile_id, 
                                              table_name, line);
        if (ret < 0) {
            compile_rt->update_err_cnt++;
        }
    }

    return 0;
}

int group2compile_runtime_update(void *g2c_runtime, void *g2c_schema, 
                                 const char *table_name, const char *line, 
                                 int valid_column)
{
    if (NULL == g2c_runtime || NULL == g2c_schema || NULL == line) {
        return -1;
    }

    struct group2compile_schema *schema = (struct group2compile_schema *)g2c_schema;
    struct group2compile_runtime *g2c_rt = (struct group2compile_runtime *)g2c_runtime;
    struct compile_runtime *compile_rt = g2c_rt->ref_compile_rt;

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
         log_error(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] g2c table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        g2c_rt->update_err_cnt++;
        return -1;
    } 
    
    int ret = -1;
    struct group2compile_item *g2c_item = group2compile_item_new(line, schema, table_name,
                                                                 compile_rt->logger);
    if (NULL == g2c_item) {
        g2c_rt->update_err_cnt++;
        return -1;
    }

    if (0 == is_valid) {
        //delete
        ret = maat_remove_group_from_compile(compile_rt->cfg_hash, g2c_item,
                                             compile_rt->logger);
        if (0 == ret) {
            if (g2c_item->not_flag) {
                g2c_rt->not_flag_group--;
            }
            g2c_rt->rule_num--;
        } else {
            g2c_rt->update_err_cnt++;
        }
    } else {
        //add
        ret = maat_add_group_to_compile(compile_rt->cfg_hash, g2c_item,
                                        compile_rt->logger);
        if (0 == ret) {
            if (g2c_item->not_flag) {
                g2c_rt->not_flag_group++;
            }
            g2c_rt->rule_num++;
        } else {
            g2c_rt->update_err_cnt++;
        }
    }
    
    group2compile_item_free(g2c_item);
    return ret;
}

long long group2compile_runtime_not_group_count(void *g2c_runtime)
{
     if (NULL == g2c_runtime) {
        return 0;
    }
    
    struct group2compile_runtime *g2c_rt = (struct group2compile_runtime *)g2c_runtime;
    return g2c_rt->not_flag_group;
}

long long group2compile_runtime_rule_count(void *g2c_runtime)
{
    if (NULL == g2c_runtime) {
        return 0;
    }
    
    struct group2compile_runtime *g2c_rt = (struct group2compile_runtime *)g2c_runtime;
    return g2c_rt->rule_num;
}

long long group2compile_runtime_update_err_count(void *g2c_runtime)
{   
    if (NULL == g2c_runtime) {
        return 0;
    }

    struct group2compile_runtime *g2c_rt = (struct group2compile_runtime *)g2c_runtime;
    return g2c_rt->update_err_cnt;
}

int compile_runtime_commit(void *compile_runtime, const char *table_name,
                           long long maat_rt_version)
{
    if (NULL == compile_runtime) {
        return -1;
    }

    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
   
    int updating_flag = rcu_hash_is_updating(compile_rt->cfg_hash);
    if (0 == updating_flag) {
        return 0;
    }
    
    int ret = 0;
    size_t compile_cnt = 0;
    struct bool_matcher *old_bool_matcher = NULL;
    struct bool_matcher *new_bool_matcher = NULL;

    new_bool_matcher = maat_compile_bool_matcher_new(compile_rt, &compile_cnt);
    if (NULL == new_bool_matcher) {
        log_error(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] table[%s] rebuild compile bool_matcher failed, compile"
                  " rules count:%zu", __FUNCTION__, __LINE__, table_name, compile_cnt);
        ret = -1;
    } else {
        log_info(compile_rt->logger, MODULE_COMPILE,
             "table[%s] commit %zu compile rules and rebuild compile bool_matcher"
             " completed, version:%lld", table_name, compile_cnt, maat_rt_version);
    }

    struct literal_clause *old_literal2clause = NULL;
    struct literal_clause *new_literal2clause = NULL;

    new_literal2clause = maat_compile_build_literal2clause_hash(compile_rt);

    old_literal2clause = compile_rt->literal2clause_hash;
    old_bool_matcher = compile_rt->bm;

    compile_rt->bm = new_bool_matcher;
    compile_rt->literal2clause_hash = new_literal2clause;

    rcu_hash_commit(compile_rt->cfg_hash);

    maat_garbage_bagging(compile_rt->ref_garbage_bin, old_bool_matcher, NULL,
                        garbage_bool_matcher_free);
    maat_garbage_bagging(compile_rt->ref_garbage_bin, old_literal2clause, NULL,
                        garbage_literal2clause_hash_free);

    compile_rt->rule_num = rcu_hash_count(compile_rt->cfg_hash);

    return ret;
}

long long compile_runtime_rule_count(void *compile_runtime)
{
    if (NULL == compile_runtime) {
        return 0;
    }
    
    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
    return compile_rt->rule_num;
}

long long compile_runtime_update_err_count(void *compile_runtime)
{   
    if (NULL == compile_runtime) {
        return 0;
    }

    struct compile_runtime *compile_rt = (struct compile_runtime *)compile_runtime;
    return compile_rt->update_err_cnt;
}

static int compile_sort_para_compare(const struct compile_sort_para *a,
                                     const struct compile_sort_para *b)
{
	//If compile rule's execute sequences are not specified or equal.
	if (a->declared_clause_num != b->declared_clause_num) {
		return (a->declared_clause_num - b->declared_clause_num);
	} else {
		return (b->compile_id - a->compile_id);
	}
}

static void compile_sort_para_set(struct compile_sort_para *para, 
                                  const struct compile_rule *rule)
{
	para->compile_id = rule->compile_id;
	para->declared_clause_num = rule->declared_clause_num;
}

static int compare_compile_rule(const void *a, const void *b)
{
	const struct compile_rule *ra = *(const struct compile_rule **)a;
	const struct compile_rule *rb = *(const struct compile_rule **)b;
	
	struct compile_sort_para sa, sb;
	compile_sort_para_set(&sa, ra);
	compile_sort_para_set(&sb, rb);

	return compile_sort_para_compare(&sa, &sb);
}

int compile_runtime_match(struct compile_runtime *compile_rt, long long *compile_ids,
                          size_t compile_ids_size, struct maat_state *state)
{
    struct maat_compile_state *compile_state = state->compile_state;
    int is_last_scan = state->is_last_scan;
    struct compile_rule *compile_rules[compile_ids_size];
    
    // all hit clause_id -> compile_id
    size_t bool_match_ret = maat_compile_bool_matcher_match(compile_rt, is_last_scan,
                                                            compile_state, state->thread_id,
                                                            (void **)compile_rules,
                                                            compile_ids_size);
    if (bool_match_ret > 0) {
        qsort(compile_rules, bool_match_ret, sizeof(struct compile_rule *), 
              compare_compile_rule);
    }
   
    for (size_t i = 0; i < bool_match_ret; i++) {
        compile_ids[i] = compile_rules[i]->compile_id;
	}
    
    return MIN(bool_match_ret, compile_ids_size);
}

void maat_compile_state_update(int vtable_id, struct maat_item *hit_items,
                              size_t n_hit_item, struct maat_state *state)
{
    size_t i = 0;
    size_t hit_cnt = n_hit_item;
    long long hit_group_ids[MAX_SCANNER_HIT_GROUP_NUM];

    if (hit_cnt >= MAX_SCANNER_HIT_GROUP_NUM) {
        hit_cnt = MAX_SCANNER_HIT_GROUP_NUM;
    }

    struct maat *maat_inst = state->maat_inst;
    if (NULL == state->compile_state) {
        state->compile_state = maat_compile_state_new();
        alignment_int64_array_add(maat_inst->stat->maat_compile_state_cnt,
                                  state->thread_id, 1);
    }
    
    for (i = 0; i < hit_cnt; i++) {
        maat_compile_state_update_hit_path(state->compile_state, hit_items[i].item_id,
                                           hit_items[i].group_id, vtable_id, state->scan_cnt, i);
        hit_group_ids[i] = hit_items[i].group_id;
    }

    /* update hit clause */
    int compile_table_id = table_manager_get_default_compile_table_id(maat_inst->tbl_mgr);
    if (state->compile_table_id > 0) {
        compile_table_id = state->compile_table_id;
    }

    struct compile_runtime *compile_rt = table_manager_get_runtime(maat_inst->tbl_mgr,
                                                                   compile_table_id);
    if (NULL == compile_rt) {
        return;
    }

    int g2g_table_id = table_manager_get_group2group_table_id(maat_inst->tbl_mgr);
    void *g2g_rt = table_manager_get_runtime(maat_inst->tbl_mgr, g2g_table_id);
    if (NULL == g2g_rt) {
        return;
    }

    long long super_group_ids[MAX_SCANNER_HIT_GROUP_NUM];
    size_t super_group_cnt = group2group_runtime_get_super_groups(g2g_rt, hit_group_ids,
                                                                  hit_cnt, super_group_ids,
                                                                  MAX_SCANNER_HIT_GROUP_NUM);
    if (super_group_cnt >= MAX_SCANNER_HIT_GROUP_NUM) {
        super_group_cnt = MAX_SCANNER_HIT_GROUP_NUM;
    }

    for (int j = 0; j < super_group_cnt; j++) {
        maat_compile_state_update_hit_clause(state->compile_state, compile_rt,
                                             super_group_ids[j], vtable_id);
    }

    for (int j = 0; j < hit_cnt; j++) {
        maat_compile_state_update_hit_clause(state->compile_state, compile_rt,
                                             hit_group_ids[j], vtable_id);
    }
}

size_t maat_compile_state_get_hit_groups(struct maat_compile_state *compile_state,
                                         struct group2group_runtime *g2g_rt,
                                         struct maat_hit_group *hit_group_array,
                                         size_t array_size)
{
    if (NULL == compile_state) {
        return 0;
    }

    size_t i = 0;
    UT_array *all_hit_groups;
    utarray_new(all_hit_groups, &ut_hit_group_icd);
    struct maat_internal_hit_path *internal_path = NULL;

    for (i = 0; i < utarray_len(compile_state->internal_hit_paths); i++) {
        internal_path = (struct maat_internal_hit_path *)utarray_eltptr(compile_state->internal_hit_paths, i);

        long long super_group_ids[MAX_SCANNER_HIT_GROUP_NUM];
        size_t super_group_cnt = group2group_runtime_get_super_groups(g2g_rt, &(internal_path->group_id), 1,
                                                                      super_group_ids, MAX_SCANNER_HIT_GROUP_NUM);
        if (super_group_cnt + 1 <= MAX_SCANNER_HIT_GROUP_NUM) {
            super_group_ids[super_group_cnt++] = internal_path->group_id;
        }

        for (size_t idx = 0; idx < super_group_cnt; idx++) {
            struct maat_hit_group hit_group;
            hit_group.group_id = super_group_ids[idx];
            hit_group.vtable_id = internal_path->vtable_id;
            if (utarray_find(all_hit_groups, &hit_group, compare_hit_group)) {
                continue;
            }
            utarray_push_back(all_hit_groups, &hit_group);
            utarray_sort(all_hit_groups, compare_hit_group);
        }
    }

    struct maat_hit_group *tmp = NULL;
    for (i = 0; i < utarray_len(all_hit_groups) && i < array_size; i++) {
        tmp = (struct maat_hit_group *)utarray_eltptr(all_hit_groups, i);
        hit_group_array[i] = *tmp;
    }
    utarray_free(all_hit_groups);

    return i;
}

UT_icd ut_compile_group_id_icd = {sizeof(long long), NULL, NULL, NULL};
size_t maat_compile_state_get_internal_hit_paths(struct maat_compile_state *compile_state,
                                                 struct compile_runtime *compile_rt,
                                                 struct group2group_runtime *g2g_rt,
                                                 struct maat_hit_path *hit_path_array, 
                                                 size_t array_size)
{
    size_t hit_path_cnt = 0;
    struct maat_internal_hit_path *internal_path = NULL;

    for (int i = 0; i < utarray_len(compile_state->internal_hit_paths); i++) {
        internal_path = (struct maat_internal_hit_path *)utarray_eltptr(compile_state->internal_hit_paths, i);
        /*
            NOTE: maybe one item has been deleted, but it's item_id still exist in internal_hit_paths
        */
        long long super_group_ids[MAX_SCANNER_HIT_GROUP_NUM];
        UT_array *valid_super_group_ids;
        utarray_new(valid_super_group_ids, &ut_compile_group_id_icd);

        size_t super_group_cnt = group2group_runtime_get_super_groups(g2g_rt, &(internal_path->group_id), 1,
                                                                      super_group_ids, MAX_SCANNER_HIT_GROUP_NUM);
        /* if super group is not referenced by compile, drop it */
        for (size_t idx = 0; idx < super_group_cnt; idx++) {
            utarray_push_back(valid_super_group_ids, &super_group_ids[idx]);
        }

        /*
            internal_path->group_id can be referenced directly by compile, 
            so add it to hit_path which super_group_ids is -1
            ------------------------------------------------------------------------------
            NOTE: Add the hit path as long as the item is hit
        */
        long long super_group_id = -1;
        utarray_push_back(valid_super_group_ids, &super_group_id);
        
        long long *p = NULL;
        struct maat_hit_path tmp_path;
    
        for (p = utarray_front(valid_super_group_ids); p != NULL && hit_path_cnt < array_size;
             p = utarray_next(valid_super_group_ids, p)) {
            memset(&tmp_path, 0, sizeof(tmp_path));
            tmp_path.Nth_scan = internal_path->Nth_scan;
            tmp_path.item_id = internal_path->item_id;
            tmp_path.sub_group_id = internal_path->group_id;
            tmp_path.top_group_id = *p;
            tmp_path.vtable_id = internal_path->vtable_id;
            tmp_path.compile_id = -1;

           /* check if internal_path is duplicated from hit_path_array[] element */
            if (hit_path_cnt > 0) {
                if (maat_compile_is_hit_path_existed(hit_path_array, hit_path_cnt, &tmp_path)) {
                    continue;
                }
            }
           
            hit_path_array[hit_path_cnt] = tmp_path;
            hit_path_cnt++;
        }
        utarray_free(valid_super_group_ids);
    }

    return hit_path_cnt;
}

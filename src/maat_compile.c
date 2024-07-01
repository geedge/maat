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

#define MAX_NOT_CLAUSE_NUM   8

enum clause_not_flag {
    CLAUSE_NOT_FLAG_UNSET = 0,
    CLAUSE_NOT_FLAG_SET
};

struct compile_schema {
    int compile_id_column;
    int rule_tag_column;
    int declared_clause_num_column;
    int table_id;
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
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct compile_item {
    int declared_clause_num;
    long long compile_id;
    char *table_line;
    size_t table_line_len;
};

struct group2compile_item {
    UT_array *group_ids;
    long long compile_id;
    int not_flag;
    int vtable_id;
    int clause_index;
};

struct clause_query_key {
	long long group_id;
    int vtable_id;
    int not_flag;
};

struct clause_id_kv {
    struct clause_query_key key;
    UT_array *clause_ids;
    UT_hash_handle hh;
};

struct table_clause {
    int vtable_id;
    int actual_clause_num;
    UT_array *clause_ids;
    UT_array *group_ids;
    UT_hash_handle hh;
};

struct table_group {
    int vtable_id;
    UT_array *group_ids;
    UT_hash_handle hh;
};

/* compile_runtime and group2compile_runtime share compile_hash_map */
struct compile_runtime {
	struct bool_matcher *bm;
    struct rcu_hash_table *cfg_hash;     // <compile_id, struct maat_compile>
    struct maat_runtime *ref_maat_rt;
    struct clause_id_kv *clause_id_kv_hash;     //store clause_ids(not_flag == 0)
    struct clause_id_kv *not_clause_id_kv_hash; //store NOT_clause_ids(not_flag == 1)
    struct bool_expr_match *expr_match_buff;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
    time_t version;

    long long rule_num;
    long long update_err_cnt;
};

struct group2compile_runtime {
    long long not_clause_cnt;
    long long rule_num;
    long long update_err_cnt;
    struct compile_runtime *ref_compile_rt;
    struct table_clause *tbl_not_clause_hash; //each virtual table's not clause number <= MAX_NOT_CLAUSE_NUM
};

struct clause_literal {
    long long group_ids[MAX_GROUP_CNT];
    int group_cnt;
    int vtable_id;
};

struct compile_clause {
	long long clause_id;
    UT_array *literals; //struct clause_literal
	char not_flag;      // 1 byte
	char in_use;        // 1 byte
    char pad[6];        // for 8 bytes alignment
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
    int table_id;
    long long compile_id;
    void *user_data; // compile_item
	struct compile_clause clauses[MAX_ITEMS_PER_BOOL_EXPR];
};

struct internal_hit_path {
    long long item_id;
	long long group_id;
	int Nth_scan;
	int vtable_id;
    int NOT_flag; // 1 means NOT clause
};

struct compile2table_id {
    long long compile_id;
    int table_id;
};

struct compile_state {
	int Nth_scan;
    int this_scan_not_logic;
    time_t compile_rt_version;

	UT_array *internal_hit_paths;
	UT_array *all_hit_clauses;
	UT_array *this_scan_hit_clauses;
	UT_array *this_scan_hit_not_clauses;
    UT_array *exclude_not_clauses;
    UT_array *direct_hit_groups;
    UT_array *indirect_hit_groups;
    UT_array *last_hit_groups;
    UT_array *hit_compile_table_ids;
    struct table_group *hit_not_tbl_groups;
};

UT_icd ut_clause_id_icd = {sizeof(long long), NULL, NULL, NULL};
UT_icd ut_clause_literal_icd = {sizeof(struct clause_literal), NULL, NULL, NULL};
UT_icd ut_compile_group_id_icd = {sizeof(long long), NULL, NULL, NULL};
UT_icd ut_maat_hit_group_icd = {sizeof(struct maat_hit_group), NULL, NULL, NULL};
UT_icd ut_hit_path_icd = {sizeof(struct internal_hit_path), NULL, NULL, NULL};
UT_icd ut_hit_compile_table_id_icd = {sizeof(struct compile2table_id), NULL, NULL, NULL};

static struct maat_compile *maat_compile_new(long long compile_id)
{
	struct maat_compile *compile = ALLOC(struct maat_compile, 1);

	compile->magic_num = MAAT_COMPILE_MAGIC;
	compile->compile_id = compile_id;

    for(int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {	
		utarray_new(compile->clauses[i].literals, &ut_clause_literal_icd);
		compile->clauses[i].in_use = 0;
        compile->clauses[i].clause_id = 0;
	}

	return compile;
}

static int maat_compile_set(struct maat_compile *compile, int table_id,
                            int declared_clause_num, void *user_data)
{
    if (NULL == compile) {
        return -1;
    }

    compile->table_id = table_id;
    compile->declared_clause_num = declared_clause_num;
    compile->user_data = user_data;

    return 0;
}

static int compile_accept_tag_match(struct compile_schema *schema, const char *line,
                                    const char *table_name, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    if (schema->rule_tag_column > 0 && n_tag > 0) {
        int ret = get_column_pos(line, schema->rule_tag_column, 
                                 &column_offset, &column_len);
        if (ret < 0) {
            log_fatal(logger, MODULE_COMPILE,
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
                log_fatal(logger, MODULE_COMPILE,
                          "[%s:%d] table: <%s> has invalid tag format in line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_ERR;
            }

            if (TAG_MATCH_UNMATCHED == ret) {
                log_fatal(logger, MODULE_COMPILE,
                          "[%s:%d] table: <%s> has unmatched tag in line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_UNMATCHED;
            }
        }
    }

    return TAG_MATCH_MATCHED;
}

static struct compile_item *
compile_item_new(const char *table_line, struct compile_schema *schema,
                 const char *table_name, struct log_handle *logger)
{
    int ret = compile_accept_tag_match(schema, table_line, table_name, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    size_t column_offset = 0;
    size_t column_len = 0;
    struct compile_item *compile_item = ALLOC(struct compile_item, 1);

    ret = get_column_pos(table_line, schema->compile_id_column,
                         &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_COMPILE,
                  "[%s:%d] table: <%s> has no compile_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, table_line);
        goto error;
    }
    compile_item->compile_id = atoll(table_line + column_offset);

    ret = get_column_pos(table_line, schema->declared_clause_num_column,
                         &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_COMPILE,
                  "[%s:%d] table: <%s> has no clause_num in line:%s",
                  __FUNCTION__, __LINE__, table_name, table_line);
		goto error;
    }

    compile_item->declared_clause_num = atoi(table_line + column_offset);
    if (compile_item->declared_clause_num < 0 ||
        compile_item->declared_clause_num > MAX_NOT_CLAUSE_NUM) {
        log_fatal(logger, MODULE_COMPILE,
                  "[%s:%d] table: <%s> clause_num:%d exceed maximum:%d in line:%s",
                  __FUNCTION__, __LINE__, table_name, compile_item->declared_clause_num,
                  MAX_NOT_CLAUSE_NUM, table_line);
		goto error;
    }

    compile_item->table_line_len = strlen(table_line);
    compile_item->table_line = ALLOC(char, compile_item->table_line_len + 1);
    memcpy(compile_item->table_line, table_line, compile_item->table_line_len);

    return compile_item;
error:
    FREE(compile_item);
    return NULL;
}

static void compile_item_free(struct compile_item *item)
{
    item->declared_clause_num = 0;

    if (item->table_line != NULL) {
        FREE(item->table_line);
    }
    
    FREE(item);
}

static void maat_compile_free(struct maat_compile *compile)
{
	struct compile_clause *clause = NULL;

	if (compile->user_data != NULL) {
		compile_item_free(compile->user_data);
        compile->user_data = NULL;
	}

	for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		clause = compile->clauses + i;

        if (clause->literals != NULL) {
            utarray_free(clause->literals);
            clause->literals = NULL;
        }
		
		clause->in_use = 0;
        clause->clause_id = 0;
	}

	compile->magic_num = 0;
	FREE(compile);
}

static void rcu_compile_cfg_free(void *user_ctx, void *data)
{
    struct maat_compile *compile = (struct maat_compile *)data;
    maat_compile_free(compile);
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
        log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no table_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

   	item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "compile_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->compile_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_COMPILE, 
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
        log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no clause_num column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
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
        log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "associated_compile_table_id");
    if (item != NULL && item->type == cJSON_Number) {
        g2c_schema->asso_compile_table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no associated_compile_table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->group_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no group_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "compile_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->compile_id_column = custom_item->valueint;
    } else {
         log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no compile_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "not_flag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->not_flag_column = custom_item->valueint;
    } else {
         log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no not_flag column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "virtual_table_name");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->vtable_name_column = custom_item->valueint;
    } else {
         log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] table: <%s> schema has no virtual_table_name column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "clause_index");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->clause_index_column = custom_item->valueint;
    } else {
         log_fatal(logger, MODULE_COMPILE, 
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

#define COMPILE_GC_TIMEOUT_S 5
void *compile_runtime_new(void *compile_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin, 
                          struct log_handle *logger)
{
	if (NULL == compile_schema) {
        return NULL;
    }

    struct compile_runtime *compile_rt = ALLOC(struct compile_runtime, 1);

    compile_rt->expr_match_buff = ALLOC(struct bool_expr_match, 
                                        max_thread_num * MAX_HIT_COMPILE_NUM);
    compile_rt->version = time(NULL);
    compile_rt->cfg_hash = rcu_hash_new(rcu_compile_cfg_free, NULL, COMPILE_GC_TIMEOUT_S);
    compile_rt->clause_id_kv_hash = NULL;
    compile_rt->not_clause_id_kv_hash = NULL;
    compile_rt->logger = logger;
    compile_rt->ref_garbage_bin = garbage_bin;

    return compile_rt;
}

static void clause_id_kv_hash_free(struct clause_id_kv *hash)
{
    struct clause_id_kv *clause_id_kv = NULL, *tmp_clause_id_kv = NULL;

    HASH_ITER(hh, hash, clause_id_kv, tmp_clause_id_kv) {
        HASH_DEL(hash, clause_id_kv);
        if (clause_id_kv->clause_ids != NULL) {
            utarray_free(clause_id_kv->clause_ids);
            clause_id_kv->clause_ids = NULL;
        }
        
        FREE(clause_id_kv);
    }
    assert(hash == NULL);
}

static void garbage_clause_id_kv_hash_free(void *hash, void *arg)
{
    clause_id_kv_hash_free((struct clause_id_kv *)hash);
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
    
    if (compile_rt->clause_id_kv_hash != NULL) {
        clause_id_kv_hash_free(compile_rt->clause_id_kv_hash);
        compile_rt->clause_id_kv_hash = NULL;
    }

    if (compile_rt->not_clause_id_kv_hash != NULL) {
        clause_id_kv_hash_free(compile_rt->not_clause_id_kv_hash);
        compile_rt->not_clause_id_kv_hash = NULL;
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

    struct compile_runtime *compile_rt =
        (struct compile_runtime *)compile_runtime;

    compile_rt->ref_maat_rt = maat_rt;
}

void *group2compile_runtime_new(void *g2c_schema, size_t max_thread_num,
                                struct maat_garbage_bin *garbage_bin, 
                                struct log_handle *logger)
{
    if (NULL == g2c_schema) {
        return NULL;
    }

    struct group2compile_runtime *g2c_rt =
        ALLOC(struct group2compile_runtime, 1);

    g2c_rt->tbl_not_clause_hash = NULL;

    return g2c_rt;
}

void group2compile_runtime_init(void *g2c_runtime, void *compile_runtime)
{
    struct group2compile_runtime *g2c_rt =
        (struct group2compile_runtime *)g2c_runtime;

    g2c_rt->ref_compile_rt = (struct compile_runtime *)compile_runtime;
}

void group2compile_runtime_free(void *g2c_runtime)
{
    if (NULL == g2c_runtime) {
        return;
    }

    struct group2compile_runtime *g2c_rt =
        (struct group2compile_runtime *)g2c_runtime;

    if (g2c_rt->tbl_not_clause_hash != NULL) {
        struct table_clause *not_clause = NULL, *tmp_not_clause = NULL;
        HASH_ITER(hh, g2c_rt->tbl_not_clause_hash, not_clause, tmp_not_clause) {
            HASH_DEL(g2c_rt->tbl_not_clause_hash, not_clause);
            FREE(not_clause);
        }
    }
    assert(g2c_rt->tbl_not_clause_hash == NULL);

    FREE(g2c_runtime);
}

static int is_valid_table_name(const char *str)
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

static void group2compile_item_free(struct group2compile_item *g2c_item)
{
    if (NULL == g2c_item) {
        return;
    }

    if (g2c_item->group_ids != NULL) {
        utarray_free(g2c_item->group_ids);
        g2c_item->group_ids = NULL;
    }

    FREE(g2c_item);
}

static struct group2compile_item *
group2compile_item_new(const char *line, struct group2compile_schema *g2c_schema,
                       const char *table_name, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char vtable_name[MAX_NAME_STR_LEN + 1] = {0};
    struct group2compile_item *g2c_item = ALLOC(struct group2compile_item, 1);
    utarray_new(g2c_item->group_ids, &ut_compile_group_id_icd);

    int ret = get_column_pos(line, g2c_schema->group_id_column, &column_offset,
                             &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> has no group_id in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }

    char group_ids_str[MAX_GROUP_IDS_STR_LEN] = {0};
    memcpy(group_ids_str, line + column_offset, MIN(MAX_GROUP_IDS_STR_LEN, column_len));

    ret = ids_str2longlong_array(group_ids_str, g2c_item->group_ids);
    if (ret < 0) {
        log_fatal(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> group_ids str2longlong failed in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error; 
    }

    if (utarray_len(g2c_item->group_ids) > MAX_GROUP_CNT) {
        log_fatal(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> group_ids exceed maximum:%d in line:%s",
				  __FUNCTION__, __LINE__, table_name, MAX_GROUP_CNT, line);
		goto error;
    }

    ret = get_column_pos(line, g2c_schema->compile_id_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> has no compile_id in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }
    g2c_item->compile_id = atoll(line + column_offset);

    ret = get_column_pos(line, g2c_schema->not_flag_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> has no NOT_flag in line:%s ",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }

    g2c_item->not_flag = atoi(line + column_offset);
    if (g2c_item->not_flag != CLAUSE_NOT_FLAG_SET && 
        g2c_item->not_flag != CLAUSE_NOT_FLAG_UNSET) {
        log_fatal(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s>  NOT_flag:%d is illegal in line:%s ",
				  __FUNCTION__, __LINE__, table_name, g2c_item->not_flag, line);
		goto error;
    }

    ret = get_column_pos(line, g2c_schema->vtable_name_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_COMPILE,
				  "[%s:%d] g2c table:<%s> has no virtual_table_name in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }

    if (column_len > MAX_NAME_STR_LEN) {
        log_fatal(logger, MODULE_COMPILE, 
                  "[%s:%d] g2c table:<%s> virtual_table_name length exceed "
                  "maxium:%d in line:%s", __FUNCTION__, __LINE__, table_name,
                  MAX_NAME_STR_LEN, line);
        goto error;
    }
    
    memset(vtable_name, 0, sizeof(vtable_name));
    memcpy(vtable_name, (line + column_offset), column_len);
    
    if (is_valid_table_name(vtable_name)) {
        g2c_item->vtable_id = table_manager_get_table_id(g2c_schema->ref_tbl_mgr,
                                                         vtable_name);
        if (g2c_item->vtable_id < 0) {
            log_fatal(logger, MODULE_COMPILE,
                      "[%s:%d] g2c table:<%s> has unknown virtual table:%s in line:%s",
                      __FUNCTION__, __LINE__, table_name, vtable_name, line);
            goto error;
        }
    }
   
    ret = get_column_pos(line, g2c_schema->clause_index_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_COMPILE,
                  "[%s:%d] g2c table:<%s> has no clause_index in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }

    g2c_item->clause_index = atoi(line + column_offset);
    if (g2c_item->clause_index < 0 || g2c_item->clause_index >= MAX_NOT_CLAUSE_NUM) {
        log_fatal(logger, MODULE_COMPILE,
                  "[%s:%d] g2c table:<%s> clause_index:%d exceed maximum:%d in line:%s",
                  __FUNCTION__, __LINE__, table_name, g2c_item->clause_index,
                  MAX_NOT_CLAUSE_NUM, line);
        goto error;
    }

    return g2c_item;

error:
    group2compile_item_free(g2c_item);
    return NULL;
}

static inline int compare_group_id(const void *a, const void *b)
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

static void compile_clause_add_literal(struct compile_clause *clause,
                                       struct group2compile_item *g2c_item)
{
    struct clause_literal tmp_literal;
    tmp_literal.vtable_id = g2c_item->vtable_id;
    tmp_literal.group_cnt = utarray_len(g2c_item->group_ids);
    utarray_sort(g2c_item->group_ids, compare_group_id);

    for (size_t i = 0; i < utarray_len(g2c_item->group_ids); i++) {
        tmp_literal.group_ids[i] = *(long long *)utarray_eltptr(g2c_item->group_ids, i);
    }
    utarray_push_back(clause->literals, &tmp_literal);
}

void compile_clause_remove_literal(struct compile_clause *clause,
                                   struct group2compile_item *g2c_item)
{
    struct clause_literal *tmp_literal = NULL;

    for (size_t i = 0; i < utarray_len(clause->literals); i++) {
        tmp_literal = (struct clause_literal *)utarray_eltptr(clause->literals, i);
        if (tmp_literal->vtable_id == g2c_item->vtable_id) {
            size_t remove_idx = utarray_eltidx(clause->literals, tmp_literal);
            utarray_erase(clause->literals, remove_idx, 1);
            break; 
        }
    } 
}

static int maat_compile_clause_find_literal(struct maat_compile *compile,
                                            struct group2compile_item *g2c_item)
{
    struct compile_clause *clause = compile->clauses + g2c_item->clause_index;
    struct clause_literal *tmp_literal = NULL;
    int found = 0;

    for (size_t i = 0; i < utarray_len(clause->literals); i++) {
        tmp_literal = (struct clause_literal *)utarray_eltptr(clause->literals, i);
        if (tmp_literal->vtable_id == g2c_item->vtable_id) {
            found = 1;
        }
    }

    return found;
}

static void maat_compile_clause_add_literal(struct maat_compile *compile,
                                            struct group2compile_item *g2c_item)
{
    struct compile_clause *clause = compile->clauses + g2c_item->clause_index;

    clause->not_flag = g2c_item->not_flag;

    if (0 == clause->in_use) {
        clause->in_use = 1;
        compile->actual_clause_num++;
    }

    compile_clause_add_literal(clause, g2c_item);
}

static void maat_compile_clause_remove_literal(struct maat_compile *compile,
                                               struct group2compile_item *g2c_item)
{
    struct compile_clause *clause = compile->clauses + g2c_item->clause_index;

    compile_clause_remove_literal(clause, g2c_item);
    if (0 == utarray_len(clause->literals)) {
        clause->in_use = 0;
        clause->clause_id = 0;
        compile->actual_clause_num--;
    }
}

static struct bool_matcher *
maat_compile_bool_matcher_new(struct compile_runtime *compile_rt,
                              size_t *compile_cnt)
{
	if (NULL == compile_rt) {
        return NULL;
    }

    size_t i = 0, j = 0, idx = 0;
    int has_clause_num = 0;

    // STEP 1, update clause_id of each compile
    void **data_array = NULL;
    struct maat_compile *iter_compile = NULL;
    size_t rule_cnt = rcu_updating_hash_list(compile_rt->cfg_hash, &data_array);
    *compile_cnt = rule_cnt;

    for (idx = 0; idx < rule_cnt; idx++) {
        iter_compile = (struct maat_compile *)data_array[idx];
        has_clause_num = 0;
        for (i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            struct compile_clause *clause = iter_compile->clauses + i;
            if (!clause->in_use) {
                continue;
            }

            has_clause_num++;
            if (0 == clause->clause_id) {
                clause->clause_id =
                    maat_runtime_get_sequence(compile_rt->ref_maat_rt, "clause_id");
            }
        }
        assert(has_clause_num == iter_compile->actual_clause_num);
    }

    // STEP 2, serial compile clause states to a bool expression array
    size_t expr_cnt = 0;
    struct bool_expr *bool_expr_array = ALLOC(struct bool_expr, rule_cnt);

    for (idx = 0; idx < rule_cnt; idx++) {
        iter_compile = (struct maat_compile *)data_array[idx];
        for (i = 0, j = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            if (iter_compile->clauses[i].in_use) {
// TODO:mytest need to delete
#if 0
                struct clause_literal *tmp_cl = NULL;
				for(tmp_cl = (struct clause_literal *)utarray_front(iter_compile->clauses[i].literals); tmp_cl !=NULL; 
                    tmp_cl = (struct clause_literal *)utarray_next(iter_compile->clauses[i].literals, tmp_cl)) {
                    for (size_t it = 0; it < tmp_cl->group_cnt; it++) {
                        printf("<before bool_matcher_new> compile_rt:%p compile_id:%lld, clause_id:%llu, clause_query_key{%lld: %d, %d}\n", 
							compile_rt, iter_compile->compile_id, iter_compile->clauses[i].clause_id, tmp_cl->group_ids[it],
                            tmp_cl->vtable_id, iter_compile->clauses[i].not_flag);
                    }
  				}
#endif
                bool_expr_array[expr_cnt].items[j].item_id = iter_compile->clauses[i].clause_id;
                bool_expr_array[expr_cnt].items[j].not_flag = 0;
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
        log_fatal(compile_rt->logger, MODULE_COMPILE,
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
        log_fatal(compile_rt->logger, MODULE_COMPILE,
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

	long long ret = la->item_id - lb->item_id;
	if (0 == ret) {
		ret = la->group_id - lb->group_id;
        if (0 == ret) {
            ret = la->vtable_id - lb->vtable_id;
        }
	}

	return ret;
}

static inline int compare_compile_id(const void *a, const void *b)
{
    long long ret = *(const long long *)a - *(const long long *)b;

    if (0 == ret) {
        return 0;
    } else if (ret < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief build <clause_query_key, clause_id_array> hash for clause or not_clause
 * 
 * @param compile_rt: compile runtime handle
 * @param not_flag: specify whether to build clause or NOT_clause hash for compile runtime
 *                  0 -> clause hash
 *                  1 -> NOT_clause hash
 * 
 * @retval generated clause_id_kv_hash
*/
static struct clause_id_kv *
build_clause_id_kv_hash(struct compile_runtime *compile_rt, int not_flag)
{
    if (NULL == compile_rt) {
        return NULL;
    }

    void **data_array = NULL;
    struct clause_id_kv *clause_id_kv_hash = NULL;
    size_t compile_cnt = rcu_updating_hash_list(compile_rt->cfg_hash, &data_array);

    for (size_t idx = 0; idx < compile_cnt; idx++) {
        struct maat_compile *compile = (struct maat_compile *)data_array[idx];
        for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            struct compile_clause *clause = compile->clauses + i;
            if (!clause->in_use) {
                continue;
            }

            if (0 == not_flag) {
                if (CLAUSE_NOT_FLAG_SET == clause->not_flag) {
                    continue;
                }
            } else {
                if (CLAUSE_NOT_FLAG_UNSET == clause->not_flag) {
                    continue;
                }
            }

            struct clause_literal *tmp_cl = NULL;
            for (size_t j = 0; j < utarray_len(clause->literals); j++) {
                tmp_cl = (struct clause_literal *)utarray_eltptr(clause->literals, j);

                for (size_t k = 0; k < tmp_cl->group_cnt; k++) {
                    struct clause_query_key key =
                        {tmp_cl->group_ids[k], tmp_cl->vtable_id, clause->not_flag};
                    struct clause_id_kv *clause_id_kv = NULL;
                    
                    HASH_FIND(hh, clause_id_kv_hash, &key, sizeof(struct clause_query_key),
                              clause_id_kv);
                    if (NULL == clause_id_kv) {
                        clause_id_kv = ALLOC(struct clause_id_kv, 1);
                        clause_id_kv->key = key;
                        utarray_new(clause_id_kv->clause_ids, &ut_clause_id_icd);
                        HASH_ADD_KEYPTR(hh, clause_id_kv_hash, &clause_id_kv->key,
                                        sizeof(clause_id_kv->key), clause_id_kv);
                    }

                    if (utarray_find(clause_id_kv->clause_ids, &(clause->clause_id),
                                     compare_clause_id)) {
                        continue;
                    }
                    utarray_push_back(clause_id_kv->clause_ids, &(clause->clause_id));
                    utarray_sort(clause_id_kv->clause_ids, compare_clause_id);
                }
            }
        }
    }

    FREE(data_array);
    return clause_id_kv_hash;
}

static int
maat_compile_has_clause(struct maat_compile *compile, long long clause_id)
{
	struct compile_clause *clause = NULL;

	for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		clause = compile->clauses + i;
		if (!clause->in_use) {
			continue;
		}

		if (clause->clause_id == clause_id) {
			return 1;
		}
	}

	return 0;
}

static size_t
compile_state_if_new_hit_compile(struct compile_state *compile_state,
                                 struct maat_compile *compile)
{
    size_t i = 0;
	size_t r_in_c_cnt = 0;
	int ret = 0;

	long long new_hit_clause_id = 0;
    if (0 == compile_state->this_scan_not_logic) {
        for (i = 0; i < utarray_len(compile_state->this_scan_hit_clauses); i++) {
		    new_hit_clause_id =
                *(long long*)utarray_eltptr(compile_state->this_scan_hit_clauses, i);
		    ret = maat_compile_has_clause(compile, new_hit_clause_id);
		    if (ret) {
			    r_in_c_cnt++;
		    }
	    }
    } else {
        for (i = 0; i < utarray_len(compile_state->this_scan_hit_not_clauses); i++) {
		    new_hit_clause_id =
                *(long long*)utarray_eltptr(compile_state->this_scan_hit_not_clauses, i);
		    ret = maat_compile_has_clause(compile, new_hit_clause_id);
		    if (ret) {
			    r_in_c_cnt++;
		    }
	    }
    }

	return r_in_c_cnt;
}

static void
compile_state_update_hit_compile_table_id(struct compile_state *compile_state,
                                          long long compile_id, int table_id)
{
    if (!utarray_find(compile_state->hit_compile_table_ids, &compile_id,
                      compare_compile_id)) {
        struct compile2table_id compile_table_id = {compile_id, table_id};
        utarray_push_back(compile_state->hit_compile_table_ids, &compile_table_id);
        utarray_sort(compile_state->hit_compile_table_ids, compare_compile_id);
    }
}

static size_t
maat_compile_bool_matcher_match(struct compile_runtime *compile_rt,
                                struct compile_state *compile_state,
                                int thread_id, void **user_data_array,
                                size_t ud_array_size)
{
    size_t ud_result_cnt = 0;
	struct maat_compile *compile = NULL;
	struct bool_expr_match *expr_match = compile_rt->expr_match_buff +
                                         (thread_id * MAX_HIT_COMPILE_NUM);
    assert(thread_id >= 0);

    if (0 == compile_state->compile_rt_version) {
        compile_state->compile_rt_version = compile_rt->version;
    }

    if (NULL == compile_rt->bm ||
        0 == utarray_len(compile_state->all_hit_clauses) ||
        compile_state->compile_rt_version != compile_rt->version) {
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
	
	int bool_match_ret =
        bool_matcher_match(compile_rt->bm, 
                          (unsigned long long *)utarray_eltptr(compile_state->all_hit_clauses, 0),
						  utarray_len(compile_state->all_hit_clauses), 
                          expr_match, MAX_HIT_COMPILE_NUM);
	for (int i = 0; i < bool_match_ret && ud_result_cnt < ud_array_size; i++) {
		compile = (struct maat_compile *)expr_match[i].user_tag;
		assert(compile->magic_num == MAAT_COMPILE_MAGIC);
		assert((unsigned long long)compile->compile_id == expr_match[i].expr_id);
		if (0 == compile->actual_clause_num) {
			continue;
		}

        size_t n_new_hit_compile =
            compile_state_if_new_hit_compile(compile_state, compile);

        if (compile->user_data != NULL && n_new_hit_compile > 0) {
            user_data_array[ud_result_cnt] = compile->user_data;
			ud_result_cnt++;
            compile_state_update_hit_compile_table_id(compile_state, compile->compile_id,
                                                      compile->table_id);
        }
	}

	return ud_result_cnt;
}

static struct compile_item *compile_item_clone(struct compile_item *item)
{
    struct compile_item *new_item = ALLOC(struct compile_item, 1);

    new_item->compile_id = item->compile_id;
    new_item->declared_clause_num = item->declared_clause_num;
    new_item->table_line_len = item->table_line_len;
    new_item->table_line = ALLOC(char, new_item->table_line_len + 1);
    memcpy(new_item->table_line, item->table_line, new_item->table_line_len);

    return new_item;
}

static struct maat_compile *
maat_compile_clone(struct maat_compile *compile, int deep_copy)
{
    struct maat_compile *new_compile = ALLOC(struct maat_compile, 1);

    new_compile->magic_num = compile->magic_num;
    new_compile->compile_id = compile->compile_id;
    new_compile->actual_clause_num = compile->actual_clause_num;
    new_compile->declared_clause_num = compile->declared_clause_num;
    if (1 == deep_copy && compile->user_data != NULL) {
        new_compile->user_data =
            compile_item_clone((struct compile_item *)compile->user_data);
    }

    struct clause_literal *tmp_literal = NULL;
    for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
        new_compile->clauses[i].clause_id = compile->clauses[i].clause_id;
        new_compile->clauses[i].in_use = compile->clauses[i].in_use;
        new_compile->clauses[i].not_flag = compile->clauses[i].not_flag;
        utarray_new(new_compile->clauses[i].literals, &ut_clause_literal_icd);
        for (size_t j = 0; j < utarray_len(compile->clauses[i].literals); j++) {
            tmp_literal =
                (struct clause_literal *)utarray_eltptr(compile->clauses[i].literals, j);
            utarray_push_back(new_compile->clauses[i].literals, tmp_literal);
        }
    }

    return new_compile;
}

static int maat_add_group_to_compile(struct rcu_hash_table *hash_tbl,
                                      struct group2compile_item *g2c_item,
                                      struct log_handle *logger)
{
	int ret = 0;
    long long compile_id = g2c_item->compile_id;
    struct maat_compile *compile = NULL;

    int updating_flag = rcu_hash_is_updating(hash_tbl);
    if (1 == updating_flag) {
        compile = rcu_updating_hash_find(hash_tbl, (char *)&compile_id, sizeof(long long));
        if (compile != NULL) {
            ret = maat_compile_clause_find_literal(compile, g2c_item);
            if (ret > 0) {
                log_fatal(logger, MODULE_COMPILE,
                          "[%s:%d]compile:%lld clause(index:%d) already has vtable_id:%d's "
                          "literal, can't add again", __FUNCTION__, __LINE__, compile->compile_id,
                          g2c_item->clause_index, g2c_item->vtable_id);
                return -1;
            }
            /* compile found in updating hash(added by compile runtime), it can
             * be modified directly */
            maat_compile_clause_add_literal(compile, g2c_item);
        } else {
            /* compile neither in effective hash nor in updating hash, so new one */
            compile = maat_compile_new(compile_id);
            assert(compile != NULL);

            maat_compile_clause_add_literal(compile, g2c_item);
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
            ret = maat_compile_clause_find_literal(compile, g2c_item);
            if (ret > 0) {
                log_fatal(logger, MODULE_COMPILE,
                          "[%s:%d]compile:%lld clause(index:%d) already has vtable_id:%d's "
                          "literal, can't add again", __FUNCTION__, __LINE__, compile->compile_id,
                          g2c_item->clause_index, g2c_item->vtable_id);
                return -1;
            }

            struct maat_compile *copy_compile = maat_compile_clone(compile, 1);
            assert(copy_compile != NULL);

            /* delete compile from rcu hash */
            rcu_hash_del(hash_tbl, (char *)&compile_id, sizeof(long long));

            maat_compile_clause_add_literal(copy_compile, g2c_item);
            rcu_hash_add(hash_tbl, (char *)&compile_id, sizeof(long long), copy_compile);
        } else {
            compile = maat_compile_new(compile_id);
            assert(compile != NULL);

            maat_compile_clause_add_literal(compile, g2c_item);
            rcu_hash_add(hash_tbl, (char *)&compile_id, sizeof(long long), compile);
        }
    }

    return 0;
}

static int maat_remove_group_from_compile(struct rcu_hash_table *hash_tbl,
                                           struct group2compile_item *g2c_item,
                                           struct log_handle *logger)
{
	int ret = 0;
    long long compile_id = g2c_item->compile_id;
    struct maat_compile *compile = NULL;

    int updating_flag = rcu_hash_is_updating(hash_tbl);
    if (1 == updating_flag) {
        compile = rcu_updating_hash_find(hash_tbl, (char *)&compile_id,
                                         sizeof(long long));
        if (NULL == compile) {
            log_fatal(logger, MODULE_COMPILE,
                      "[%s:%d] Remove clause(index:%d) from compile %lld failed,"
                      "compile not existed.", __FUNCTION__, __LINE__,
                      g2c_item->clause_index, compile_id);
            return -1;
        } else {
            ret = maat_compile_clause_find_literal(compile, g2c_item);
            if (0 == ret) {
                log_fatal(logger, MODULE_COMPILE,
                          "[%s:%d]compile:%lld clause(index:%d) has no vtable_id:%d's "
                          "literal, can't be removed", __FUNCTION__, __LINE__,
                          compile->compile_id, g2c_item->clause_index, g2c_item->vtable_id);
                return -1;
            }

            /* compile found in updating hash, it can be modified directly */
            maat_compile_clause_remove_literal(compile, g2c_item);
            if (0 == compile->actual_clause_num && NULL == compile->user_data) {
                rcu_hash_del(hash_tbl, (char *)&compile_id, sizeof(long long));
            } 
        }
    } else {
        //find in effetive hash
        compile = rcu_hash_find(hash_tbl, (char *)&compile_id, sizeof(long long));
        if (compile != NULL) {
            ret = maat_compile_clause_find_literal(compile, g2c_item);
            if (0 == ret) {
                log_fatal(logger, MODULE_COMPILE,
                          "[%s:%d]compile:%lld clause(index:%d) has no vtable_id:%d's "
                          "literal, can't be removed", __FUNCTION__, __LINE__,
                          compile->compile_id, g2c_item->clause_index, g2c_item->vtable_id);
                return -1;
            }

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
            maat_compile_clause_remove_literal(copy_compile, g2c_item);

            if (0 == copy_compile->actual_clause_num && NULL == copy_compile->user_data) {
                maat_compile_free(copy_compile);
            } else {
                rcu_hash_add(hash_tbl, (char *)&compile_id, sizeof(long long), copy_compile);
            }
        } else {
            log_fatal(logger, MODULE_COMPILE,
                      "[%s:%d] Remove clause(index:%d) from compile_id %lld failed,"
                      "compile is not existed.", __FUNCTION__, __LINE__, 
                      g2c_item->clause_index, compile_id);
            return -1;
        }
    }

    return 0;
}

struct compile_state *compile_state_new(void)
{
    struct compile_state *compile_state = ALLOC(struct compile_state, 1);

	utarray_new(compile_state->internal_hit_paths, &ut_hit_path_icd);
	utarray_new(compile_state->all_hit_clauses, &ut_clause_id_icd);
	utarray_new(compile_state->this_scan_hit_clauses, &ut_clause_id_icd);
	utarray_new(compile_state->this_scan_hit_not_clauses, &ut_clause_id_icd);
    utarray_new(compile_state->exclude_not_clauses, &ut_clause_id_icd);
    utarray_new(compile_state->direct_hit_groups, &ut_maat_hit_group_icd);
    utarray_new(compile_state->indirect_hit_groups, &ut_maat_hit_group_icd);
    utarray_new(compile_state->last_hit_groups, &ut_maat_hit_group_icd);
    utarray_new(compile_state->hit_compile_table_ids, &ut_hit_compile_table_id_icd);
    compile_state->hit_not_tbl_groups = NULL;

	return compile_state;
}

static long long
compile_state_hit_not_tbl_groups_free(struct compile_state *compile_state)
{
    if (NULL == compile_state) {
        return 0;
    }

    long long free_bytes = 0;
    struct table_group *tbl_group = NULL, *tmp_tbl_group = NULL;
    HASH_ITER(hh, compile_state->hit_not_tbl_groups, tbl_group, tmp_tbl_group) {
        free_bytes +=
            (sizeof(tbl_group) + utarray_len(tbl_group->group_ids) * sizeof(long long));
        HASH_DEL(compile_state->hit_not_tbl_groups, tbl_group);
        if (tbl_group->group_ids != NULL) {
            utarray_free(tbl_group->group_ids);
            tbl_group->group_ids = NULL;
        }
        FREE(tbl_group);
    }

    return free_bytes;
}

void compile_state_reset(struct compile_state *compile_state)
{
    if (NULL == compile_state) {
        return;
    }

    compile_state->this_scan_not_logic = 0;
    compile_state->Nth_scan = 0;
    compile_state->compile_rt_version = 0;

    utarray_clear(compile_state->internal_hit_paths);
    utarray_clear(compile_state->all_hit_clauses);
    utarray_clear(compile_state->this_scan_hit_clauses);
    utarray_clear(compile_state->this_scan_hit_not_clauses);
    utarray_clear(compile_state->exclude_not_clauses);
    utarray_clear(compile_state->direct_hit_groups);
    utarray_clear(compile_state->indirect_hit_groups);
    utarray_clear(compile_state->last_hit_groups);
    utarray_clear(compile_state->hit_compile_table_ids);

    struct table_group *tbl_group = NULL, *tmp_tbl_group = NULL;
    HASH_ITER(hh, compile_state->hit_not_tbl_groups, tbl_group, tmp_tbl_group) {
        utarray_clear(tbl_group->group_ids);
    }
}

void compile_state_free(struct compile_state *compile_state,
                        struct maat *maat_inst, int thread_id)
{
    if (NULL == compile_state) {
        return;
    }
    
    long long free_bytes = 0;
    if (compile_state->internal_hit_paths != NULL) {
        free_bytes += utarray_size(compile_state->internal_hit_paths) * 
                      sizeof(struct internal_hit_path);
        utarray_free(compile_state->internal_hit_paths);
        compile_state->internal_hit_paths = NULL;
    }
    
    if (compile_state->all_hit_clauses != NULL) {
        free_bytes += utarray_size(compile_state->all_hit_clauses) *
                      sizeof(long long);
        utarray_free(compile_state->all_hit_clauses);
        compile_state->all_hit_clauses = NULL;
    }
	
    if (compile_state->this_scan_hit_clauses != NULL) {
        free_bytes += utarray_size(compile_state->this_scan_hit_clauses) *
                      sizeof(long long);
        utarray_free(compile_state->this_scan_hit_clauses);
        compile_state->this_scan_hit_clauses = NULL;
    }
	
    if (compile_state->this_scan_hit_not_clauses != NULL) {
        free_bytes += utarray_size(compile_state->this_scan_hit_not_clauses) *
                      sizeof(long long);
        utarray_free(compile_state->this_scan_hit_not_clauses);
        compile_state->this_scan_hit_not_clauses = NULL;
    }

    if (compile_state->exclude_not_clauses != NULL) {
        free_bytes += utarray_size(compile_state->exclude_not_clauses) *
                      sizeof(long long);
        utarray_free(compile_state->exclude_not_clauses);
        compile_state->exclude_not_clauses = NULL;
    }

    if (compile_state->direct_hit_groups != NULL) {
        free_bytes += utarray_size(compile_state->direct_hit_groups) *
                      sizeof(struct maat_hit_group);
        utarray_free(compile_state->direct_hit_groups);
        compile_state->direct_hit_groups = NULL;
    }

    if (compile_state->indirect_hit_groups != NULL) {
        free_bytes += utarray_size(compile_state->indirect_hit_groups) *
                      sizeof(struct maat_hit_group);
        utarray_free(compile_state->indirect_hit_groups);
        compile_state->indirect_hit_groups = NULL;
    }

    if (compile_state->last_hit_groups != NULL) {
        free_bytes += utarray_size(compile_state->last_hit_groups) *
                      sizeof(struct maat_hit_group);
        utarray_free(compile_state->last_hit_groups);
        compile_state->last_hit_groups = NULL;
    }

    if (compile_state->hit_compile_table_ids != NULL) {
        free_bytes += utarray_size(compile_state->hit_compile_table_ids) *
                      sizeof(struct compile2table_id);
        utarray_free(compile_state->hit_compile_table_ids);
        compile_state->hit_compile_table_ids = NULL;
    }

    free_bytes += compile_state_hit_not_tbl_groups_free(compile_state);

	FREE(compile_state);

    free_bytes += sizeof(struct compile_state);
    alignment_int64_array_add(maat_inst->stat->maat_state_free_bytes,
                              thread_id, free_bytes);
}

static void
compile_state_add_internal_hit_path(struct compile_state *compile_state,
                                    long long item_id, long long group_id,
                                    int vtable_id, int NOT_flag, int Nth_scan)
{
    if (NULL == compile_state) {
        return;
    }

	struct internal_hit_path new_path;
	new_path.item_id = item_id;
	new_path.Nth_scan = Nth_scan;
	new_path.group_id = group_id;
	new_path.vtable_id = vtable_id;
    new_path.NOT_flag = NOT_flag;

	utarray_push_back(compile_state->internal_hit_paths, &new_path);
}

static int maat_compile_has_clause_query_key(struct maat_compile *compile,
                                             struct clause_query_key *key)
{
	for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		struct compile_clause *clause = compile->clauses+i;
		if(!clause->in_use) {
			continue;
		}

        struct clause_literal *tmp_cl = NULL;
        for (size_t j = 0; j < utarray_len(clause->literals); j++) {
            tmp_cl = (struct clause_literal *)utarray_eltptr(clause->literals, j);
            if (tmp_cl->vtable_id != key->vtable_id) {
                continue;
            }

            if (clause->not_flag != key->not_flag) {
                continue;
            }

            long long *tmp_group_id = bsearch(&(key->group_id), tmp_cl->group_ids,
                                              tmp_cl->group_cnt, sizeof(long long),
                                              compare_group_id);
            if (tmp_group_id != NULL) {
                return 1;
            }
        }
	}

	return 0;
}

static size_t
maat_compile_get_hit_clause_index(struct maat_compile *compile, 
                                  int vtable_id, long long hit_group_id,
                                  int *clause_idx_array, size_t array_size)
{
    size_t hit_clause_cnt = 0;
    struct compile_clause *tmp_clause = NULL;

    for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
        tmp_clause = &compile->clauses[i];
        if (!tmp_clause->in_use) {
            continue;
        }

        struct clause_literal *tmp_cl = NULL;
        for (size_t j = 0; j < utarray_len(tmp_clause->literals); j++) {
            tmp_cl = (struct clause_literal *)utarray_eltptr(tmp_clause->literals, j);
            if (tmp_cl->vtable_id != vtable_id) {
                continue;
            }

            long long *tmp_group_id = bsearch(&hit_group_id, tmp_cl->group_ids,
                                              tmp_cl->group_cnt, sizeof(long long),
                                              compare_group_id);
            if (tmp_group_id != NULL) {
                clause_idx_array[hit_clause_cnt++] = i;
                break;
            }
        }
    }

    return hit_clause_cnt;
}

static int
maat_compile_is_hit_path_existed(const struct maat_hit_path *hit_paths,
                                 size_t n_path, const struct maat_hit_path *find)
{
	for (size_t i = 0; i < n_path; i++) {
		if (0 == memcmp(hit_paths + i, find, sizeof(*find))) {
			return 1;
		}
	}

	return 0;
}

void populate_hit_path_with_compile(struct maat_hit_path *hit_path_array,
                                    size_t array_idx, size_t n_hit_path,
                                    size_t *n_new_hit_path,
                                    struct maat_compile *compile)
{
    size_t i = 0;
    size_t idx = array_idx;
    size_t n_clause_index = 0;
    size_t new_hit_path_cnt = *n_new_hit_path;
    int clause_index_array[MAX_ITEMS_PER_BOOL_EXPR] = {0};

    if (hit_path_array[idx].top_group_id < 0) {
        hit_path_array[idx].top_group_id = hit_path_array[idx].sub_group_id;
    }

    struct maat_hit_path tmp_path;
    if (hit_path_array[idx].compile_id < 0) {
        hit_path_array[idx].compile_id = compile->compile_id;
        // find out which clause in compile hit
        n_clause_index =
            maat_compile_get_hit_clause_index(compile, hit_path_array[idx].vtable_id,
                                              hit_path_array[idx].top_group_id,
                                              clause_index_array,
                                              MAX_ITEMS_PER_BOOL_EXPR);
        hit_path_array[idx].clause_index = clause_index_array[0];
        if (n_clause_index > 1) {
            for (i = 1; i < n_clause_index; i++) {
                tmp_path = hit_path_array[idx];
                tmp_path.clause_index = clause_index_array[i];
                hit_path_array[n_hit_path + new_hit_path_cnt] = tmp_path;
                new_hit_path_cnt++;
            }
        }
    } else {
        // means same clause_query_id hit more than one compile_id
        tmp_path = hit_path_array[idx];
        tmp_path.compile_id = compile->compile_id;
        if (!maat_compile_is_hit_path_existed(hit_path_array, n_hit_path + new_hit_path_cnt, &tmp_path)) {
            hit_path_array[n_hit_path + new_hit_path_cnt] = tmp_path;
            new_hit_path_cnt++;
            n_clause_index =
                maat_compile_get_hit_clause_index(compile, tmp_path.vtable_id, tmp_path.top_group_id,
                                                  clause_index_array, MAX_ITEMS_PER_BOOL_EXPR);
            hit_path_array[n_hit_path + new_hit_path_cnt - 1].clause_index = clause_index_array[0];
            if (n_clause_index > 1) {
                for (i = 1; i < n_clause_index; i++) {
                    tmp_path = hit_path_array[n_hit_path + new_hit_path_cnt - 1];
                    tmp_path.clause_index = clause_index_array[i];
                    hit_path_array[n_hit_path + new_hit_path_cnt] = tmp_path;
                    new_hit_path_cnt++;
                }
            }
        }
    }

    *n_new_hit_path = new_hit_path_cnt;
}

size_t compile_runtime_get_hit_paths(struct compile_runtime *compile_rt, int thread_id,
									 struct compile_state *compile_state, 
                                  	 struct maat_hit_path *hit_path_array, 
                                     size_t array_size, size_t n_hit_path)
{
    /* assign hit_path_array[].compile_id */
    size_t n_new_hit_path = 0;
    struct maat_compile *compile = NULL;
    struct clause_query_key key = {0, 0, 0};
    struct bool_expr_match *expr_match = compile_rt->expr_match_buff + 
                                         (thread_id * MAX_HIT_COMPILE_NUM);
    assert(thread_id >= 0);

    if (compile_state->compile_rt_version != compile_rt->version) {
        return 0;
    }

    int bool_match_ret =
        bool_matcher_match(compile_rt->bm, 
                          (unsigned long long *)utarray_eltptr(compile_state->all_hit_clauses, 0),
						  utarray_len(compile_state->all_hit_clauses), expr_match, MAX_HIT_COMPILE_NUM);

	for (int idx = 0; idx < bool_match_ret; idx++) {
        compile = (struct maat_compile *)expr_match[idx].user_tag;
		assert(compile->magic_num == MAAT_COMPILE_MAGIC);
		assert((unsigned long long)compile->compile_id == expr_match[idx].expr_id);
		if (0 == compile->actual_clause_num || NULL == compile->user_data) {
			continue;
		}

        for (size_t j = 0; j < n_hit_path && (n_hit_path + n_new_hit_path) < array_size; j++) {
			if (hit_path_array[j].top_group_id < 0) {
                key.group_id = hit_path_array[j].sub_group_id;
			} else {
                key.group_id = hit_path_array[j].top_group_id;
            }

			key.vtable_id = hit_path_array[j].vtable_id;
            key.not_flag = hit_path_array[j].NOT_flag;
			if (maat_compile_has_clause_query_key(compile, &key)) {
                populate_hit_path_with_compile(hit_path_array, j, n_hit_path,
                                               &n_new_hit_path, compile);
			}
		}
	}

    return (n_hit_path + n_new_hit_path);
}

static void
compile_state_add_direct_hit_groups(struct compile_state *compile_state,
                                    struct maat_item *hit_items,
                                    size_t n_hit_items, int vtable_id)
{
    if (NULL == compile_state || NULL == hit_items) {
        return;
    }

    struct maat_hit_group hit_group;
    for (size_t i = 0; i < n_hit_items; i++) {
        hit_group.item_id = hit_items[i].item_id;
        hit_group.group_id = hit_items[i].group_id;
        hit_group.vtable_id = vtable_id;
        utarray_push_back(compile_state->direct_hit_groups, &hit_group);
    }
}

static void
compile_state_add_indirect_hit_groups(struct compile_state *compile_state,
                                      long long *group_ids,
                                      size_t n_group_ids, int vtable_id)
{
    if (NULL == compile_state || NULL == group_ids) {
        return;
    }

    struct maat_hit_group hit_group;
    for (size_t i = 0; i < n_group_ids; i++) {
        hit_group.item_id = 0;
        hit_group.group_id = group_ids[i];
        hit_group.vtable_id = vtable_id;
        utarray_push_back(compile_state->indirect_hit_groups, &hit_group);
    }
}

static void
compile_state_add_hit_clauses(struct compile_state *compile_state,
                              UT_array *clause_id_array)
{
    size_t i = 0;
    long long *clause_id = NULL;
    size_t new_clause_idx = utarray_len(compile_state->this_scan_hit_clauses);

    for (i = 0; i < utarray_len(clause_id_array); i++) {
        clause_id = (long long *)utarray_eltptr(clause_id_array, i);
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

static void
compile_state_add_exclude_not_clauses(struct compile_state *compile_state,
                                      UT_array *clause_id_array)
{
    for (size_t i = 0; i < utarray_len(clause_id_array); i++) {
        long long *clause_id = (long long *)utarray_eltptr(clause_id_array, i);
        if (utarray_find(compile_state->exclude_not_clauses, clause_id,
                         compare_clause_id)) {
            continue;
        }
        utarray_push_back(compile_state->exclude_not_clauses, clause_id);
    }
    utarray_sort(compile_state->exclude_not_clauses, compare_clause_id);
}

static void
compile_state_add_hit_not_clauses(struct compile_state *compile_state,
                                  UT_array *clause_id_array)
{
    size_t i = 0;
    long long *clause_id = NULL;
    size_t new_clause_idx = utarray_len(compile_state->this_scan_hit_not_clauses);

    for (i = 0; i < utarray_len(clause_id_array); i++) {
        clause_id = (long long *)utarray_eltptr(clause_id_array, i);
        if (utarray_find(compile_state->all_hit_clauses, clause_id, compare_clause_id)) {
            continue;
        }

        if (utarray_find(compile_state->exclude_not_clauses, clause_id, compare_clause_id)) {
            continue;
        }

        utarray_push_back(compile_state->this_scan_hit_not_clauses, clause_id);
    }

    if ((utarray_len(compile_state->this_scan_hit_not_clauses) - new_clause_idx) > 0) {
        utarray_reserve(compile_state->all_hit_clauses,
                        utarray_len(compile_state->this_scan_hit_not_clauses) - new_clause_idx);

        for (i = new_clause_idx; i < utarray_len(compile_state->this_scan_hit_not_clauses); i++) {
            clause_id = (long long *)utarray_eltptr(compile_state->this_scan_hit_not_clauses, i);
            utarray_push_back(compile_state->all_hit_clauses, clause_id);
        }
        utarray_sort(compile_state->all_hit_clauses, compare_clause_id);
    }
}

static void
compile_state_update_hit_clauses(struct compile_state *compile_state,
                                 struct compile_runtime *compile_rt,
                                 long long group_id, int vtable_id)
{
    if (NULL == compile_state || NULL == compile_rt) {
        return;
    }

    struct clause_query_key key = {group_id, vtable_id, 0};
    struct clause_id_kv *clause_id_kv = NULL;

    HASH_FIND(hh, compile_rt->clause_id_kv_hash, &key, sizeof(key), clause_id_kv);
    if (clause_id_kv != NULL) {
        compile_state_add_hit_clauses(compile_state, clause_id_kv->clause_ids);
    }

    key.not_flag = 1;
    HASH_FIND(hh, compile_rt->not_clause_id_kv_hash, &key, sizeof(key), clause_id_kv);
    if (clause_id_kv != NULL) {
        compile_state_add_exclude_not_clauses(compile_state, clause_id_kv->clause_ids);
    }
}

static void
compile_state_cache_hit_not_groups(struct compile_state *compile_state,
                                   struct compile_runtime *compile_rt,
                                   long long *hit_group_ids,
                                   size_t n_hit_group_id, int vtable_id)
{
    if (NULL == compile_state || NULL == compile_rt) {
        return;
    }

    if (n_hit_group_id != 0) {
        qsort(hit_group_ids, n_hit_group_id, sizeof(long long), compare_group_id);
    }

    struct table_group *tbl_group = NULL;
    HASH_FIND(hh, compile_state->hit_not_tbl_groups, &vtable_id, sizeof(int), tbl_group);
    if (tbl_group != NULL) {
        for (size_t i = 0; i < n_hit_group_id; i++) {
            long long *group_id = (long long *)utarray_find(tbl_group->group_ids,
                                                            &hit_group_ids[i],
                                                            compare_group_id);
            if (NULL == group_id) {
                continue;
            }
            size_t remove_idx = utarray_eltidx(tbl_group->group_ids, group_id);
            utarray_erase(tbl_group->group_ids, remove_idx, 1);
        }
    }

    struct clause_id_kv *clause_id_kv = NULL, *tmp_clause_id_kv = NULL;
    HASH_ITER(hh, compile_rt->not_clause_id_kv_hash, clause_id_kv, tmp_clause_id_kv) {
        if (clause_id_kv->key.vtable_id != vtable_id) {
            continue;
        }

        long long *tmp_group_id =
            bsearch(&(clause_id_kv->key.group_id), hit_group_ids,
                    n_hit_group_id, sizeof(long long), compare_group_id);
        if (tmp_group_id != NULL) {
            continue;
        }

        if (NULL == tbl_group) {
            tbl_group = ALLOC(struct table_group, 1);
            tbl_group->vtable_id = vtable_id;
            utarray_new(tbl_group->group_ids, &ut_compile_group_id_icd);
            HASH_ADD_INT(compile_state->hit_not_tbl_groups, vtable_id, tbl_group);
        }

        if (!utarray_find(tbl_group->group_ids, &(clause_id_kv->key.group_id),
                          compare_group_id)) {
            utarray_push_back(tbl_group->group_ids, &(clause_id_kv->key.group_id));
        }
    }

    if (tbl_group != NULL) {
        utarray_sort(tbl_group->group_ids, compare_group_id);
    }
}

int compile_state_get_compile_table_id(struct compile_state *compile_state,
                                       long long compile_id)
{
    struct compile2table_id *tmp = NULL;

    tmp = utarray_find(compile_state->hit_compile_table_ids, &compile_id,
                                 compare_compile_id);
    if (NULL == tmp) {
        return -1;
    }

    return tmp->table_id;
}

static int
compile_runtime_add_compile(struct compile_runtime *compile_rt,
                            struct compile_schema *schema,
                            long long compile_id, const char *table_name,
                            const char *line, struct log_handle *logger)
{
    struct maat_compile *compile = NULL;
    struct compile_item *compile_item = compile_item_new(line, schema, table_name,
                                                         compile_rt->logger);
    if (NULL == compile_item) {
        return -1;
    }

    int table_id = table_manager_get_table_id(schema->ref_tbl_mgr, table_name);
    if (table_id < 0) {
        log_fatal(logger, MODULE_COMPILE,
                  "[%s:%d]table_name:%s has invalid table_id:%d, drop line:%s",
                  __FUNCTION__, __LINE__, table_name, table_id, line);
        return -1;
    }

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
            maat_compile_set(compile, table_id, compile_item->declared_clause_num, compile_item);
        } else {
            // compile neither in effective hash nor in updating hash
            compile = maat_compile_new(compile_item->compile_id);
            assert(compile != NULL);
            maat_compile_set(compile, table_id, compile_item->declared_clause_num, compile_item);
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
            maat_compile_set(copy_compile, table_id, compile_item->declared_clause_num, compile_item);
            /* add copy_compile to rcu hash */
            rcu_hash_add(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long), copy_compile);
        } else {
            compile = maat_compile_new(compile_item->compile_id);
            assert(compile != NULL);
            maat_compile_set(compile, table_id, compile_item->declared_clause_num, compile_item);
            rcu_hash_add(compile_rt->cfg_hash, (char *)&compile_id, sizeof(long long), compile);
        }
    }

    return 0;
}

static void garbage_compile_item_free(void *data, void *arg)
{
    if (NULL == data) {
        return;
    }

    struct compile_item *compile_item = (struct compile_item *)data;

    compile_item_free(compile_item);
}

static void compile_runtime_del_compile(struct compile_runtime *compile_rt,
                                        long long compile_id)
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
            if (compile->user_data != NULL) {
                maat_garbage_bagging(compile_rt->ref_garbage_bin, compile->user_data, NULL,
                                     garbage_compile_item_free);
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
        log_fatal(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] compile table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        compile_rt->update_err_cnt++;
        return -1;
    }

    long long compile_id = get_column_value(line, schema->compile_id_column);
    if (compile_id < 0) {
        log_fatal(compile_rt->logger, MODULE_COMPILE,
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
                                              table_name, line, compile_rt->logger);
        if (ret < 0) {
            compile_rt->update_err_cnt++;
        }
    }

    return 0;
}

static int validate_table_not_clause(struct group2compile_runtime *g2c_rt,
                                     struct table_manager *tbl_mgr, int table_id,
                                     int is_valid, struct log_handle *logger)
{
    struct table_clause *not_clause = NULL;
    HASH_FIND_INT(g2c_rt->tbl_not_clause_hash, &table_id, not_clause);

    if (0 == is_valid) {
        //delete
        if (NULL == not_clause || 0 == not_clause->actual_clause_num) {
            return 0;
        } else {
            not_clause->actual_clause_num--;
        }
    } else {
        //add
        if (NULL == not_clause) {
            not_clause = ALLOC(struct table_clause, 1);
            not_clause->vtable_id = table_id;
            not_clause->actual_clause_num++;
            HASH_ADD_INT(g2c_rt->tbl_not_clause_hash, vtable_id, not_clause);
        } else {
            if (not_clause->actual_clause_num >= MAX_NOT_CLAUSE_NUM) {
                const char *table_name = table_manager_get_table_name(tbl_mgr, table_id);
                log_fatal(logger, MODULE_COMPILE,
                          "[%s:%d]table:<%s> NOT clause num exceed maximum:%d",
                          __FUNCTION__, __LINE__, table_name, MAX_NOT_CLAUSE_NUM);
                return -1;
            }
            not_clause->actual_clause_num++;
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
         log_fatal(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] g2c table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        g2c_rt->update_err_cnt++;
        return -1;
    } 
    
    int ret = -1;
    struct group2compile_item *g2c_item =
        group2compile_item_new(line, schema, table_name, compile_rt->logger);
    if (NULL == g2c_item) {
        g2c_rt->update_err_cnt++;
        return -1;
    }

    if (1 == g2c_item->not_flag) {
        ret = validate_table_not_clause(g2c_rt, schema->ref_tbl_mgr,
                                        g2c_item->vtable_id, is_valid,
                                        compile_rt->logger);
        if (ret < 0) {
            log_fatal(compile_rt->logger, MODULE_COMPILE,
                      "[%s:%d]validate NOT clause failed, abandon config:%s",
                      __FUNCTION__, __LINE__, line);
            goto next;
        }
    }

    if (0 == is_valid) {
        //delete
        ret = maat_remove_group_from_compile(compile_rt->cfg_hash, g2c_item,
                                             compile_rt->logger);
        if (0 == ret) {
            if (g2c_item->not_flag) {
                g2c_rt->not_clause_cnt--;
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
                g2c_rt->not_clause_cnt++;
            }
            g2c_rt->rule_num++;
        } else {
            g2c_rt->update_err_cnt++;
        }
    }

next:
    group2compile_item_free(g2c_item);
    return ret;
}

long long group2compile_runtime_not_clause_count(void *g2c_runtime)
{
     if (NULL == g2c_runtime) {
        return 0;
    }
    
    struct group2compile_runtime *g2c_rt =
        (struct group2compile_runtime *)g2c_runtime;

    return g2c_rt->not_clause_cnt;
}

long long group2compile_runtime_rule_count(void *g2c_runtime)
{
    if (NULL == g2c_runtime) {
        return 0;
    }
    
    struct group2compile_runtime *g2c_rt =
        (struct group2compile_runtime *)g2c_runtime;

    return g2c_rt->rule_num;
}

long long group2compile_runtime_update_err_count(void *g2c_runtime)
{   
    if (NULL == g2c_runtime) {
        return 0;
    }

    struct group2compile_runtime *g2c_rt =
        (struct group2compile_runtime *)g2c_runtime;

    return g2c_rt->update_err_cnt;
}

int compile_runtime_commit(void *compile_runtime, const char *table_name,
                           long long maat_rt_version)
{
    if (NULL == compile_runtime) {
        return -1;
    }

    struct compile_runtime *compile_rt =
        (struct compile_runtime *)compile_runtime;
   
    int updating_flag = rcu_hash_is_updating(compile_rt->cfg_hash);
    if (0 == updating_flag) {
        return 0;
    }
    
    int ret = 0;
    size_t compile_cnt = 0;
    struct bool_matcher *old_bool_matcher = NULL;
    struct bool_matcher *new_bool_matcher = NULL;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    new_bool_matcher = maat_compile_bool_matcher_new(compile_rt, &compile_cnt);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                               (end.tv_nsec - start.tv_nsec) / 1000000;

    if (NULL == new_bool_matcher) {
        log_fatal(compile_rt->logger, MODULE_COMPILE,
                  "[%s:%d] table[%s] rebuild compile bool_matcher failed, compile"
                  " rules count:%zu", __FUNCTION__, __LINE__, table_name, compile_cnt);
        ret = -1;
    } else {
        log_info(compile_rt->logger, MODULE_COMPILE,
                 "table[%s] commit %zu compile rules and rebuild compile bool_matcher"
                 " completed, version:%lld, consume:%lldms", table_name, compile_cnt,
                 maat_rt_version, time_elapse_ms);
    }

    struct clause_id_kv *old_clause_id_kv_hash = NULL;
    struct clause_id_kv *new_clause_id_kv_hash = NULL;
    struct clause_id_kv *old_not_clause_id_kv_hash = NULL;
    struct clause_id_kv *new_not_clause_id_kv_hash = NULL;

    new_clause_id_kv_hash = build_clause_id_kv_hash(compile_rt, 0);
    new_not_clause_id_kv_hash = build_clause_id_kv_hash(compile_rt, 1);

    old_clause_id_kv_hash = compile_rt->clause_id_kv_hash;
    old_not_clause_id_kv_hash = compile_rt->not_clause_id_kv_hash;
    old_bool_matcher = compile_rt->bm;

    /*
        rule_monitor_loop thread
        STEP_1. compile_rt->bm = new_bool_matcher
        STEP_2: rcu_hash_commit(new_compile)

        scan thread
        Assume_1. If scan thread is using bool_matcher_match(compile_rt->bm) 
                  before STEP_1 or after STEP_2, it's ok.
        Assume_2. If scan thread is using bool_matcher_match(compile_rt->bm) 
                  between STEP_1 and STEP_2. 
                  P1: If new compile is hit and returned, then caller can get this compile's
                      ex_data by using maat_plugin_table_get_ex_data(hit_compile_id) because
                      STEP_2 is fast enough.
    */

    compile_rt->bm = new_bool_matcher;
    compile_rt->clause_id_kv_hash = new_clause_id_kv_hash;
    compile_rt->not_clause_id_kv_hash = new_not_clause_id_kv_hash;
    rcu_hash_commit(compile_rt->cfg_hash); //after commit, old cfg still available within COMPILE_GC_TIMEOUT_S.

    maat_garbage_bagging(compile_rt->ref_garbage_bin, old_bool_matcher, NULL,
                        garbage_bool_matcher_free);
    maat_garbage_bagging(compile_rt->ref_garbage_bin, old_clause_id_kv_hash, NULL,
                        garbage_clause_id_kv_hash_free);
    maat_garbage_bagging(compile_rt->ref_garbage_bin, old_not_clause_id_kv_hash, NULL,
                        garbage_clause_id_kv_hash_free);

    compile_rt->rule_num = rcu_hash_count(compile_rt->cfg_hash);

    return ret;
}

long long compile_runtime_rule_count(void *compile_runtime)
{
    if (NULL == compile_runtime) {
        return 0;
    }
    
    struct compile_runtime *compile_rt =
        (struct compile_runtime *)compile_runtime;

    return compile_rt->rule_num;
}

long long compile_runtime_update_err_count(void *compile_runtime)
{   
    if (NULL == compile_runtime) {
        return 0;
    }

    struct compile_runtime *compile_rt =
        (struct compile_runtime *)compile_runtime;

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
                                  const struct compile_item *item)
{
	para->compile_id = item->compile_id;
	para->declared_clause_num = item->declared_clause_num;
}

static int compare_compile_item(const void *a, const void *b)
{
	const struct compile_item *ra = *(const struct compile_item **)a;
	const struct compile_item *rb = *(const struct compile_item **)b;
	
	struct compile_sort_para sa, sb;
	compile_sort_para_set(&sa, ra);
	compile_sort_para_set(&sb, rb);

	return compile_sort_para_compare(&sa, &sb);
}

int compile_runtime_match(struct compile_runtime *compile_rt, long long *compile_ids,
                          size_t compile_ids_size, struct maat_state *state)
{
    struct compile_state *compile_state = state->compile_state;
    struct compile_item *compile_items[compile_ids_size];
    
    // all hit clause_id -> compile_id
    size_t bool_match_ret =
        maat_compile_bool_matcher_match(compile_rt, compile_state,
                                        state->thread_id,
                                        (void **)compile_items,
                                        compile_ids_size);
    if (bool_match_ret > 0) {
        qsort(compile_items, bool_match_ret, sizeof(struct compile_item *),
              compare_compile_item);
    }
   
    for (size_t i = 0; i < bool_match_ret; i++) {
        compile_ids[i] = compile_items[i]->compile_id;
	}
    
    return MIN(bool_match_ret, compile_ids_size);
}

int compile_state_update(struct compile_state *compile_state, struct maat *maat_inst,
                         int vtable_id, int custom_compile_tbl_id, int Nth_scan,
                         struct maat_item *hit_items, size_t n_hit_item)
{
    size_t i = 0, j = 0;
    size_t hit_cnt = n_hit_item;
    long long hit_group_ids[MAX_HIT_GROUP_NUM];
    struct maat_hit_group hit_group;

    utarray_clear(compile_state->this_scan_hit_clauses);
    compile_state->this_scan_not_logic = 0;
    compile_state->Nth_scan = Nth_scan;

    for (i = 0; i < hit_cnt; i++) {
        hit_group_ids[i] = hit_items[i].group_id;

        hit_group.item_id = hit_items[i].item_id;
        hit_group.group_id = hit_items[i].group_id;
        hit_group.vtable_id = vtable_id;
        utarray_push_back(compile_state->last_hit_groups, &hit_group);
    }

    int g2g_table_id = table_manager_get_group2group_table_id(maat_inst->tbl_mgr);
    void *g2g_rt = table_manager_get_runtime(maat_inst->tbl_mgr, g2g_table_id);

    long long super_group_ids[MAX_HIT_GROUP_NUM];
    size_t super_group_cnt = group2group_runtime_get_super_groups(g2g_rt, hit_group_ids,
                                                                  hit_cnt, super_group_ids,
                                                                  MAX_HIT_GROUP_NUM);
    for (i = 0; i < super_group_cnt; i++) {
        hit_group.item_id = 0;
        hit_group.group_id = super_group_ids[i];
        hit_group.vtable_id = vtable_id;
        utarray_push_back(compile_state->last_hit_groups, &hit_group);
    }

    if (1 == maat_inst->opts.hit_path_on && hit_cnt > 0) {
        for (i = 0; i < hit_cnt; i++) {
            compile_state_add_internal_hit_path(compile_state, hit_items[i].item_id,
                                                hit_items[i].group_id, vtable_id, 0, Nth_scan);
        }
    }

    if (1 == maat_inst->opts.hit_group_on) {
        compile_state_add_direct_hit_groups(compile_state, hit_items, hit_cnt, vtable_id);
        compile_state_add_indirect_hit_groups(compile_state, super_group_ids,
                                              super_group_cnt, vtable_id);
    }

    /* update hit clause */
    int compile_table_id = table_manager_get_default_compile_table_id(maat_inst->tbl_mgr);
    if (custom_compile_tbl_id > 0) {
        compile_table_id = custom_compile_tbl_id;
    }

    struct compile_runtime *compile_rt = table_manager_get_runtime(maat_inst->tbl_mgr,
                                                                   compile_table_id);
    if (NULL == compile_rt) {
        return 0;
    }

    for (j = 0; j < super_group_cnt && hit_cnt < MAX_HIT_GROUP_NUM; j++) {
        hit_group_ids[hit_cnt++] = super_group_ids[j];
    }

    for (i = 0; i < hit_cnt; i++) {
        compile_state_update_hit_clauses(compile_state, compile_rt,
                                         hit_group_ids[i], vtable_id);
    }

    compile_state_cache_hit_not_groups(compile_state, compile_rt, hit_group_ids,
                                       hit_cnt, vtable_id); 
    return hit_cnt;
}

void compile_state_clear_last_hit_group(struct compile_state *compile_state)
{
    if (NULL == compile_state) {
        return;
    }

    utarray_clear(compile_state->last_hit_groups);
}

void compile_state_not_logic_update(struct compile_state *compile_state,
                                    struct compile_runtime *compile_rt,
                                    struct maat *maat_inst, int vtable_id,
                                    int Nth_scan)
{
    if (NULL == compile_state || NULL == maat_inst) {
        return;
    }

    compile_state->this_scan_not_logic = 1;
    compile_state->Nth_scan = Nth_scan;
    utarray_clear(compile_state->this_scan_hit_not_clauses);

    struct table_group *tbl_group = NULL;
    HASH_FIND(hh, compile_state->hit_not_tbl_groups, &vtable_id, sizeof(int), tbl_group);
    if (NULL == tbl_group) {
        return;
    }

    struct clause_id_kv *clause_id_kv = NULL;
    for (size_t i = 0; i < utarray_len(tbl_group->group_ids); i++) {
        long long *group_id = utarray_eltptr(tbl_group->group_ids, i);
        struct clause_query_key key = {*group_id, vtable_id, 1};
        
        HASH_FIND(hh, compile_rt->not_clause_id_kv_hash, &key, sizeof(key), clause_id_kv);
        if (NULL == clause_id_kv) {
            continue;
        }

        compile_state_add_hit_not_clauses(compile_state, clause_id_kv->clause_ids);
        if (1 == maat_inst->opts.hit_path_on) {
            compile_state_add_internal_hit_path(compile_state, -1, *group_id,
                                                vtable_id, 1, Nth_scan);
        }
    }
}

size_t compile_state_get_indirect_hit_groups(struct compile_state *compile_state,
                                             struct maat_hit_group *group_array,
                                             size_t array_size)
{
    size_t i = 0;
    struct maat_hit_group *hit_group = NULL;
    for (i = 0; i < utarray_len(compile_state->indirect_hit_groups) && i < array_size; i++) {
        hit_group =
            (struct maat_hit_group *)utarray_eltptr(compile_state->indirect_hit_groups, i);
        group_array[i].item_id = hit_group->item_id;
        group_array[i].group_id = hit_group->group_id;
        group_array[i].vtable_id = hit_group->vtable_id;
    }

    utarray_clear(compile_state->indirect_hit_groups);

    return i;
}

size_t compile_state_get_indirect_hit_group_cnt(struct compile_state *compile_state)
{
    return utarray_len(compile_state->indirect_hit_groups);
}

size_t compile_state_get_last_hit_groups(struct compile_state *compile_state,
                                         struct maat_hit_group *group_array,
                                         size_t array_size)
{
    size_t i = 0;

    for (i = 0; i < utarray_len(compile_state->last_hit_groups) && i < array_size; i++) {
        group_array[i] =
            *(struct maat_hit_group *)utarray_eltptr(compile_state->last_hit_groups, i);
    }

    return i;
}

size_t compile_state_get_last_hit_group_cnt(struct compile_state *compile_state)
{
    return utarray_len(compile_state->last_hit_groups);
}

size_t compile_state_get_direct_hit_groups(struct compile_state *compile_state,
                                           struct maat_hit_group *group_array,
                                           size_t array_size)
{
    UT_array *direct_hit_group = compile_state->direct_hit_groups;

    size_t i = 0;
    struct maat_hit_group *group = NULL;
    for (i = 0; i < utarray_len(direct_hit_group) && i < array_size; i++) {
        group = (struct maat_hit_group *)utarray_eltptr(direct_hit_group, i);
        group_array[i].item_id = group->item_id;
        group_array[i].group_id = group->group_id;
        group_array[i].vtable_id = group->vtable_id;
    }
   
    utarray_clear(compile_state->direct_hit_groups);

    return i;
}

size_t compile_state_get_direct_hit_group_cnt(struct compile_state *compile_state)
{
    return utarray_len(compile_state->direct_hit_groups);
}

size_t compile_state_get_internal_hit_paths(struct compile_state *compile_state,
                                            struct compile_runtime *compile_rt,
                                            struct group2group_runtime *g2g_rt,
                                            struct maat_hit_path *hit_path_array, 
                                            size_t array_size)
{
    size_t hit_path_cnt = 0;
    struct internal_hit_path *internal_path = NULL;

    for (int i = 0; i < utarray_len(compile_state->internal_hit_paths); i++) {
        internal_path =
            (struct internal_hit_path *)utarray_eltptr(compile_state->internal_hit_paths, i);
        /*
            NOTE: maybe one item has been deleted, but it's item_id still exist in internal_hit_paths
        */
        long long super_group_ids[MAX_HIT_GROUP_NUM];
        UT_array *valid_super_group_ids;
        utarray_new(valid_super_group_ids, &ut_compile_group_id_icd);

        size_t super_group_cnt =
            group2group_runtime_get_super_groups(g2g_rt, &(internal_path->group_id), 1,
                                                 super_group_ids, MAX_HIT_GROUP_NUM);
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
    
        for (p = utarray_front(valid_super_group_ids);
             p != NULL && hit_path_cnt < array_size;
             p = utarray_next(valid_super_group_ids, p)) {
            memset(&tmp_path, 0, sizeof(tmp_path));
            tmp_path.Nth_scan = internal_path->Nth_scan;
            tmp_path.item_id = internal_path->item_id;
            tmp_path.sub_group_id = internal_path->group_id;
            tmp_path.top_group_id = *p;
            tmp_path.vtable_id = internal_path->vtable_id;
            tmp_path.NOT_flag = internal_path->NOT_flag;
            tmp_path.clause_index = -1;
            tmp_path.compile_id = -1;

            /* check if internal_path is duplicated from hit_path_array[]
             * element */
            if (hit_path_cnt > 0) {
                if (maat_compile_is_hit_path_existed(hit_path_array, hit_path_cnt,
                                                     &tmp_path)) {
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

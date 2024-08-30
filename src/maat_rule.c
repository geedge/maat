/*
**********************************************************************************************
*	File: maat_rule.c
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
#include "maat_rule.h"
#include "maat_garbage_collection.h"
#include "maat_object.h"
#include "maat_ex_data.h"
#include "maat_table.h"
#include "alignment.h"

#define MODULE_RULE	 module_name_str("maat.rule")

#define MAX_NOT_CONDITION_NUM   8

enum condition_negate_option {
    CONDITION_NEGATE_OPTION_UNSET = 0,
    CONDITION_NEGATE_OPTION_SET
};

struct rule_schema {
    int rule_id_column;
    int rule_tag_column;
    int declared_condition_num_column;
    int table_id;
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

struct object2rule_schema {
    int object_id_column;
    int rule_id_column;
    int negate_option_column;
    int attribute_name_column;
    int condition_index_column;
    int asso_rule_table_id; //asso is abbreviation for associated
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct rule_item {
    int declared_condition_num;
    long long rule_id;
    char *table_line;
    size_t table_line_len;
};

struct object2rule_item {
    UT_array *object_ids;
    long long rule_id;
    int negate_option;
    int attribute_id;
    int condition_index;
};

struct condition_query_key {
	long long object_id;
    int attribute_id;
    int negate_option;
};

struct condition_id_kv {
    struct condition_query_key key;
    UT_array *condition_ids;
    UT_hash_handle hh;
};

struct table_condition {
    int attribute_id;
    int actual_condition_num;
    UT_array *condition_ids;
    UT_array *object_ids;
    UT_hash_handle hh;
};

struct table_object {
    int attribute_id;
    UT_array *object_ids;
    UT_hash_handle hh;
};

/* rule_runtime and object2rule_runtime share rule_hash_map */
struct rule_runtime {
	struct bool_matcher *bm;
    struct rcu_hash_table *cfg_hash;     // <rule_id, struct maat_rule>
    struct maat_runtime *ref_maat_rt;
    struct condition_id_kv *condition_id_kv_hash;     //store condition_ids(negate_option == 0)
    struct condition_id_kv *not_condition_id_kv_hash; //store NOT_condition_ids(negate_option == 1)
    struct bool_expr_match *expr_match_buff;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
    time_t version;

    long long rule_num;
    long long update_err_cnt;
};

struct object2rule_runtime {
    long long not_condition_cnt;
    long long rule_num;
    long long update_err_cnt;
    struct rule_runtime *ref_rule_rt;
    struct table_condition *tbl_not_condition_hash; //each attribute's negate condition number <= MAX_NOT_CONDITION_NUM
};

struct condition_literal {
    long long object_ids[MAX_OBJECT_CNT];
    int object_cnt;
    int attribute_id;
};

struct rule_condition {
	long long condition_id;
    UT_array *literals; //struct condition_literal
	char negate_option;      // 1 byte
	char in_use;        // 1 byte
    char pad[6];        // for 8 bytes alignment
};

struct rule_sort_para {
	int declared_condition_num;
	long long rule_id;
};

#define MAAT_RULE_MAGIC	0x4a5b6c7d
struct maat_rule {
	uint32_t magic_num;
    int actual_condition_num;
	int declared_condition_num;
    int table_id;
    long long rule_id;
    void *user_data; // rule_item
	struct rule_condition conditions[MAX_ITEMS_PER_BOOL_EXPR];
};

struct internal_hit_path {
    long long item_id;
	long long object_id;
	int Nth_scan;
	int attribute_id;
    int negate_option; // 1 means negate condition
};

struct rule2table_id {
    long long rule_id;
    int table_id;
};

struct rule_compile_state {
	int Nth_scan;
    int this_scan_not_logic;
    time_t rule_rt_version;

	UT_array *internal_hit_paths;
	UT_array *all_hit_conditions;
	UT_array *this_scan_hit_conditions;
	UT_array *this_scan_hit_not_conditions;
    UT_array *exclude_not_conditions;
    UT_array *direct_hit_objects;
    UT_array *indirect_hit_objects;
    UT_array *last_hit_objects;
    UT_array *hit_rule_table_ids;
    struct table_object *hit_not_tbl_objects;
};

UT_icd ut_condition_id_icd = {sizeof(long long), NULL, NULL, NULL};
UT_icd ut_condition_literal_icd = {sizeof(struct condition_literal), NULL, NULL, NULL};
UT_icd ut_rule_object_id_icd = {sizeof(long long), NULL, NULL, NULL};
UT_icd ut_maat_hit_object_icd = {sizeof(struct maat_hit_object), NULL, NULL, NULL};
UT_icd ut_hit_path_icd = {sizeof(struct internal_hit_path), NULL, NULL, NULL};
UT_icd ut_hit_rule_table_id_icd = {sizeof(struct rule2table_id), NULL, NULL, NULL};

static struct maat_rule *maat_rule_new(long long rule_id)
{
	struct maat_rule *rule = ALLOC(struct maat_rule, 1);

	rule->magic_num = MAAT_RULE_MAGIC;
	rule->rule_id = rule_id;

    for(int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {	
		utarray_new(rule->conditions[i].literals, &ut_condition_literal_icd);
		rule->conditions[i].in_use = 0;
        rule->conditions[i].condition_id = 0;
	}

	return rule;
}

static int maat_rule_set(struct maat_rule *rule, int table_id,
                            int declared_condition_num, void *user_data)
{
    if (NULL == rule) {
        return -1;
    }

    rule->table_id = table_id;
    rule->declared_condition_num = declared_condition_num;
    rule->user_data = user_data;

    return 0;
}

static int rule_accept_tag_match(struct rule_schema *schema, const char *line,
                                    const char *table_name, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    if (schema->rule_tag_column > 0 && n_tag > 0) {
        int ret = get_column_pos(line, schema->rule_tag_column, 
                                 &column_offset, &column_len);
        if (ret < 0) {
            log_fatal(logger, MODULE_RULE,
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
                log_fatal(logger, MODULE_RULE,
                          "[%s:%d] table: <%s> has invalid tag format in line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_ERR;
            }

            if (TAG_MATCH_UNMATCHED == ret) {
                log_fatal(logger, MODULE_RULE,
                          "[%s:%d] table: <%s> has unmatched tag in line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_UNMATCHED;
            }
        }
    }

    return TAG_MATCH_MATCHED;
}

static struct rule_item *
rule_item_new(const char *table_line, struct rule_schema *schema,
                 const char *table_name, struct log_handle *logger)
{
    int ret = rule_accept_tag_match(schema, table_line, table_name, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    size_t column_offset = 0;
    size_t column_len = 0;
    struct rule_item *rule_item = ALLOC(struct rule_item, 1);

    ret = get_column_pos(table_line, schema->rule_id_column,
                         &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] table: <%s> has no rule_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, table_line);
        goto error;
    }
    rule_item->rule_id = atoll(table_line + column_offset);

    ret = get_column_pos(table_line, schema->declared_condition_num_column,
                         &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] table: <%s> has no condition_num in line:%s",
                  __FUNCTION__, __LINE__, table_name, table_line);
		goto error;
    }

    rule_item->declared_condition_num = atoi(table_line + column_offset);
    if (rule_item->declared_condition_num < 0 ||
        rule_item->declared_condition_num > MAX_NOT_CONDITION_NUM) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] table: <%s> condition_num:%d exceed maximum:%d in line:%s",
                  __FUNCTION__, __LINE__, table_name, rule_item->declared_condition_num,
                  MAX_NOT_CONDITION_NUM, table_line);
		goto error;
    }

    rule_item->table_line_len = strlen(table_line);
    rule_item->table_line = ALLOC(char, rule_item->table_line_len + 1);
    memcpy(rule_item->table_line, table_line, rule_item->table_line_len);

    return rule_item;
error:
    FREE(rule_item);
    return NULL;
}

static void rule_item_free(struct rule_item *item)
{
    item->declared_condition_num = 0;

    if (item->table_line != NULL) {
        FREE(item->table_line);
    }
    
    FREE(item);
}

static void maat_rule_free(struct maat_rule *rule)
{
	struct rule_condition *condition = NULL;

	if (rule->user_data != NULL) {
		rule_item_free(rule->user_data);
        rule->user_data = NULL;
	}

	for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		condition = rule->conditions + i;

        if (condition->literals != NULL) {
            utarray_free(condition->literals);
            condition->literals = NULL;
        }
		
		condition->in_use = 0;
        condition->condition_id = 0;
	}

	rule->magic_num = 0;
	FREE(rule);
}

static void rcu_rule_cfg_free(void *user_ctx, void *data)
{
    struct maat_rule *rule = (struct maat_rule *)data;
    maat_rule_free(rule);
}

void *rule_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name,
                         struct log_handle *logger)
{
	struct rule_schema *schema = ALLOC(struct rule_schema, 1);
    schema->logger = logger;

	cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no table_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

   	item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "rule_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->rule_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no rule_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "tags");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->rule_tag_column = custom_item->valueint;
    }

    custom_item = cJSON_GetObjectItem(item, "condition_num");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->declared_condition_num_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no condition_num column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    schema->ref_tbl_mgr = tbl_mgr;
	return schema;
error:
	FREE(schema);
	return NULL;
}

void rule_schema_free(void *rule_schema)
{
	FREE(rule_schema);
}

void *object2rule_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                               const char *table_name, struct log_handle *logger)
{
	struct object2rule_schema *g2c_schema = ALLOC(struct object2rule_schema, 1);

	cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        g2c_schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "associated_rule_table_id");
    if (item != NULL && item->type == cJSON_Number) {
        g2c_schema->asso_rule_table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no associated_rule_table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "object_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->object_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no object_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "rule_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->rule_id_column = custom_item->valueint;
    } else {
         log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no rule_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "negate_option");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->negate_option_column = custom_item->valueint;
    } else {
         log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no negate_option column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "attribute_name");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->attribute_name_column = custom_item->valueint;
    } else {
         log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no attribute_name column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "condition_index");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2c_schema->condition_index_column = custom_item->valueint;
    } else {
         log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no condition_index column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    g2c_schema->ref_tbl_mgr = tbl_mgr;
	return g2c_schema;
error:
	FREE(g2c_schema);
	return NULL;
}

void object2rule_schema_free(void *g2c_schema)
{
	FREE(g2c_schema);
}

int object2rule_associated_rule_table_id(void *g2c_schema)
{
    struct object2rule_schema *schema = (struct object2rule_schema *)g2c_schema;

    return schema->asso_rule_table_id;
}

#define RULE_GC_TIMEOUT_S 5
void *rule_runtime_new(void *rule_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin, 
                          struct log_handle *logger)
{
	if (NULL == rule_schema) {
        return NULL;
    }

    struct rule_runtime *rule_rt = ALLOC(struct rule_runtime, 1);

    rule_rt->expr_match_buff = ALLOC(struct bool_expr_match, 
                                        max_thread_num * MAX_HIT_RULE_NUM);
    rule_rt->version = time(NULL);
    rule_rt->cfg_hash = rcu_hash_new(rcu_rule_cfg_free, NULL, RULE_GC_TIMEOUT_S);
    rule_rt->condition_id_kv_hash = NULL;
    rule_rt->not_condition_id_kv_hash = NULL;
    rule_rt->logger = logger;
    rule_rt->ref_garbage_bin = garbage_bin;

    return rule_rt;
}

static void condition_id_kv_hash_free(struct condition_id_kv *hash)
{
    struct condition_id_kv *condition_id_kv = NULL, *tmp_condition_id_kv = NULL;

    HASH_ITER(hh, hash, condition_id_kv, tmp_condition_id_kv) {
        HASH_DEL(hash, condition_id_kv);
        if (condition_id_kv->condition_ids != NULL) {
            utarray_free(condition_id_kv->condition_ids);
            condition_id_kv->condition_ids = NULL;
        }
        
        FREE(condition_id_kv);
    }
    assert(hash == NULL);
}

static void garbage_condition_id_kv_hash_free(void *hash, void *arg)
{
    condition_id_kv_hash_free((struct condition_id_kv *)hash);
}

void rule_runtime_free(void *rule_runtime)
{
    if (NULL == rule_runtime) {
        return;
    }

    struct rule_runtime *rule_rt = (struct rule_runtime *)rule_runtime;

    if (rule_rt->bm != NULL) {
        bool_matcher_free(rule_rt->bm);
        rule_rt->bm = NULL;
    }

    if (rule_rt->cfg_hash != NULL) {
        rcu_hash_free(rule_rt->cfg_hash);
        rule_rt->cfg_hash = NULL;
    }
    
    if (rule_rt->condition_id_kv_hash != NULL) {
        condition_id_kv_hash_free(rule_rt->condition_id_kv_hash);
        rule_rt->condition_id_kv_hash = NULL;
    }

    if (rule_rt->not_condition_id_kv_hash != NULL) {
        condition_id_kv_hash_free(rule_rt->not_condition_id_kv_hash);
        rule_rt->not_condition_id_kv_hash = NULL;
    }

    if (rule_rt->expr_match_buff != NULL) {
        FREE(rule_rt->expr_match_buff);
    }

    FREE(rule_rt);
}

void rule_runtime_init(void *rule_runtime, struct maat_runtime *maat_rt)
{
    if (NULL == rule_runtime) {
        return;
    }

    struct rule_runtime *rule_rt =
        (struct rule_runtime *)rule_runtime;

    rule_rt->ref_maat_rt = maat_rt;
}

void *object2rule_runtime_new(void *g2c_schema, size_t max_thread_num,
                                struct maat_garbage_bin *garbage_bin, 
                                struct log_handle *logger)
{
    if (NULL == g2c_schema) {
        return NULL;
    }

    struct object2rule_runtime *g2c_rt =
        ALLOC(struct object2rule_runtime, 1);

    g2c_rt->tbl_not_condition_hash = NULL;

    return g2c_rt;
}

void object2rule_runtime_init(void *g2c_runtime, void *rule_runtime)
{
    struct object2rule_runtime *g2c_rt =
        (struct object2rule_runtime *)g2c_runtime;

    g2c_rt->ref_rule_rt = (struct rule_runtime *)rule_runtime;
}

void object2rule_runtime_free(void *g2c_runtime)
{
    if (NULL == g2c_runtime) {
        return;
    }

    struct object2rule_runtime *g2c_rt =
        (struct object2rule_runtime *)g2c_runtime;

    if (g2c_rt->tbl_not_condition_hash != NULL) {
        struct table_condition *not_condition = NULL, *tmp_not_condition = NULL;
        HASH_ITER(hh, g2c_rt->tbl_not_condition_hash, not_condition, tmp_not_condition) {
            HASH_DEL(g2c_rt->tbl_not_condition_hash, not_condition);
            FREE(not_condition);
        }
    }
    assert(g2c_rt->tbl_not_condition_hash == NULL);

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

static void object2rule_item_free(struct object2rule_item *g2c_item)
{
    if (NULL == g2c_item) {
        return;
    }

    if (g2c_item->object_ids != NULL) {
        utarray_free(g2c_item->object_ids);
        g2c_item->object_ids = NULL;
    }

    FREE(g2c_item);
}

static struct object2rule_item *
object2rule_item_new(const char *line, struct object2rule_schema *g2c_schema,
                       const char *table_name, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char attribute_name[MAX_NAME_STR_LEN + 1] = {0};
    struct object2rule_item *g2c_item = ALLOC(struct object2rule_item, 1);
    utarray_new(g2c_item->object_ids, &ut_rule_object_id_icd);

    int ret = get_column_pos(line, g2c_schema->object_id_column, &column_offset,
                             &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_RULE,
				  "[%s:%d] g2c table:<%s> has no object_id in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }

    char object_ids_str[MAX_OBJECT_IDS_STR_LEN] = {0};
    memcpy(object_ids_str, line + column_offset, MIN(MAX_OBJECT_IDS_STR_LEN, column_len));

    ret = ids_str2longlong_array(object_ids_str, g2c_item->object_ids);
    if (ret < 0) {
        log_fatal(logger, MODULE_RULE,
				  "[%s:%d] g2c table:<%s> object_ids str2longlong failed in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error; 
    }

    if (utarray_len(g2c_item->object_ids) > MAX_OBJECT_CNT) {
        log_fatal(logger, MODULE_RULE,
				  "[%s:%d] g2c table:<%s> object_ids exceed maximum:%d in line:%s",
				  __FUNCTION__, __LINE__, table_name, MAX_OBJECT_CNT, line);
		goto error;
    }

    ret = get_column_pos(line, g2c_schema->rule_id_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_RULE,
				  "[%s:%d] g2c table:<%s> has no rule_id in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }
    g2c_item->rule_id = atoll(line + column_offset);

    ret = get_column_pos(line, g2c_schema->negate_option_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_RULE,
				  "[%s:%d] g2c table:<%s> has no negate_option in line:%s ",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }

    g2c_item->negate_option = atoi(line + column_offset);
    if (g2c_item->negate_option != CONDITION_NEGATE_OPTION_SET && 
        g2c_item->negate_option != CONDITION_NEGATE_OPTION_UNSET) {
        log_fatal(logger, MODULE_RULE,
				  "[%s:%d] g2c table:<%s>  negate_option:%d is illegal in line:%s ",
				  __FUNCTION__, __LINE__, table_name, g2c_item->negate_option, line);
		goto error;
    }

    ret = get_column_pos(line, g2c_schema->attribute_name_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_RULE,
				  "[%s:%d] g2c table:<%s> has no attribute_name in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error;
    }

    if (column_len > MAX_NAME_STR_LEN) {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] g2c table:<%s> attribute_name length exceed "
                  "maxium:%d in line:%s", __FUNCTION__, __LINE__, table_name,
                  MAX_NAME_STR_LEN, line);
        goto error;
    }
    
    memset(attribute_name, 0, sizeof(attribute_name));
    memcpy(attribute_name, (line + column_offset), column_len);
    
    if (is_valid_table_name(attribute_name)) {
        g2c_item->attribute_id = table_manager_get_table_id(g2c_schema->ref_tbl_mgr,
                                                         attribute_name);
        if (g2c_item->attribute_id < 0) {
            log_fatal(logger, MODULE_RULE,
                      "[%s:%d] g2c table:<%s> has unknown attribute:%s in line:%s",
                      __FUNCTION__, __LINE__, table_name, attribute_name, line);
            goto error;
        }
    }
   
    ret = get_column_pos(line, g2c_schema->condition_index_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] g2c table:<%s> has no condition_index in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }

    g2c_item->condition_index = atoi(line + column_offset);
    if (g2c_item->condition_index < 0 || g2c_item->condition_index >= MAX_NOT_CONDITION_NUM) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] g2c table:<%s> condition_index:%d exceed maximum:%d in line:%s",
                  __FUNCTION__, __LINE__, table_name, g2c_item->condition_index,
                  MAX_NOT_CONDITION_NUM, line);
        goto error;
    }

    return g2c_item;

error:
    object2rule_item_free(g2c_item);
    return NULL;
}

static inline int compare_object_id(const void *a, const void *b)
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

static void rule_condition_add_literal(struct rule_condition *condition,
                                       struct object2rule_item *g2c_item)
{
    struct condition_literal tmp_literal;
    tmp_literal.attribute_id = g2c_item->attribute_id;
    tmp_literal.object_cnt = utarray_len(g2c_item->object_ids);
    utarray_sort(g2c_item->object_ids, compare_object_id);

    for (size_t i = 0; i < utarray_len(g2c_item->object_ids); i++) {
        tmp_literal.object_ids[i] = *(long long *)utarray_eltptr(g2c_item->object_ids, i);
    }
    utarray_push_back(condition->literals, &tmp_literal);
}

void rule_condition_remove_literal(struct rule_condition *condition,
                                   struct object2rule_item *g2c_item)
{
    struct condition_literal *tmp_literal = NULL;

    for (size_t i = 0; i < utarray_len(condition->literals); i++) {
        tmp_literal = (struct condition_literal *)utarray_eltptr(condition->literals, i);
        if (tmp_literal->attribute_id == g2c_item->attribute_id) {
            size_t remove_idx = utarray_eltidx(condition->literals, tmp_literal);
            utarray_erase(condition->literals, remove_idx, 1);
            break; 
        }
    } 
}

static int maat_rule_condition_find_literal(struct maat_rule *rule,
                                            struct object2rule_item *g2c_item)
{
    struct rule_condition *condition = rule->conditions + g2c_item->condition_index;
    struct condition_literal *tmp_literal = NULL;
    int found = 0;

    for (size_t i = 0; i < utarray_len(condition->literals); i++) {
        tmp_literal = (struct condition_literal *)utarray_eltptr(condition->literals, i);
        if (tmp_literal->attribute_id == g2c_item->attribute_id) {
            found = 1;
        }
    }

    return found;
}

static void maat_rule_condition_add_literal(struct maat_rule *rule,
                                            struct object2rule_item *g2c_item)
{
    struct rule_condition *condition = rule->conditions + g2c_item->condition_index;

    condition->negate_option = g2c_item->negate_option;

    if (0 == condition->in_use) {
        condition->in_use = 1;
        rule->actual_condition_num++;
    }

    rule_condition_add_literal(condition, g2c_item);
}

static void maat_rule_condition_remove_literal(struct maat_rule *rule,
                                               struct object2rule_item *g2c_item)
{
    struct rule_condition *condition = rule->conditions + g2c_item->condition_index;

    rule_condition_remove_literal(condition, g2c_item);
    if (0 == utarray_len(condition->literals)) {
        condition->in_use = 0;
        condition->condition_id = 0;
        rule->actual_condition_num--;
    }
}

static struct bool_matcher *
maat_rule_bool_matcher_new(struct rule_runtime *rule_rt,
                              size_t *rule_cnt)
{
	if (NULL == rule_rt) {
        return NULL;
    }

    size_t i = 0, j = 0, idx = 0;
    int has_condition_num = 0;

    // STEP 1, update condition_id of each rule
    void **data_array = NULL;
    struct maat_rule *iter_rule = NULL;
    *rule_cnt = rcu_updating_hash_list(rule_rt->cfg_hash, &data_array);

    for (idx = 0; idx < *rule_cnt; idx++) {
        iter_rule = (struct maat_rule *)data_array[idx];
        has_condition_num = 0;
        for (i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            struct rule_condition *condition = iter_rule->conditions + i;
            if (!condition->in_use) {
                continue;
            }

            has_condition_num++;
            if (0 == condition->condition_id) {
                condition->condition_id =
                    maat_runtime_get_sequence(rule_rt->ref_maat_rt, "condition_id");
            }
        }
        assert(has_condition_num == iter_rule->actual_condition_num);
    }

    // STEP 2, serial rule condition states to a bool expression array
    size_t expr_cnt = 0;
    struct bool_expr *bool_expr_array = ALLOC(struct bool_expr, *rule_cnt);

    for (idx = 0; idx < *rule_cnt; idx++) {
        iter_rule = (struct maat_rule *)data_array[idx];
        for (i = 0, j = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            if (iter_rule->conditions[i].in_use) {
                bool_expr_array[expr_cnt].items[j].item_id = iter_rule->conditions[i].condition_id;
                bool_expr_array[expr_cnt].items[j].negate_option = 0;
                j++;
            }
        }

        // some rule may have zero objects, e.g. default policy.
        if (j == (size_t)iter_rule->declared_condition_num && j > 0) {
            bool_expr_array[expr_cnt].expr_id = iter_rule->rule_id;
            bool_expr_array[expr_cnt].user_tag = iter_rule;
            bool_expr_array[expr_cnt].item_num = j;
            expr_cnt++;
        }
    }

    FREE(data_array);

    // STEP 3, build bool matcher
    size_t mem_size = 0;
    if (0 == expr_cnt) {
        log_fatal(rule_rt->logger, MODULE_RULE,
                  "[%s:%d] No bool expression to build bool matcher.",
                  __FUNCTION__, __LINE__);
        FREE(bool_expr_array);
        return NULL;
    }

    struct bool_matcher *bm = bool_matcher_new(bool_expr_array, expr_cnt, &mem_size);
    if (bm != NULL) {
        log_info(rule_rt->logger, MODULE_RULE,
                 "Build bool matcher of %zu expressions with %zu bytes memory.",
                 expr_cnt, mem_size);
    } else {
        log_fatal(rule_rt->logger, MODULE_RULE,
                  "[%s:%d] Build bool matcher failed!", __FUNCTION__, __LINE__);
    }

    FREE(bool_expr_array);
    return bm;
}

static inline int compare_condition_id(const void *a, const void *b)
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

static inline int compare_hit_object(const void *pa, const void *pb)
{
	struct maat_hit_object *la=(struct maat_hit_object *)pa;
	struct maat_hit_object *lb=(struct maat_hit_object *)pb;

	long long ret = la->item_id - lb->item_id;
	if (0 == ret) {
		ret = la->object_id - lb->object_id;
        if (0 == ret) {
            ret = la->attribute_id - lb->attribute_id;
        }
	}

	return ret;
}

static inline int compare_rule_id(const void *a, const void *b)
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
 * @brief build <condition_query_key, condition_id_array> hash for condition or not_condition
 * 
 * @param rule_rt: rule runtime handle
 * @param negate_option: specify whether to build condition or NOT_condition hash for rule runtime
 *                  0 -> condition hash
 *                  1 -> NOT_condition hash
 * 
 * @retval generated condition_id_kv_hash
*/
static struct condition_id_kv *
build_condition_id_kv_hash(struct rule_runtime *rule_rt, int negate_option)
{
    if (NULL == rule_rt) {
        return NULL;
    }

    void **data_array = NULL;
    struct condition_id_kv *condition_id_kv_hash = NULL;
    size_t rule_cnt = rcu_updating_hash_list(rule_rt->cfg_hash, &data_array);

    for (size_t idx = 0; idx < rule_cnt; idx++) {
        struct maat_rule *rule = (struct maat_rule *)data_array[idx];
        for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            struct rule_condition *condition = rule->conditions + i;
            if (!condition->in_use) {
                continue;
            }

            if (0 == negate_option) {
                if (CONDITION_NEGATE_OPTION_SET == condition->negate_option) {
                    continue;
                }
            } else {
                if (CONDITION_NEGATE_OPTION_UNSET == condition->negate_option) {
                    continue;
                }
            }

            struct condition_literal *tmp_cl = NULL;
            for (size_t j = 0; j < utarray_len(condition->literals); j++) {
                tmp_cl = (struct condition_literal *)utarray_eltptr(condition->literals, j);

                for (size_t k = 0; k < tmp_cl->object_cnt; k++) {
                    struct condition_query_key key =
                        {tmp_cl->object_ids[k], tmp_cl->attribute_id, condition->negate_option};
                    struct condition_id_kv *condition_id_kv = NULL;
                    
                    HASH_FIND(hh, condition_id_kv_hash, &key, sizeof(struct condition_query_key),
                              condition_id_kv);
                    if (NULL == condition_id_kv) {
                        condition_id_kv = ALLOC(struct condition_id_kv, 1);
                        condition_id_kv->key = key;
                        utarray_new(condition_id_kv->condition_ids, &ut_condition_id_icd);
                        HASH_ADD_KEYPTR(hh, condition_id_kv_hash, &condition_id_kv->key,
                                        sizeof(condition_id_kv->key), condition_id_kv);
                    }

                    if (utarray_find(condition_id_kv->condition_ids, &(condition->condition_id),
                                     compare_condition_id)) {
                        continue;
                    }
                    utarray_push_back(condition_id_kv->condition_ids, &(condition->condition_id));
                    utarray_sort(condition_id_kv->condition_ids, compare_condition_id);
                }
            }
        }
    }

    FREE(data_array);
    return condition_id_kv_hash;
}

static int
maat_rule_has_condition(struct maat_rule *rule, long long condition_id)
{
	struct rule_condition *condition = NULL;

	for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		condition = rule->conditions + i;
		if (!condition->in_use) {
			continue;
		}

		if (condition->condition_id == condition_id) {
			return 1;
		}
	}

	return 0;
}

static size_t
rule_compile_state_if_new_hit_rule(struct rule_compile_state *rule_compile_state,
                                 struct maat_rule *rule)
{
    size_t i = 0;
	size_t r_in_c_cnt = 0;
	int ret = 0;

	long long new_hit_condition_id = 0;
    if (0 == rule_compile_state->this_scan_not_logic) {
        for (i = 0; i < utarray_len(rule_compile_state->this_scan_hit_conditions); i++) {
		    new_hit_condition_id =
                *(long long*)utarray_eltptr(rule_compile_state->this_scan_hit_conditions, i);
		    ret = maat_rule_has_condition(rule, new_hit_condition_id);
		    if (ret) {
			    r_in_c_cnt++;
		    }
	    }
    } else {
        for (i = 0; i < utarray_len(rule_compile_state->this_scan_hit_not_conditions); i++) {
		    new_hit_condition_id =
                *(long long*)utarray_eltptr(rule_compile_state->this_scan_hit_not_conditions, i);
		    ret = maat_rule_has_condition(rule, new_hit_condition_id);
		    if (ret) {
			    r_in_c_cnt++;
		    }
	    }
    }

	return r_in_c_cnt;
}

static void
rule_compile_state_update_hit_rule_table_id(struct rule_compile_state *rule_compile_state,
                                          long long rule_id, int table_id)
{
    if (!utarray_find(rule_compile_state->hit_rule_table_ids, &rule_id,
                      compare_rule_id)) {
        struct rule2table_id rule_table_id = {rule_id, table_id};
        utarray_push_back(rule_compile_state->hit_rule_table_ids, &rule_table_id);
        utarray_sort(rule_compile_state->hit_rule_table_ids, compare_rule_id);
    }
}

static size_t
maat_rule_bool_matcher_match(struct rule_runtime *rule_rt,
                                struct rule_compile_state *rule_compile_state,
                                int thread_id, void **user_data_array,
                                size_t ud_array_size)
{
    size_t ud_result_cnt = 0;
	struct maat_rule *rule = NULL;
	struct bool_expr_match *expr_match = rule_rt->expr_match_buff +
                                         (thread_id * MAX_HIT_RULE_NUM);
    assert(thread_id >= 0);

    if (0 == rule_compile_state->rule_rt_version) {
        rule_compile_state->rule_rt_version = rule_rt->version;
    }

    if (NULL == rule_rt->bm ||
        0 == utarray_len(rule_compile_state->all_hit_conditions) ||
        rule_compile_state->rule_rt_version != rule_rt->version) {
        return 0;
    }
	
	int bool_match_ret =
        bool_matcher_match(rule_rt->bm, 
                          (unsigned long long *)utarray_eltptr(rule_compile_state->all_hit_conditions, 0),
						  utarray_len(rule_compile_state->all_hit_conditions), 
                          expr_match, MAX_HIT_RULE_NUM);
	for (int i = 0; i < bool_match_ret && ud_result_cnt < ud_array_size; i++) {
		rule = (struct maat_rule *)expr_match[i].user_tag;
		assert(rule->magic_num == MAAT_RULE_MAGIC);
		assert((unsigned long long)rule->rule_id == expr_match[i].expr_id);
		if (0 == rule->actual_condition_num) {
			continue;
		}

        size_t n_new_hit_rule =
            rule_compile_state_if_new_hit_rule(rule_compile_state, rule);

        if (rule->user_data != NULL && n_new_hit_rule > 0) {
            user_data_array[ud_result_cnt] = rule->user_data;
			ud_result_cnt++;
            rule_compile_state_update_hit_rule_table_id(rule_compile_state, rule->rule_id,
                                                      rule->table_id);
        }
	}

	return ud_result_cnt;
}

static struct rule_item *rule_item_clone(struct rule_item *item)
{
    struct rule_item *new_item = ALLOC(struct rule_item, 1);

    new_item->rule_id = item->rule_id;
    new_item->declared_condition_num = item->declared_condition_num;
    new_item->table_line_len = item->table_line_len;
    new_item->table_line = ALLOC(char, new_item->table_line_len + 1);
    memcpy(new_item->table_line, item->table_line, new_item->table_line_len);

    return new_item;
}

static struct maat_rule *
maat_rule_clone(struct maat_rule *rule, int deep_copy)
{
    struct maat_rule *new_rule = ALLOC(struct maat_rule, 1);

    new_rule->magic_num = rule->magic_num;
    new_rule->rule_id = rule->rule_id;
    new_rule->actual_condition_num = rule->actual_condition_num;
    new_rule->declared_condition_num = rule->declared_condition_num;
    if (1 == deep_copy && rule->user_data != NULL) {
        new_rule->user_data =
            rule_item_clone((struct rule_item *)rule->user_data);
    }

    struct condition_literal *tmp_literal = NULL;
    for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
        new_rule->conditions[i].condition_id = rule->conditions[i].condition_id;
        new_rule->conditions[i].in_use = rule->conditions[i].in_use;
        new_rule->conditions[i].negate_option = rule->conditions[i].negate_option;
        utarray_new(new_rule->conditions[i].literals, &ut_condition_literal_icd);
        for (size_t j = 0; j < utarray_len(rule->conditions[i].literals); j++) {
            tmp_literal =
                (struct condition_literal *)utarray_eltptr(rule->conditions[i].literals, j);
            utarray_push_back(new_rule->conditions[i].literals, tmp_literal);
        }
    }

    return new_rule;
}

static int maat_add_object_to_rule(struct rcu_hash_table *hash_tbl,
                                      struct object2rule_item *g2c_item,
                                      struct log_handle *logger)
{
	int ret = 0;
    long long rule_id = g2c_item->rule_id;
    struct maat_rule *rule = NULL;

    int updating_flag = rcu_hash_is_updating(hash_tbl);
    if (1 == updating_flag) {
        rule = rcu_updating_hash_find(hash_tbl, (char *)&rule_id, sizeof(long long));
        if (rule != NULL) {
            ret = maat_rule_condition_find_literal(rule, g2c_item);
            if (ret > 0) {
                log_fatal(logger, MODULE_RULE,
                          "[%s:%d]rule:%lld condition(index:%d) already has attribute_id:%d's "
                          "literal, can't add again", __FUNCTION__, __LINE__, rule->rule_id,
                          g2c_item->condition_index, g2c_item->attribute_id);
                return -1;
            }
            /* rule found in updating hash(added by rule runtime), it can
             * be modified directly */
            maat_rule_condition_add_literal(rule, g2c_item);
        } else {
            /* rule neither in effective hash nor in updating hash, so new one */
            rule = maat_rule_new(rule_id);
            assert(rule != NULL);

            maat_rule_condition_add_literal(rule, g2c_item);
            rcu_hash_add(hash_tbl, (char *)&rule_id, sizeof(long long), rule);
        }
    } else {
        rule = rcu_hash_find(hash_tbl, (char *)&rule_id, sizeof(long long));
        if (rule != NULL) {
            /*******************************************************************
                rule found in effective hash(added by rule runtime), which means

                1. rcu_hash_add(hash_tbl, rule)  ==> finished
                2. rcu_hash_commit(hash_tbl)        ==> finished

                can only be deleted but not modified
                before delete it, we need to make a copy for further use
            *********************************************************************/
            ret = maat_rule_condition_find_literal(rule, g2c_item);
            if (ret > 0) {
                log_fatal(logger, MODULE_RULE,
                          "[%s:%d]rule:%lld condition(index:%d) already has attribute_id:%d's "
                          "literal, can't add again", __FUNCTION__, __LINE__, rule->rule_id,
                          g2c_item->condition_index, g2c_item->attribute_id);
                return -1;
            }

            struct maat_rule *copy_rule = maat_rule_clone(rule, 1);
            assert(copy_rule != NULL);

            /* delete rule from rcu hash */
            rcu_hash_del(hash_tbl, (char *)&rule_id, sizeof(long long));

            maat_rule_condition_add_literal(copy_rule, g2c_item);
            rcu_hash_add(hash_tbl, (char *)&rule_id, sizeof(long long), copy_rule);
        } else {
            rule = maat_rule_new(rule_id);
            assert(rule != NULL);

            maat_rule_condition_add_literal(rule, g2c_item);
            rcu_hash_add(hash_tbl, (char *)&rule_id, sizeof(long long), rule);
        }
    }

    return 0;
}

static int maat_remove_object_from_rule(struct rcu_hash_table *hash_tbl,
                                           struct object2rule_item *g2c_item,
                                           struct log_handle *logger)
{
	int ret = 0;
    long long rule_id = g2c_item->rule_id;
    struct maat_rule *rule = NULL;

    int updating_flag = rcu_hash_is_updating(hash_tbl);
    if (1 == updating_flag) {
        rule = rcu_updating_hash_find(hash_tbl, (char *)&rule_id,
                                         sizeof(long long));
        if (NULL == rule) {
            log_fatal(logger, MODULE_RULE,
                      "[%s:%d] Remove condition(index:%d) from rule %lld failed,"
                      "rule not existed.", __FUNCTION__, __LINE__,
                      g2c_item->condition_index, rule_id);
            return -1;
        } else {
            ret = maat_rule_condition_find_literal(rule, g2c_item);
            if (0 == ret) {
                log_fatal(logger, MODULE_RULE,
                          "[%s:%d]rule:%lld condition(index:%d) has no attribute_id:%d's "
                          "literal, can't be removed", __FUNCTION__, __LINE__,
                          rule->rule_id, g2c_item->condition_index, g2c_item->attribute_id);
                return -1;
            }

            /* rule found in updating hash, it can be modified directly */
            maat_rule_condition_remove_literal(rule, g2c_item);
            if (0 == rule->actual_condition_num && NULL == rule->user_data) {
                rcu_hash_del(hash_tbl, (char *)&rule_id, sizeof(long long));
            } 
        }
    } else {
        //find in effetive hash
        rule = rcu_hash_find(hash_tbl, (char *)&rule_id, sizeof(long long));
        if (rule != NULL) {
            ret = maat_rule_condition_find_literal(rule, g2c_item);
            if (0 == ret) {
                log_fatal(logger, MODULE_RULE,
                          "[%s:%d]rule:%lld condition(index:%d) has no attribute_id:%d's "
                          "literal, can't be removed", __FUNCTION__, __LINE__,
                          rule->rule_id, g2c_item->condition_index, g2c_item->attribute_id);
                return -1;
            }

            /*******************************************************************
                rule found in effective hash, which means

                1. rcu_hash_add(hash_tbl, rule)  ==> finished
                2. rcu_hash_commit(hash_tbl)        ==> finished

                can only be deleted but not modified
                before delete it, we need to make a copy for further use
            *********************************************************************/
            struct maat_rule *copy_rule = maat_rule_clone(rule, 1);
            assert(copy_rule != NULL);

            /* delete rule from rcu hash */
            rcu_hash_del(hash_tbl, (char *)&rule_id, sizeof(long long));
            maat_rule_condition_remove_literal(copy_rule, g2c_item);

            if (0 == copy_rule->actual_condition_num && NULL == copy_rule->user_data) {
                maat_rule_free(copy_rule);
            } else {
                rcu_hash_add(hash_tbl, (char *)&rule_id, sizeof(long long), copy_rule);
            }
        } else {
            log_fatal(logger, MODULE_RULE,
                      "[%s:%d] Remove condition(index:%d) from rule_id %lld failed,"
                      "rule is not existed.", __FUNCTION__, __LINE__, 
                      g2c_item->condition_index, rule_id);
            return -1;
        }
    }

    return 0;
}

struct rule_compile_state *rule_compile_state_new(void)
{
    struct rule_compile_state *rule_compile_state = ALLOC(struct rule_compile_state, 1);

	utarray_new(rule_compile_state->internal_hit_paths, &ut_hit_path_icd);
	utarray_new(rule_compile_state->all_hit_conditions, &ut_condition_id_icd);
	utarray_new(rule_compile_state->this_scan_hit_conditions, &ut_condition_id_icd);
	utarray_new(rule_compile_state->this_scan_hit_not_conditions, &ut_condition_id_icd);
    utarray_new(rule_compile_state->exclude_not_conditions, &ut_condition_id_icd);
    utarray_new(rule_compile_state->direct_hit_objects, &ut_maat_hit_object_icd);
    utarray_new(rule_compile_state->indirect_hit_objects, &ut_maat_hit_object_icd);
    utarray_new(rule_compile_state->last_hit_objects, &ut_maat_hit_object_icd);
    utarray_new(rule_compile_state->hit_rule_table_ids, &ut_hit_rule_table_id_icd);
    rule_compile_state->hit_not_tbl_objects = NULL;

	return rule_compile_state;
}

static long long
rule_compile_state_hit_not_tbl_objects_free(struct rule_compile_state *rule_compile_state)
{
    if (NULL == rule_compile_state) {
        return 0;
    }

    long long free_bytes = 0;
    struct table_object *tbl_object = NULL, *tmp_tbl_object = NULL;
    HASH_ITER(hh, rule_compile_state->hit_not_tbl_objects, tbl_object, tmp_tbl_object) {
        free_bytes +=
            (sizeof(tbl_object) + utarray_len(tbl_object->object_ids) * sizeof(long long));
        HASH_DEL(rule_compile_state->hit_not_tbl_objects, tbl_object);
        if (tbl_object->object_ids != NULL) {
            utarray_free(tbl_object->object_ids);
            tbl_object->object_ids = NULL;
        }
        FREE(tbl_object);
    }

    return free_bytes;
}

void rule_compile_state_reset(struct rule_compile_state *rule_compile_state)
{
    if (NULL == rule_compile_state) {
        return;
    }

    rule_compile_state->this_scan_not_logic = 0;
    rule_compile_state->Nth_scan = 0;
    rule_compile_state->rule_rt_version = 0;

    utarray_clear(rule_compile_state->internal_hit_paths);
    utarray_clear(rule_compile_state->all_hit_conditions);
    utarray_clear(rule_compile_state->this_scan_hit_conditions);
    utarray_clear(rule_compile_state->this_scan_hit_not_conditions);
    utarray_clear(rule_compile_state->exclude_not_conditions);
    utarray_clear(rule_compile_state->direct_hit_objects);
    utarray_clear(rule_compile_state->indirect_hit_objects);
    utarray_clear(rule_compile_state->last_hit_objects);
    utarray_clear(rule_compile_state->hit_rule_table_ids);

    struct table_object *tbl_object = NULL, *tmp_tbl_object = NULL;
    HASH_ITER(hh, rule_compile_state->hit_not_tbl_objects, tbl_object, tmp_tbl_object) {
        utarray_clear(tbl_object->object_ids);
    }
}

void rule_compile_state_free(struct rule_compile_state *rule_compile_state,
                        struct maat *maat_inst, int thread_id)
{
    if (NULL == rule_compile_state) {
        return;
    }
    
    long long free_bytes = 0;
    if (rule_compile_state->internal_hit_paths != NULL) {
        free_bytes += utarray_size(rule_compile_state->internal_hit_paths) * 
                      sizeof(struct internal_hit_path);
        utarray_free(rule_compile_state->internal_hit_paths);
        rule_compile_state->internal_hit_paths = NULL;
    }
    
    if (rule_compile_state->all_hit_conditions != NULL) {
        free_bytes += utarray_size(rule_compile_state->all_hit_conditions) *
                      sizeof(long long);
        utarray_free(rule_compile_state->all_hit_conditions);
        rule_compile_state->all_hit_conditions = NULL;
    }
	
    if (rule_compile_state->this_scan_hit_conditions != NULL) {
        free_bytes += utarray_size(rule_compile_state->this_scan_hit_conditions) *
                      sizeof(long long);
        utarray_free(rule_compile_state->this_scan_hit_conditions);
        rule_compile_state->this_scan_hit_conditions = NULL;
    }
	
    if (rule_compile_state->this_scan_hit_not_conditions != NULL) {
        free_bytes += utarray_size(rule_compile_state->this_scan_hit_not_conditions) *
                      sizeof(long long);
        utarray_free(rule_compile_state->this_scan_hit_not_conditions);
        rule_compile_state->this_scan_hit_not_conditions = NULL;
    }

    if (rule_compile_state->exclude_not_conditions != NULL) {
        free_bytes += utarray_size(rule_compile_state->exclude_not_conditions) *
                      sizeof(long long);
        utarray_free(rule_compile_state->exclude_not_conditions);
        rule_compile_state->exclude_not_conditions = NULL;
    }

    if (rule_compile_state->direct_hit_objects != NULL) {
        free_bytes += utarray_size(rule_compile_state->direct_hit_objects) *
                      sizeof(struct maat_hit_object);
        utarray_free(rule_compile_state->direct_hit_objects);
        rule_compile_state->direct_hit_objects = NULL;
    }

    if (rule_compile_state->indirect_hit_objects != NULL) {
        free_bytes += utarray_size(rule_compile_state->indirect_hit_objects) *
                      sizeof(struct maat_hit_object);
        utarray_free(rule_compile_state->indirect_hit_objects);
        rule_compile_state->indirect_hit_objects = NULL;
    }

    if (rule_compile_state->last_hit_objects != NULL) {
        free_bytes += utarray_size(rule_compile_state->last_hit_objects) *
                      sizeof(struct maat_hit_object);
        utarray_free(rule_compile_state->last_hit_objects);
        rule_compile_state->last_hit_objects = NULL;
    }

    if (rule_compile_state->hit_rule_table_ids != NULL) {
        free_bytes += utarray_size(rule_compile_state->hit_rule_table_ids) *
                      sizeof(struct rule2table_id);
        utarray_free(rule_compile_state->hit_rule_table_ids);
        rule_compile_state->hit_rule_table_ids = NULL;
    }

    free_bytes += rule_compile_state_hit_not_tbl_objects_free(rule_compile_state);

	FREE(rule_compile_state);

    free_bytes += sizeof(struct rule_compile_state);
    alignment_int64_array_add(maat_inst->stat->maat_state_free_bytes,
                              thread_id, free_bytes);
}

static void
rule_compile_state_add_internal_hit_path(struct rule_compile_state *rule_compile_state,
                                    long long item_id, long long object_id,
                                    int attribute_id, int negate_option, int Nth_scan)
{
    if (NULL == rule_compile_state) {
        return;
    }

	struct internal_hit_path new_path;
	new_path.item_id = item_id;
	new_path.Nth_scan = Nth_scan;
	new_path.object_id = object_id;
	new_path.attribute_id = attribute_id;
    new_path.negate_option = negate_option;

	utarray_push_back(rule_compile_state->internal_hit_paths, &new_path);
}

static int maat_rule_has_condition_query_key(struct maat_rule *rule,
                                             struct condition_query_key *key)
{
	for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		struct rule_condition *condition = rule->conditions+i;
		if(!condition->in_use) {
			continue;
		}

        struct condition_literal *tmp_cl = NULL;
        for (size_t j = 0; j < utarray_len(condition->literals); j++) {
            tmp_cl = (struct condition_literal *)utarray_eltptr(condition->literals, j);
            if (tmp_cl->attribute_id != key->attribute_id) {
                continue;
            }

            if (condition->negate_option != key->negate_option) {
                continue;
            }

            long long *tmp_object_id = bsearch(&(key->object_id), tmp_cl->object_ids,
                                              tmp_cl->object_cnt, sizeof(long long),
                                              compare_object_id);
            if (tmp_object_id != NULL) {
                return 1;
            }
        }
	}

	return 0;
}

static size_t
maat_rule_get_hit_condition_index(struct maat_rule *rule, 
                                  int attribute_id, long long hit_object_id,
                                  int *condition_idx_array, size_t array_size)
{
    size_t hit_condition_cnt = 0;
    struct rule_condition *tmp_condition = NULL;

    for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
        tmp_condition = &rule->conditions[i];
        if (!tmp_condition->in_use) {
            continue;
        }

        struct condition_literal *tmp_cl = NULL;
        for (size_t j = 0; j < utarray_len(tmp_condition->literals); j++) {
            tmp_cl = (struct condition_literal *)utarray_eltptr(tmp_condition->literals, j);
            if (tmp_cl->attribute_id != attribute_id) {
                continue;
            }

            long long *tmp_object_id = bsearch(&hit_object_id, tmp_cl->object_ids,
                                              tmp_cl->object_cnt, sizeof(long long),
                                              compare_object_id);
            if (tmp_object_id != NULL) {
                condition_idx_array[hit_condition_cnt++] = i;
                break;
            }
        }
    }

    return hit_condition_cnt;
}

static int
maat_rule_is_hit_path_existed(const struct maat_hit_path *hit_paths,
                                 size_t n_path, const struct maat_hit_path *find)
{
	for (size_t i = 0; i < n_path; i++) {
		if (0 == memcmp(hit_paths + i, find, sizeof(*find))) {
			return 1;
		}
	}

	return 0;
}

void populate_hit_path_with_rule(struct maat_hit_path *hit_path_array,
                                    size_t array_idx, size_t n_hit_path,
                                    size_t *n_new_hit_path,
                                    struct maat_rule *rule)
{
    size_t i = 0;
    size_t idx = array_idx;
    size_t n_condition_index = 0;
    size_t new_hit_path_cnt = *n_new_hit_path;
    int condition_index_array[MAX_ITEMS_PER_BOOL_EXPR] = {0};

    if (hit_path_array[idx].top_object_id < 0) {
        hit_path_array[idx].top_object_id = hit_path_array[idx].sub_object_id;
    }

    struct maat_hit_path tmp_path;
    if (hit_path_array[idx].rule_id < 0) {
        hit_path_array[idx].rule_id = rule->rule_id;
        // find out which condition in rule hit
        n_condition_index =
            maat_rule_get_hit_condition_index(rule, hit_path_array[idx].attribute_id,
                                              hit_path_array[idx].top_object_id,
                                              condition_index_array,
                                              MAX_ITEMS_PER_BOOL_EXPR);
        hit_path_array[idx].condition_index = condition_index_array[0];
        if (n_condition_index > 1) {
            for (i = 1; i < n_condition_index; i++) {
                tmp_path = hit_path_array[idx];
                tmp_path.condition_index = condition_index_array[i];
                hit_path_array[n_hit_path + new_hit_path_cnt] = tmp_path;
                new_hit_path_cnt++;
            }
        }
    } else {
        // means same condition_query_id hit more than one rule_id
        tmp_path = hit_path_array[idx];
        tmp_path.rule_id = rule->rule_id;
        if (!maat_rule_is_hit_path_existed(hit_path_array, n_hit_path + new_hit_path_cnt, &tmp_path)) {
            hit_path_array[n_hit_path + new_hit_path_cnt] = tmp_path;
            new_hit_path_cnt++;
            n_condition_index =
                maat_rule_get_hit_condition_index(rule, tmp_path.attribute_id, tmp_path.top_object_id,
                                                  condition_index_array, MAX_ITEMS_PER_BOOL_EXPR);
            hit_path_array[n_hit_path + new_hit_path_cnt - 1].condition_index = condition_index_array[0];
            if (n_condition_index > 1) {
                for (i = 1; i < n_condition_index; i++) {
                    tmp_path = hit_path_array[n_hit_path + new_hit_path_cnt - 1];
                    tmp_path.condition_index = condition_index_array[i];
                    hit_path_array[n_hit_path + new_hit_path_cnt] = tmp_path;
                    new_hit_path_cnt++;
                }
            }
        }
    }

    *n_new_hit_path = new_hit_path_cnt;
}

size_t rule_runtime_get_hit_paths(struct rule_runtime *rule_rt, int thread_id,
									 struct rule_compile_state *rule_compile_state, 
                                  	 struct maat_hit_path *hit_path_array, 
                                     size_t array_size, size_t n_hit_path)
{
    /* assign hit_path_array[].rule_id */
    size_t n_new_hit_path = 0;
    struct maat_rule *rule = NULL;
    struct condition_query_key key = {0, 0, 0};
    struct bool_expr_match *expr_match = rule_rt->expr_match_buff + 
                                         (thread_id * MAX_HIT_RULE_NUM);
    assert(thread_id >= 0);

    if (rule_compile_state->rule_rt_version != rule_rt->version) {
        return 0;
    }

    int bool_match_ret =
        bool_matcher_match(rule_rt->bm, 
                          (unsigned long long *)utarray_eltptr(rule_compile_state->all_hit_conditions, 0),
						  utarray_len(rule_compile_state->all_hit_conditions), expr_match, MAX_HIT_RULE_NUM);

	for (int idx = 0; idx < bool_match_ret; idx++) {
        rule = (struct maat_rule *)expr_match[idx].user_tag;
		assert(rule->magic_num == MAAT_RULE_MAGIC);
		assert((unsigned long long)rule->rule_id == expr_match[idx].expr_id);
		if (0 == rule->actual_condition_num || NULL == rule->user_data) {
			continue;
		}

        for (size_t j = 0; j < n_hit_path && (n_hit_path + n_new_hit_path) < array_size; j++) {
			if (hit_path_array[j].top_object_id < 0) {
                key.object_id = hit_path_array[j].sub_object_id;
			} else {
                key.object_id = hit_path_array[j].top_object_id;
            }

			key.attribute_id = hit_path_array[j].attribute_id;
            key.negate_option = hit_path_array[j].negate_option;
			if (maat_rule_has_condition_query_key(rule, &key)) {
                populate_hit_path_with_rule(hit_path_array, j, n_hit_path,
                                               &n_new_hit_path, rule);
			}
		}
	}

    return (n_hit_path + n_new_hit_path);
}

static void
rule_compile_state_add_direct_hit_objects(struct rule_compile_state *rule_compile_state,
                                    struct maat_item *hit_items,
                                    size_t n_hit_items, int attribute_id)
{
    if (NULL == rule_compile_state || NULL == hit_items) {
        return;
    }

    struct maat_hit_object hit_object;
    for (size_t i = 0; i < n_hit_items; i++) {
        hit_object.item_id = hit_items[i].item_id;
        hit_object.object_id = hit_items[i].object_id;
        hit_object.attribute_id = attribute_id;
        utarray_push_back(rule_compile_state->direct_hit_objects, &hit_object);
    }
}

static void
rule_compile_state_add_indirect_hit_objects(struct rule_compile_state *rule_compile_state,
                                      long long *object_ids,
                                      size_t n_object_ids, int attribute_id)
{
    if (NULL == rule_compile_state || NULL == object_ids) {
        return;
    }

    struct maat_hit_object hit_object;
    for (size_t i = 0; i < n_object_ids; i++) {
        hit_object.item_id = 0;
        hit_object.object_id = object_ids[i];
        hit_object.attribute_id = attribute_id;
        utarray_push_back(rule_compile_state->indirect_hit_objects, &hit_object);
    }
}

static void
rule_compile_state_add_hit_conditions(struct rule_compile_state *rule_compile_state,
                              UT_array *condition_id_array)
{
    size_t i = 0;
    long long *condition_id = NULL;
    size_t new_condition_idx = utarray_len(rule_compile_state->this_scan_hit_conditions);

    for (i = 0; i < utarray_len(condition_id_array); i++) {
        condition_id = (long long *)utarray_eltptr(condition_id_array, i);
        if (utarray_find(rule_compile_state->all_hit_conditions, condition_id, compare_condition_id)) {
            continue;
        }
        utarray_push_back(rule_compile_state->this_scan_hit_conditions, condition_id);
    }

    if ((utarray_len(rule_compile_state->this_scan_hit_conditions) - new_condition_idx) > 0) {
        utarray_reserve(rule_compile_state->all_hit_conditions,
                        utarray_len(rule_compile_state->this_scan_hit_conditions) - new_condition_idx);

        for (i = new_condition_idx; i < utarray_len(rule_compile_state->this_scan_hit_conditions); i++) {
            condition_id = (long long *)utarray_eltptr(rule_compile_state->this_scan_hit_conditions, i);
            utarray_push_back(rule_compile_state->all_hit_conditions, condition_id);
        }
        utarray_sort(rule_compile_state->all_hit_conditions, compare_condition_id);
    }
}

static void
rule_compile_state_add_exclude_not_conditions(struct rule_compile_state *rule_compile_state,
                                      UT_array *condition_id_array)
{
    for (size_t i = 0; i < utarray_len(condition_id_array); i++) {
        long long *condition_id = (long long *)utarray_eltptr(condition_id_array, i);
        if (utarray_find(rule_compile_state->exclude_not_conditions, condition_id,
                         compare_condition_id)) {
            continue;
        }
        utarray_push_back(rule_compile_state->exclude_not_conditions, condition_id);
    }
    utarray_sort(rule_compile_state->exclude_not_conditions, compare_condition_id);
}

static void
rule_compile_state_add_hit_not_conditions(struct rule_compile_state *rule_compile_state,
                                  UT_array *condition_id_array)
{
    size_t i = 0;
    long long *condition_id = NULL;
    size_t new_condition_idx = utarray_len(rule_compile_state->this_scan_hit_not_conditions);

    for (i = 0; i < utarray_len(condition_id_array); i++) {
        condition_id = (long long *)utarray_eltptr(condition_id_array, i);
        if (utarray_find(rule_compile_state->all_hit_conditions, condition_id, compare_condition_id)) {
            continue;
        }

        if (utarray_find(rule_compile_state->exclude_not_conditions, condition_id, compare_condition_id)) {
            continue;
        }

        utarray_push_back(rule_compile_state->this_scan_hit_not_conditions, condition_id);
    }

    if ((utarray_len(rule_compile_state->this_scan_hit_not_conditions) - new_condition_idx) > 0) {
        utarray_reserve(rule_compile_state->all_hit_conditions,
                        utarray_len(rule_compile_state->this_scan_hit_not_conditions) - new_condition_idx);

        for (i = new_condition_idx; i < utarray_len(rule_compile_state->this_scan_hit_not_conditions); i++) {
            condition_id = (long long *)utarray_eltptr(rule_compile_state->this_scan_hit_not_conditions, i);
            utarray_push_back(rule_compile_state->all_hit_conditions, condition_id);
        }
        utarray_sort(rule_compile_state->all_hit_conditions, compare_condition_id);
    }
}

static void
rule_compile_state_update_hit_conditions(struct rule_compile_state *rule_compile_state,
                                 struct rule_runtime *rule_rt,
                                 long long object_id, int attribute_id)
{
    if (NULL == rule_compile_state || NULL == rule_rt) {
        return;
    }

    struct condition_query_key key = {object_id, attribute_id, 0};
    struct condition_id_kv *condition_id_kv = NULL;

    HASH_FIND(hh, rule_rt->condition_id_kv_hash, &key, sizeof(key), condition_id_kv);
    if (condition_id_kv != NULL) {
        rule_compile_state_add_hit_conditions(rule_compile_state, condition_id_kv->condition_ids);
    }

    key.negate_option = 1;
    HASH_FIND(hh, rule_rt->not_condition_id_kv_hash, &key, sizeof(key), condition_id_kv);
    if (condition_id_kv != NULL) {
        rule_compile_state_add_exclude_not_conditions(rule_compile_state, condition_id_kv->condition_ids);
    }
}

static void
rule_compile_state_cache_hit_not_objects(struct rule_compile_state *rule_compile_state,
                                   struct rule_runtime *rule_rt,
                                   long long *hit_object_ids,
                                   size_t n_hit_object_id, int attribute_id)
{
    if (NULL == rule_compile_state || NULL == rule_rt) {
        return;
    }

    if (n_hit_object_id != 0) {
        qsort(hit_object_ids, n_hit_object_id, sizeof(long long), compare_object_id);
    }

    struct table_object *tbl_object = NULL;
    HASH_FIND(hh, rule_compile_state->hit_not_tbl_objects, &attribute_id, sizeof(int), tbl_object);
    if (tbl_object != NULL) {
        for (size_t i = 0; i < n_hit_object_id; i++) {
            long long *object_id = (long long *)utarray_find(tbl_object->object_ids,
                                                            &hit_object_ids[i],
                                                            compare_object_id);
            if (NULL == object_id) {
                continue;
            }
            size_t remove_idx = utarray_eltidx(tbl_object->object_ids, object_id);
            utarray_erase(tbl_object->object_ids, remove_idx, 1);
        }
    }

    struct condition_id_kv *condition_id_kv = NULL, *tmp_condition_id_kv = NULL;
    HASH_ITER(hh, rule_rt->not_condition_id_kv_hash, condition_id_kv, tmp_condition_id_kv) {
        if (condition_id_kv->key.attribute_id != attribute_id) {
            continue;
        }

        long long *tmp_object_id =
            bsearch(&(condition_id_kv->key.object_id), hit_object_ids,
                    n_hit_object_id, sizeof(long long), compare_object_id);
        if (tmp_object_id != NULL) {
            continue;
        }

        if (NULL == tbl_object) {
            tbl_object = ALLOC(struct table_object, 1);
            tbl_object->attribute_id = attribute_id;
            utarray_new(tbl_object->object_ids, &ut_rule_object_id_icd);
            HASH_ADD_INT(rule_compile_state->hit_not_tbl_objects, attribute_id, tbl_object);
        }

        if (!utarray_find(tbl_object->object_ids, &(condition_id_kv->key.object_id),
                          compare_object_id)) {
            utarray_push_back(tbl_object->object_ids, &(condition_id_kv->key.object_id));
        }
    }

    if (tbl_object != NULL) {
        utarray_sort(tbl_object->object_ids, compare_object_id);
    }
}

int rule_compile_state_get_rule_table_id(struct rule_compile_state *rule_compile_state,
                                       long long rule_id)
{
    struct rule2table_id *tmp = NULL;

    tmp = utarray_find(rule_compile_state->hit_rule_table_ids, &rule_id,
                                 compare_rule_id);
    if (NULL == tmp) {
        return -1;
    }

    return tmp->table_id;
}

static int
rule_runtime_add_rule(struct rule_runtime *rule_rt,
                            struct rule_schema *schema,
                            long long rule_id, const char *table_name,
                            const char *line, struct log_handle *logger)
{
    struct maat_rule *rule = NULL;
    struct rule_item *rule_item = rule_item_new(line, schema, table_name,
                                                         rule_rt->logger);
    if (NULL == rule_item) {
        return -1;
    }

    int table_id = table_manager_get_table_id(schema->ref_tbl_mgr, table_name);
    if (table_id < 0) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d]table_name:%s has invalid table_id:%d, drop line:%s",
                  __FUNCTION__, __LINE__, table_name, table_id, line);
        return -1;
    }

    int updating_flag = rcu_hash_is_updating(rule_rt->cfg_hash);
    if (1 == updating_flag) {
        rule = rcu_updating_hash_find(rule_rt->cfg_hash, (char *)&rule_id,
                                         sizeof(long long));
        if (rule != NULL) {
            /****************************************************************
               rule found in updating hash(added by object2rule runtime), which means

               1. rcu_hash_add(htable, rule) ==> finished
               2. rcu_hash_commit(htable)       ==> undo
               because it's in updating hash, we can modify it directly
           ******************************************************************/

            /* rule has object2rule_table info, so set rule_table info */
            maat_rule_set(rule, table_id, rule_item->declared_condition_num, rule_item);
        } else {
            // rule neither in effective hash nor in updating hash
            rule = maat_rule_new(rule_item->rule_id);
            assert(rule != NULL);
            maat_rule_set(rule, table_id, rule_item->declared_condition_num, rule_item);
            rcu_hash_add(rule_rt->cfg_hash, (char *)&rule_id, sizeof(long long), rule);
        }
    } else {
        rule = rcu_hash_find(rule_rt->cfg_hash, (char *)&rule_id, sizeof(long long));
        if (rule != NULL) {
            /********************************************************************************
               rule found in effective hash(added by object2rule runtime), which means

               1. rcu_hash_add(htable, rule)  ==> finished
               2. rcu_hash_commit(htable)        ==> finished

               can only be deleted but not modified
               before delete it, we need to make a copy for further use
           ***********************************************************************************/
            struct maat_rule *copy_rule = maat_rule_clone(rule, 0);
            assert(copy_rule != NULL);

            /* delete rule from rcu hash */
            rcu_hash_del(rule_rt->cfg_hash, (char *)&rule_id, sizeof(long long));

            /* copy_rule has object2rule_table info, so set rule_table info */
            maat_rule_set(copy_rule, table_id, rule_item->declared_condition_num, rule_item);
            /* add copy_rule to rcu hash */
            rcu_hash_add(rule_rt->cfg_hash, (char *)&rule_id, sizeof(long long), copy_rule);
        } else {
            rule = maat_rule_new(rule_item->rule_id);
            assert(rule != NULL);
            maat_rule_set(rule, table_id, rule_item->declared_condition_num, rule_item);
            rcu_hash_add(rule_rt->cfg_hash, (char *)&rule_id, sizeof(long long), rule);
        }
    }

    return 0;
}

static void garbage_rule_item_free(void *data, void *arg)
{
    if (NULL == data) {
        return;
    }

    struct rule_item *rule_item = (struct rule_item *)data;

    rule_item_free(rule_item);
}

static void rule_runtime_del_rule(struct rule_runtime *rule_rt,
                                        long long rule_id)
{
    struct maat_rule *rule = NULL;

    int updating_flag = rcu_hash_is_updating(rule_rt->cfg_hash);
    if (1 == updating_flag) {
        // find in updating hash
        rule = rcu_updating_hash_find(rule_rt->cfg_hash, (char *)&rule_id,
                                         sizeof(long long));
        if (rule != NULL) {
            /****************************************************************
                rule found in updating hash, which means

                1. rcu_hash_del(htable, rule) ==> finished
                2. rcu_hash_commit(htable)       ==> undo
                because it's in updating hash, we can modify it directly
            ******************************************************************/
            if (rule->user_data != NULL) {
                maat_garbage_bagging(rule_rt->ref_garbage_bin, rule->user_data, NULL,
                                     garbage_rule_item_free);
                rule->user_data = NULL;
            }

            if (0 == rule->actual_condition_num) {
                rcu_hash_del(rule_rt->cfg_hash, (char *)&rule_id, sizeof(long long));
            }
        }
    } else {
        // find in effective hash
        rule = rcu_hash_find(rule_rt->cfg_hash, (char *)&rule_id, sizeof(long long));
        if (rule != NULL) {
            /*******************************************************************
                rule found in effective hash, which means

                1. rcu_hash_add(htable, rule)  ==> finished
                2. rcu_hash_commit(htable)        ==> finished

                can only be deleted but not modified
                before delete it, we need to make a copy for further use
            *********************************************************************/
            struct maat_rule *copy_rule = maat_rule_clone(rule, 0);
            assert(copy_rule != NULL);

            /* delete rule from rcu hash */
            rcu_hash_del(rule_rt->cfg_hash, (char *)&rule_id, sizeof(long long));

            if (0 == copy_rule->actual_condition_num) {
                maat_rule_free(copy_rule);
            } else {
                rcu_hash_add(rule_rt->cfg_hash, (char *)&rule_id, 
                             sizeof(long long), copy_rule);
            }
        }
    }
}

int rule_runtime_update(void *rule_runtime, void *rule_schema, 
                           const char *table_name, const char *line, 
                           int valid_column)
{
    if (NULL == rule_runtime || NULL == rule_schema || NULL == line) {
        return -1;
    }

    struct rule_schema *schema = (struct rule_schema *)rule_schema;
    struct rule_runtime *rule_rt = (struct rule_runtime *)rule_runtime;
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        log_fatal(rule_rt->logger, MODULE_RULE,
                  "[%s:%d] rule table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        rule_rt->update_err_cnt++;
        return -1;
    }

    long long rule_id = get_column_value(line, schema->rule_id_column);
    if (rule_id < 0) {
        log_fatal(rule_rt->logger, MODULE_RULE,
                  "[%s:%d] rule table:<%s> has no rule_id(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  schema->rule_id_column, line);
        rule_rt->update_err_cnt++;
        return -1;
    }

    if (0 == is_valid) {
        // delete
        rule_runtime_del_rule(rule_rt, rule_id);
    } else {
        // add
        int ret = rule_runtime_add_rule(rule_rt, schema, rule_id, 
                                              table_name, line, rule_rt->logger);
        if (ret < 0) {
            rule_rt->update_err_cnt++;
        }
    }

    return 0;
}

static int validate_table_not_condition(struct object2rule_runtime *g2c_rt,
                                     struct table_manager *tbl_mgr, int table_id,
                                     int is_valid, struct log_handle *logger)
{
    struct table_condition *not_condition = NULL;
    HASH_FIND_INT(g2c_rt->tbl_not_condition_hash, &table_id, not_condition);

    if (0 == is_valid) {
        //delete
        if (NULL == not_condition || 0 == not_condition->actual_condition_num) {
            return 0;
        } else {
            not_condition->actual_condition_num--;
        }
    } else {
        //add
        if (NULL == not_condition) {
            not_condition = ALLOC(struct table_condition, 1);
            not_condition->attribute_id = table_id;
            not_condition->actual_condition_num++;
            HASH_ADD_INT(g2c_rt->tbl_not_condition_hash, attribute_id, not_condition);
        } else {
            if (not_condition->actual_condition_num >= MAX_NOT_CONDITION_NUM) {
                const char *table_name = table_manager_get_table_name(tbl_mgr, table_id);
                log_fatal(logger, MODULE_RULE,
                          "[%s:%d]table:<%s> negate condition num exceed maximum:%d",
                          __FUNCTION__, __LINE__, table_name, MAX_NOT_CONDITION_NUM);
                return -1;
            }
            not_condition->actual_condition_num++;
        }
    }
    
    return 0;
}

int object2rule_runtime_update(void *g2c_runtime, void *g2c_schema, 
                                 const char *table_name, const char *line, 
                                 int valid_column)
{
    if (NULL == g2c_runtime || NULL == g2c_schema || NULL == line) {
        return -1;
    }

    struct object2rule_schema *schema = (struct object2rule_schema *)g2c_schema;
    struct object2rule_runtime *g2c_rt = (struct object2rule_runtime *)g2c_runtime;
    struct rule_runtime *rule_rt = g2c_rt->ref_rule_rt;

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
         log_fatal(rule_rt->logger, MODULE_RULE,
                  "[%s:%d] g2c table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        g2c_rt->update_err_cnt++;
        return -1;
    } 
    
    int ret = -1;
    struct object2rule_item *g2c_item =
        object2rule_item_new(line, schema, table_name, rule_rt->logger);
    if (NULL == g2c_item) {
        g2c_rt->update_err_cnt++;
        return -1;
    }

    if (1 == g2c_item->negate_option) {
        ret = validate_table_not_condition(g2c_rt, schema->ref_tbl_mgr,
                                        g2c_item->attribute_id, is_valid,
                                        rule_rt->logger);
        if (ret < 0) {
            log_fatal(rule_rt->logger, MODULE_RULE,
                      "[%s:%d]validate negate condition failed, abandon config:%s",
                      __FUNCTION__, __LINE__, line);
            goto next;
        }
    }

    if (0 == is_valid) {
        //delete
        ret = maat_remove_object_from_rule(rule_rt->cfg_hash, g2c_item,
                                             rule_rt->logger);
        if (0 == ret) {
            if (g2c_item->negate_option) {
                g2c_rt->not_condition_cnt--;
            }
            g2c_rt->rule_num--;
        } else {
            g2c_rt->update_err_cnt++;
        }
    } else {
        //add
        ret = maat_add_object_to_rule(rule_rt->cfg_hash, g2c_item,
                                        rule_rt->logger);
        if (0 == ret) {
            if (g2c_item->negate_option) {
                g2c_rt->not_condition_cnt++;
            }
            g2c_rt->rule_num++;
        } else {
            g2c_rt->update_err_cnt++;
        }
    }

next:
    object2rule_item_free(g2c_item);
    return ret;
}

long long object2rule_runtime_not_condition_count(void *g2c_runtime)
{
     if (NULL == g2c_runtime) {
        return 0;
    }
    
    struct object2rule_runtime *g2c_rt =
        (struct object2rule_runtime *)g2c_runtime;

    return g2c_rt->not_condition_cnt;
}

long long object2rule_runtime_rule_count(void *g2c_runtime)
{
    if (NULL == g2c_runtime) {
        return 0;
    }
    
    struct object2rule_runtime *g2c_rt =
        (struct object2rule_runtime *)g2c_runtime;

    return g2c_rt->rule_num;
}

long long object2rule_runtime_update_err_count(void *g2c_runtime)
{   
    if (NULL == g2c_runtime) {
        return 0;
    }

    struct object2rule_runtime *g2c_rt =
        (struct object2rule_runtime *)g2c_runtime;

    return g2c_rt->update_err_cnt;
}

int rule_runtime_commit(void *rule_runtime, const char *table_name,
                           long long maat_rt_version)
{
    if (NULL == rule_runtime) {
        return -1;
    }

    struct rule_runtime *rule_rt =
        (struct rule_runtime *)rule_runtime;
   
    int updating_flag = rcu_hash_is_updating(rule_rt->cfg_hash);
    if (0 == updating_flag) {
        return 0;
    }
    
    int ret = 0;
    size_t rule_cnt = 0;
    struct bool_matcher *old_bool_matcher = NULL;
    struct bool_matcher *new_bool_matcher = NULL;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    new_bool_matcher = maat_rule_bool_matcher_new(rule_rt, &rule_cnt);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                               (end.tv_nsec - start.tv_nsec) / 1000000;

    if (NULL == new_bool_matcher) {
        log_fatal(rule_rt->logger, MODULE_RULE,
                  "[%s:%d] table[%s] rebuild rule bool_matcher failed, rule"
                  " rules count:%zu", __FUNCTION__, __LINE__, table_name, rule_cnt);
        ret = -1;
    } else {
        log_info(rule_rt->logger, MODULE_RULE,
                 "table[%s] commit %zu rule rules and rebuild rule bool_matcher"
                 " completed, version:%lld, consume:%lldms", table_name, rule_cnt,
                 maat_rt_version, time_elapse_ms);
    }

    struct condition_id_kv *old_condition_id_kv_hash = NULL;
    struct condition_id_kv *new_condition_id_kv_hash = NULL;
    struct condition_id_kv *old_not_condition_id_kv_hash = NULL;
    struct condition_id_kv *new_not_condition_id_kv_hash = NULL;

    new_condition_id_kv_hash = build_condition_id_kv_hash(rule_rt, 0);
    new_not_condition_id_kv_hash = build_condition_id_kv_hash(rule_rt, 1);

    old_condition_id_kv_hash = rule_rt->condition_id_kv_hash;
    old_not_condition_id_kv_hash = rule_rt->not_condition_id_kv_hash;
    old_bool_matcher = rule_rt->bm;

    /*
        rule_monitor_loop thread
        STEP_1. rule_rt->bm = new_bool_matcher
        STEP_2: rcu_hash_commit(new_rule)

        scan thread
        Assume_1. If scan thread is using bool_matcher_match(rule_rt->bm) 
                  before STEP_1 or after STEP_2, it's ok.
        Assume_2. If scan thread is using bool_matcher_match(rule_rt->bm) 
                  between STEP_1 and STEP_2. 
                  P1: If new rule is hit and returned, then caller can get this rule's
                      ex_data by using maat_plugin_table_get_ex_data(hit_rule_id) because
                      STEP_2 is fast enough.
    */

    rule_rt->bm = new_bool_matcher;
    rule_rt->condition_id_kv_hash = new_condition_id_kv_hash;
    rule_rt->not_condition_id_kv_hash = new_not_condition_id_kv_hash;
    rcu_hash_commit(rule_rt->cfg_hash); //after commit, old cfg still available within RULE_GC_TIMEOUT_S.

    maat_garbage_bagging(rule_rt->ref_garbage_bin, old_bool_matcher, NULL,
                        garbage_bool_matcher_free);
    maat_garbage_bagging(rule_rt->ref_garbage_bin, old_condition_id_kv_hash, NULL,
                        garbage_condition_id_kv_hash_free);
    maat_garbage_bagging(rule_rt->ref_garbage_bin, old_not_condition_id_kv_hash, NULL,
                        garbage_condition_id_kv_hash_free);

    rule_rt->rule_num = rcu_hash_count(rule_rt->cfg_hash);

    return ret;
}

long long rule_runtime_rule_count(void *rule_runtime)
{
    if (NULL == rule_runtime) {
        return 0;
    }
    
    struct rule_runtime *rule_rt =
        (struct rule_runtime *)rule_runtime;

    return rule_rt->rule_num;
}

long long rule_runtime_update_err_count(void *rule_runtime)
{   
    if (NULL == rule_runtime) {
        return 0;
    }

    struct rule_runtime *rule_rt =
        (struct rule_runtime *)rule_runtime;

    return rule_rt->update_err_cnt;
}

static int rule_sort_para_compare(const struct rule_sort_para *a,
                                     const struct rule_sort_para *b)
{
	//If rule rule's execute sequences are not specified or equal.
	if (a->declared_condition_num != b->declared_condition_num) {
		return (a->declared_condition_num - b->declared_condition_num);
	} else {
		return (b->rule_id - a->rule_id);
	}
}

static void rule_sort_para_set(struct rule_sort_para *para, 
                                  const struct rule_item *item)
{
	para->rule_id = item->rule_id;
	para->declared_condition_num = item->declared_condition_num;
}

static int compare_rule_item(const void *a, const void *b)
{
	const struct rule_item *ra = *(const struct rule_item **)a;
	const struct rule_item *rb = *(const struct rule_item **)b;
	
	struct rule_sort_para sa, sb;
	rule_sort_para_set(&sa, ra);
	rule_sort_para_set(&sb, rb);

	return rule_sort_para_compare(&sa, &sb);
}

int rule_runtime_match(struct rule_runtime *rule_rt, long long *rule_ids,
                          size_t rule_ids_size, struct maat_state *state)
{
    struct rule_compile_state *rule_compile_state = state->rule_compile_state;
    struct rule_item *rule_items[rule_ids_size];
    
    // all hit condition_id -> rule_id
    size_t bool_match_ret =
        maat_rule_bool_matcher_match(rule_rt, rule_compile_state,
                                        state->thread_id,
                                        (void **)rule_items,
                                        rule_ids_size);
    if (bool_match_ret > 0) {
        qsort(rule_items, bool_match_ret, sizeof(struct rule_item *),
              compare_rule_item);
    }
   
    for (size_t i = 0; i < bool_match_ret; i++) {
        rule_ids[i] = rule_items[i]->rule_id;
	}
    
    return MIN(bool_match_ret, rule_ids_size);
}

int rule_compile_state_update(struct rule_compile_state *rule_compile_state, struct maat *maat_inst,
                         int attribute_id, int custom_rule_tbl_id, int Nth_scan,
                         struct maat_item *hit_items, size_t n_hit_item)
{
    size_t i = 0, j = 0;
    size_t hit_cnt = n_hit_item;
    long long hit_object_ids[MAX_HIT_OBJECT_NUM];
    struct maat_hit_object hit_object;

    utarray_clear(rule_compile_state->this_scan_hit_conditions);
    rule_compile_state->this_scan_not_logic = 0;
    rule_compile_state->Nth_scan = Nth_scan;

    for (i = 0; i < hit_cnt; i++) {
        hit_object_ids[i] = hit_items[i].object_id;

        hit_object.item_id = hit_items[i].item_id;
        hit_object.object_id = hit_items[i].object_id;
        hit_object.attribute_id = attribute_id;
        utarray_push_back(rule_compile_state->last_hit_objects, &hit_object);
    }

    int g2g_table_id = table_manager_get_object2object_table_id(maat_inst->tbl_mgr);
    void *g2g_rt = table_manager_get_runtime(maat_inst->tbl_mgr, g2g_table_id);

    long long super_object_ids[MAX_HIT_OBJECT_NUM];
    size_t super_object_cnt = object2object_runtime_get_super_objects(g2g_rt, hit_object_ids,
                                                                  hit_cnt, super_object_ids,
                                                                  MAX_HIT_OBJECT_NUM);
    for (i = 0; i < super_object_cnt; i++) {
        hit_object.item_id = 0;
        hit_object.object_id = super_object_ids[i];
        hit_object.attribute_id = attribute_id;
        utarray_push_back(rule_compile_state->last_hit_objects, &hit_object);
    }

    if (1 == maat_inst->opts.hit_path_on && hit_cnt > 0) {
        for (i = 0; i < hit_cnt; i++) {
            rule_compile_state_add_internal_hit_path(rule_compile_state, hit_items[i].item_id,
                                                hit_items[i].object_id, attribute_id, 0, Nth_scan);
        }
    }

    if (1 == maat_inst->opts.hit_object_on) {
        rule_compile_state_add_direct_hit_objects(rule_compile_state, hit_items, hit_cnt, attribute_id);
        rule_compile_state_add_indirect_hit_objects(rule_compile_state, super_object_ids,
                                              super_object_cnt, attribute_id);
    }

    /* update hit condition */
    int rule_table_id = table_manager_get_default_rule_table_id(maat_inst->tbl_mgr);
    if (custom_rule_tbl_id > 0) {
        rule_table_id = custom_rule_tbl_id;
    }

    struct rule_runtime *rule_rt = table_manager_get_runtime(maat_inst->tbl_mgr,
                                                                   rule_table_id);
    if (NULL == rule_rt) {
        return 0;
    }

    for (j = 0; j < super_object_cnt && hit_cnt < MAX_HIT_OBJECT_NUM; j++) {
        hit_object_ids[hit_cnt++] = super_object_ids[j];
    }

    for (i = 0; i < hit_cnt; i++) {
        rule_compile_state_update_hit_conditions(rule_compile_state, rule_rt,
                                         hit_object_ids[i], attribute_id);
    }

    rule_compile_state_cache_hit_not_objects(rule_compile_state, rule_rt, hit_object_ids,
                                       hit_cnt, attribute_id); 
    return hit_cnt;
}

void rule_compile_state_clear_last_hit_object(struct rule_compile_state *rule_compile_state)
{
    if (NULL == rule_compile_state) {
        return;
    }

    utarray_clear(rule_compile_state->last_hit_objects);
}

void rule_compile_state_not_logic_update(struct rule_compile_state *rule_compile_state,
                                    struct rule_runtime *rule_rt,
                                    struct maat *maat_inst, int attribute_id,
                                    int Nth_scan)
{
    if (NULL == rule_compile_state || NULL == maat_inst) {
        return;
    }

    rule_compile_state->this_scan_not_logic = 1;
    rule_compile_state->Nth_scan = Nth_scan;
    utarray_clear(rule_compile_state->this_scan_hit_not_conditions);

    struct table_object *tbl_object = NULL;
    HASH_FIND(hh, rule_compile_state->hit_not_tbl_objects, &attribute_id, sizeof(int), tbl_object);
    if (NULL == tbl_object) {
        return;
    }

    struct condition_id_kv *condition_id_kv = NULL;
    for (size_t i = 0; i < utarray_len(tbl_object->object_ids); i++) {
        long long *object_id = utarray_eltptr(tbl_object->object_ids, i);
        struct condition_query_key key = {*object_id, attribute_id, 1};
        
        HASH_FIND(hh, rule_rt->not_condition_id_kv_hash, &key, sizeof(key), condition_id_kv);
        if (NULL == condition_id_kv) {
            continue;
        }

        rule_compile_state_add_hit_not_conditions(rule_compile_state, condition_id_kv->condition_ids);
        if (1 == maat_inst->opts.hit_path_on) {
            rule_compile_state_add_internal_hit_path(rule_compile_state, -1, *object_id,
                                                attribute_id, 1, Nth_scan);
        }
    }
}

size_t rule_compile_state_get_indirect_hit_objects(struct rule_compile_state *rule_compile_state,
                                             struct maat_hit_object *object_array,
                                             size_t array_size)
{
    size_t i = 0;
    struct maat_hit_object *hit_object = NULL;
    for (i = 0; i < utarray_len(rule_compile_state->indirect_hit_objects) && i < array_size; i++) {
        hit_object =
            (struct maat_hit_object *)utarray_eltptr(rule_compile_state->indirect_hit_objects, i);
        object_array[i].item_id = hit_object->item_id;
        object_array[i].object_id = hit_object->object_id;
        object_array[i].attribute_id = hit_object->attribute_id;
    }

    utarray_clear(rule_compile_state->indirect_hit_objects);

    return i;
}

size_t rule_compile_state_get_indirect_hit_object_cnt(struct rule_compile_state *rule_compile_state)
{
    return utarray_len(rule_compile_state->indirect_hit_objects);
}

size_t rule_compile_state_get_last_hit_objects(struct rule_compile_state *rule_compile_state,
                                         struct maat_hit_object *object_array,
                                         size_t array_size)
{
    size_t i = 0;

    for (i = 0; i < utarray_len(rule_compile_state->last_hit_objects) && i < array_size; i++) {
        object_array[i] =
            *(struct maat_hit_object *)utarray_eltptr(rule_compile_state->last_hit_objects, i);
    }

    return i;
}

size_t rule_compile_state_get_last_hit_object_cnt(struct rule_compile_state *rule_compile_state)
{
    return utarray_len(rule_compile_state->last_hit_objects);
}

size_t rule_compile_state_get_direct_hit_objects(struct rule_compile_state *rule_compile_state,
                                           struct maat_hit_object *object_array,
                                           size_t array_size)
{
    UT_array *direct_hit_object = rule_compile_state->direct_hit_objects;

    size_t i = 0;
    struct maat_hit_object *object = NULL;
    for (i = 0; i < utarray_len(direct_hit_object) && i < array_size; i++) {
        object = (struct maat_hit_object *)utarray_eltptr(direct_hit_object, i);
        object_array[i].item_id = object->item_id;
        object_array[i].object_id = object->object_id;
        object_array[i].attribute_id = object->attribute_id;
    }
   
    utarray_clear(rule_compile_state->direct_hit_objects);

    return i;
}

size_t rule_compile_state_get_direct_hit_object_cnt(struct rule_compile_state *rule_compile_state)
{
    return utarray_len(rule_compile_state->direct_hit_objects);
}

size_t rule_compile_state_get_internal_hit_paths(struct rule_compile_state *rule_compile_state,
                                            struct rule_runtime *rule_rt,
                                            struct object2object_runtime *g2g_rt,
                                            struct maat_hit_path *hit_path_array, 
                                            size_t array_size)
{
    size_t hit_path_cnt = 0;
    struct internal_hit_path *internal_path = NULL;

    for (int i = 0; i < utarray_len(rule_compile_state->internal_hit_paths); i++) {
        internal_path =
            (struct internal_hit_path *)utarray_eltptr(rule_compile_state->internal_hit_paths, i);
        /*
            NOTE: maybe one item has been deleted, but it's item_id still exist in internal_hit_paths
        */
        long long super_object_ids[MAX_HIT_OBJECT_NUM];
        UT_array *valid_super_object_ids;
        utarray_new(valid_super_object_ids, &ut_rule_object_id_icd);

        size_t super_object_cnt =
            object2object_runtime_get_super_objects(g2g_rt, &(internal_path->object_id), 1,
                                                 super_object_ids, MAX_HIT_OBJECT_NUM);
        for (size_t idx = 0; idx < super_object_cnt; idx++) {
            utarray_push_back(valid_super_object_ids, &super_object_ids[idx]);
        }

        /*
            internal_path->object_id can be referenced directly by rule, 
            so add it to hit_path which super_object_ids is -1
            ------------------------------------------------------------------------------
            NOTE: Add the hit path as long as the item is hit
        */
        long long super_object_id = -1;
        utarray_push_back(valid_super_object_ids, &super_object_id);
        
        long long *p = NULL;
        struct maat_hit_path tmp_path;
    
        for (p = utarray_front(valid_super_object_ids);
             p != NULL && hit_path_cnt < array_size;
             p = utarray_next(valid_super_object_ids, p)) {
            memset(&tmp_path, 0, sizeof(tmp_path));
            tmp_path.Nth_scan = internal_path->Nth_scan;
            tmp_path.item_id = internal_path->item_id;
            tmp_path.sub_object_id = internal_path->object_id;
            tmp_path.top_object_id = *p;
            tmp_path.attribute_id = internal_path->attribute_id;
            tmp_path.negate_option = internal_path->negate_option;
            tmp_path.condition_index = -1;
            tmp_path.rule_id = -1;

            /* check if internal_path is duplicated from hit_path_array[]
             * element */
            if (hit_path_cnt > 0) {
                if (maat_rule_is_hit_path_existed(hit_path_array, hit_path_cnt,
                                                     &tmp_path)) {
                    continue;
                }
            }
           
            hit_path_array[hit_path_cnt] = tmp_path;
            hit_path_cnt++;
        }
        utarray_free(valid_super_object_ids);
    }

    return hit_path_cnt;
}

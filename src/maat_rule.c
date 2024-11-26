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
    int table_id;
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

struct rule_item {
    int condition_num;
    uuid_t rule_uuid;
    char *table_line;
    size_t table_line_len;
};

struct condition_query_key {
	uuid_t object_uuid;
    char field_name[MAX_FIELD_NAME_LEN];
    int negate_option;
};

struct condition_id_kv {
    struct condition_query_key key;
    UT_array *condition_ids;
    UT_hash_handle hh;
};

struct table_condition {
    char field_name[MAX_FIELD_NAME_LEN];
    int actual_condition_num;
    UT_array *condition_ids;
    UT_array *object_ids;
    UT_hash_handle hh;
};

struct field_hit_object_collection {
    char field_name[MAX_FIELD_NAME_LEN];
    UT_array *direct_items;
    UT_array *indirect_object_uuids;//TODO: change it to graph?
    UT_array *all_object_uuids;
    UT_array *negate_object_uuids;
    int need_negate_condition;
    int need_scan_not_object;
    int Nth_scan;
    UT_hash_handle hh;
};

struct rule_compile_runtime_state {
    int table_id;//key
    time_t rule_rt_version;
    int hit_object_changed;
    int need_scan_not_logic;
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
    struct table_condition *tbl_not_condition_hash; //each field's negate condition number <= MAX_NOT_CONDITION_NUM
    struct log_handle *logger;
    time_t version;

    long long rule_num;
    long long update_err_cnt;
};

struct condition_literal {
    uuid_t object_uuids[MAX_OBJECT_CNT];
    int object_cnt;
    char field_name[MAX_FIELD_NAME_LEN];
};

struct rule_condition {
	long long condition_id;
    UT_array *literals;
	char negate_option;      // 1 byte
	char in_use;        // 1 byte
    char pad[6];        // for 8 bytes alignment
};

struct rule_sort_para {
	int condition_num;
	uuid_t rule_uuid;
};

#define MAAT_RULE_MAGIC	0x4a5b6c7d
struct maat_rule {
	uint32_t magic_num;
    int condition_num;
    int table_id;
    uuid_t rule_uuid;
    void *user_data; // rule_item
	struct rule_condition conditions[MAX_ITEMS_PER_BOOL_EXPR];
};

struct internal_hit_path {
    uuid_t item_uuid;
	uuid_t object_uuid;
	int Nth_scan;
    int negate_option; // 1 means negate condition
    char field_name[MAX_FIELD_NAME_LEN];
};

struct rule_compile_state {
	int Nth_scan;

	UT_array *internal_hit_paths;
	UT_array *all_hit_conditions;
    UT_array *exclude_not_conditions;
    struct field_hit_object_collection *attr_hit_objects_hashtbl;
    struct rule_compile_runtime_state *rule_runtime_state_hash;
};

static UT_icd ut_condition_id_icd = {sizeof(long long), NULL, NULL, NULL};
static UT_icd ut_condition_literal_icd = {sizeof(struct condition_literal), NULL, NULL, NULL};
static UT_icd ut_object_uuid_icd = {sizeof(uuid_t), NULL, NULL, NULL};
static UT_icd ut_maat_item_icd = {sizeof(struct maat_item), NULL, NULL, NULL};
static UT_icd ut_hit_path_icd = {sizeof(struct internal_hit_path), NULL, NULL, NULL};

static void rule_item_free(struct rule_item *item)
{
    item->condition_num = 0;

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

static int validate_table_not_condition(struct rule_runtime *rule_rt,
                                     struct table_manager *tbl_mgr, const char *field_name,
                                     enum maat_operation op, struct log_handle *logger)
{
    struct table_condition *not_condition = NULL;
    HASH_FIND_STR(rule_rt->tbl_not_condition_hash, field_name, not_condition);

    if (MAAT_OP_DEL == op) {
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
            snprintf(not_condition->field_name, sizeof(not_condition->field_name), "%s", field_name);
            not_condition->actual_condition_num++;
            HASH_ADD_STR(rule_rt->tbl_not_condition_hash, field_name, not_condition);
        } else {
            if (not_condition->actual_condition_num >= MAX_NOT_CONDITION_NUM) {
                log_fatal(logger, MODULE_RULE,
                          "[%s:%d]field:<%s> negate condition num exceed maximum:%d",
                          __FUNCTION__, __LINE__, field_name, MAX_NOT_CONDITION_NUM);
                return -1;
            }
            not_condition->actual_condition_num++;
        }
    }
    
    return 0;
}

static struct maat_rule *maat_rule_new(struct rule_runtime *rule_rt, struct rule_schema *schema,
                                        const char *table_name, uuid_t rule_uuid, 
                                        const char *table_line, struct rule_item *rule_item)
{
	struct maat_rule *rule = ALLOC(struct maat_rule, 1);
    struct log_handle *logger = rule_rt->logger;
    cJSON *tmp_obj = NULL;
    cJSON *conditions_obj = NULL;
    cJSON *table_json = cJSON_Parse(table_line);
    int table_id = table_manager_get_table_id(schema->ref_tbl_mgr, table_name);

    if (table_id < 0) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] table: <%s> not found in table manager",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    rule->table_id = table_id;
	rule->magic_num = MAAT_RULE_MAGIC;
    uuid_copy(rule->rule_uuid, rule_uuid);

    for(int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {	
        utarray_new(rule->conditions[i].literals, &ut_condition_literal_icd);
		rule->conditions[i].in_use = 0;
        rule->conditions[i].condition_id = 0;
	}

    conditions_obj = cJSON_GetObjectItem(table_json, "and_conditions");
    if (conditions_obj == NULL || conditions_obj->type != cJSON_Array) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] table: <%s> has no and_conditions or not array format",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    rule->condition_num = cJSON_GetArraySize(conditions_obj);
    if (rule->condition_num > MAX_ITEMS_PER_BOOL_EXPR) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] table: <%s> condition_num:%d exceed maximum:%d",
                  __FUNCTION__, __LINE__, table_name, rule->condition_num, MAX_ITEMS_PER_BOOL_EXPR);
        goto error;
    }

    for (int i = 0; i < rule->condition_num; i++) {
        cJSON *condition_obj = cJSON_GetArrayItem(conditions_obj, i);
        struct rule_condition *condition = rule->conditions + i;

        tmp_obj = cJSON_GetObjectItem(condition_obj, "negate_option");
        if (tmp_obj) {
            if (tmp_obj->type == cJSON_True) {
                condition->negate_option = CONDITION_NEGATE_OPTION_SET;
            } else if (tmp_obj->type == cJSON_False) {
                condition->negate_option = CONDITION_NEGATE_OPTION_UNSET;
            } else {
                log_fatal(logger, MODULE_RULE,
                            "[%s:%d] table: <%s> negate_option:%s is illegal",
                            __FUNCTION__, __LINE__, table_name, tmp_obj->valuestring);
                goto error;
            }
        }

        cJSON *or_conditions_obj = cJSON_GetObjectItem(condition_obj, "or_conditions");
        cJSON *literal_obj = NULL;
        cJSON_ArrayForEach(literal_obj, or_conditions_obj) {
            struct condition_literal tmp_literal;
            memset(&tmp_literal, 0, sizeof(tmp_literal));

            tmp_obj = cJSON_GetObjectItem(literal_obj, "field_name");
            if (tmp_obj == NULL || tmp_obj->type != cJSON_String) {
                log_fatal(rule_rt->logger, MODULE_RULE,
                            "[%s:%d] table: <%s> has no field_name or not string format",
                            __FUNCTION__, __LINE__, table_name);
                goto error;
            }

            if (strlen(tmp_obj->valuestring) >= sizeof(tmp_literal.field_name)) {
                log_fatal(logger, MODULE_RULE,
                        "[%s:%d] table: <%s> field_name:%s length exceed maximum:%d",
                        __FUNCTION__, __LINE__, table_name, tmp_obj->valuestring, sizeof(tmp_literal.field_name));
                goto error;
            }
            snprintf(tmp_literal.field_name, sizeof(tmp_literal.field_name), "%s", tmp_obj->valuestring);  

            if (condition->negate_option == CONDITION_NEGATE_OPTION_SET) {
                int ret = validate_table_not_condition(rule_rt, schema->ref_tbl_mgr, tmp_literal.field_name, MAAT_OP_ADD, logger);
                if (ret < 0) {
                    log_fatal(logger, MODULE_RULE,
                            "[%s:%d] table: <%s> validate negate_option failed, line: %s",
                            __FUNCTION__, __LINE__, table_name, table_line);
                    goto error;
                }
            }

            tmp_obj = cJSON_GetObjectItem(literal_obj, "object_uuids");
            if (tmp_obj && tmp_obj->type == cJSON_Array) {
                int n_object_ids = cJSON_GetArraySize(tmp_obj);

                tmp_literal.object_cnt = n_object_ids;

                for (int j = 0; j < n_object_ids; j++) {
                    cJSON *object_id_obj = cJSON_GetArrayItem(tmp_obj, j);
                    if (object_id_obj && object_id_obj->type == cJSON_String) {
                        uuid_parse(object_id_obj->valuestring, tmp_literal.object_uuids[j]);
                    }
                }
            }

            utarray_push_back(condition->literals, &tmp_literal);
        }

        condition->in_use = 1;
    }

    rule_item->condition_num = rule->condition_num;
    rule->user_data = rule_item;

    if (table_json) {
        cJSON_Delete(table_json);
    }

	return rule;

error:
    if (rule) {
        maat_rule_free(rule);
    }

    if (table_json) {
        cJSON_Delete(table_json);
    }

    return NULL;
}

static int rule_accept_tag_match(struct rule_schema *schema, const char *line,
                                    const char *table_name, struct log_handle *logger)
{
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);
    cJSON *tmp_obj = NULL;
    cJSON *table_json = cJSON_Parse(line);
    int ret = TAG_MATCH_MATCHED;

    tmp_obj = cJSON_GetObjectItem(table_json, "effective_range");

    if ((tmp_obj && cJSON_GetArraySize(tmp_obj) > 0) && n_tag > 0) {
        char *tag_str = cJSON_Print(tmp_obj);
        ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag_str);
        FREE(tag_str);
        if (TAG_MATCH_ERR == ret) {
            log_fatal(logger, MODULE_RULE,
                      "[%s:%d] table: <%s> has invalid tag format in line:%s",
                      __FUNCTION__, __LINE__, table_name, line);
            goto END;
        }

        if (TAG_MATCH_UNMATCHED == ret) {
            log_fatal(logger, MODULE_RULE,
                      "[%s:%d] table: <%s> has unmatched tag in line:%s",
                      __FUNCTION__, __LINE__, table_name, line);
            goto END;
        }
    }

END:
    if (table_json) {
        cJSON_Delete(table_json);
    }

    return ret;
}

static struct rule_item *rule_item_new(const char *table_line, struct rule_schema *schema,
                 const char *table_name, struct log_handle *logger)
{
    int ret = rule_accept_tag_match(schema, table_line, table_name, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    cJSON *tmp_obj = NULL;
    struct rule_item *rule_item = ALLOC(struct rule_item, 1);
    cJSON *table_json = cJSON_Parse(table_line);

    tmp_obj = cJSON_GetObjectItem(table_json, "uuid");
    if (tmp_obj == NULL && tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d] table: <%s> has no rule_id or not string format in line:%s",
                  __FUNCTION__, __LINE__, table_name, table_line);
        goto error;
    }
    uuid_parse(tmp_obj->valuestring, rule_item->rule_uuid);

    rule_item->table_line_len = strlen(table_line);
    rule_item->table_line = ALLOC(char, rule_item->table_line_len + 1);
    memcpy(rule_item->table_line, table_line, rule_item->table_line_len);

    cJSON_Delete(table_json);
    return rule_item;
error:
    if (table_json) {
        cJSON_Delete(table_json);
    }
    FREE(rule_item);
    return NULL;
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

    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_RULE, 
                  "[%s:%d] table: <%s> schema has no table_id column",
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
    rule_rt->tbl_not_condition_hash = NULL;

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

    if (rule_rt->tbl_not_condition_hash != NULL) {
        struct table_condition *not_condition = NULL, *tmp_not_condition = NULL;
        HASH_ITER(hh, rule_rt->tbl_not_condition_hash, not_condition, tmp_not_condition) {
            HASH_DEL(rule_rt->tbl_not_condition_hash, not_condition);
            if (not_condition->condition_ids != NULL) {
                utarray_free(not_condition->condition_ids);
                not_condition->condition_ids = NULL;
            }

            if (not_condition->object_ids != NULL) {
                utarray_free(not_condition->object_ids);
                not_condition->object_ids = NULL;
            }

            FREE(not_condition);
        }
        assert(rule_rt->tbl_not_condition_hash == NULL);
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

static inline int compare_object_uuid(const void *a, const void *b)
{
    return uuid_compare(*(uuid_t *)a, *(uuid_t *)b);
}

static struct bool_matcher *
maat_rule_bool_matcher_new(struct rule_runtime *rule_rt,
                              size_t *rule_cnt)
{
	if (NULL == rule_rt) {
        return NULL;
    }

    size_t i = 0, j = 0, idx = 0;

    // STEP 1, update condition_id of each rule
    void **data_array = NULL;
    struct maat_rule *iter_rule = NULL;
    *rule_cnt = rcu_updating_hash_list(rule_rt->cfg_hash, &data_array);

    for (idx = 0; idx < *rule_cnt; idx++) {
        iter_rule = (struct maat_rule *)data_array[idx];
        for (i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
            struct rule_condition *condition = iter_rule->conditions + i;
            if (!condition->in_use) {
                continue;
            }

            if (0 == condition->condition_id) {
                condition->condition_id =
                    maat_runtime_get_sequence(rule_rt->ref_maat_rt, "condition_id");
            }
        }
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
        if (j == (size_t)iter_rule->condition_num && j > 0) {
            uuid_copy(bool_expr_array[expr_cnt].expr_uuid, iter_rule->rule_uuid);
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

            struct condition_literal *tmp_literal = NULL;
            for (size_t j = 0; j < utarray_len(condition->literals); j++) {
                tmp_literal = (struct condition_literal *)utarray_eltptr(condition->literals, j);

                for (size_t k = 0; k < tmp_literal->object_cnt; k++) {
                    struct condition_query_key key;
                    struct condition_id_kv *condition_id_kv = NULL;

                    memset(&key, 0, sizeof(key));

                    memcpy(key.field_name, tmp_literal->field_name, sizeof(key.field_name));
                    key.negate_option = condition->negate_option;
                    uuid_copy(key.object_uuid, tmp_literal->object_uuids[k]);
                    
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

    if (NULL == rule_rt->bm ||
        0 == utarray_len(rule_compile_state->all_hit_conditions)) {
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
        assert(uuid_compare(rule->rule_uuid, expr_match[i].expr_uuid) == 0);

		if (0 == rule->condition_num) {
			continue;
		}

        if (rule->user_data != NULL) {
            user_data_array[ud_result_cnt] = rule->user_data;
			ud_result_cnt++;
        }
	}

	return ud_result_cnt;
}

struct rule_compile_state *rule_compile_state_new(void)
{
    struct rule_compile_state *rule_compile_state = ALLOC(struct rule_compile_state, 1);

	utarray_new(rule_compile_state->internal_hit_paths, &ut_hit_path_icd);
	utarray_new(rule_compile_state->all_hit_conditions, &ut_condition_id_icd);
    utarray_new(rule_compile_state->exclude_not_conditions, &ut_condition_id_icd);

	return rule_compile_state;
}

void rule_compile_state_reset(struct rule_compile_state *rule_compile_state)
{
    if (NULL == rule_compile_state) {
        return;
    }

    rule_compile_state->Nth_scan = 0;

    utarray_clear(rule_compile_state->internal_hit_paths);
    utarray_clear(rule_compile_state->all_hit_conditions);
    utarray_clear(rule_compile_state->exclude_not_conditions);

    struct field_hit_object_collection *attr_hit_obj = NULL, *tmp_hit_attr_obj = NULL;
    HASH_ITER(hh, rule_compile_state->attr_hit_objects_hashtbl, attr_hit_obj, tmp_hit_attr_obj) {
        if (attr_hit_obj->direct_items != NULL) {
            utarray_clear(attr_hit_obj->direct_items);
        }

        if (attr_hit_obj->indirect_object_uuids != NULL) {
            utarray_clear(attr_hit_obj->indirect_object_uuids);
        }

        if (attr_hit_obj->all_object_uuids != NULL) {
            utarray_clear(attr_hit_obj->all_object_uuids);
        }

        attr_hit_obj->need_negate_condition = 0;
        attr_hit_obj->need_scan_not_object = 0;
        attr_hit_obj->Nth_scan = 0;
    }

    struct rule_compile_runtime_state *rule_runtime_state = NULL, *tmp_rule_runtime_state = NULL;
    HASH_ITER(hh, rule_compile_state->rule_runtime_state_hash, rule_runtime_state, tmp_rule_runtime_state) {
        rule_runtime_state->rule_rt_version = 0;
        rule_runtime_state->hit_object_changed = 0;
        rule_runtime_state->need_scan_not_logic = 0;
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

    if (rule_compile_state->exclude_not_conditions != NULL) {
        free_bytes += utarray_size(rule_compile_state->exclude_not_conditions) *
                      sizeof(long long);
        utarray_free(rule_compile_state->exclude_not_conditions);
        rule_compile_state->exclude_not_conditions = NULL;
    }

    struct field_hit_object_collection *attr_hit_obj = NULL, *tmp_hit_attr_obj = NULL;
    HASH_ITER(hh, rule_compile_state->attr_hit_objects_hashtbl, attr_hit_obj, tmp_hit_attr_obj) {
        if (attr_hit_obj->direct_items != NULL) {
            free_bytes += utarray_size(attr_hit_obj->direct_items) * sizeof(struct maat_item);
            utarray_free(attr_hit_obj->direct_items);
            attr_hit_obj->direct_items = NULL;
        }

        if (attr_hit_obj->indirect_object_uuids != NULL) {
            free_bytes += utarray_size(attr_hit_obj->indirect_object_uuids) * sizeof(uuid_t);
            utarray_free(attr_hit_obj->indirect_object_uuids);
            attr_hit_obj->indirect_object_uuids = NULL;
        }

        if (attr_hit_obj->all_object_uuids != NULL) {
            free_bytes += utarray_size(attr_hit_obj->all_object_uuids) * sizeof(uuid_t);
            utarray_free(attr_hit_obj->all_object_uuids);
            attr_hit_obj->all_object_uuids = NULL;
        }

        HASH_DEL(rule_compile_state->attr_hit_objects_hashtbl, attr_hit_obj);
        free_bytes += sizeof(struct field_hit_object_collection);
        FREE(attr_hit_obj);
    }

    struct rule_compile_runtime_state *rule_runtime_state = NULL, *tmp_rule_runtime_state = NULL;
    HASH_ITER(hh, rule_compile_state->rule_runtime_state_hash, rule_runtime_state, tmp_rule_runtime_state) {
        HASH_DEL(rule_compile_state->rule_runtime_state_hash, rule_runtime_state);
        free_bytes += sizeof(struct rule_compile_runtime_state);
        FREE(rule_runtime_state);
    }

	FREE(rule_compile_state);

    free_bytes += sizeof(struct rule_compile_state);
    alignment_int64_array_add(maat_inst->stat->maat_state_free_bytes,
                              thread_id, free_bytes);
}

static void
rule_compile_state_add_internal_hit_path(struct rule_compile_state *rule_compile_state,
                                    uuid_t item_uuid, uuid_t object_uuid,
                                    const char *field_name, int negate_option, int Nth_scan)
{
    if (NULL == rule_compile_state) {
        return;
    }

	struct internal_hit_path new_path;
    uuid_copy(new_path.item_uuid, item_uuid);
	new_path.Nth_scan = Nth_scan;
    uuid_copy(new_path.object_uuid, object_uuid);
    snprintf(new_path.field_name, sizeof(new_path.field_name), "%s", field_name);
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

        struct condition_literal *tmp_literal = NULL;
        for (size_t j = 0; j < utarray_len(condition->literals); j++) {
            tmp_literal = (struct condition_literal *)utarray_eltptr(condition->literals, j);

            if (strcmp(tmp_literal->field_name, key->field_name) != 0) {
                continue;
            }

            if (condition->negate_option != key->negate_option) {
                continue;
            }

            uuid_t *tmp_object_uuid = bsearch(&(key->object_uuid), tmp_literal->object_uuids,
                                                tmp_literal->object_cnt, sizeof(uuid_t),
                                                compare_object_uuid);
            if (tmp_object_uuid != NULL) {
                return 1;
            }
        }
	}

	return 0;
}

static size_t
maat_rule_get_hit_condition_index(struct maat_rule *rule, 
                                  const char *field_name, uuid_t *hit_object_uuid,
                                  int *condition_idx_array, size_t array_size)
{
    size_t hit_condition_cnt = 0;
    struct rule_condition *tmp_condition = NULL;

    for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
        tmp_condition = &rule->conditions[i];
        if (!tmp_condition->in_use) {
            continue;
        }

        struct condition_literal *tmp_literal = NULL;
        for (size_t j = 0; j < utarray_len(tmp_condition->literals); j++) {
            tmp_literal = (struct condition_literal *)utarray_eltptr(tmp_condition->literals, j);
        
            if (strcmp(tmp_literal->field_name, field_name) != 0) {
                continue;
            }

            uuid_t *tmp_object_uuid = bsearch(hit_object_uuid, tmp_literal->object_uuids,
                                                tmp_literal->object_cnt, sizeof(uuid_t),
                                                compare_object_uuid);
            if (tmp_object_uuid != NULL) {
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

static void populate_hit_path_with_rule(struct maat_hit_path *hit_path_array,
                                    size_t array_idx, size_t n_hit_path,
                                    size_t *n_new_hit_path, const char *field_name,
                                    struct maat_rule *rule)
{
    size_t i = 0;
    size_t idx = array_idx;
    size_t n_condition_index = 0;
    size_t new_hit_path_cnt = *n_new_hit_path;
    int condition_index_array[MAX_ITEMS_PER_BOOL_EXPR] = {0};

    if (uuid_is_null(hit_path_array[idx].top_object_uuid)) {
        uuid_copy(hit_path_array[idx].top_object_uuid, hit_path_array[idx].sub_object_uuid);
    }

    struct maat_hit_path tmp_path;
    if (uuid_is_null(hit_path_array[idx].rule_uuid)) {
        uuid_copy(hit_path_array[idx].rule_uuid, rule->rule_uuid);
        // find out which condition in rule hit
        n_condition_index =
            maat_rule_get_hit_condition_index(rule, field_name,
                                              &hit_path_array[idx].top_object_uuid,
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
        uuid_copy(tmp_path.rule_uuid, rule->rule_uuid);
        if (!maat_rule_is_hit_path_existed(hit_path_array, n_hit_path + new_hit_path_cnt, &tmp_path)) {
            hit_path_array[n_hit_path + new_hit_path_cnt] = tmp_path;
            new_hit_path_cnt++;
            n_condition_index =
                maat_rule_get_hit_condition_index(rule, field_name, &tmp_path.top_object_uuid,
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
    struct condition_query_key key;
    struct bool_expr_match *expr_match = rule_rt->expr_match_buff + 
                                         (thread_id * MAX_HIT_RULE_NUM);
    assert(thread_id >= 0);

    int bool_match_ret =
        bool_matcher_match(rule_rt->bm, 
                          (unsigned long long *)utarray_eltptr(rule_compile_state->all_hit_conditions, 0),
						  utarray_len(rule_compile_state->all_hit_conditions), expr_match, MAX_HIT_RULE_NUM);

	for (int idx = 0; idx < bool_match_ret; idx++) {
        rule = (struct maat_rule *)expr_match[idx].user_tag;
		assert(rule->magic_num == MAAT_RULE_MAGIC);
        assert(uuid_compare(rule->rule_uuid, expr_match[idx].expr_uuid) == 0);
		if (0 == rule->condition_num || NULL == rule->user_data) {
			continue;
		}

        for (size_t j = 0; j < n_hit_path && (n_hit_path + n_new_hit_path) < array_size; j++) {
			if (uuid_is_null(hit_path_array[j].top_object_uuid)) {
                uuid_copy(key.object_uuid, hit_path_array[j].sub_object_uuid);
			} else {
                uuid_copy(key.object_uuid, hit_path_array[j].top_object_uuid);
            }
            
            memcpy(key.field_name, hit_path_array[j].field_name, sizeof(key.field_name));
            key.negate_option = hit_path_array[j].negate_option;
			if (maat_rule_has_condition_query_key(rule, &key)) {
                populate_hit_path_with_rule(hit_path_array, j, n_hit_path,
                                               &n_new_hit_path, key.field_name, rule);
			}
		}
	}

    return (n_hit_path + n_new_hit_path);
}

static void
rule_compile_state_add_direct_hit_objects(struct rule_compile_state *rule_compile_state,
                                    struct maat_item *hit_items,
                                    size_t n_hit_items, struct field_hit_object_collection * attr_hit_obj_coll)
{
    if (NULL == rule_compile_state || NULL == hit_items) {
        return;
    }

    for (size_t i = 0; i < n_hit_items; i++) {
        utarray_push_back(attr_hit_obj_coll->direct_items, &hit_items[i]);
    }
}

static void
rule_compile_state_add_indirect_hit_objects(struct rule_compile_state *rule_compile_state,
                                      uuid_t *object_uuids, size_t n_object_uuids, 
                                      struct field_hit_object_collection * attr_hit_obj_coll)
{
    if (NULL == rule_compile_state || NULL == object_uuids) {
        return;
    }

    for (size_t i = 0; i < n_object_uuids; i++) {
        utarray_push_back(attr_hit_obj_coll->indirect_object_uuids, &object_uuids[i]);
    }
}

static void
rule_compile_state_add_hit_conditions(struct rule_compile_state *rule_compile_state,
                              UT_array *condition_id_array)
{
    int condition_id_idx_array[utarray_len(condition_id_array)];
    int condition_id_idx_array_len = 0;
    long long *condition_id = NULL;

    for (size_t i = 0; i < utarray_len(condition_id_array); i++) {
        condition_id = (long long *)utarray_eltptr(condition_id_array, i);
        if (utarray_find(rule_compile_state->all_hit_conditions, condition_id, compare_condition_id)) {
            continue;
        }
        condition_id_idx_array[condition_id_idx_array_len] = i;
        condition_id_idx_array_len++;
    }

    if (condition_id_idx_array_len > 0) {
        utarray_reserve(rule_compile_state->all_hit_conditions, condition_id_idx_array_len);

        for (size_t i = 0; i < condition_id_idx_array_len; i++) {
            condition_id = (long long *)utarray_eltptr(condition_id_array, condition_id_idx_array[i]);
            utarray_push_back(rule_compile_state->all_hit_conditions, condition_id);
        }
        utarray_sort(rule_compile_state->all_hit_conditions, compare_condition_id);
    }
}

static void
rule_compile_state_add_exclude_not_conditions(struct rule_compile_state *rule_compile_state,
                                      UT_array *condition_id_array)
{
    int condition_id_idx_array[utarray_len(condition_id_array)];
    int condition_id_idx_array_len = 0;
    long long *condition_id = NULL;

    for (size_t i = 0; i < utarray_len(condition_id_array); i++) {
        condition_id = (long long *)utarray_eltptr(condition_id_array, i);
        if (utarray_find(rule_compile_state->exclude_not_conditions, condition_id, compare_condition_id)) {
            continue;
        }
        condition_id_idx_array[condition_id_idx_array_len] = i;
        condition_id_idx_array_len++;
    }

    if (condition_id_idx_array_len > 0) {
        utarray_reserve(rule_compile_state->exclude_not_conditions, condition_id_idx_array_len);

        for (size_t i = 0; i < condition_id_idx_array_len; i++) {
            condition_id = (long long *)utarray_eltptr(condition_id_array, condition_id_idx_array[i]);
            utarray_push_back(rule_compile_state->exclude_not_conditions, condition_id);
        }
        utarray_sort(rule_compile_state->exclude_not_conditions, compare_condition_id);
    }
}

static void
rule_compile_state_add_hit_not_conditions(struct rule_compile_state *rule_compile_state,
                                  UT_array *condition_id_array)
{ 
    int condition_id_idx_array[utarray_len(condition_id_array)];
    int condition_id_idx_array_len = 0;
    long long *condition_id = NULL;

    for (size_t i = 0; i < utarray_len(condition_id_array); i++) {
        condition_id = (long long *)utarray_eltptr(condition_id_array, i);
        if (utarray_find(rule_compile_state->all_hit_conditions, condition_id, compare_condition_id)) {
            continue;
        }

        if (utarray_find(rule_compile_state->exclude_not_conditions, condition_id, compare_condition_id)) {
            continue;
        }
        condition_id_idx_array[condition_id_idx_array_len] = i;
        condition_id_idx_array_len++;
    }

    if (condition_id_idx_array_len > 0) {
        utarray_reserve(rule_compile_state->all_hit_conditions, condition_id_idx_array_len);

        for (size_t i = 0; i < condition_id_idx_array_len; i++) {
            condition_id = (long long *)utarray_eltptr(condition_id_array, condition_id_idx_array[i]);
            utarray_push_back(rule_compile_state->all_hit_conditions, condition_id);
        }
        utarray_sort(rule_compile_state->all_hit_conditions, compare_condition_id);
    }
}

static int
rule_runtime_add_rule(struct rule_runtime *rule_rt,
                            struct rule_schema *schema,
                            uuid_t *rule_uuid, const char *table_name,
                            const char *line, struct log_handle *logger)
{
    struct maat_rule *rule = NULL;
    struct rule_item *rule_item = rule_item_new(line, schema, table_name,
                                                         rule_rt->logger);
    if (NULL == rule_item) {
        goto ERROR;
    }

    int table_id = table_manager_get_table_id(schema->ref_tbl_mgr, table_name);
    if (table_id < 0) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d]table_name:%s has invalid table_id:%d, drop line:%s",
                  __FUNCTION__, __LINE__, table_name, table_id, line);
        goto ERROR;
    }

    int updating_flag = rcu_hash_is_updating(rule_rt->cfg_hash);

    if (1 == updating_flag) {
        rule = rcu_updating_hash_find(rule_rt->cfg_hash, (char *)rule_uuid,
                                         sizeof(uuid_t));
    } else {
        rule = rcu_hash_find(rule_rt->cfg_hash, (char *)rule_uuid, sizeof(uuid_t));
    }
    if (rule != NULL) {
        char rule_uuid_str[UUID_STR_LEN] = {0};
        uuid_unparse(*rule_uuid, rule_uuid_str);
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d]rule_id:%s already existed in rule table, drop line:%s",
                  __FUNCTION__, __LINE__, rule_uuid_str, line);
        goto ERROR;
    }

    rule = maat_rule_new(rule_rt, schema, table_name, *rule_uuid, line, rule_item);
    if (NULL == rule) {
        log_fatal(logger, MODULE_RULE,
                  "[%s:%d]maat_rule_new failed, drop line:%s",
                  __FUNCTION__, __LINE__, line);
        goto ERROR;
    }

    rcu_hash_add(rule_rt->cfg_hash, (char *)rule_uuid, sizeof(uuid_t), rule);

    return 0;

ERROR:
    if (rule_item != NULL) {
        rule_item_free(rule_item);
    }

    return -1;
}

static void rule_runtime_del_rule(struct rule_runtime *rule_rt,
                                    struct rule_schema *schema,
                                    uuid_t *rule_uuid,
                                    struct log_handle *logger)
{
    struct maat_rule *rule = NULL;

    int updating_flag = rcu_hash_is_updating(rule_rt->cfg_hash);
    if (1 == updating_flag) {
        // find in updating hash
        rule = rcu_updating_hash_find(rule_rt->cfg_hash, (char *)rule_uuid,
                                         sizeof(uuid_t));
    } else {
        // find in effective hash
        rule = rcu_hash_find(rule_rt->cfg_hash, (char *)rule_uuid, sizeof(uuid_t));
    }

    if (rule != NULL) {
        for (int i = 0; i < rule->condition_num; i++) {
            struct rule_condition *condition = rule->conditions + i;
            if (condition->in_use && condition->negate_option == CONDITION_NEGATE_OPTION_SET) {
                for (size_t j = 0; j < utarray_len(condition->literals); j++) {
                    struct condition_literal *literal = (struct condition_literal *)utarray_eltptr(condition->literals, j);
                    validate_table_not_condition(rule_rt, schema->ref_tbl_mgr, literal->field_name, MAAT_OP_DEL, logger);
                }
            }
        }

        rcu_hash_del(rule_rt->cfg_hash, (char *)rule_uuid, sizeof(uuid_t));
    }
}

int rule_runtime_update(void *rule_runtime, void *rule_schema, 
                           const char *table_name, const char *line, 
                           enum maat_operation op)
{
    if (NULL == rule_runtime || NULL == rule_schema || NULL == line) {
        return -1;
    }

    struct rule_schema *schema = (struct rule_schema *)rule_schema;
    struct rule_runtime *rule_rt = (struct rule_runtime *)rule_runtime;
    cJSON *tmp_obj = NULL;
    cJSON *json = cJSON_Parse(line);

    if (NULL == json) {
        log_fatal(rule_rt->logger, MODULE_RULE,
                  "[%s:%d]parse json failed, line:%s", __FUNCTION__, __LINE__, line);
        rule_rt->update_err_cnt++;
        return -1;
    }

    tmp_obj = cJSON_GetObjectItem(json, "uuid");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(rule_rt->logger, MODULE_RULE,
                  "[%s:%d] rule table:<%s> has no rule_id or not string format in table_line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        rule_rt->update_err_cnt++;
        cJSON_Delete(json);
        return -1;
    }
    uuid_t rule_uuid;
    uuid_parse(tmp_obj->valuestring, rule_uuid);

    if (MAAT_OP_DEL == op) {
        // delete
        rule_runtime_del_rule(rule_rt, schema, &rule_uuid, rule_rt->logger);
    } else {
        // add
        int ret = rule_runtime_add_rule(rule_rt, schema, &rule_uuid, 
                                              table_name, line, rule_rt->logger);
        if (ret < 0) {
            rule_rt->update_err_cnt++;
        }
    }

    cJSON_Delete(json);
    return 0;
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
	if (a->condition_num != b->condition_num) {
		return (a->condition_num - b->condition_num);
	} else {
        return uuid_compare(b->rule_uuid, a->rule_uuid);
	}
}

static void rule_sort_para_set(struct rule_sort_para *para, 
                                  const struct rule_item *item)
{
    uuid_copy(para->rule_uuid, item->rule_uuid);
	para->condition_num = item->condition_num;
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

int rule_runtime_match(int table_id, struct rule_runtime *rule_rt, uuid_t *rule_uuids,
                          size_t rule_ids_size, struct maat_state *state)
{
    struct rule_compile_state *rule_compile_state = state->rule_compile_state;
    struct rule_item *rule_items[rule_ids_size];
    int clear_scan_not_obj_flag = 0;

    utarray_clear(rule_compile_state->all_hit_conditions);
    utarray_clear(rule_compile_state->exclude_not_conditions);

    struct rule_compile_runtime_state *rule_compile_rt_state = NULL;
    HASH_FIND_INT(rule_compile_state->rule_runtime_state_hash, &table_id, rule_compile_rt_state);
    if (rule_compile_rt_state == NULL) {
        rule_compile_rt_state = ALLOC(struct rule_compile_runtime_state, 1);
        rule_compile_rt_state->table_id = table_id;
        HASH_ADD_INT(rule_compile_state->rule_runtime_state_hash, table_id, rule_compile_rt_state);
    }

    rule_compile_rt_state->hit_object_changed = 0;
    rule_compile_rt_state->need_scan_not_logic = 0;

    if (rule_compile_rt_state->rule_rt_version != rule_rt->version) {
        rule_compile_rt_state->rule_rt_version = rule_rt->version;
    }
    
    struct field_hit_object_collection *attr_hit_obj_coll = NULL, *tmp = NULL;
    HASH_ITER(hh, rule_compile_state->attr_hit_objects_hashtbl, attr_hit_obj_coll, tmp) {
        struct condition_query_key key;
        memset(&key, 0, sizeof(key));
        snprintf(key.field_name, sizeof(key.field_name), "%s", attr_hit_obj_coll->field_name);

        for (int i = 0; i < utarray_len(attr_hit_obj_coll->all_object_uuids); i++) {
            uuid_t *object_uuid = utarray_eltptr(attr_hit_obj_coll->all_object_uuids, i);
            uuid_copy(key.object_uuid, *object_uuid);
            key.negate_option = 0;

            struct condition_id_kv *condition_id_kv = NULL;
            HASH_FIND(hh, rule_rt->condition_id_kv_hash, &key, sizeof(key), condition_id_kv);
            if (condition_id_kv != NULL) {
                rule_compile_state_add_hit_conditions(rule_compile_state, condition_id_kv->condition_ids);
            }
        
            if (attr_hit_obj_coll->need_negate_condition) {
                key.negate_option = 1;
                HASH_FIND(hh, rule_rt->not_condition_id_kv_hash, &key, sizeof(key), condition_id_kv);
                if (condition_id_kv != NULL) {
                    rule_compile_state_add_exclude_not_conditions(rule_compile_state, condition_id_kv->condition_ids);
                }
            }
        }

        if (attr_hit_obj_coll->need_scan_not_object) {
            clear_scan_not_obj_flag = 1;
        }
    }

    //not conditions
    struct condition_id_kv *condition_id_kv = NULL, *tmp_condition_id_kv = NULL;
    HASH_ITER(hh, rule_rt->not_condition_id_kv_hash, condition_id_kv, tmp_condition_id_kv) {
        HASH_FIND_STR(rule_compile_state->attr_hit_objects_hashtbl, condition_id_kv->key.field_name, attr_hit_obj_coll);
        if (attr_hit_obj_coll == NULL || attr_hit_obj_coll->need_negate_condition == 0) {
            continue;
        }

        if (utarray_find(attr_hit_obj_coll->all_object_uuids, &(condition_id_kv->key.object_uuid), compare_object_uuid) != NULL) {
            continue;
        }

        rule_compile_state_add_hit_not_conditions(rule_compile_state, condition_id_kv->condition_ids);

        if (state->maat_inst->opts.hit_path_on && attr_hit_obj_coll->need_scan_not_object) {
            uuid_t null_uuid;
            uuid_clear(null_uuid);
            rule_compile_state_add_internal_hit_path(rule_compile_state, null_uuid,
                                                condition_id_kv->key.object_uuid,
                                                condition_id_kv->key.field_name, 1,
                                                attr_hit_obj_coll->Nth_scan);
        }
    }

    if (clear_scan_not_obj_flag) {
        HASH_ITER(hh, rule_compile_state->attr_hit_objects_hashtbl, attr_hit_obj_coll, tmp) {
            if (attr_hit_obj_coll->need_scan_not_object) {
                attr_hit_obj_coll->need_scan_not_object = 0;
            }
        }
    }

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
        uuid_copy(rule_uuids[i], rule_items[i]->rule_uuid);
	}
    
    return MIN(bool_match_ret, rule_ids_size);
}

int rule_runtime_need_compile(int table_id, struct rule_runtime *rule_rt, struct rule_compile_state *rule_compile_state)
{
    struct rule_compile_runtime_state *rule_compile_rt_state = NULL;
    
    HASH_FIND_INT(rule_compile_state->rule_runtime_state_hash, &table_id, rule_compile_rt_state);
    if (rule_compile_rt_state == NULL || rule_compile_rt_state->rule_rt_version == 0) {//haven't compiled yet, need compile
        return 1;
    }

    if (rule_compile_rt_state->rule_rt_version != rule_rt->version) {
        return 0;
    }

    if (rule_compile_rt_state->hit_object_changed || rule_compile_rt_state->need_scan_not_logic) {
        return 1;
    }

    return 0;
}

static struct field_hit_object_collection * rule_compile_state_get_attr_hit_obj_coll(struct maat *maat_inst, struct rule_compile_state *rule_compile_state,
                                                                                          const char *field_name)
{
    struct field_hit_object_collection *attr_hit_obj_coll = NULL;
    HASH_FIND_STR(rule_compile_state->attr_hit_objects_hashtbl, field_name, attr_hit_obj_coll);
    if (attr_hit_obj_coll == NULL) {
        attr_hit_obj_coll = ALLOC(struct field_hit_object_collection, 1);
        snprintf(attr_hit_obj_coll->field_name, sizeof(attr_hit_obj_coll->field_name), "%s", field_name);
        utarray_new(attr_hit_obj_coll->all_object_uuids, &ut_object_uuid_icd);

        if (1 == maat_inst->opts.hit_object_on) {
            utarray_new(attr_hit_obj_coll->direct_items, &ut_maat_item_icd);
            utarray_new(attr_hit_obj_coll->indirect_object_uuids, &ut_object_uuid_icd);
        }
        HASH_ADD_STR(rule_compile_state->attr_hit_objects_hashtbl, field_name, attr_hit_obj_coll);
    }

    return attr_hit_obj_coll;
}

static int rule_compile_state_add_hit_objects(struct rule_compile_state *rule_compile_state, 
                                            struct field_hit_object_collection * attr_hit_obj_coll,
                                            uuid_t object_uuids[], size_t n_object_uuids)
{
    int object_uuid_idx_array[n_object_uuids];
    int object_uuid_idx_array_len = 0;
    uuid_t *object_uuid = NULL;

    for (size_t i = 0; i < n_object_uuids; i++) {
        object_uuid = object_uuids + i;
        if (utarray_find(attr_hit_obj_coll->all_object_uuids, object_uuid, compare_object_uuid)) {
            continue;
        }
        object_uuid_idx_array[object_uuid_idx_array_len] = i;
        object_uuid_idx_array_len++;
    }

    if (object_uuid_idx_array_len > 0) {
        utarray_reserve(attr_hit_obj_coll->all_object_uuids, object_uuid_idx_array_len);

        for (size_t i = 0; i < object_uuid_idx_array_len; i++) {
            object_uuid = object_uuids + object_uuid_idx_array[i];
            utarray_push_back(attr_hit_obj_coll->all_object_uuids, object_uuid);
        }
        utarray_sort(attr_hit_obj_coll->all_object_uuids, compare_object_uuid);
    }

    return object_uuid_idx_array_len;
}

int rule_compile_state_update(struct rule_compile_state *rule_compile_state, struct maat *maat_inst,
                         const char *field_name, int custom_rule_tbl_id, int Nth_scan,
                         struct maat_item *hit_items, size_t n_hit_item)
{
    size_t i = 0, j = 0;
    size_t hit_cnt = n_hit_item;
    uuid_t hit_object_uuids[MAX_HIT_OBJECT_NUM];

    rule_compile_state->Nth_scan = Nth_scan;

    for (i = 0; i < hit_cnt; i++) {
        uuid_copy(hit_object_uuids[i], hit_items[i].object_uuid);
    }

    int object_group_table_id = table_manager_get_object_group_table_id(maat_inst->tbl_mgr);
    void *object_group_rt = table_manager_get_runtime(maat_inst->tbl_mgr, object_group_table_id);

    uuid_t super_object_uuids[MAX_HIT_OBJECT_NUM];
    size_t super_object_cnt = object_group_runtime_get_super_objects(object_group_rt, hit_object_uuids,
                                                                  hit_cnt, super_object_uuids,
                                                                  MAX_HIT_OBJECT_NUM);

    struct field_hit_object_collection * attr_hit_obj_coll = rule_compile_state_get_attr_hit_obj_coll(maat_inst, rule_compile_state, field_name);
    assert(attr_hit_obj_coll != NULL);

    if (1 == maat_inst->opts.hit_path_on && hit_cnt > 0) {
        for (i = 0; i < hit_cnt; i++) {
            rule_compile_state_add_internal_hit_path(rule_compile_state, hit_items[i].item_uuid,
                                                hit_items[i].object_uuid, field_name, 0, Nth_scan);
        }
    }

    if (1 == maat_inst->opts.hit_object_on) {
        rule_compile_state_add_direct_hit_objects(rule_compile_state, hit_items, hit_cnt, attr_hit_obj_coll);
        rule_compile_state_add_indirect_hit_objects(rule_compile_state, super_object_uuids,
                                              super_object_cnt, attr_hit_obj_coll);
    }

    for (j = 0; j < super_object_cnt && hit_cnt < MAX_HIT_OBJECT_NUM; j++) {
        uuid_copy(hit_object_uuids[hit_cnt++], super_object_uuids[j]);
    }

    if (rule_compile_state_add_hit_objects(rule_compile_state, attr_hit_obj_coll, hit_object_uuids, hit_cnt) > 0) {
        struct rule_compile_runtime_state *rule_compile_rt_state = NULL, *tmp = NULL;
        HASH_ITER(hh, rule_compile_state->rule_runtime_state_hash, rule_compile_rt_state, tmp) {
            rule_compile_rt_state->hit_object_changed = 1;
        }
    }

    return hit_cnt;
}

void rule_compile_state_not_logic_update(struct maat *maat_inst, struct rule_compile_state *rule_compile_state, const char *field_name, int Nth_scan)
{
    if (NULL == maat_inst || NULL == rule_compile_state) {
        return;
    }

    struct field_hit_object_collection *attr_hit_obj_coll = rule_compile_state_get_attr_hit_obj_coll(maat_inst, rule_compile_state, field_name);
    assert(attr_hit_obj_coll != NULL);

    attr_hit_obj_coll->need_negate_condition = 1;
    attr_hit_obj_coll->need_scan_not_object = 1;
    attr_hit_obj_coll->Nth_scan = Nth_scan;

    struct rule_compile_runtime_state *rule_compile_rt_state = NULL, *tmp = NULL;
    HASH_ITER(hh, rule_compile_state->rule_runtime_state_hash, rule_compile_rt_state, tmp) {
        rule_compile_rt_state->need_scan_not_logic = 1;
    }

    return;
}

size_t rule_compile_state_get_indirect_hit_objects(struct maat *maat_inst, struct rule_compile_state *rule_compile_state, 
                                                    const char *field_name, uuid_t object_array[], size_t array_size)
{
    struct field_hit_object_collection *attr_hit_obj_coll = rule_compile_state_get_attr_hit_obj_coll(maat_inst, rule_compile_state, field_name);
    assert(attr_hit_obj_coll != NULL);

    size_t i = 0;
    for (i = 0; i < utarray_len(attr_hit_obj_coll->indirect_object_uuids) && i < array_size; i++) {
        uuid_copy(object_array[i], *(uuid_t *)utarray_eltptr(attr_hit_obj_coll->indirect_object_uuids, i));
    }

    utarray_clear(attr_hit_obj_coll->indirect_object_uuids);

    return i;
}

size_t rule_compile_state_get_indirect_hit_object_cnt(struct maat *maat_inst, struct rule_compile_state *rule_compile_state, const char *field_name)
{
    struct field_hit_object_collection *attr_hit_obj_coll = rule_compile_state_get_attr_hit_obj_coll(maat_inst, rule_compile_state, field_name);
    assert(attr_hit_obj_coll != NULL);

    return utarray_len(attr_hit_obj_coll->indirect_object_uuids);
}

size_t rule_compile_state_get_direct_hit_items(struct maat * maat_inst, struct rule_compile_state *rule_compile_state, const char *field_name,
                                                uuid_t item_array[],  uuid_t direct_object_array[], size_t array_size)
{
    size_t i = 0;

    struct field_hit_object_collection *attr_hit_obj_coll = rule_compile_state_get_attr_hit_obj_coll(maat_inst, rule_compile_state, field_name);
    assert(attr_hit_obj_coll != NULL);

    for (i = 0; i < utarray_len(attr_hit_obj_coll->direct_items) && i < array_size; i++) {
        struct maat_item *item = (struct maat_item *)utarray_eltptr(attr_hit_obj_coll->direct_items, i);
        uuid_copy(direct_object_array[i], item->object_uuid);
        uuid_copy(item_array[i], item->item_uuid);
    }
    utarray_clear(attr_hit_obj_coll->direct_items);

    return i;
}

size_t rule_compile_state_get_direct_hit_item_cnt(struct maat * maat_inst, struct rule_compile_state *rule_compile_state, const char *field_name)
{
    struct field_hit_object_collection *attr_hit_obj_coll = rule_compile_state_get_attr_hit_obj_coll(maat_inst, rule_compile_state, field_name);
    assert(attr_hit_obj_coll != NULL);

    return utarray_len(attr_hit_obj_coll->direct_items);
}

size_t rule_compile_state_get_hit_objects(struct maat *maat_inst, struct rule_compile_state *rule_compile_state, const char *field_name,
                                          uuid_t object_array[], size_t array_size)
{
    struct field_hit_object_collection *attr_hit_obj_coll = rule_compile_state_get_attr_hit_obj_coll(maat_inst, rule_compile_state, field_name);
    assert(attr_hit_obj_coll != NULL);

    size_t i = 0;
    for (i = 0; i < utarray_len(attr_hit_obj_coll->all_object_uuids) && i < array_size; i++) {
        uuid_copy(object_array[i], *(uuid_t *)utarray_eltptr(attr_hit_obj_coll->all_object_uuids, i));
    }

    return i;
}

size_t rule_compile_state_get_hit_object_cnt(struct maat *maat_inst, struct rule_compile_state *rule_compile_state, const char *field_name)
{
    struct field_hit_object_collection *attr_hit_obj_coll = rule_compile_state_get_attr_hit_obj_coll(maat_inst, rule_compile_state, field_name);
    assert(attr_hit_obj_coll != NULL);

    return utarray_len(attr_hit_obj_coll->all_object_uuids);
}

size_t rule_compile_state_get_field_names(struct rule_compile_state *rule_compile_state, const char *field_name_array[], size_t array_size)
{
    size_t i = 0;
    struct field_hit_object_collection *attr_hit_obj_coll = NULL, *tmp = NULL;
    HASH_ITER(hh, rule_compile_state->attr_hit_objects_hashtbl, attr_hit_obj_coll, tmp) {
        field_name_array[i] = attr_hit_obj_coll->field_name;
        i++;
        if (i >= array_size) {
            break;
        }
    }

    return i;
}

size_t rule_compile_state_get_field_cnt(struct rule_compile_state *rule_compile_state)
{
    return HASH_COUNT(rule_compile_state->attr_hit_objects_hashtbl);
}

size_t rule_compile_state_get_internal_hit_paths(struct rule_compile_state *rule_compile_state,
                                            struct rule_runtime *rule_rt,
                                            struct object_group_runtime *object_group_rt,
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
        uuid_t super_object_uuids[MAX_HIT_OBJECT_NUM];
        UT_array *valid_super_object_uuids;
        utarray_new(valid_super_object_uuids, &ut_object_uuid_icd);

        size_t super_object_cnt =
            object_group_runtime_get_super_objects(object_group_rt, &(internal_path->object_uuid), 1,
                                                 super_object_uuids, MAX_HIT_OBJECT_NUM);
        for (size_t idx = 0; idx < super_object_cnt; idx++) {
            utarray_push_back(valid_super_object_uuids, &super_object_uuids[idx]);
        }

        /*
            internal_path->object_id can be referenced directly by rule, 
            so add it to hit_path which super_object_ids is -1
            ------------------------------------------------------------------------------
            NOTE: Add the hit path as long as the item is hit
        */
        uuid_t super_object_uuid;
        uuid_clear(super_object_uuid);
        utarray_push_back(valid_super_object_uuids, &super_object_uuid);
        
        uuid_t *p = NULL;
        struct maat_hit_path tmp_path;
    
        for (p = utarray_front(valid_super_object_uuids);
             p != NULL && hit_path_cnt < array_size;
             p = utarray_next(valid_super_object_uuids, p)) {
            memset(&tmp_path, 0, sizeof(tmp_path));
            tmp_path.Nth_scan = internal_path->Nth_scan;
            uuid_copy(tmp_path.item_uuid, internal_path->item_uuid);
            uuid_copy(tmp_path.sub_object_uuid, internal_path->object_uuid);
            uuid_copy(tmp_path.top_object_uuid, *p);

            memcpy(tmp_path.field_name, internal_path->field_name, sizeof(tmp_path.field_name));
            tmp_path.negate_option = internal_path->negate_option;
            tmp_path.condition_index = -1;
            uuid_clear(tmp_path.rule_uuid);

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
        utarray_free(valid_super_object_uuids);
    }

    return hit_path_cnt;
}

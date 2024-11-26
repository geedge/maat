#include "test_utils.h"
#include "maat_redis_monitor.h"
#include "maat_utils.h"
#include "maat_table.h"
#include "maat_core.h"
#include "maat_config_monitor.h"
#include "yyjson/yyjson.h"

#include <assert.h>
#include <unistd.h>

int line_idx = 0;
long long absolute_expire_time = 0;

static int
count_line_num_cb(const char *table_name, const char *line, void *u_para, enum maat_operation op)
{
	(*((unsigned int *)u_para))++;
	return 0;
}

static int
make_serial_rule(const char *table_name, const char *line, void *u_para, enum maat_operation op)
{
	struct serial_rule *s_rule=(struct serial_rule *)u_para;
    redisContext *ctx = s_rule->ref_ctx;
	char *buff = ALLOC(char, strlen(line) + 1);
    cJSON *rule_uuid = NULL;
    int ret = 0;

    memcpy(buff, line, strlen(line) + 1);

	while (buff[strlen(line) - 1] == '\n' ||
           buff[strlen(line) - 1] == '\t') {
		buff[strlen(line) - 1] = '\0';
	}

    cJSON *json = cJSON_Parse(line);
    if (NULL == json) {
        ret = -1;
        goto END;
    }
    rule_uuid = cJSON_GetObjectItem(json, "uuid");
    
    if (NULL == rule_uuid) {
        rule_uuid = cJSON_GetObjectItem(json, "object_uuid");//for object_group table
    }

    if (NULL == rule_uuid || rule_uuid->type != cJSON_String) {
        ret = -1;
        goto END;
    }

	maat_set_serial_rule(s_rule + line_idx, op, rule_uuid->valuestring,
                         table_name, buff, absolute_expire_time);
    (s_rule + line_idx)->ref_ctx = ctx;
	line_idx++;

END:
    if (json) {
        cJSON_Delete(json);
    }
    if (buff) {
        FREE(buff);
    }

	return ret;
}

int write_json_to_redis(const char *json_filename, char *redis_ip, int redis_port,
                        int redis_db, struct log_handle *logger)
{
    char *json_buff = NULL;
    size_t json_buff_sz = 0;
    cJSON *json_root = NULL;
    
    int ret = load_file_to_memory(json_filename, (unsigned char **)&json_buff,
                                  &json_buff_sz);
    if (ret < 0) {
        return -1;
    }

    convert_maat_json_rule(&json_root, (unsigned char *)json_buff);

    if (json_buff) {
        FREE(json_buff);
    }

    redisContext *c = maat_connect_redis(redis_ip, redis_port, redis_db, logger);
    if (NULL == c) {
        return -1;
    }

    redisReply *reply = maat_wrap_redis_command(c, logger, "flushdb");
    if (NULL == reply) {
        return -1;
    } else {
        freeReplyObject(reply);
	    reply = NULL;
    }

    size_t total_line_cnt = 0;
    config_monitor_traverse(0, json_root, NULL, count_line_num_cb,
                            NULL, &total_line_cnt, NULL, logger);

    struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
    s_rule->ref_ctx = c;
    long long server_time = maat_redis_server_time_s(c);
    if (server_time < 0) {
        return -1;
    }

    absolute_expire_time = server_time + 300;
    config_monitor_traverse(0, json_root, NULL, make_serial_rule,
                            NULL, s_rule, NULL, logger);
    s_rule->ref_ctx = NULL;
    line_idx = 0;
    absolute_expire_time = 0;

    int success_cnt = 0;
    do {
        success_cnt = maat_cmd_write_rule(c, s_rule, total_line_cnt,
                                          server_time, logger);
    } while (success_cnt < 0);

    assert(success_cnt == (int)total_line_cnt);

    for (size_t i = 0; i < total_line_cnt; i++) {
        maat_clear_rule_cache(s_rule + i);
    }
    FREE(s_rule);
    redisFree(c);
    cJSON_Delete(json_root);

    return 0;
}

int rule_table_set_line(struct maat *maat_inst, const char *table_name,
                           enum maat_operation op, const char *rule_uuid_str,
                           struct maat_cmd_and_condition and_conditions[],
                           int condition_num, const char *action_para_str, int expire_after)
{
    cJSON *json_root = cJSON_CreateObject();

    cJSON_AddStringToObject(json_root, "uuid", rule_uuid_str);
    cJSON *and_conditions_array = cJSON_CreateArray();

    for (int i = 0; i < condition_num; i++) {
        cJSON *and_condition = cJSON_CreateObject();
        cJSON *or_conditions_array = cJSON_CreateArray();
        for (int j = 0; j < and_conditions[i].or_condition_num; j++) {
            cJSON *or_condition = cJSON_CreateObject();
            cJSON *object_uuids_array = cJSON_CreateArray();
            for (int k = 0; k < and_conditions[i].or_conditions[j].object_num; k++) {
                cJSON_AddItemToArray(object_uuids_array, cJSON_CreateString(and_conditions[i].or_conditions[j].object_uuids_str[k]));
            }
            cJSON_AddItemToObject(or_condition, "object_uuids", object_uuids_array);
            cJSON_AddStringToObject(or_condition, "field_name", and_conditions[i].or_conditions[j].field_name);

            cJSON_AddItemToArray(or_conditions_array, or_condition);
        }

        cJSON_AddItemToObject(and_condition, "or_conditions", or_conditions_array);
        
        if (and_conditions[i].negate_option) {
            cJSON_AddBoolToObject(and_condition, "negate_option", true);
        } else {
            cJSON_AddBoolToObject(and_condition, "negate_option", false);
        }
        
        cJSON_AddItemToArray(and_conditions_array, and_condition);
    }

    cJSON_AddItemToObject(json_root, "and_conditions", and_conditions_array);

    if (action_para_str) {
        cJSON_AddStringToObject(json_root, "action_parameter", action_para_str);
    }

    cJSON_AddNumberToObject(json_root, "priority", 1000);//TODO: support config priority

    char *json_str = cJSON_PrintUnformatted(json_root);

    struct maat_cmd_line line_rule;
    line_rule.rule_uuid_str = rule_uuid_str;
    line_rule.table_line = json_str;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    int ret = maat_cmd_set_line(maat_inst, &line_rule, op);
    free(json_str);

    cJSON_Delete(json_root);

    return ret;
}

int object_group_table_set_line(struct maat *maat_inst, const char *table_name,
                               enum maat_operation op, const char *object_uuid_str,
                               const char inc_object_uuid_strs[][UUID_STR_LEN], int inc_object_num,
                               const char exc_object_uuid_strs[][UUID_STR_LEN], int exc_object_num, int expire_after)
{
    cJSON *json_root = cJSON_CreateObject();

    cJSON_AddStringToObject(json_root, "object_uuid", object_uuid_str);

    if (inc_object_num > 0) {
        cJSON *inc_object_uuid_str_array = cJSON_CreateArray();
        for (int i = 0; i < inc_object_num; i++) {
            cJSON_AddItemToArray(inc_object_uuid_str_array, cJSON_CreateString(inc_object_uuid_strs[i]));
        }
        cJSON_AddItemToObject(json_root, "included_sub_object_uuids", inc_object_uuid_str_array);
    }

    if (exc_object_num > 0) {
        cJSON *exc_object_uuid_str_array = cJSON_CreateArray();
        for (int i = 0; i < exc_object_num; i++) {
            cJSON_AddItemToArray(exc_object_uuid_str_array, cJSON_CreateString(exc_object_uuid_strs[i]));
        }
        cJSON_AddItemToObject(json_root, "excluded_sub_object_uuids", exc_object_uuid_str_array);
    }

    char *json_str = cJSON_PrintUnformatted(json_root);

    struct maat_cmd_line line_rule;
    line_rule.rule_uuid_str = object_uuid_str;
    line_rule.table_line = json_str;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    int ret = maat_cmd_set_line(maat_inst, &line_rule, op);
    free(json_str);

    cJSON_Delete(json_root);

    return ret;
}

int expr_table_set_line(struct maat *maat_inst, const char *table_name,
                        enum maat_operation op, const char *item_uuid_str,
                        const char *object_uuid_str, const char *expression,
                        enum expr_type expr_type, int expire_after)
{
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }
    
    enum table_type table_type =
        table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    assert(table_type == TABLE_TYPE_EXPR);

    cJSON *json_root = cJSON_CreateObject();
    const char *expr_type_str = NULL;
    switch (expr_type) {
        case EXPR_TYPE_AND:
            expr_type_str = "and";
            break;
        case EXPR_TYPE_REGEX:
            expr_type_str = "regex";
            break;
        default:
            expr_type_str = "invalid";
            break;
    }

    cJSON_AddStringToObject(json_root, "uuid", item_uuid_str);
    cJSON_AddStringToObject(json_root, "object_uuid", object_uuid_str);
    cJSON_AddStringToObject(json_root, "expression", expression);
    cJSON_AddStringToObject(json_root, "expr_type", expr_type_str);

    char *json_str = cJSON_PrintUnformatted(json_root);

    struct maat_cmd_line line_rule;
    line_rule.rule_uuid_str = item_uuid_str;
    line_rule.table_line = json_str;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    int ret = maat_cmd_set_line(maat_inst, &line_rule, op);
    free(json_str);

    cJSON_Delete(json_root);

    return ret;
}

int interval_table_set_line(struct maat *maat_inst, const char *table_name,
    enum maat_operation op, const char *item_uuid_str, const char *object_uuid_str,
    const char *interval_str, int expire_after)
{
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    enum table_type table_type =
        table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    assert(table_type == TABLE_TYPE_INTERVAL);

    cJSON *json_root = cJSON_CreateObject();
    cJSON_AddStringToObject(json_root, "uuid", item_uuid_str);
    cJSON_AddStringToObject(json_root, "object_uuid", object_uuid_str);
    cJSON_AddStringToObject(json_root, "interval", interval_str);

    char *json_str = cJSON_PrintUnformatted(json_root);

    struct maat_cmd_line line_rule;
    line_rule.rule_uuid_str = item_uuid_str;
    line_rule.table_line = json_str;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    int ret = maat_cmd_set_line(maat_inst, &line_rule, op);
    free(json_str);

    cJSON_Delete(json_root);

    return ret;
}

int ip_table_set_line(struct maat *maat_inst, const char *table_name,
                      enum maat_operation op, const char *item_uuid_str,
                      const char *object_uuid_str, const char *ip_str, 
                      const char *port_str, int expire_after)
{
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    cJSON *json_root = cJSON_CreateObject();
    cJSON_AddStringToObject(json_root, "uuid", item_uuid_str);
    cJSON_AddStringToObject(json_root, "object_uuid", object_uuid_str);
    cJSON_AddStringToObject(json_root, "ip", ip_str);
    if (port_str) {
        cJSON_AddStringToObject(json_root, "port", port_str);
    }

    char *json_str = cJSON_PrintUnformatted(json_root);
    struct maat_cmd_line line_rule;
    
    line_rule.rule_uuid_str = item_uuid_str;
    line_rule.table_line = json_str;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    int ret = maat_cmd_set_line(maat_inst, &line_rule, op);
    free(json_str);

    cJSON_Delete(json_root);

    return ret;
}

int flag_table_set_line(struct maat *maat_inst, const char *table_name,
                    enum maat_operation op, const char *item_uuid_str,
                    const char *object_uuid_str, long long flag,
                    long long flag_mask, int expire_after)
{
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *json_root = yyjson_mut_obj(doc);

    yyjson_mut_obj_add_str(doc, json_root, "uuid", item_uuid_str);
    yyjson_mut_obj_add_str(doc, json_root, "object_uuid", object_uuid_str);
    yyjson_mut_obj_add_int(doc, json_root, "flag", flag);
    yyjson_mut_obj_add_int(doc, json_root, "mask", flag_mask);

    yyjson_mut_doc_set_root(doc, json_root);

    char *json_str = yyjson_mut_write(doc, YYJSON_WRITE_NOFLAG, NULL);

    struct maat_cmd_line line_rule;

    line_rule.rule_uuid_str = item_uuid_str;
    line_rule.table_line = json_str;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    int ret = maat_cmd_set_line(maat_inst, &line_rule, op);
    free(json_str);

    yyjson_mut_doc_free(doc);

    return ret;
}

void random_keyword_generate(char *keyword_buf, size_t sz)
{
#define MIN_KEYWORD_LEN	4
	size_t i = 0, len = 0;
	len = random() % (sz - 1 - MIN_KEYWORD_LEN) + MIN_KEYWORD_LEN;

	for (i = 0; i < len; i++) {
		keyword_buf[i] = 'a' + random() % ('z' - 'a');
	}
	keyword_buf[i] = '\0';
}

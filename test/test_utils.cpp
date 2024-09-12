#include "test_utils.h"
#include "maat_redis_monitor.h"
#include "maat_utils.h"
#include "maat_table.h"
#include "maat_core.h"
#include "maat_config_monitor.h"

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

    memcpy(buff, line, strlen(line) + 1);

	while (buff[strlen(line) - 1] == '\n' ||
           buff[strlen(line) - 1] == '\t') {
		buff[strlen(line) - 1] = '\0';
	}

    const char *redis_rule_key = "TEST_RULE_KEY";
    redisReply *reply =
        maat_wrap_redis_command(ctx, NULL, "INCRBY %s %d", redis_rule_key, 1);

	if (reply->type == REDIS_REPLY_NIL) {
		printf("incrby redis_rule_key:%s failed.", redis_rule_key);
        return -1;
	} else {
		s_rule->rule_id = maat_read_redis_integer(reply);
		freeReplyObject(reply);
		reply = NULL;
	}

	maat_set_serial_rule(s_rule + line_idx, MAAT_OP_ADD, s_rule->rule_id,
                         table_name, buff, absolute_expire_time);
    (s_rule + line_idx)->ref_ctx = ctx;
	line_idx++;

    FREE(buff);

	return 0;
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

    convert_maat_json_rule(json_root, (unsigned char *)json_buff);

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
                           enum maat_operation op, long long rule_id,
                           const char *user_region, int condition_num,
                           int expire_after)
{
    char table_line[1024 * 16] = {0};
    sprintf(table_line, "%lld\t0\t0\t0\t0\t0\t%s\t%d\t%d\t0.0", 
            rule_id, user_region, condition_num, op);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = rule_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule, op);
}

#define TO_OBJECT2X_KEY(object_id, parent_id, condition_index) \
        (((unsigned long)object_id<<32|parent_id) + condition_index)

int object2rule_table_set_line(struct maat *maat_inst, const char *table_name,
                                 enum maat_operation op, long long object_id,
                                 long long rule_id, int negate_option,
                                 const char *attribute_name, int condition_index,
                                 int expire_after)
{
    char table_line[128] = {0};
    sprintf(table_line, "%lld\t%lld\t%d\t%s\t%d\t%d", 
            object_id, rule_id, negate_option, attribute_name, condition_index, op);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = TO_OBJECT2X_KEY(object_id, rule_id, condition_index);
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule, op);
}

int object2object_table_set_line(struct maat *maat_inst, const char *table_name,
                               enum maat_operation op, long long object_id,
                               long long sub_object_id, int expire_after)
{
    char table_line[128] = {0};
    sprintf(table_line, "%lld\t%lld\t%s\t%d", object_id, sub_object_id,
            "null", op);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = TO_OBJECT2X_KEY(object_id, sub_object_id, 0);
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule, op);
}

int expr_table_set_line(struct maat *maat_inst, const char *table_name,
                        enum maat_operation op, long long item_id,
                        long long object_id, const char *keywords,
                        const char *district, int expr_type, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }
    
    enum table_type table_type =
        table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    assert(table_type == TABLE_TYPE_EXPR ||
           table_type == TABLE_TYPE_EXPR_PLUS);

    if (table_type == TABLE_TYPE_EXPR_PLUS) {
        sprintf(table_line, "%lld\t%lld\t%s\t%d\t%s\t%d",
                item_id, object_id, district, expr_type, keywords, op);
    } else {
        sprintf(table_line, "%lld\t%lld\t%d\t%s\t%d",
                item_id, object_id, expr_type, keywords, op);
    }

    struct maat_cmd_line line_rule;
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule, op);
}

int interval_table_set_line(struct maat *maat_inst, const char *table_name,
    enum maat_operation op, long long item_id, long long object_id,
    const char *port_str, const char *district, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    enum table_type table_type =
        table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    assert(table_type == TABLE_TYPE_INTERVAL ||
           table_type == TABLE_TYPE_INTERVAL_PLUS);

    if (table_type == TABLE_TYPE_INTERVAL_PLUS) {
        sprintf(table_line, "%lld\t%lld\t%s\t%s\t%d",
                item_id, object_id, district, port_str, op);
    } else {
        sprintf(table_line, "%lld\t%lld\t%s\t%d",
                item_id, object_id, port_str, op);
    }

    struct maat_cmd_line line_rule;
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule, op);
}

int ip_table_set_line(struct maat *maat_inst, const char *table_name,
                      enum maat_operation op, long long item_id,
                      long long object_id, const char *ip, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    sprintf(table_line, "%lld\t%lld\t%s\t0-65535\t%d",
            item_id, object_id, ip, op);
    struct maat_cmd_line line_rule;
    
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule, op);
}
int flag_table_set_line(struct maat *maat_inst, const char *table_name,
                    enum maat_operation op, long long item_id,
                    long long object_id, long long flag,
                    long long flag_mask, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    sprintf(table_line, "%lld\t%lld\t%lld\t%lld\t%d",
            item_id, object_id, flag, flag_mask, op);
    struct maat_cmd_line line_rule;

    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule, op);
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

#pragma once

#include "maat_utils.h"
#include "maat_command.h"
#include "maat_expr.h"
#include "ip_matcher/ip_matcher.h"

struct maat_cmd_or_condition {
    const char *object_uuids_str[8];
    int object_num;
    const char *attribute_name;
};

struct maat_cmd_and_condition {
    int negate_option;
    int or_condition_num;
    struct maat_cmd_or_condition or_conditions[8];
};

int write_json_to_redis(const char *json_filename, char *redis_ip, int redis_port,
                        int redis_db, struct log_handle *logger);

int rule_table_set_line(struct maat *maat_inst, const char *table_name,
                           enum maat_operation op, const char *rule_uuid_str,
                           struct maat_cmd_and_condition and_conditions[],
                           int condition_num, const char *action_para_str, int expire_after);

int object2object_table_set_line(struct maat *maat_inst, const char *table_name,
                               enum maat_operation op, const char *object_uuid_str,
                               const char inc_object_uuid_strs[][UUID_STR_LEN], int inc_object_num,
                               const char exc_object_uuid_strs[][UUID_STR_LEN], int exc_object_num, int expire_after);

int expr_table_set_line(struct maat *maat_inst, const char *table_name,
                        enum maat_operation op, const char *item_uuid_str,
                        const char *object_uuid_str, const char *expression,
                        enum expr_type expr_type, int expire_after);

int interval_table_set_line(struct maat *maat_inst, const char *table_name,
    enum maat_operation op, const char *item_uuid_str, const char *object_uuid_str,
    const char *interval_str, int expire_after);

int ip_table_set_line(struct maat *maat_inst, const char *table_name,
                      enum maat_operation op, const char *item_uuid_str,
                      const char *object_uuid_str, const char *ip_str, 
                      const char *port_str, int expire_after);

int flag_table_set_line(struct maat *maat_inst, const char *table_name,
                    enum maat_operation op, const char *item_uuid_str,
                    const char *object_uuid_str, long long flag,
                    long long flag_mask, int expire_after);

void random_keyword_generate(char *keyword_buf, size_t sz);
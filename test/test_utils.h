#pragma once

#include "maat_utils.h"
#include "maat_command.h"
#include "ip_matcher/ip_matcher.h"

struct maat_cmd_condition {
    const char *object_uuids_str[8];
    int object_num;
    int negate_option;
    const char *attribute_name;
};
int write_json_to_redis(const char *json_filename, char *redis_ip, int redis_port,
                        int redis_db, struct log_handle *logger);

int rule_table_set_line(struct maat *maat_inst, const char *table_name,
                           enum maat_operation op, uuid_t rule_uuid,
                           const char *user_region, struct maat_cmd_condition conditions[],
                           int condition_num, int expire_after);

int object2object_table_set_line(struct maat *maat_inst, const char *table_name,
                               enum maat_operation op, long long object_id,
                               long long sub_object_id, int expire_after);

int expr_table_set_line(struct maat *maat_inst, const char *table_name,
                        enum maat_operation op, long long item_id,
                        long long object_id, const char *keywords,
                        const char *district, int expr_type, int expire_after);

int interval_table_set_line(struct maat *maat_inst, const char *table_name,
                        enum maat_operation op, long long item_id, 
                        long long object_id, const char *port_str, 
                        const char *district, int expire_after);

int ip_table_set_line(struct maat *maat_inst, const char *table_name,
                      enum maat_operation op, long long item_id,
                      long long object_id, const char *ip, int expire_after);

int flag_table_set_line(struct maat *maat_inst, const char *table_name,
                        enum maat_operation op, long long item_id,
                        long long object_id, long long flag,
                        long long flag_mask, int expire_after);

void random_keyword_generate(char *keyword_buf, size_t sz);
/**********************************************************************************************
*	File: maat_redis_monitor.c
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-11-29
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <stdio.h>

#include "maat.h"
#include "log/log.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "maat_command.h"
#include "hiredis/hiredis.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "maat_plugin.h"
#include "maat_virtual.h"

#define MODULE_REDIS_MONITOR	 module_name_str("maat.redis_monitor")

const time_t MAAT_REDIS_RECONNECT_INTERVAL_S = 5;
const int MAAT_REDIS_SYNC_TIME = 30 * 60;

const char *mr_expire_lock = "EXPIRE_OP_LOCK";
const long	mr_expire_lock_timeout_ms = 300 * 1000;

const char *mr_version_sset = "MAAT_VERSION_TIMER";
const char *mr_status_sset = "MAAT_UPDATE_STATUS";
const char *mr_expire_sset = "MAAT_EXPIRE_TIMER";
const char *mr_label_sset = "MAAT_LABEL_INDEX";

const char *mr_key_prefix[2] = {"OBSOLETE_RULE", "EFFECTIVE_RULE"};
const char *foreign_source_prefix = "redis://";
const char *foreign_key_prefix = "__FILE_";

const char *mr_op_str[] = {"DEL", "ADD", "RENEW_TIMEOUT"};

#define	POSSIBLE_REDIS_REPLY_SIZE	2
struct expected_reply {
	int s_rule_seq;
	int possible_reply_num;
	redisReply possible_replies[POSSIBLE_REDIS_REPLY_SIZE];
};

static char *get_foreign_cont_filename(const char *table_name, long long rule_id, 
                                	   const char *foreign_key, const char *dir)
{
	char buffer[512] = {0};

	snprintf(buffer, sizeof(buffer),"%s/%s-%lld-%s", dir, 
             table_name, rule_id, foreign_key);
    char *filename = ALLOC(char, strlen(buffer) + 1);
	memcpy(filename, buffer, strlen(buffer));

	return filename;
}

static const char *maat_cmd_find_Nth_column(const char *line, int Nth, int *column_len)
{
    size_t i = 0;
	int j = 0;
	size_t start=0, end=0;
	size_t line_len = strlen(line);

	for (i = 0; i < line_len; i++) {
		if (line[i] != ' ' && line[i] != '\t') {
			continue;
		}

		j++;
		if (j == Nth - 1) {
			start = i + 1;
		}

		if(j == Nth) {
			end = i;
			break;
		}
	}

	if (start == end) {
		return NULL;
	}

	if (end == 0) {
		end = i;
	}

	*column_len = end - start;

	return line + start;
}

static void _get_foregin_keys(struct serial_rule *p_rule, int *foreign_columns, 
                       		  int n_foreign, const char *dir, struct log_handle *logger)
{
	int foreign_key_size = 0;
	p_rule->f_keys = ALLOC(struct foreign_key, n_foreign);

	for (int i = 0; i < n_foreign; i++) {
		const char *p_foreign = maat_cmd_find_Nth_column(p_rule->table_line, 
                                                         foreign_columns[i], 
                                                         &foreign_key_size);
		if (NULL == p_foreign) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Get %s,%lld foreign keys failed: No %dth column",
					  __FUNCTION__, __LINE__, p_rule->table_name, p_rule->rule_id, 
                      foreign_columns[i]);
			continue;
		}

        //emtpy file
		if (0 == strncasecmp(p_foreign, "null", strlen("null"))) {
			continue;
		}

		if (0 != strncmp(p_foreign, foreign_source_prefix, strlen(foreign_source_prefix))) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Get %s,%lld foreign key failed: Invalid source prefix %s",
					  __FUNCTION__, __LINE__, p_rule->table_name, p_rule->rule_id, p_foreign);
			continue;
		}

		p_rule->f_keys[p_rule->n_foreign].column = foreign_columns[i];
		foreign_key_size = foreign_key_size - strlen(foreign_source_prefix);
		p_foreign += strlen(foreign_source_prefix);

		if (0 != strncmp(p_foreign, foreign_key_prefix, strlen(foreign_key_prefix))) {
			log_info(logger, MODULE_REDIS_MONITOR, 
                     "[%s:%d] %s, %lld foreign key prefix %s is not recommended",
					 __FUNCTION__, __LINE__, p_rule->table_name, p_rule->rule_id, p_foreign);
		}

		p_rule->f_keys[p_rule->n_foreign].key = ALLOC(char, foreign_key_size+1);
		memcpy(p_rule->f_keys[p_rule->n_foreign].key, p_foreign, foreign_key_size);
		p_rule->f_keys[p_rule->n_foreign].filename = get_foreign_cont_filename(p_rule->table_name, 
                                                                               p_rule->rule_id, 
                                                                               p_rule->f_keys[p_rule->n_foreign].key, 
                                                                               dir);
		p_rule->n_foreign++;
	}

	if (0 == p_rule->n_foreign) {
		FREE(p_rule->f_keys);
	}
}

static int get_foreign_keys_define(redisContext *ctx, struct serial_rule *rule_list, 
                            	   int rule_num, struct maat *maat_inst, const char *dir)
{
	int rule_with_foreign_key = 0;

	for (int i = 0; i < rule_num; i++) {
		if (NULL == rule_list[i].table_line) {
			continue;
		}

        int table_id = table_manager_get_table_id(maat_inst->tbl_mgr, rule_list[i].table_name);
		void *schema = table_manager_get_schema(maat_inst->tbl_mgr, table_id);
        enum table_type table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
		if (!schema || table_type != TABLE_TYPE_PLUGIN) {
			continue;
		}

        int foreign_columns[8];
        int n_foreign_column = plugin_table_get_foreign_column((struct plugin_schema *)schema, 
                                                                foreign_columns);
        if (0 == n_foreign_column) {
            continue;
        }

		_get_foregin_keys(rule_list+i, foreign_columns, n_foreign_column, dir, maat_inst->logger);
		rule_with_foreign_key++;
	}

	return rule_with_foreign_key;
}

int maat_get_foreign_keys_by_prefix(redisContext *ctx, struct serial_rule *rule_list, 
                                    int rule_num, const char* dir, struct log_handle *logger)
{
	int j = 0;
    int foreign_key_size = 0;
	int rule_with_foreign_key = 0;
	const char *p_foreign = NULL;

	int n_foreign = 0;
	int foreign_columns[MAX_FOREIGN_CLMN_NUM];

	for (int i = 0; i < rule_num; i++) {
		j = 1;
		n_foreign = 0;
		do {
			p_foreign = maat_cmd_find_Nth_column(rule_list[i].table_line, j, &foreign_key_size);			
			if (p_foreign != NULL && foreign_key_size > (int)strlen(foreign_source_prefix) && 
                0 == strncmp(p_foreign, foreign_source_prefix, strlen(foreign_source_prefix))) {
				foreign_columns[n_foreign] = j;
				n_foreign++;
			}
			j++;
		} while (p_foreign != NULL && n_foreign < MAX_FOREIGN_CLMN_NUM);

		if (n_foreign > 0) {
			_get_foregin_keys(rule_list+i, foreign_columns, n_foreign, dir, logger);
			rule_with_foreign_key++;
		}
	}

	return rule_with_foreign_key;
}

struct foreign_conts_track {
	int rule_idx;
	int foreign_idx;
};

static int _get_maat_redis_value(redisContext *c, struct serial_rule *rule_list,
								 int rule_num, struct log_handle *logger)
{
	int i = 0;
    int failed_cnt = 0;
	UNUSED int ret = 0;
	int error_happened = 0;
    int *retry_ids = ALLOC(int, rule_num);
	char redis_cmd[256] = {0};
	redisReply* reply = NULL;

	for (i = 0; i < rule_num; i++) {
		snprintf(redis_cmd, sizeof(redis_cmd), 
                 "GET %s:%s,%lld", mr_key_prefix[rule_list[i].op],
                 rule_list[i].table_name,
                 rule_list[i].rule_id);
		ret = redisAppendCommand(c, redis_cmd);
		assert(ret == REDIS_OK);
	}

	for (i = 0; i < rule_num; i++) {
		ret = maat_wrap_redis_get_reply(c, &reply);
		if (ret == REDIS_ERR) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Redis GET %s:%s,%lld failed, redis server error", 
                      __FUNCTION__, __LINE__, mr_key_prefix[rule_list[i].op], 
                      rule_list[i].table_name, rule_list[i].rule_id);
			error_happened = 1;
			break;			
		}

		if (reply->type == REDIS_REPLY_STRING) {
			rule_list[i].table_line = maat_strdup(reply->str);
		} else {
			if (reply->type == REDIS_REPLY_NIL) {
				retry_ids[failed_cnt] = i;
				failed_cnt++;
			} else {
				log_error(logger, MODULE_REDIS_MONITOR, 
                          "[%s:%d] Redis GET %s:%s,%lld failed",
                          __FUNCTION__, __LINE__, mr_key_prefix[rule_list[i].op],
						  rule_list[i].table_name, rule_list[i].rule_id);
				error_happened = 1;
			}
		}

		freeReplyObject(reply);
		reply = NULL;
	}

	if (1 == error_happened) {
		FREE(retry_ids);
		return -1;
	}
	
    int idx = 0;
	for (i = 0; i < failed_cnt; i++) {
		idx = retry_ids[i];
		snprintf(redis_cmd, sizeof(redis_cmd), 
                 "GET %s:%s,%lld", mr_key_prefix[MAAT_OP_DEL],
                 rule_list[idx].table_name,
                 rule_list[idx].rule_id);
		ret = redisAppendCommand(c, redis_cmd);
	}

	for (i = 0; i < failed_cnt; i++) {
		idx = retry_ids[i];
		ret = maat_wrap_redis_get_reply(c, &reply);
		if (ret == REDIS_ERR) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] redis command %s failed, redis server error", 
                      __FUNCTION__, __LINE__, redis_cmd);
			FREE(retry_ids);
			return -1;
		}

		if (reply->type == REDIS_REPLY_STRING) {
			rule_list[idx].table_line = maat_strdup(reply->str);
		} else if(reply->type==REDIS_REPLY_ERROR) {
            //Deal with Redis response: "Loading Redis is loading the database in memory" 
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] redis command %s error, reply type=%d, error str=%s", 
                      __FUNCTION__, __LINE__, redis_cmd, reply->type, reply->str);
		} else {
            //Handle type "nil"
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] redis command %s failed, reply type=%d", 
                      __FUNCTION__, __LINE__, redis_cmd, reply->type);
		}
	
		freeReplyObject(reply);
		reply = NULL;

	}

	FREE(retry_ids);
	return 0;
}

int maat_get_redis_value(redisContext *c, struct serial_rule *rule_list, 
                         int rule_num, int print_process, struct log_handle *logger)
{
	int max_redis_batch = 4096;
	int success_cnt = 0;
	int next_print = 10;

	while (success_cnt < rule_num) {
		int batch_cnt = MIN(rule_num-success_cnt, max_redis_batch);
		int ret = _get_maat_redis_value(c, rule_list+success_cnt, batch_cnt, logger);
		if (ret < 0) {
			return -1;
		} else {
			success_cnt += batch_cnt;
		}

		if (print_process == 1) {
			if ((success_cnt * 100) / rule_num > next_print) {
				printf(" >%d%%",next_print);
				next_print += 10;
			}
		}
	}

	if (print_process == 1) {
		printf(" >100%%\n");
	}

	return 0;
}

static int get_inc_key_list(long long instance_version, long long target_version, 
                     		redisContext *c, struct serial_rule **list, 
                     		struct log_handle *logger)
{	
	//Returns all the elements in the sorted set at key with a score that instance_version < score <= redis_version.
	//The elements are considered to be ordered from low to high scores(instance_version).
	redisReply *reply = (redisReply *)redisCommand(c, "ZRANGEBYSCORE %s (%lld %lld", 
                                                   mr_status_sset, instance_version,
                                                   target_version);
	if (NULL == reply) {
		log_error(logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] GET %s failed with a NULL reply, error: %s", 
                  __FUNCTION__, __LINE__, mr_status_sset, c->errstr);
		return -1;
	}

	assert(reply->type == REDIS_REPLY_ARRAY);

	int rule_num = reply->elements;
	if (0 == reply->elements) {
		freeReplyObject(reply);
		reply = NULL;
		return 0;
	}

	redisReply *tmp_reply= maat_wrap_redis_command(c, "ZSCORE %s %s", 
                                                   mr_status_sset, 
                                                   reply->element[0]->str);
	if (tmp_reply->type != REDIS_REPLY_STRING) {
		log_error(logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] ZSCORE %s %s failed Version: %lld->%lld", 
                  __FUNCTION__, __LINE__, mr_status_sset, 
                  reply->element[0]->str, instance_version, 
                  target_version);
		freeReplyObject(tmp_reply);
		tmp_reply = NULL;
		freeReplyObject(reply);
		reply = NULL;
		return -1;
	}

	long long nearest_rule_version = maat_read_redis_integer(tmp_reply);
	freeReplyObject(tmp_reply);
	tmp_reply = NULL;

	if (nearest_rule_version < 0) {
		return -1;
	}

	if (nearest_rule_version != instance_version + 1) {
		log_info(logger, MODULE_REDIS_MONITOR, 
                 "Noncontinuous VERSION Redis: %lld MAAT: %lld", 
                 nearest_rule_version, instance_version);
	}

    int i = 0;
    int j = 0;
    char op_str[4] = {0};
    struct serial_rule *s_rule = ALLOC(struct serial_rule, reply->elements);

	for (i = 0, j = 0; i < (int)reply->elements; i++) {
		assert(reply->element[i]->type == REDIS_REPLY_STRING);
		int ret = sscanf(reply->element[i]->str, "%3s,%[^,],%lld", 
                         op_str, s_rule[j].table_name, &(s_rule[j].rule_id));
		if (ret != 3 || s_rule[i].rule_id < 0) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Invalid Redis Key: %s", 
                      __FUNCTION__, __LINE__, reply->element[i]->str);
			continue;
		}

		if (strncmp(op_str, "ADD", strlen("ADD")) == 0) {
			s_rule[j].op = MAAT_OP_ADD;
		} else if(strncmp(op_str, "DEL", strlen("DEL")) == 0) {
			s_rule[j].op = MAAT_OP_DEL;
		} else {
			log_error(logger, MODULE_REDIS_MONITOR, 
                     "[%s:%d] Invalid Redis Key: %s", 
                     __FUNCTION__, __LINE__, reply->element[i]->str);
			continue;
		}
		j++;
	}

	rule_num = j;
	*list = s_rule;
	freeReplyObject(reply);
	reply = NULL;
	
	return rule_num;
}

void maat_clear_rule_cache(struct serial_rule *s_rule)
{
	if (s_rule->table_line != NULL) {
		FREE(s_rule->table_line);
	}

	if (s_rule->n_foreign > 0) {
		for (int i = 0; i < s_rule->n_foreign; i++) {
			FREE(s_rule->f_keys[i].filename);
			FREE(s_rule->f_keys[i].key);
		}

		FREE(s_rule->f_keys);
	}

	memset(s_rule, 0, sizeof(struct serial_rule));
}

void maat_set_serial_rule(struct serial_rule *rule, enum maat_operation op,
                          long long rule_id, const char *table_name,
                          const char *line, long long timeout)
{
	memset(rule, 0, sizeof(struct serial_rule));
    rule->op = op;
	rule->rule_id = rule_id;
	rule->timeout = timeout;
	assert(strlen(table_name) < sizeof(rule->table_name));
	strncpy(rule->table_name, table_name, sizeof(rule->table_name));
	if (line != NULL) {
		rule->table_line = maat_strdup(line);
	}
}

static void serial_rule_free(struct serial_rule *s_rule)
{
    if (NULL == s_rule) {
        return;
    }

    if (s_rule->table_line != NULL) {
		FREE(s_rule->table_line);
	}

	if (s_rule->n_foreign > 0) {
		for (int i = 0; i < s_rule->n_foreign; i++) {
            if (s_rule->f_keys[i].filename != NULL) {
                FREE(s_rule->f_keys[i].filename);
            }
			
            if (s_rule->f_keys[i].key != NULL) {
                FREE(s_rule->f_keys[i].key);
            }
		}

        if (s_rule->f_keys != NULL) {
            FREE(s_rule->f_keys);
        }
	}

	FREE(s_rule);
}

static struct serial_rule *serial_rule_clone(const struct serial_rule *s_rule)
{
    struct serial_rule *new_rule = ALLOC(struct serial_rule, 1);

    new_rule->op = s_rule->op;
    new_rule->rule_id = s_rule->rule_id;
    new_rule->timeout = s_rule->timeout;
    memcpy(new_rule->table_name, s_rule->table_name, strlen(s_rule->table_name));
    new_rule->n_foreign = s_rule->n_foreign;
    new_rule->table_line = ALLOC(char, strlen(s_rule->table_line));
    memcpy(new_rule->table_line, s_rule->table_line, strlen(s_rule->table_line));

    new_rule->f_keys = ALLOC(struct foreign_key, new_rule->n_foreign);
    for (int j = 0; j < new_rule->n_foreign; j++) {
        new_rule->f_keys[j].key = ALLOC(char, s_rule->f_keys[j].key_len);
        memcpy(new_rule->f_keys[j].key, s_rule->f_keys[j].key, s_rule->f_keys[j].key_len);
        new_rule->f_keys[j].filename = ALLOC(char, strlen(s_rule->f_keys[j].filename));
        memcpy(new_rule->f_keys[j].filename, s_rule->f_keys[j].filename, 
               strlen(s_rule->f_keys[j].filename));
    }

    return new_rule;
}

static int recovery_history_version(const struct serial_rule *current, int current_num, 
                             		const struct serial_rule *changed, int changed_num, 
                             		struct serial_rule **history_result)
{
	int i = 0;
    int ret = 0;
	unsigned int history_num = 0;
	int hash_slot_size = 1;
	char hkey[256+20] = {0};
	int tmp = current_num + changed_num;
	for (; tmp > 0; tmp = tmp/2) {
		hash_slot_size *= 2;
	}

    struct serial_rule *s_rule_map = NULL;
    struct serial_rule *rule_node = NULL;
	for (i = 0; i < current_num; i++) {
		snprintf(hkey, sizeof(hkey), "%lld,%s", current[i].rule_id, current[i].table_name);
        rule_node = serial_rule_clone(current + i);
        HASH_ADD_KEYPTR(hh, s_rule_map, hkey, strlen(hkey), rule_node);
	}

	for (i = changed_num - 1; i >= 0; i--) {
		snprintf(hkey, sizeof(hkey), "%lld,%s", changed[i].rule_id, changed[i].table_name);
        //newly added rule is need to delete from current, so that history version can be recovered.
		if (changed[i].op == MAAT_OP_ADD) {
            rule_node = NULL;
            HASH_FIND(hh, s_rule_map, hkey, strlen(hkey), rule_node);
            if (rule_node != NULL) {
                HASH_DELETE(hh, s_rule_map, rule_node);
            }
            serial_rule_free(rule_node);
		} else {
            rule_node = serial_rule_clone(changed + i);
            HASH_ADD_KEYPTR(hh, s_rule_map, hkey, strlen(hkey), rule_node);
		}
	}

	history_num = HASH_CNT(hh, s_rule_map);
	struct serial_rule *array = ALLOC(struct serial_rule, history_num);
    struct serial_rule *elem_node = NULL;
    struct serial_rule *tmp_node = NULL;
    i = 0;
    HASH_ITER(hh, s_rule_map, elem_node, tmp_node) {
        memcpy(&array[i], elem_node, sizeof(struct serial_rule));
	    array[i].op = MAAT_OP_ADD;
        i++;
    }
	elem_node = NULL;
    tmp_node = NULL;

	*history_result = array;
	ret = history_num;

    HASH_ITER(hh, s_rule_map, elem_node, tmp_node) {
        HASH_DELETE(hh, s_rule_map, elem_node);
        serial_rule_free(elem_node);
    }

	return ret;
}

int maat_get_rm_key_list(redisContext *c, long long instance_version, 
                         long long desired_version, long long *new_version, 
                         struct table_manager *tbl_mgr, struct serial_rule **list, 
                         int *update_type, int cumulative_off, struct log_handle *logger)
{
    int rule_num = 0;
	long long target_version = 0;
	struct serial_rule *s_rule_array = NULL;

	redisReply *reply = (redisReply *)redisCommand(c, "GET MAAT_VERSION");
	if (reply != NULL) {
		if (reply->type == REDIS_REPLY_NIL || reply->type == REDIS_REPLY_ERROR) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] GET MAAT_VERSION failed, maybe Redis is busy",
                      __FUNCTION__, __LINE__);
			freeReplyObject(reply);
			reply = NULL;
			return -1;
		}
	} else {
		log_error(logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] GET MAAT_VERSION failed with NULL reply, error: %s",
                  __FUNCTION__, __LINE__, c->errstr);
		return -1;
	}

	long long redis_version = maat_read_redis_integer(reply);
	if (redis_version < 0) {
		if (reply->type == REDIS_REPLY_ERROR) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Redis Communication error: %s", 
                      __FUNCTION__, __LINE__, reply->str);
		}
		return -1;
	}

	freeReplyObject(reply);
	reply = NULL;

	if (redis_version == instance_version) {		
		return 0;
	}

	if (0 == instance_version || desired_version != 0) {
		goto FULL_UPDATE;
	}

	if (redis_version < instance_version) {
		log_error(logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] VERSION roll back MAAT: %lld -> Redis: %lld", 
                  __FUNCTION__, __LINE__, instance_version, redis_version);
		goto FULL_UPDATE;
	}

	if (redis_version > instance_version && 1 == cumulative_off) {
		target_version = instance_version;
	} else {
		target_version = redis_version - 1;
	}

	do {
		target_version++;
		rule_num = get_inc_key_list(instance_version, target_version, 
                                    c, &s_rule_array, logger);
		if (rule_num > 0) {
			break;
		} else if (rule_num < 0) {
			goto FULL_UPDATE;
		} else {
			//ret=0, nothing to do.
		}
		
	} while (0 == rule_num && target_version <= redis_version && 1 == cumulative_off);

	if (0 == rule_num) {
		log_info(logger, MODULE_REDIS_MONITOR, 
                 "Got nothing after ZRANGEBYSCORE %s (%lld %lld, cumulative %s", 
                 mr_status_sset, instance_version, target_version-1, 
                 cumulative_off == 1 ? "OFF" : "ON");
		return 0;
	}

	log_info(logger, MODULE_REDIS_MONITOR, 
             "Inc Update from instance_version %lld to %lld (%d entries)", 
             instance_version, target_version, rule_num);

	*list = s_rule_array;
	*update_type = MAAT_UPDATE_TYPE_INC;
	*new_version = target_version;
	return rule_num;

FULL_UPDATE:
	log_info(logger, MODULE_REDIS_MONITOR, 
             "Initiate full update from instance_version %lld to %lld", 
             instance_version, desired_version == 0 ? redis_version : desired_version);
	size_t append_cmd_cnt = 0;
	int ret = redisAppendCommand(c, "MULTI");
	append_cmd_cnt++;

	ret = redisAppendCommand(c, "GET MAAT_VERSION");
	append_cmd_cnt++;

	ret = redisAppendCommand(c, "KEYS EFFECTIVE_RULE:*");
	append_cmd_cnt++;

    size_t i = 0;
	//consume reply "OK" and "QUEUED".
	for (i = 0; i < append_cmd_cnt; i++) {
		maat_wrap_redis_get_reply(c, &reply);
		freeReplyObject(reply);
		reply = NULL;
	}

	reply = maat_wrap_redis_command(c, "EXEC");
	if (NULL == reply) {
		log_error(logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] Redis Communication error: %s", 
                  __FUNCTION__, __LINE__, c->errstr);
		return -1;
	}

	if (reply->type != REDIS_REPLY_ARRAY) {
		log_error(logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] Invalid Redis Key List type %d", 
                  __FUNCTION__, __LINE__, reply->type);
		freeReplyObject(reply);
		reply = NULL;
		return -1;
	}

	*new_version = maat_read_redis_integer(reply->element[0]);
	redisReply *sub_reply = reply->element[1];
	if (sub_reply->type != REDIS_REPLY_ARRAY) {
		log_error(logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] Invalid Redis Key List type %d", 
                  __FUNCTION__, __LINE__, sub_reply->type);
		freeReplyObject(reply);
		reply = NULL;
		return -1;
	}

    size_t full_idx = 0;
	s_rule_array = ALLOC(struct serial_rule, sub_reply->elements);
	for (i = 0, full_idx = 0; i < sub_reply->elements; i++) {
		if (sub_reply->element[i]->type != REDIS_REPLY_STRING) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Invalid Redis Key Type: %d",
                      __FUNCTION__, __LINE__, sub_reply->element[i]->type);
			continue;
		}

		ret = sscanf(sub_reply->element[i]->str, "%*[^:]:%[^,],%lld", 
                     s_rule_array[full_idx].table_name, 
                     &(s_rule_array[full_idx].rule_id));
		s_rule_array[full_idx].op = MAAT_OP_ADD;

		if (ret != 2 || s_rule_array[full_idx].rule_id < 0 || 
            strlen(s_rule_array[full_idx].table_name) == 0) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Invalid Redis Key Format: %s", 
                      __FUNCTION__, __LINE__, sub_reply->element[i]->str);
			continue;
		}

		if (tbl_mgr) {
			int table_id = table_manager_get_table_id(tbl_mgr, s_rule_array[full_idx].table_name);
			//Unrecognized table.
            if (table_id < 0) {
				continue;
			}
		}
		full_idx++;
	}

	rule_num = full_idx;
	freeReplyObject(reply);
	reply = NULL;

	if (desired_version != 0) {
        struct serial_rule *changed_rule_array = NULL;
		int changed_rule_num = get_inc_key_list(desired_version, redis_version, 
                                                c, &changed_rule_array, logger);
		if (changed_rule_num < 0) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Recover history version %lld faild where as redis version is %lld", 
                      __FUNCTION__, __LINE__, desired_version, redis_version);
		} else if(0 == changed_rule_num) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Nothing to recover from history version %lld to redis version is %lld", 
                      __FUNCTION__, __LINE__, desired_version, redis_version);
		} else {
            struct serial_rule *history_rule_array = NULL;
			ret = recovery_history_version(s_rule_array, full_idx, changed_rule_array, 
                                           changed_rule_num, &history_rule_array);
			if (ret > 0) {
				FREE(s_rule_array);
				s_rule_array = history_rule_array;
				rule_num = ret;
				*new_version = desired_version;
				log_info(logger, MODULE_REDIS_MONITOR, 
                         "Successfully recovered from history version %lld to redis version is %lld", 
                         desired_version, redis_version);
			}
		}		
		FREE(changed_rule_array);
	}

	*list = s_rule_array;
	*update_type = MAAT_UPDATE_TYPE_FULL;
	log_info(logger, MODULE_REDIS_MONITOR, 
             "Full update %d keys of version %lld", rule_num, *new_version);

	return rule_num ;
}

static void _get_foreign_conts(redisContext *c, struct serial_rule *rule_list, 
                        	   int rule_num, int print_fn, struct log_handle *logger)
{
	int i = 0;
    int j = 0;
	UNUSED int ret = 0;
	int key_num = 0;
	struct serial_rule *s_rule = NULL;
    struct foreign_conts_track *track = ALLOC(struct foreign_conts_track,
											  rule_num * MAX_FOREIGN_CLMN_NUM); 

	for (i = 0; i < rule_num; i++) {
		s_rule = rule_list + i;
		if (s_rule->n_foreign == 0) {
			continue;
		}

		if (s_rule->op == MAAT_OP_DEL) {
			for (j = 0; j < rule_list[i].n_foreign; j++) {
				if (NULL == rule_list[i].f_keys[j].filename) {
					continue;
				}
				
				ret = remove(rule_list[i].f_keys[j].filename);
				if (ret == -1) {
					log_error(logger, MODULE_REDIS_MONITOR, 
                              "[%s:%d] Foreign content file %s remove failed",
							  __FUNCTION__, __LINE__, rule_list[i].f_keys[j].filename);
				}
			}
		} else {
			for (j = 0; j < s_rule->n_foreign; j++) {
				if (NULL == rule_list[i].f_keys[j].filename) {
					continue;
				}

                struct stat file_info;
				ret = stat(s_rule->f_keys[j].filename, &file_info);
				if (0 == ret) {
					continue;
				}

                char redis_cmd[256] = {0};
				snprintf(redis_cmd, sizeof(redis_cmd), "GET %s", s_rule->f_keys[j].key);
				ret = redisAppendCommand(c, redis_cmd);
				track[key_num].rule_idx = i;
				track[key_num].foreign_idx = j;
				key_num++;
				assert(ret == REDIS_OK);
			}
		}
	}

    redisReply *reply = NULL;
	for (i = 0; i < key_num; i++) {
		ret = maat_wrap_redis_get_reply(c, &reply);
		if (ret == REDIS_ERR) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Get %s,%lld foreign key %s content failed, redis server error",
                      __FUNCTION__, __LINE__,
                      rule_list[track[i].rule_idx].table_name,
                      rule_list[track[i].rule_idx].rule_id,
                      rule_list[track[i].rule_idx].f_keys[track[i].foreign_idx].key);
			break;
		}
		
		if (reply->type != REDIS_REPLY_STRING) {
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Get %s,%lld foreign key %s content failed",
                      __FUNCTION__, __LINE__,
                      rule_list[track[i].rule_idx].table_name,
                      rule_list[track[i].rule_idx].rule_id,
                      rule_list[track[i].rule_idx].f_keys[track[i].foreign_idx].key);
			continue;
		} else {
			s_rule = rule_list+track[i].rule_idx;
			FILE *fp = fopen(s_rule->f_keys[track[i].foreign_idx].filename, "w");
			if (NULL == fp) {
				log_error(logger, MODULE_REDIS_MONITOR, 
                          "[%s:%d] Write foreign content failed: fopen %s error",
                          __FUNCTION__, __LINE__, s_rule->f_keys[track[i].foreign_idx].filename);
			} else {
				fwrite(reply->str, 1, reply->len, fp);
				fclose(fp);
				fp = NULL;
				if (1 == print_fn) {
					printf("[%s:%d] Written foreign content %s\n", 
                            __FUNCTION__, __LINE__, s_rule->f_keys[track[i].foreign_idx].filename);
				}
			}
		}

		freeReplyObject(reply);
		reply = NULL;	
	}
	
	FREE(track);
	return;
}

void maat_get_foreign_conts(redisContext *c, struct serial_rule *rule_list, 
                            int rule_num, int print_fn, struct log_handle *logger)
{
	int max_redis_batch = 4096;
	int success_cnt = 0;

	while (success_cnt < rule_num) {
		int batch_cnt = MIN(rule_num - success_cnt, max_redis_batch);
		_get_foreign_conts(c, rule_list + success_cnt, batch_cnt, print_fn, logger);
		success_cnt += batch_cnt;	
	}
}

static int invalidate_line(char *line, int column_seq)
{
    if (NULL == line || column_seq < 0) {
        return -1;
    }

	int offset = maat_get_valid_flag_offset(line, column_seq);
	if (offset < 0) {
		return -1;
	}

	line[offset] = '0';

	return 0;
}

void maat_rewrite_table_line_with_foreign(struct serial_rule *s_rule)
{
    int i = 0;
	size_t fn_size = 0;
	
	for (i = 0; i < s_rule->n_foreign; i++) {
		fn_size += strlen(s_rule->f_keys[i].filename);
	}
	
    char *rewrite_line = ALLOC(char, strlen(s_rule->table_line) + fn_size);
    char *pos_rewrite_line = rewrite_line;
	const char *pos_origin_line = s_rule->table_line;
	
	for (i = 0; i < s_rule->n_foreign; i++) {
        int origin_column_size = 0;
		const char *origin_column = maat_cmd_find_Nth_column(s_rule->table_line, 
                                                             s_rule->f_keys[i].column, 
                                                             &origin_column_size);
		strncat(pos_rewrite_line, pos_origin_line, origin_column - pos_origin_line);
		pos_rewrite_line += origin_column - pos_origin_line;
		pos_origin_line = origin_column+origin_column_size;
		strncat(pos_rewrite_line, s_rule->f_keys[i].filename, strlen(s_rule->f_keys[i].filename));
		pos_rewrite_line += strlen(s_rule->f_keys[i].filename);
	}

	strncat(pos_rewrite_line, pos_origin_line, 
            strlen(s_rule->table_line) - (pos_origin_line - s_rule->table_line));
	FREE(s_rule->table_line);
	s_rule->table_line = rewrite_line;
}

static void expected_reply_add(struct expected_reply* expected, int s_rule_seq, 
                        	   int type, long long integer)
{
	int i = expected->possible_reply_num;
	assert(i < POSSIBLE_REDIS_REPLY_SIZE);
	expected->s_rule_seq = s_rule_seq;
	expected->possible_replies[i].type = type;
	expected->possible_replies[i].integer = integer;
	expected->possible_reply_num++;
}

static int redlock_try_lock(redisContext *c, const char *lock_name,
							long long expire)
{
	int ret = 0;
    
	redisReply *reply = maat_wrap_redis_command(c, "SET %s locked NX PX %lld", 
                                                lock_name, expire);
	if (reply->type == REDIS_REPLY_NIL) {
		ret = 0;
	} else {
		ret = 1;
	}

	freeReplyObject(reply);
	reply = NULL;
	
	return ret;
}

static long long exec_serial_rule_begin(redisContext* c, size_t rule_num, 
                                 		size_t renew_rule_num, int *renew_allowed, 
                                 		long long *transaction_version)
{
	int ret = -1;
	redisReply *data_reply = NULL;

	if (renew_rule_num > 0) {
		while (0 == redlock_try_lock(c, mr_expire_lock, mr_expire_lock_timeout_ms)) {
			usleep(1000);
		}
		*renew_allowed = 1;
	}

	if (rule_num > renew_rule_num) {
		data_reply = maat_wrap_redis_command(c, "INCRBY MAAT_PRE_VER 1");
		*transaction_version = maat_read_redis_integer(data_reply);
		freeReplyObject(data_reply);
		data_reply = NULL; 
		if (*transaction_version < 0) {
			return -1;
		}
	}

	if (*renew_allowed == 1 || rule_num > renew_rule_num) {
		data_reply = maat_wrap_redis_command(c, "MULTI");
		freeReplyObject(data_reply);
		data_reply = NULL;
		ret = 0;
	}

	return ret;
}

static void redlock_unlock(redisContext *c, const char *lock_name)
{
	redisReply *reply = maat_wrap_redis_command(c, "DEL %s", lock_name);
	freeReplyObject(reply);
	reply = NULL;
}

const char* lua_exec_done=
"local maat_version=redis.call(\'incrby\', KEYS[1], 1);"
"local transaction=redis.call(\'lrange\', KEYS[4], 0, -1);"
"for k,v in pairs(transaction) do"
"	redis.call(\'zadd\', KEYS[2], maat_version, v);"
"end;"
"redis.call(\'del\', KEYS[4]);"
"redis.call(\'zadd\', KEYS[3], ARGV[1], maat_version);"
"return maat_version;";
static redisReply* exec_serial_rule_end(redisContext *c, const char *transaction_list, 
                                 		long long server_time, int renew_allowed, 
                                 		struct expected_reply *expect_reply,  size_t *cnt)
{
	redisReply *data_reply = NULL;

	if (1 == renew_allowed) {
		redlock_unlock(c, mr_expire_lock);
		expect_reply[*cnt].s_rule_seq = -1;
		(*cnt)++;
	}

	if (strlen(transaction_list) > 0) {
		data_reply = maat_wrap_redis_command(c, "eval %s 4 MAAT_VERSION %s %s %s %lld",
											        lua_exec_done,
											        mr_status_sset,
											        mr_version_sset,
											        transaction_list,
											        server_time);
		freeReplyObject(data_reply);
		data_reply = NULL;
		expected_reply_add(expect_reply + *cnt, -1, REDIS_REPLY_INTEGER, 0);
		(*cnt)++;
	}

	data_reply = maat_wrap_redis_command(c, "EXEC");

	return data_reply;
}

static void exec_serial_rule(redisContext *c,	const char *transaction_list, 
                      		struct serial_rule *s_rule, size_t rule_num,  
                      		struct expected_reply *expect_reply, size_t *cnt, 
                      		size_t offset, int renew_allowed)
{
    size_t i = 0;
    size_t append_cmd_cnt = 0;
	redisReply *data_reply = NULL;
	
	for (i = 0; i < rule_num; i++) {
		switch (s_rule[i].op) {
			case MAAT_OP_ADD:
				redisAppendCommand(c, "SET %s:%s,%lld %s",
						              mr_key_prefix[MAAT_OP_ADD],
						              s_rule[i].table_name,
						              s_rule[i].rule_id,
						              s_rule[i].table_line);
				expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_STATUS, 0);
				(*cnt)++;
				append_cmd_cnt++;
				//Allowing add duplicated members for rule id recycling.
				redisAppendCommand(c, "RPUSH %s ADD,%s,%lld",
						              transaction_list,
						              s_rule[i].table_name,
						              s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
				if (s_rule[i].timeout > 0) {
					redisAppendCommand(c, "ZADD %s %lld %s,%lld",
							              mr_expire_sset,
							              s_rule[i].timeout,
							              s_rule[i].table_name,
							              s_rule[i].rule_id);
					expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_INTEGER, 1);
					expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_INTEGER, 0);
					(*cnt)++;
					append_cmd_cnt++;
				}
				break;
			case MAAT_OP_DEL:
				redisAppendCommand(c, "RENAME %s:%s,%lld %s:%s,%lld",
						              mr_key_prefix[MAAT_OP_ADD],
						              s_rule[i].table_name,
						              s_rule[i].rule_id,
						              mr_key_prefix[MAAT_OP_DEL],
						              s_rule[i].table_name,
						              s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_STATUS, 0);
				(*cnt)++;
				append_cmd_cnt++;
				
				redisAppendCommand(c, "EXPIRE %s:%s,%lld %d",
						              mr_key_prefix[MAAT_OP_DEL],
						              s_rule[i].table_name,
						              s_rule[i].rule_id,
						              MAAT_REDIS_SYNC_TIME);		
				expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_INTEGER, 1);
				(*cnt)++;
				append_cmd_cnt++;
				
				//NX: Don't update already exisiting elements. Always add new elements.
				redisAppendCommand(c, "RPUSH %s DEL,%s,%lld",
						              transaction_list,
						              s_rule[i].table_name,
						              s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
				
				// Try to remove from expiration sorted set, no matter wheather it exists or not.
				redisAppendCommand(c, "ZREM %s %s,%lld",
						              mr_expire_sset,
						              s_rule[i].table_name,
						              s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
				
				// Try to remove from label sorted set, no matter wheather it exists or not.
				redisAppendCommand(c, "ZREM %s %s,%lld",
						              mr_label_sset,
						              s_rule[i].table_name,
						              s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
				break;
			case	MAAT_OP_RENEW_TIMEOUT:
				if (renew_allowed != 1) {
					continue;
				}
				//s_rule[i].timeout>0 was checked by caller.
				redisAppendCommand(c, "ZADD %s %lld %s,%lld",
						              mr_expire_sset,
						              s_rule[i].timeout,
						              s_rule[i].table_name,
						              s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
								
				break;
			default:
				assert(0);
				break;
		}
	}

	for (i = 0; i < append_cmd_cnt; i++) {
		maat_wrap_redis_get_reply(c, &data_reply);
		freeReplyObject(data_reply);
		data_reply=NULL;
	}
}

static int mr_operation_success(redisReply *actual_reply,
								struct expected_reply *expected)
{
	if (expected->possible_replies[0].type != actual_reply->type) {
		return 0;
	}
    
	for (int i = 0; i < expected->possible_reply_num; i++) {
		if (expected->possible_replies[i].type == REDIS_REPLY_INTEGER &&
			expected->possible_replies[i].type == actual_reply->type &&
			expected->possible_replies[i].integer == actual_reply->integer) {
			return 1;
		}

		if (expected->possible_replies[i].type == REDIS_REPLY_STATUS &&
			expected->possible_replies[i].type == actual_reply->type &&
			0 == strcasecmp(actual_reply->str, "OK")) {
			return 1;
		}
	}

	return 0;
}

int maat_cmd_write_rule(redisContext *c, struct serial_rule *s_rule, 
                        size_t serial_rule_num, long long server_time, 
                        struct log_handle *logger)
{
	size_t i = 0;
    size_t rule_seq = 0;
	size_t multi_cmd_cnt = 0;
    size_t success_cnt = 0;
    size_t renew_num = 0;
    size_t max_redis_batch = 1024;
    int renew_allowed = 0;
    int last_failed = -1;
    redisReply *p = NULL;
    redisReply *transaction_reply = NULL;
	const int MAX_REDIS_OP_PER_SRULE = 8;
    char transaction_list[NAME_MAX * 2] = {0};
    long long transaction_version = 0;
    long long transaction_finished_version = 0;
	size_t max_multi_cmd_num = MAX_REDIS_OP_PER_SRULE * serial_rule_num + 2;// 2 for operation in exec_serial_rule_end()
	struct expected_reply *expected_reply = ALLOC(struct expected_reply, max_multi_cmd_num);
	
	for (i = 0; i < serial_rule_num; i++) {
		if (s_rule[i].op == MAAT_OP_RENEW_TIMEOUT) {
			renew_num++;
		}
	}

	int ret = exec_serial_rule_begin(c, serial_rule_num, renew_num, &renew_allowed, 
                                     &transaction_version);
	//Preconditions for transaction are not satisfied.
    if (ret != 0) {
		success_cnt = -1;
		goto error_out;
	}

	if (transaction_version > 0) {
		snprintf(transaction_list, sizeof(transaction_list), "MAAT_TRANSACTION_%lld", 
                 transaction_version);
	}
    
	while (success_cnt < serial_rule_num) {
		size_t batch_cnt = MIN(serial_rule_num - success_cnt, max_redis_batch);
		exec_serial_rule(c, transaction_list, s_rule + success_cnt, batch_cnt, 
                         expected_reply, &multi_cmd_cnt, success_cnt, renew_allowed);
		assert(multi_cmd_cnt<max_multi_cmd_num);
		success_cnt+=batch_cnt;
	}

	transaction_reply = exec_serial_rule_end(c, transaction_list, server_time, renew_allowed, 
                                             expected_reply, &multi_cmd_cnt);
	if (transaction_reply->type != REDIS_REPLY_NIL) {
		assert(transaction_reply->elements == multi_cmd_cnt);
		for (i = 0; i < multi_cmd_cnt; i++) {
			p = transaction_reply->element[i];
			//failed is acceptable 
            //or transaciton is success
			//or continuation of last failed
			if (expected_reply[i].s_rule_seq == -1 || 
                1 == mr_operation_success(p, expected_reply+i) || 
                last_failed == expected_reply[i].s_rule_seq) {
				continue;
			}

			rule_seq = expected_reply[i].s_rule_seq;
			log_error(logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] %s %s %lld failed, rule id maybe conflict or not exist",
					  __FUNCTION__, __LINE__, mr_op_str[s_rule[rule_seq].op], 
                      s_rule[rule_seq].table_name, s_rule[rule_seq].rule_id);
			success_cnt--;
			last_failed = rule_seq;
		}
	} else {
		success_cnt = -1;
	}

	if (transaction_version > 0) {
		transaction_finished_version = maat_read_redis_integer(transaction_reply->element[multi_cmd_cnt - 1]);
		log_info(logger, MODULE_REDIS_MONITOR, 
                 "Redis transaction MAAT_PRE_VER = %lld , MAAT_VERSION = %lld",
				 transaction_version, transaction_finished_version);
	}

	freeReplyObject(transaction_reply);
	transaction_reply = NULL;
	
error_out:
	if (renew_num > 0 && renew_allowed != 1) {
		for (i = 0; i < (unsigned int)serial_rule_num; i++) {
			if (s_rule[i].op == MAAT_OP_RENEW_TIMEOUT) {
				log_error(logger, MODULE_REDIS_MONITOR, 
                          "[%s:%d] %s %s %lld is not allowed due to lock contention",
                          __FUNCTION__, __LINE__, mr_op_str[MAAT_OP_RENEW_TIMEOUT],
                          s_rule[i].table_name, s_rule[i].rule_id);
			}
		}

		if (success_cnt > 0) {
			success_cnt -= renew_num;
		}
	}

	FREE(expected_reply);

	return success_cnt;
}

static void cleanup_update_status(redisContext *c, struct log_handle *logger)
{
	long long version_upper_bound = 0;
    long long version_lower_bound = 0;
    long long version_num = 0;
    long long entry_num = 0;

	long long server_time = maat_redis_server_time_s(c);
	if (!server_time) {
		return;
	}

	redisReply *reply = maat_wrap_redis_command(c, "MULTI");
	freeReplyObject(reply);
	reply = NULL;

    int append_cmd_cnt = 0;
	redisAppendCommand(c, "ZRANGEBYSCORE %s -inf %lld", 
                        mr_version_sset, server_time - MAAT_REDIS_SYNC_TIME);
	append_cmd_cnt++;

	redisAppendCommand(c, "ZREMRANGEBYSCORE %s -inf %lld",
                        mr_version_sset,server_time - MAAT_REDIS_SYNC_TIME);
	append_cmd_cnt++;

	//consume reply "OK" and "QUEUED".
	for(int i = 0; i < append_cmd_cnt; i++) {
		maat_wrap_redis_get_reply(c, &reply);
		freeReplyObject(reply);
		reply = NULL;
	}

    redisReply *sub_reply = NULL;
	reply = maat_wrap_redis_command(c, "EXEC");
	if (reply->type != REDIS_REPLY_ARRAY) {
		goto error_out;
	}

	sub_reply = reply->element[0];
	if (sub_reply->type != REDIS_REPLY_ARRAY) {
		goto error_out;
	}

	version_num = sub_reply->elements;
	if (version_num == 0) {
		goto error_out;
	}

	version_lower_bound = maat_read_redis_integer(sub_reply->element[0]);
	version_upper_bound = maat_read_redis_integer(sub_reply->element[sub_reply->elements-1]);
	freeReplyObject(reply);	
	reply = NULL;

	//To deal with maat_version reset to 0, do NOT use -inf as lower bound intentionally.
	reply = maat_wrap_redis_command(c, "ZREMRANGEBYSCORE %s %lld %lld", 
                                        mr_status_sset, version_lower_bound, 
                                        version_upper_bound);
	entry_num = maat_read_redis_integer(reply);
	freeReplyObject(reply);	
	reply = NULL;

	log_info(logger, MODULE_REDIS_MONITOR, 
             "Clean up update status from version %lld to %lld (%lld versions, %lld entries)",
             version_lower_bound, version_upper_bound, version_num, entry_num);
	return;
	
error_out:
	freeReplyObject(reply);
	reply = NULL;
}

static void check_maat_expiration(redisContext *c, struct log_handle *logger)
{
	UNUSED int ret = 0;

	long long server_time = maat_redis_server_time_s(c);
	if (!server_time) {
		return;
	}

	redisReply *data_reply= maat_wrap_redis_command(c, "ZRANGEBYSCORE %s -inf %lld", 
                                                        mr_expire_sset, server_time);
	if (data_reply->type != REDIS_REPLY_ARRAY || 0 == data_reply->elements) {
		freeReplyObject(data_reply);
		data_reply = NULL;
		return;
	}

	size_t s_rule_num = data_reply->elements;
	struct serial_rule *s_rule = ALLOC(struct serial_rule, s_rule_num);

	for (size_t i = 0; i < s_rule_num; i++) {
		s_rule[i].op = MAAT_OP_DEL;
		ret = sscanf(data_reply->element[i]->str, "%[^,],%lld", 
                    s_rule[i].table_name, &(s_rule[i].rule_id));
		assert(ret == 2);
	}
	freeReplyObject(data_reply);
	data_reply = NULL;

	int success_cnt = maat_cmd_write_rule(c, s_rule, s_rule_num, server_time, logger);
    if (success_cnt < 0) {
        log_error(logger, MODULE_REDIS_MONITOR, "[%s:%d] maat_cmd_write_rule failed.",
                  __FUNCTION__, __LINE__);
    } else if (success_cnt == (int)s_rule_num) {
		log_info(logger, MODULE_REDIS_MONITOR, 
                 "Succesfully expired %zu rules in Redis", s_rule_num);
	} else {
		log_error(logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] Failed to expired %d of %zu rules in Redis, try later", 
                  __FUNCTION__, __LINE__, s_rule_num - success_cnt, s_rule_num);
	}

	FREE(s_rule);
}

void redis_monitor_traverse(long long version, struct source_redis_ctx *mr_ctx,
							void (*start_fn)(long long, int, void *),
							int (*update_fn)(const char *, const char *, void *),
							void (*finish_fn)(void *), void *u_param)
{
    int i = 0;
    int ret = 0;
    int table_id = 0;
    int empty_value_num = 0;
    int no_table_num = 0;
    int call_update_num = 0;
    int valid_column = -1;
    struct maat *maat_inst = (struct maat *)u_param;

    //authorized to write
	if (mr_ctx->write_ctx != NULL && mr_ctx->write_ctx->err == 0) {
		//For thread safe, deliberately use redis_read_ctx but not redis_write_ctx.
		if (1 == redlock_try_lock(mr_ctx->read_ctx, mr_expire_lock, mr_expire_lock_timeout_ms)) {
			check_maat_expiration(mr_ctx->read_ctx, maat_inst->logger);
			cleanup_update_status(mr_ctx->read_ctx, maat_inst->logger);
			redlock_unlock(mr_ctx->read_ctx, mr_expire_lock);
		}
	}

	if (NULL == mr_ctx->read_ctx || mr_ctx->read_ctx->err) {
		if (time(NULL) - mr_ctx->last_reconnect_time < MAAT_REDIS_RECONNECT_INTERVAL_S) {
			return;
		}

		mr_ctx->last_reconnect_time = time(NULL);
		if (mr_ctx->read_ctx != NULL) {
			redisFree(mr_ctx->read_ctx);
            mr_ctx->read_ctx = NULL;
		}
		log_info(maat_inst->logger, MODULE_REDIS_MONITOR, "Reconnecting...");

		mr_ctx->read_ctx = maat_connect_redis(mr_ctx->redis_ip, 
                                                  mr_ctx->redis_port, 
                                                  mr_ctx->redis_db,
                                                  maat_inst->logger);
		if (NULL == mr_ctx->read_ctx) {
			return;
		} else {
			version = 0; //Trigger full update when reconnect to redis.
		}
	}
	
    struct serial_rule *rule_list = NULL;
    long long new_version = 0;
    int update_type = MAAT_UPDATE_TYPE_INC;

	int rule_num = maat_get_rm_key_list(mr_ctx->read_ctx, version, 
                                            maat_inst->load_specific_version, 
                                            &new_version, maat_inst->tbl_mgr, 
                                            &rule_list, &update_type, 
                                            maat_inst->opts.cumulative_update_off,
                                            maat_inst->logger);
	//redis communication error
    if (rule_num < 0) {		
		redisFree(mr_ctx->read_ctx);
		mr_ctx->read_ctx = NULL;
		return;
	}

	maat_inst->load_specific_version = 0;//only valid for one time.
    //error or nothing changed
	if (0 == rule_num && update_type == MAAT_UPDATE_TYPE_INC) {
		return;
	}

	if (rule_num > 0) {
		ret = maat_get_redis_value(mr_ctx->read_ctx, rule_list, rule_num, 
                                    0, maat_inst->logger);
        //redis communication error
		if (ret < 0) {
			redisFree(mr_ctx->read_ctx);
			mr_ctx->read_ctx = NULL;
			log_error(maat_inst->logger, MODULE_REDIS_MONITOR, 
                      "[%s:%d] Get Redis value failed, abandon update and close connection",
                      __FUNCTION__, __LINE__);
			goto clean_up;
		}

		for (i = 0; i < rule_num; i++) {
			if (NULL == rule_list[i].table_line) {
				empty_value_num++;
			}
		}

		if (empty_value_num == rule_num) {
			log_info(maat_inst->logger, MODULE_REDIS_MONITOR, 
                     "All %d rules are empty, abandon update", empty_value_num);
			goto clean_up;
		}

		ret = get_foreign_keys_define(mr_ctx->read_ctx, rule_list, rule_num, 
                                      maat_inst, maat_inst->opts.foreign_cont_dir);
		if (ret > 0) {
			maat_get_foreign_conts(mr_ctx->read_ctx, rule_list, rule_num, 0, 
                                    maat_inst->logger);
		}
	}

	start_fn(new_version, update_type, u_param);
	log_info(maat_inst->logger, MODULE_REDIS_MONITOR, 
             "Start %s update: %lld -> %lld (%d entries)",
			 update_type == MAAT_UPDATE_TYPE_INC ? "INC" : "FULL", 
             version, new_version, rule_num);

	for (i = 0; i < rule_num; i++) {
		if (NULL == rule_list[i].table_line) {
			continue;
		}

		table_id = table_manager_get_table_id(maat_inst->tbl_mgr, rule_list[i].table_name);
		//Unrecognized table.
        if (table_id < 0) {
			no_table_num++;
			continue;
		}

		if (rule_list[i].op == MAAT_OP_DEL) {
			valid_column = table_manager_get_valid_column(maat_inst->tbl_mgr, table_id);
			ret = invalidate_line(rule_list[i].table_line, valid_column);
			if (ret < 0) {
				log_error(maat_inst->logger, MODULE_REDIS_MONITOR, 
                          "[%s:%d] Invalidate line failed, invaid format %s", 
                          __FUNCTION__, __LINE__, rule_list[i].table_line);
				continue;
			}
		}

		if (rule_list[i].n_foreign > 0) {
			maat_rewrite_table_line_with_foreign(rule_list+i);
		}

		update_fn(rule_list[i].table_name, rule_list[i].table_line, u_param);
		call_update_num++;
	}

	finish_fn(u_param);

	if (call_update_num < rule_num) {		
		log_error(maat_inst->logger, MODULE_REDIS_MONITOR, 
                  "[%s:%d] Load %d entries to match engine, no table: %d, empty value: %d",
				  __FUNCTION__, __LINE__, call_update_num, no_table_num, empty_value_num);
	}

clean_up:
	for (i = 0; i < rule_num; i++) {
		maat_clear_rule_cache(rule_list + i);
	}

	FREE(rule_list);
}
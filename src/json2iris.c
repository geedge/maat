/*
**********************************************************************************************
*	File: json2iris.c
*   Description: rule for transform json2iris
*	Authors: Zheng Chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <linux/limits.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>

#include "json2iris.h"
#include "cJSON/cJSON.h"
#include "maat_kv.h"
#include "maat_utils.h"
#include "maat_core.h"
#include "uthash/uthash.h"
#include "maat_redis_monitor.h"

#define MODULE_JSON2IRIS  module_name_str("maat.json2iris")

#define	MAX_COLUMN_NUM	 32
#define MAX_PATH_LINE    512
#define MAX_BUFF_LEN     4096
#define MAX_OBJECT_ID_STR 128

const int json_version = 1;
const char *untitled_object_name = "Untitled";
long long untitled_object_id = 123456789;

enum maat_object_relation {
	PARENT_TYPE_RULE = 0,
	PARENT_TYPE_OBJECT
};

struct object_info {
    int object_id;
    char object_name[NAME_MAX];
    UT_array *incl_sub_object_ids;
    UT_array *excl_sub_object_ids;
    UT_hash_handle hh;
};

struct iris_table {
	char table_name[MAX_NAME_STR_LEN];
	char table_path[PATH_MAX];
	int line_count;
	enum table_type table_type;
	void *buff;
	size_t write_pos;
	size_t buff_sz;
    UT_hash_handle hh;
};

struct iris_description {
	int object_cnt;
	int region_cnt;
	
	char tmp_iris_dir[MAX_PATH_LINE];
	char tmp_iris_index_dir[MAX_PATH_LINE];
	char index_path[PATH_MAX];

	struct iris_table *object_table;
	struct iris_table *object2object_table;
	struct iris_table *object2rule_table;
	struct iris_table *rule_table;

	struct object_info *object_name_map;
	struct iris_table *iris_table_map;

	struct maat_kv_store *str2int_map;
	redisContext *redis_write_ctx;

	char *encrypt_key;
	char *encrypt_algo;
	FILE *idx_fp;
};

struct translate_command {
	const char *json_string;
	char *json_value;
	int json_type;
	int str2int_flag;
	int empty_allowed;
	const char *default_string;
	int default_int;
};

static struct iris_table *
query_table_info(struct iris_description *p_iris, const char *table_name, 
                 enum table_type table_type)
{
    if (NULL == p_iris || NULL == table_name || 
        table_type == TABLE_TYPE_INVALID) {
        return NULL;
    }

    struct iris_table *table_info = NULL;
    HASH_FIND(hh, p_iris->iris_table_map, table_name, strlen(table_name), table_info);
    if (NULL == table_info) {
        table_info = ALLOC(struct iris_table, 1);
        table_info->line_count = 0;
		table_info->table_type = table_type;
		memcpy(table_info->table_name, table_name, MIN(sizeof(table_info->table_name) - 1,
               strlen(table_name)));
		snprintf(table_info->table_path, sizeof(table_info->table_path), 
                 "%s/%s.local", p_iris->tmp_iris_dir, table_info->table_name);
        HASH_ADD_KEYPTR(hh, p_iris->iris_table_map, table_info->table_name,
                        strlen(table_name), table_info);
    }

	return table_info;
}

static void free_iris_table_info(void *p)
{
	struct iris_table *table = (struct iris_table *)p;
    if (table != NULL) {
        FREE(table->buff);
    }
    FREE(table);
}

static int
set_iris_descriptor(const char *json_file, cJSON *json,
                    const char *encrypt_key, const char *encrypt_algo, 
                    const char *rule_tn, const char *object2rule_tn,
                    const char* object2object_tn, redisContext *redis_write_ctx,
                    struct iris_description *iris_cfg)
{
	memset(iris_cfg, 0, sizeof(struct iris_description));
	snprintf(iris_cfg->tmp_iris_dir, sizeof(iris_cfg->tmp_iris_dir),
             "%s_iris_tmp", json_file);
	snprintf(iris_cfg->tmp_iris_index_dir, sizeof(iris_cfg->tmp_iris_index_dir), 
             "%s_iris_tmp/index", json_file);
	snprintf(iris_cfg->index_path, sizeof(iris_cfg->index_path),
             "%s/full_config_index.%010d", iris_cfg->tmp_iris_index_dir,
             json_version);

	iris_cfg->redis_write_ctx = redis_write_ctx;
	iris_cfg->str2int_map = maat_kv_store_new();
	
	maat_kv_register(iris_cfg->str2int_map, "yes", 1);
	maat_kv_register(iris_cfg->str2int_map, "no", 0);
	
    maat_kv_register(iris_cfg->str2int_map, "flag", TABLE_TYPE_FLAG);
    maat_kv_register(iris_cfg->str2int_map, "flag_plus", TABLE_TYPE_FLAG_PLUS);
	maat_kv_register(iris_cfg->str2int_map, "ip", TABLE_TYPE_IP);
	maat_kv_register(iris_cfg->str2int_map, "string", TABLE_TYPE_EXPR);
	maat_kv_register(iris_cfg->str2int_map, "expr", TABLE_TYPE_EXPR);
	maat_kv_register(iris_cfg->str2int_map, "expr_plus", TABLE_TYPE_EXPR_PLUS);
	maat_kv_register(iris_cfg->str2int_map, "interval", TABLE_TYPE_INTERVAL);
	maat_kv_register(iris_cfg->str2int_map, "interval_plus", TABLE_TYPE_INTERVAL_PLUS);
	
	maat_kv_register(iris_cfg->str2int_map, "ipv4", 4);
	maat_kv_register(iris_cfg->str2int_map, "ipv6", 6);

	maat_kv_register(iris_cfg->str2int_map, "double", 0);
	maat_kv_register(iris_cfg->str2int_map, "single", 1);

	maat_kv_register(iris_cfg->str2int_map, "none", 0);
	maat_kv_register(iris_cfg->str2int_map, "and", 1);
	maat_kv_register(iris_cfg->str2int_map, "regex", 2);
	maat_kv_register(iris_cfg->str2int_map, "offset", 3);

	maat_kv_register(iris_cfg->str2int_map, "sub", 0);
	maat_kv_register(iris_cfg->str2int_map, "right", 1);
	maat_kv_register(iris_cfg->str2int_map, "suffix", 1);
	maat_kv_register(iris_cfg->str2int_map, "left", 2);
	maat_kv_register(iris_cfg->str2int_map, "prefix", 2);
	maat_kv_register(iris_cfg->str2int_map, "complete", 3);
	maat_kv_register(iris_cfg->str2int_map, "exact", 3);

	maat_kv_register(iris_cfg->str2int_map, "uncase plain", 0);
	maat_kv_register(iris_cfg->str2int_map, "hexbin", 1);
	maat_kv_register(iris_cfg->str2int_map, "case plain", 2);

	iris_cfg->rule_table = query_table_info(iris_cfg, rule_tn,
                                               TABLE_TYPE_RULE);
	iris_cfg->object2rule_table = query_table_info(iris_cfg, object2rule_tn,
                                                     TABLE_TYPE_OBJECT2RULE);
	iris_cfg->object2object_table = query_table_info(iris_cfg, object2object_tn,
                                                   TABLE_TYPE_OBJECT2OBJECT);
	
	if (encrypt_key && encrypt_algo) {
		iris_cfg->encrypt_key = maat_strdup(encrypt_key);
		iris_cfg->encrypt_algo = maat_strdup(encrypt_algo);
	}

	return 0;
}

static void clear_iris_descriptor(struct iris_description *iris_cfg)
{
	if (iris_cfg->object_name_map != NULL) {
        struct object_info *node = NULL;
        struct object_info *tmp = NULL;
        HASH_ITER(hh, iris_cfg->object_name_map, node, tmp) {
			if (node->incl_sub_object_ids != NULL) {
				utarray_free(node->incl_sub_object_ids);
				node->incl_sub_object_ids = NULL;
			}

			if (node->excl_sub_object_ids != NULL) {
				utarray_free(node->excl_sub_object_ids);
				node->excl_sub_object_ids = NULL;
			}

            HASH_DELETE(hh, iris_cfg->object_name_map, node);
            FREE(node);
        }
	}

	if(iris_cfg->iris_table_map != NULL) {
        struct iris_table *node = NULL;
        struct iris_table *tmp = NULL;
        HASH_ITER(hh, iris_cfg->iris_table_map, node, tmp) {
            HASH_DELETE(hh, iris_cfg->iris_table_map, node);
            free_iris_table_info(node);
        }
	}

	maat_kv_store_free(iris_cfg->str2int_map);
	iris_cfg->str2int_map = NULL;
	
	FREE(iris_cfg->encrypt_algo);
	FREE(iris_cfg->encrypt_key);
    
	return;
}

static int create_tmp_dir(struct iris_description *p)
{
	if ((access(p->tmp_iris_dir,F_OK)) < 0) {
		if ((mkdir(p->tmp_iris_dir, 0777)) < 0) {
			return -1;
		}
	}

	if ((access(p->tmp_iris_index_dir,F_OK)) < 0) {
		if ((mkdir(p->tmp_iris_index_dir, 0777)) < 0) {
			return -1;
		}
	}

	return 0;
}

static int
write_plugin_line(cJSON *plug_table_json, int sequence,
                  struct iris_description *p_iris, 
                  struct log_handle *logger)
{
	cJSON *item = cJSON_GetObjectItem(plug_table_json, "table_name");
	if (NULL == item || item->type != cJSON_String) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] The %d plugin_table's table_name "
                  "not defined or format error", __FUNCTION__,
                  __LINE__, sequence);
		return -1;
	}
	const char *table_name = item->valuestring;

	cJSON *table_content = cJSON_GetObjectItem(plug_table_json, "table_content");
	if (NULL == table_content || table_content->type != cJSON_Array) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] %d plugin_table's table_content not defined or format error",
                  __FUNCTION__, __LINE__, sequence);
		return -1;
	}
	int line_cnt = cJSON_GetArraySize(table_content);
    struct iris_table *table_info = query_table_info(p_iris, table_name,
                                                     TABLE_TYPE_PLUGIN);

    cJSON *each_line = NULL;
	const char *line_content = NULL;
	for (int i = 0; i < line_cnt; i++) {
		each_line = cJSON_GetArrayItem(table_content, i);
		if (NULL == each_line || each_line->type != cJSON_String) {
			log_fatal(logger, MODULE_JSON2IRIS,
                      "[%s:%d] plugin_table %s's line %d format error", 
                      __FUNCTION__, __LINE__, table_info->table_name, i + 1);
			continue;
		}
        
		line_content = each_line->valuestring;
		table_info->write_pos += memcat(&(table_info->buff), table_info->write_pos, 
                                        &(table_info->buff_sz), line_content,
                                        strlen(line_content));
		table_info->write_pos += memcat(&(table_info->buff), table_info->write_pos, 
                                        &(table_info->buff_sz), "\n", 1);
		table_info->line_count++;
	}

	return 0;
}

static struct object_info *object_info_read(struct object_info *object_name_map,
                                          const char *object_name)
{
    struct object_info *node = NULL;
    HASH_FIND(hh, object_name_map, object_name, strlen(object_name), node);

    return node;
}

UT_icd ut_json2iris_object_id_icd = {sizeof(int), NULL, NULL, NULL};
static struct object_info *
object_info_add_unsafe(struct iris_description *p_iris, const char *object_name,
					  long long object_id)
{
	struct object_info *object_info = ALLOC(struct object_info, 1);
	utarray_new(object_info->incl_sub_object_ids, &ut_json2iris_object_id_icd);
	utarray_new(object_info->excl_sub_object_ids, &ut_json2iris_object_id_icd);

	object_info->object_id = object_id;
	strncpy(object_info->object_name, object_name, sizeof(object_info->object_name));

    HASH_ADD_KEYPTR(hh, p_iris->object_name_map, object_info->object_name,
                    strlen(object_name), object_info);

	return object_info;
}

static int get_region_seq(struct iris_description *iris_cfg)
{
	int sequence = 0;

	if (NULL == iris_cfg->redis_write_ctx) {
		sequence = iris_cfg->region_cnt + 1;
	} else {
		redisReply *data_reply =
			maat_wrap_redis_command(iris_cfg->redis_write_ctx, NULL,
                                    "INCRBY %s 1", mr_region_id_var);
									
		sequence = (int)data_reply->integer;
		freeReplyObject(data_reply);
	}
	iris_cfg->region_cnt++;

	return sequence;
}

static int
direct_write_rule(cJSON *json, struct maat_kv_store *str2int, 
                  struct translate_command *cmd, int cmd_cnt, 
                  struct iris_table *table, struct log_handle *logger)
{
	int i = 0;
    int ret = -1;
	cJSON dummy;

	for (i = 0; i < cmd_cnt; i++) {
		cJSON *item = cJSON_GetObjectItem(json, cmd[i].json_string);
		if (NULL == item && (1 == cmd[i].empty_allowed)) {
			dummy.valuestring = (char *)cmd[i].default_string;
			dummy.valueint = cmd[i].default_int;
			dummy.valuedouble = cmd[i].default_int;
			dummy.type = cmd[i].json_type;
			item = &dummy;
		}

		if (NULL == item || item->type != cmd[i].json_type) {
			log_fatal(logger, MODULE_JSON2IRIS, 
                      "[%s:%d] %s not defined or wrong format", 
                      __FUNCTION__, __LINE__, cmd[i].json_string);
			ret = -1;
			goto error_out;
		}

		if (1 == cmd[i].str2int_flag) {
            long long int_value = 0;
			char *p = item->valuestring;
			ret = maat_kv_read(str2int, p, &int_value, 1);			
			if (ret < 0) {
				log_fatal(logger, MODULE_JSON2IRIS, 
                          "[%s:%d] %s's value %s is not valid format", 
                          __FUNCTION__, __LINE__, cmd[i].json_string, p);
				FREE(p);
				ret = -1;
				goto error_out;
			}
			cmd[i].json_value = (char *)malloc(21);/* 2^64+1 can be represented in 21 chars. */
			snprintf(cmd[i].json_value, 21, "%d", (int)int_value);
		} else {
			switch (item->type) {
				case cJSON_Number:
					cmd[i].json_value = cJSON_Print(item);
					break;
				case cJSON_String:
					cmd[i].json_value = ALLOC(char, strlen(item->valuestring) + 1);
					memcpy(cmd[i].json_value, item->valuestring, strlen(item->valuestring));
					break;
				default://impossible ,already checked
					assert(0);
					break;
			}
		}
	}

	for (i = 0; i < cmd_cnt; i++) {
		table->write_pos += memcat(&(table->buff), table->write_pos, &table->buff_sz, 
                                   cmd[i].json_value, strlen(cmd[i].json_value));
		table->write_pos += memcat(&(table->buff), table->write_pos,
								   &table->buff_sz, "\t", 1);
	}
	table->write_pos += memcat(&(table->buff), table->write_pos,
							   &table->buff_sz, "\n", 1);
	table->line_count++;
	ret = 0;
error_out:	
	for (i = 0; i < cmd_cnt; i++) {
		if (cmd[i].json_value != NULL) {
			FREE(cmd[i].json_value);
		}
	}
	return ret;
}

static int
write_flag_line(cJSON *region_json, struct iris_description *p_iris, 
                struct iris_table *table, struct log_handle *logger)
{
    struct translate_command json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt = 0;
	memset(json_cmd, 0, sizeof(json_cmd));

	json_cmd[cmd_cnt].json_string = "region_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "object_id";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;
	
    if (table->table_type==TABLE_TYPE_FLAG_PLUS) {
		json_cmd[cmd_cnt].json_string = "district";
		json_cmd[cmd_cnt].json_type = cJSON_String;
		cmd_cnt++;
	}

	json_cmd[cmd_cnt].json_string = "flag";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

    json_cmd[cmd_cnt].json_string = "flag_mask";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "is_valid";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;
	
	return direct_write_rule(region_json, p_iris->str2int_map, 
                             json_cmd, cmd_cnt, table, logger);
}

static int
write_expr_line(cJSON *region_json, struct iris_description *p_iris,
                struct iris_table *table, struct log_handle *logger)
{
	struct translate_command json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt = 0;
	memset(json_cmd, 0, sizeof(json_cmd));

	json_cmd[cmd_cnt].json_string = "region_id";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "object_id";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;
	
	if (table->table_type==TABLE_TYPE_EXPR_PLUS) {
		json_cmd[cmd_cnt].json_string = "district";
		json_cmd[cmd_cnt].json_type = cJSON_String;
		cmd_cnt++;
	}

	json_cmd[cmd_cnt].json_string = "expr_type";
	json_cmd[cmd_cnt].json_type = cJSON_String;
	json_cmd[cmd_cnt].str2int_flag = 1;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "keywords";
	json_cmd[cmd_cnt].json_type = cJSON_String;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "is_valid";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;
	
	return direct_write_rule(region_json, p_iris->str2int_map, 
                             json_cmd, cmd_cnt, table, logger);
}

static int
write_ip_line(cJSON *region_json, struct iris_description *p_iris,
              struct iris_table *table, struct log_handle *logger)
{
	struct translate_command json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt = 0;
	memset(json_cmd, 0, sizeof(json_cmd));

	json_cmd[cmd_cnt].json_string = "region_id";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "object_id";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;	

	json_cmd[cmd_cnt].json_string = "ip";
	json_cmd[cmd_cnt].json_type = cJSON_String;
	json_cmd[cmd_cnt].empty_allowed = 1;
	json_cmd[cmd_cnt].default_string = "0.0.0.0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "port";
	json_cmd[cmd_cnt].json_type = cJSON_String;
	json_cmd[cmd_cnt].empty_allowed = 1;
	json_cmd[cmd_cnt].default_string = "0-65535";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "is_valid";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

	return direct_write_rule(region_json, p_iris->str2int_map,
                             json_cmd, cmd_cnt, table, logger);
}

static int
write_interval_line(cJSON *region_json, struct iris_description *p_iris,
                    struct iris_table *table, struct log_handle *logger)
{
	struct translate_command json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt = 0;
	memset(json_cmd, 0, sizeof(json_cmd));
	
	json_cmd[cmd_cnt].json_string = "region_id";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "object_id";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

	if (table->table_type == TABLE_TYPE_INTERVAL_PLUS) {
		json_cmd[cmd_cnt].json_string = "district";
		json_cmd[cmd_cnt].json_type = cJSON_String;
		cmd_cnt++;
	}

	json_cmd[cmd_cnt].json_string = "interval";
	json_cmd[cmd_cnt].json_type = cJSON_String;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string = "is_valid";
	json_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;
	
	return direct_write_rule(region_json, p_iris->str2int_map,
                             json_cmd, cmd_cnt, table, logger);
}

static int
write_region_rule(cJSON *region_json, int rule_id, int object_id,
                  struct iris_description *p_iris, struct log_handle *logger)
{
    cJSON *item = cJSON_GetObjectItem(region_json, "table_name");
	if (NULL == item || item->type != cJSON_String) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] rule rule %d's table_name not defined "
                  "or format error", __FUNCTION__, __LINE__, rule_id);
		return -1;
	}
    const char *table_name = item->valuestring;

	item = cJSON_GetObjectItem(region_json, "table_type");
	if (NULL == item || item->type != cJSON_String) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] rule rule %d's table name %s's table_type "
                  "not defined or format error", __FUNCTION__, __LINE__,
                  rule_id, table_name);
		return -1;
	}

	const char *table_type_str = item->valuestring;
    long long table_type_int;
	int ret = maat_kv_read(p_iris->str2int_map, table_type_str, &table_type_int, 1);
	if (ret != 1) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] rule rule %d table name %s's table_type %s invalid",
                  __FUNCTION__, __LINE__, rule_id, table_name, table_type_str);
		return -1;
	}
	
	cJSON *table_content = cJSON_GetObjectItem(region_json, "table_content");
	if (NULL == table_content || table_content->type != cJSON_Object) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] rule rule %d table name %s's table_content "
                  "not defined or format error", __FUNCTION__, __LINE__,
                  rule_id, table_name);
		return -1;
	}

	int region_id = get_region_seq(p_iris);
	cJSON_AddNumberToObject(table_content, "region_id", region_id);
	cJSON_AddNumberToObject(table_content, "object_id", object_id);
	cJSON_AddNumberToObject(table_content, "is_valid", 1);

    struct iris_table *table_info = query_table_info(p_iris, table_name,
                                                     table_type_int);
	switch (table_type_int) {
        case TABLE_TYPE_FLAG:
        case TABLE_TYPE_FLAG_PLUS:
            ret = write_flag_line(table_content, p_iris, table_info, logger);
            break;
		case TABLE_TYPE_EXPR:
		case TABLE_TYPE_EXPR_PLUS:
			ret = write_expr_line(table_content, p_iris, table_info, logger);
			break;
		case TABLE_TYPE_IP:
			ret = write_ip_line(table_content, p_iris, table_info, logger);
			break;
		case TABLE_TYPE_INTERVAL:
		case TABLE_TYPE_INTERVAL_PLUS:
			ret = write_interval_line(table_content, p_iris, table_info, logger);
			break;
		default:
			assert(0);
			break;
	}
	return ret;
}

static int
write_object2rule_line(int *object_ids, size_t n_object_id,
						 int rule_id, int object_negate_option,
                         int condition_index, const char *attribute, 
                         struct iris_description *p_iris,
                         struct iris_table *g2c_table)
{
	char buff[4096] = {0};
    struct iris_table *table = NULL;
    
    if (g2c_table != NULL) {
        table = g2c_table;
    } else {
        if (NULL == p_iris->object2rule_table) {
            return -1;
        }
        table = p_iris->object2rule_table;
    }

	if (n_object_id > 1) {
		char tmp_str[64] = {0};
		char object_id_str[2048] = {0};

		for (size_t i = 0; i < n_object_id; i++) {
			snprintf(tmp_str, sizeof(tmp_str), "%d,", object_ids[i]);
			strcat(object_id_str, tmp_str);
		}
		object_id_str[strlen(object_id_str) - 1] = '\0';
		snprintf(buff, sizeof(buff), "%s\t%d\t%d\t%s\t%d\t1\n", object_id_str,
				 rule_id, object_negate_option, attribute, condition_index);
	} else {
		snprintf(buff, sizeof(buff), "%d\t%d\t%d\t%s\t%d\t1\n", object_ids[0],
				 rule_id, object_negate_option, attribute, condition_index);
	}
	
	table->write_pos += memcat(&(table->buff), table->write_pos,
							   &(table->buff_sz), buff, strlen(buff));
	table->line_count++;

	return 0;
}

static int
write_object2object_line(int object_id, UT_array *incl_sub_object_ids,
					   UT_array *excl_sub_object_ids,
                       struct iris_description *p_iris)
{
	char buff[MAX_BUFF_LEN*4] = {0};
	struct iris_table *table = p_iris->object2object_table;
    if (NULL == table) {
        return -1;
    }

    size_t i = 0, pos = 0;
    char incl_sub_object_id_str[MAX_BUFF_LEN] = {0};
    char excl_sub_object_id_str[MAX_BUFF_LEN] = {0};

	if (0 == utarray_len(incl_sub_object_ids) &&
		0 == utarray_len(excl_sub_object_ids)) {
		return 0;
	}

	int *tmp_id = NULL;
	char tmp_str[MAX_OBJECT_ID_STR] = {0};
    for (i = 0; i < utarray_len(incl_sub_object_ids); i++) {
        tmp_id = (int *)utarray_eltptr(incl_sub_object_ids, i);
        sprintf(tmp_str, "%d,", *tmp_id);
        sprintf(incl_sub_object_id_str + pos, "%s", tmp_str);
        pos += strlen(tmp_str);
    }

	const char *null_str = "null";
    size_t str_len = strlen(incl_sub_object_id_str);
	if (str_len > 0) {
		incl_sub_object_id_str[str_len - 1] = '\0';
	} else {
		memcpy(incl_sub_object_id_str, null_str, strlen(null_str));
	}
	
	pos = 0;
	memset(tmp_str, 0, sizeof(tmp_str));
	for (i = 0; i < utarray_len(excl_sub_object_ids); i++) {
        tmp_id = (int *)utarray_eltptr(excl_sub_object_ids, i);
        sprintf(tmp_str, "%d,", *tmp_id);
        sprintf(excl_sub_object_id_str + pos, "%s", tmp_str);
        pos += strlen(tmp_str);
    }

	str_len = strlen(excl_sub_object_id_str);
	if (str_len > 0) {
		excl_sub_object_id_str[str_len - 1] = '\0';
	} else {
		memcpy(excl_sub_object_id_str, null_str, strlen(null_str));
	}

    snprintf(buff, sizeof(buff), "%d\t%s\t%s\t1\n", object_id,
			 incl_sub_object_id_str, excl_sub_object_id_str);

    table->write_pos += memcat(&(table->buff), table->write_pos,
                               &(table->buff_sz), buff, strlen(buff));
    table->line_count++;

    return 0;
}

static int
write_object_rule(cJSON *object_json, int parent_id, 
                 int parent_type, int tracking_rule_id, 
                 int Nth_object, struct iris_description *p_iris, 
                 struct log_handle *logger)
{
    int ret = 0;
    int object_negate_option = 0;
    int condition_index = 0;
	const char *object_name = NULL;
	char object_name_array[32][MAX_NAME_STR_LEN];
	size_t object_name_cnt = 0;
	long long object_id = -1;
    const char *attribute = NULL;
    struct iris_table *g2c_table = NULL;

	cJSON *item = cJSON_GetObjectItem(object_json, "object_name");
	if (NULL == item) {
		object_name = untitled_object_name;
	} else if (item->type == cJSON_String) {
		object_name = item->valuestring;
	} else if (item->type == cJSON_Array) {
		object_name_cnt = cJSON_GetArraySize(item);
		assert(object_name_cnt <= 32);
		for (size_t i = 0; i < object_name_cnt; i++) {
			cJSON *tmp_json = cJSON_GetArrayItem(item, i);
			if (NULL == tmp_json || tmp_json->type != cJSON_String) {
				log_fatal(logger, MODULE_JSON2IRIS,
					  "[%s:%d] object_name of rule:%d format error",
					  __FUNCTION__, __LINE__, parent_id);
				return -1;	
			}
			memset(object_name_array[i], 0, sizeof(object_name_array[i]));
			memcpy(object_name_array[i], tmp_json->valuestring,
				   strlen(tmp_json->valuestring));
		}
	}

	item = cJSON_GetObjectItem(object_json, "object_id");
    if (item != NULL && item->type == cJSON_Number) {
		object_id = item->valueint;
	}

	if (parent_type == PARENT_TYPE_RULE) {
		item = cJSON_GetObjectItem(object_json, "attribute");
		if (NULL == item || item->type != cJSON_String) {
			attribute = "null";
		} else {
			attribute = item->valuestring;
		}

        item = cJSON_GetObjectItem(object_json, "negate_option");
		if (NULL == item || item->type != cJSON_Number) {
			object_negate_option = 0;
		} else {
			object_negate_option = item->valueint;
		}

		item = cJSON_GetObjectItem(object_json, "condition_index");
		if (NULL == item || item->type != cJSON_Number) {
			condition_index = Nth_object;
		} else {
			condition_index = item->valueint;
		}

        item = cJSON_GetObjectItem(object_json, "g2c_table_name");
        if (item != NULL && item->type == cJSON_String) {
            g2c_table = query_table_info(p_iris, item->valuestring, 
                                         TABLE_TYPE_OBJECT2RULE);
        }
	}

    if (object_name_cnt > 0) {
		int object_ids[object_name_cnt];
		for (size_t i = 0; i < object_name_cnt; i++) {
			struct object_info *object_info =
				object_info_read(p_iris->object_name_map, object_name_array[i]);
			if (NULL == object_info) {
				log_fatal(logger, MODULE_JSON2IRIS, "[%s:%d] object_name:%s"
						  " has no object_id", __FUNCTION__, __LINE__,
						  object_name_array[i]);
				return -1;
			}
			object_ids[i] = object_info->object_id;
		}
		assert(parent_type == PARENT_TYPE_RULE);
		ret = write_object2rule_line(object_ids, object_name_cnt, parent_id,
                                       object_negate_option, condition_index,
                                       attribute, p_iris, g2c_table);

    } else {
        struct object_info *object_info =
			object_info_read(p_iris->object_name_map, object_name);
        // exist object name, regions and sub objects will be ommit.
        if (NULL == object_info) {
        	if (0 == strncasecmp(object_name, untitled_object_name,
                                 strlen(untitled_object_name))) {
            	object_id = untitled_object_id;
            }

            if (-1 == object_id) {
            	log_fatal(logger, MODULE_JSON2IRIS,
                    	  "[%s:%d] object_name:<%s> has no object_id",
						  __FUNCTION__, __LINE__, object_name);
            	return -1;
            }

            object_info = object_info_add_unsafe(p_iris, object_name, object_id);
            cJSON *region_json = cJSON_GetObjectItem(object_json, "regions");
            if (region_json != NULL) {
            	cJSON *region_rule = NULL;
            	cJSON_ArrayForEach(region_rule, region_json) {
            		ret = write_region_rule(region_rule, tracking_rule_id,
                                       		object_info->object_id, p_iris, logger);
                	if (ret < 0) {
                		log_fatal(logger, MODULE_JSON2IRIS,
                        	  	  "[%s:%d] rule rule %d write region error",
                              	  __FUNCTION__, __LINE__, tracking_rule_id);
                		return -1;
                	}
              	}
            }

            cJSON *sub_objects = cJSON_GetObjectItem(object_json, "sub_objects");
            if (sub_objects != NULL) {
            	// recursively
            	int i = 0;
            	cJSON_ArrayForEach(item, sub_objects) {
                	i++;
                	ret = write_object_rule(item, object_info->object_id,
                                       	   PARENT_TYPE_OBJECT, tracking_rule_id,
                                       	   i, p_iris, logger);
                	if (ret < 0) {
                  		return -1;
                	}
              	}
            }

            if (NULL == region_json && NULL == sub_objects) {
            	log_info(logger, MODULE_JSON2IRIS,
                    	 "[%s:%d] A object of rule rule %d has neither regions, "
                         "sub objects, nor refered another existed object",
                         __FUNCTION__, __LINE__, tracking_rule_id);
            }
        }

        if (parent_type == PARENT_TYPE_RULE) {
            ret = write_object2rule_line(&(object_info->object_id), 1, parent_id,
                                           object_negate_option, condition_index,
                                           attribute, p_iris, g2c_table);
			if (ret < 0) {
				log_fatal(logger, MODULE_JSON2IRIS, 
                  		  "[%s:%d] rule:%d write object error", 
                  		  __FUNCTION__, __LINE__, parent_id);
				return -1;
			}
		}
    }

	return 0;
}

static int
write_rule_line(cJSON *rule, struct iris_description *p_iris,
                   struct log_handle *logger)
{
	cJSON *item=cJSON_GetObjectItem(rule, "rule_id");
	if (item->type != cJSON_Number) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] rule_id format not number",
				  __FUNCTION__, __LINE__);
		return -1;
	}
	int rule_id = item->valueint;

    cJSON *object_array = cJSON_GetObjectItem(rule, "objects");
    int object_num = cJSON_GetArraySize(object_array);
    int *condition_ids = ALLOC(int, object_num);
    int condition_num = 0;
    cJSON *object_obj = NULL;

	cJSON_ArrayForEach(object_obj, object_array) {
		item = cJSON_GetObjectItem(object_obj, "condition_index");
		if (item) {
            int i = 0;
			int condition_index = item->valueint;
			for (i = 0; i < condition_num; i++) {
				if (condition_ids[i] == condition_index) {
					break;
				}
			}

			if (i == condition_num) {
				condition_ids[condition_num] = condition_index;
				condition_num++;
			}			
		}
	}
	FREE(condition_ids);
	
	if (condition_num == 0) {
		condition_num = object_num;
	}

	cJSON_AddNumberToObject(rule, "condition_num", condition_num);

	struct translate_command rule_cmd[MAX_COLUMN_NUM];
	memset(rule_cmd, 0, sizeof(rule_cmd));

    int cmd_cnt = 0;
	rule_cmd[cmd_cnt].json_string = "rule_id";
	rule_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;
	
	rule_cmd[cmd_cnt].json_string = "service";
	rule_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;
	
	rule_cmd[cmd_cnt].json_string = "action";
	rule_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;
	
	rule_cmd[cmd_cnt].json_string = "do_blacklist";
	rule_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

	rule_cmd[cmd_cnt].json_string = "do_log";
	rule_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;


	rule_cmd[cmd_cnt].json_string = "tags";
	rule_cmd[cmd_cnt].json_type = cJSON_String;
	rule_cmd[cmd_cnt].empty_allowed = 1;
	rule_cmd[cmd_cnt].default_string = "{}";
	cmd_cnt++;
	
	rule_cmd[cmd_cnt].json_string = "user_region";
	rule_cmd[cmd_cnt].json_type = cJSON_String;
	cmd_cnt++;
	
	rule_cmd[cmd_cnt].json_string = "condition_num";
	rule_cmd[cmd_cnt].json_type = cJSON_Number;
	cmd_cnt++;

	rule_cmd[cmd_cnt].json_string = "is_valid";
	rule_cmd[cmd_cnt].json_type = cJSON_String;
	rule_cmd[cmd_cnt].str2int_flag = 1;
	cmd_cnt++;

	rule_cmd[cmd_cnt].json_string = "modified_time";
	rule_cmd[cmd_cnt].json_type = cJSON_String;
	rule_cmd[cmd_cnt].empty_allowed = 1;
	time_t curr_time;
	time(&curr_time);
	static char temp[21];
	snprintf(temp, 21, "%ld", curr_time);
	rule_cmd[cmd_cnt].default_string = temp;
	cmd_cnt++;

    struct iris_table *table_info = NULL;
	item = cJSON_GetObjectItem(rule,"rule_table_name");
	if (NULL == item || item->type != cJSON_String) {
        if (NULL == p_iris->rule_table) {
            return -1;
        }
		table_info = p_iris->rule_table;
	} else {
		table_info = query_table_info(p_iris, item->valuestring, TABLE_TYPE_RULE);
	}
	
	int ret = direct_write_rule(rule, p_iris->str2int_map, rule_cmd,
								cmd_cnt, table_info, logger);
	if (ret < 0) {
		return -1;
	}

	return rule_id;
}

static void write_table_idx(struct iris_description *p_iris,
							struct iris_table *table)
{
	char line_cnt_str[32] = {0};
    char err_str[256] = {0};

	snprintf(line_cnt_str, sizeof(line_cnt_str), "%010d\n", table->line_count);

	size_t table_file_sz = strlen(line_cnt_str) + table->write_pos;
    unsigned char *buff = ALLOC(unsigned char, table_file_sz);
	memcpy(buff, line_cnt_str, strlen(line_cnt_str));
	memcpy(buff + strlen(line_cnt_str), table->buff, table->write_pos);

    UNUSED int ret = 0;
	FILE *table_fp = fopen(table->table_path, "w");
	if (p_iris->encrypt_key) {
        unsigned char *encrypt_buff = NULL;
        size_t encrypt_buff_sz = 0;
		ret = crypt_memory(buff, table_file_sz, &encrypt_buff, 
                           &encrypt_buff_sz, p_iris->encrypt_key, 
                           p_iris->encrypt_algo, 1, err_str, sizeof(err_str));
		assert(ret == 0);
		fwrite(encrypt_buff, encrypt_buff_sz, 1, table_fp);
		fprintf(p_iris->idx_fp, "%s\t%d\t%s\t%s\n", table->table_name,
				table->line_count, table->table_path, p_iris->encrypt_algo);
		FREE(encrypt_buff);
	} else {
		fwrite(buff, table_file_sz, 1, table_fp);		
		fprintf(p_iris->idx_fp, "%s\t%d\t%s\n", table->table_name,
				table->line_count, table->table_path);
	}

	fclose(table_fp);
	FREE(buff);
}

static int write_index_file(struct iris_description *p_iris,
							struct log_handle *logger)
{
	p_iris->idx_fp = fopen(p_iris->index_path, "w");
	if (NULL == p_iris->idx_fp) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] index file %s fopen error %s",
                  __FUNCTION__, __LINE__, p_iris->index_path,
				  strerror(errno));
		return -1;
	}

    struct iris_table *node = NULL;
    struct iris_table *tmp = NULL;
    HASH_ITER(hh, p_iris->iris_table_map, node, tmp) {
        write_table_idx(p_iris, node);
    }
    
	fclose(p_iris->idx_fp);
	p_iris->idx_fp = NULL;

	return 0;
}

int recursive_traverse_sub_objects(cJSON *object_obj, struct iris_description *p_iris,
								  struct log_handle *logger)
{
    cJSON *sub_object_array = cJSON_GetObjectItem(object_obj, "sub_objects");
	if (NULL == sub_object_array) {
		return 0;
	}

	cJSON *item = cJSON_GetObjectItem(object_obj, "object_name");
	if (NULL == item || item->type != cJSON_String) {
		log_fatal(logger, MODULE_JSON2IRIS,
				  "[%s:%d] has no object_name before sub_objects.");
		return -1;
	}

	const char *parent_object_name = item->valuestring;
	struct object_info *parent_object = object_info_read(p_iris->object_name_map,
													  item->valuestring);
	if (NULL == parent_object) {
		item = cJSON_GetObjectItem(object_obj, "object_id");
		if (NULL == item || item->type != cJSON_Number) {
			log_fatal(logger, MODULE_JSON2IRIS,
				  	 "[%s:%d] object_name:%s has no object_id.", parent_object_name);
			return -1;
		}	
		parent_object = object_info_add_unsafe(p_iris, parent_object_name, item->valueint);
	}

	cJSON *sub_object_obj = NULL;
	cJSON_ArrayForEach(sub_object_obj, sub_object_array) {
		cJSON *tmp_item1 = cJSON_GetObjectItem(sub_object_obj, "object_name");
		if (NULL == tmp_item1 || tmp_item1->type != cJSON_String) {
			log_fatal(logger, MODULE_JSON2IRIS,
					  "[%s:%d]object:%s's sub_objects has no object_name",
					  __FUNCTION__, __LINE__, parent_object_name);
			return -1;
		}

		int object_id = -1;
		int is_exclude = 0;
		cJSON *tmp_item2 = cJSON_GetObjectItem(sub_object_obj, "object_id");
		if (NULL == tmp_item2) {
			struct object_info *object = object_info_read(p_iris->object_name_map,
													   tmp_item1->valuestring);
			assert(object != NULL);
			object_id = object->object_id;
		} else {
			object_id = tmp_item2->valueint;
		}

		cJSON *tmp_item3 = cJSON_GetObjectItem(sub_object_obj, "is_exclude");
		if (tmp_item3 != NULL && tmp_item3->type == cJSON_Number) {
			is_exclude = tmp_item3->valueint;
		}
		if (0 == is_exclude) {
			utarray_push_back(parent_object->incl_sub_object_ids, &object_id);
		} else {
			utarray_push_back(parent_object->excl_sub_object_ids, &object_id);
		}

		int ret = recursive_traverse_sub_objects(sub_object_obj, p_iris, logger);
		if (ret < 0) {
			return -1;
		}
	}

	return 0;
}

static int write_object2object_rule(struct iris_description *p_iris,
						    	  struct log_handle *logger)
{
    int ret = 0;
    struct object_info *object_info = NULL, *tmp_object_info = NULL;

    HASH_ITER(hh, p_iris->object_name_map, object_info, tmp_object_info) {
        ret = write_object2object_line(object_info->object_id,
									 object_info->incl_sub_object_ids,
                                     object_info->excl_sub_object_ids,
									 p_iris);
		if (ret < 0) {
        	log_fatal(logger, MODULE_JSON2IRIS,
                      "[%s:%d] write object2object line failed for super_object:%d",
					  __FUNCTION__, __LINE__, object_info->object_id);
            return -1;
        }
    }

    return 0;
}

static int write_iris(cJSON *json, struct iris_description *p_iris,
                      struct log_handle *logger)
{
    int i = 0;
    int ret = 0;
    static struct object_info *parent_object = NULL; // TODO

    cJSON *plug_tables = cJSON_GetObjectItem(json, "plugin_table");
    if (plug_tables != NULL) {
        cJSON *each_plug_table = NULL;
        cJSON_ArrayForEach(each_plug_table, plug_tables) {
            write_plugin_line(each_plug_table, i, p_iris, logger);
            i++;
        }
    }

    cJSON *object_array = cJSON_GetObjectItem(json, "objects"); // sub-object to object
    if (object_array != NULL) {
        cJSON *object_obj = NULL;
        cJSON_ArrayForEach(object_obj, object_array) {
            const char *parent_object_name = NULL;
            cJSON *item = cJSON_GetObjectItem(object_obj, "parent_object");
            if (NULL == item || item->type != cJSON_String) {
                parent_object_name = untitled_object_name;
            } else {
                parent_object_name = item->string;
            }

            parent_object = object_info_read(p_iris->object_name_map, parent_object_name);
            if (NULL == parent_object) {
                parent_object = object_info_add_unsafe(p_iris, parent_object_name,
                                                     untitled_object_id);
            }

            item = cJSON_GetObjectItem(object_obj, "object_id");
            if (NULL == item || item->type != cJSON_Number) {
                log_fatal(logger, MODULE_JSON2IRIS,
                          "[%s:%d]Global objects has object with no object_id.",
                          __FUNCTION__, __LINE__);
                return -1;
            }

            utarray_push_back(parent_object->incl_sub_object_ids, &item->valueint);
            ret = write_object_rule(object_obj, parent_object->object_id,
            						PARENT_TYPE_OBJECT, 0, 0, p_iris, logger);
			if (ret < 0) {
            	return -1;
            }
        }
    }

    int rule_cnt = 0;
    cJSON *rule_array = cJSON_GetObjectItem(json, "rules");
    if (rule_array != NULL) {
        rule_cnt = cJSON_GetArraySize(rule_array);
    }

    if (rule_cnt > 0) {
        cJSON *rule_obj = NULL;
        cJSON_ArrayForEach(rule_obj, rule_array) {
            int rule_id = write_rule_line(rule_obj, p_iris, logger);
            if (rule_id < 0) {
                log_fatal(logger, MODULE_JSON2IRIS,
                          "[%s:%d] In %d rule rule",
						  __FUNCTION__, __LINE__, i);
                return -1;
            }

            object_array = cJSON_GetObjectItem(rule_obj, "objects");
            if (NULL == object_array) {
                log_fatal(logger, MODULE_JSON2IRIS,
                          "[%s:%d] rule rule %d have no object",
						  __FUNCTION__, __LINE__, rule_id);
                return -1;
            }

            int object_cnt = cJSON_GetArraySize(object_array);
            if (object_cnt <= 0) {
                log_fatal(logger, MODULE_JSON2IRIS,
                          "[%s:%d] rule rule %d have no objects",
                          __FUNCTION__, __LINE__, rule_id);
                return -1;
            }

            i = 0;
            cJSON *object_obj = NULL;
            cJSON_ArrayForEach(object_obj, object_array) {
                ret = write_object_rule(object_obj, rule_id, PARENT_TYPE_RULE,
                                       rule_id, i, p_iris, logger);
                if (ret < 0) {
                    return -1;
                }
                i++;
            }
        }

        cJSON_ArrayForEach(rule_obj, rule_array) {
            cJSON *object_array = cJSON_GetObjectItem(rule_obj, "objects");

            cJSON *object_obj = NULL;
            cJSON_ArrayForEach(object_obj, object_array) {
                ret = recursive_traverse_sub_objects(object_obj, p_iris, logger);
                if (ret < 0) {
                    return -1;
                }
            }
        }
    }

    ret = write_object2object_rule(p_iris, logger);
	if (ret < 0) {
		return -1;
	}

    ret = write_index_file(p_iris, logger);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int json2iris(const char *json_buff, const char *json_filename,
              redisContext *redis_write_ctx, char *iris_dir_buf, 
              int buf_len, char *encrypt_key, char *encrypt_algo,
              struct log_handle *logger)
{
    int ret = -1;
    cJSON *tmp_obj = NULL;
    const char *rule_tbl_name = NULL;
    const char *object2rule_tbl_name = NULL;
    const char *object2object_tbl_name = NULL;
	struct iris_description iris_cfg;

	memset(&iris_cfg, 0, sizeof(iris_cfg));

	cJSON *json = cJSON_Parse(json_buff);
	if (!json) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] error message: %-200.200s", 
                  __FUNCTION__, __LINE__, cJSON_GetErrorPtr());
		goto error_out;
	}

	tmp_obj = cJSON_GetObjectItem(json, "rule_table");
	if (tmp_obj) {
		rule_tbl_name = tmp_obj->valuestring;
	}

	tmp_obj = cJSON_GetObjectItem(json, "object2rule_table");
	if (tmp_obj) {
		object2rule_tbl_name = tmp_obj->valuestring;
	}

	tmp_obj = cJSON_GetObjectItem(json, "object2object_table");
	if (tmp_obj) {
		object2object_tbl_name = tmp_obj->valuestring;
	}

	ret = set_iris_descriptor(json_filename, json, encrypt_key, encrypt_algo, 
                              rule_tbl_name, object2rule_tbl_name, 
                              object2object_tbl_name, redis_write_ctx, &iris_cfg);
	if (ret < 0) {
		goto error_out;
	}

	ret = create_tmp_dir(&iris_cfg);
	if (ret < 0) {
		log_fatal(logger, MODULE_JSON2IRIS, 
                  "[%s:%d] create tmp folder %s error", 
                  __FUNCTION__, __LINE__, iris_cfg.tmp_iris_dir);
		goto error_out;
	}

	ret = write_iris(json, &iris_cfg, logger);
	if (ret < 0) {
		goto error_out;
	}
	memcpy(iris_dir_buf, iris_cfg.tmp_iris_index_dir, 
           MIN(strlen(iris_cfg.tmp_iris_index_dir) + 1, (unsigned int)buf_len));

	cJSON_Delete(json);
	clear_iris_descriptor(&iris_cfg);
	return 0;	

error_out:
	cJSON_Delete(json);
	clear_iris_descriptor(&iris_cfg);
	return -1;
}
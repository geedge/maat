/*
**********************************************************************************************
*	File: maat_plugin.c
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <errno.h>
#include <limits.h>

#include "log/log.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "maat_plugin.h"
#include "maat_limits.h"
#include "maat_table.h"

#define MODULE_PLUGIN	 module_name_str("maat.plugin")
#define IPV4 4
#define IPV6 6

struct plugin_callback_schema {
	maat_start_callback_t *start;
	maat_update_callback_t *update;
	maat_finish_callback_t *finish;
	void *u_para;
};

struct plugin_runtime {
    long long acc_line_num;
    struct ex_data_runtime *ex_data_rt;
    long long version;
    long long rule_num;
    long long update_err_cnt;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

enum plugin_key_type {
    PLUGIN_KEY_TYPE_INVALID = 0,
    PLUGIN_KEY_TYPE_POINTER,
    PLUGIN_KEY_TYPE_INTEGER,
    PLUGIN_KEY_TYPE_IP_ADDR
};

#define	MAX_PLUGIN_PER_TABLE 32
struct plugin_schema {
    enum plugin_key_type key_type;
    int key_len;
    int key_column;
    int addr_type_column;
    int rule_tag_column;
    int n_foreign;
    int foreign_columns[MAX_FOREIGN_CLMN_NUM];
    size_t cb_cnt;
    struct plugin_callback_schema cb[MAX_PLUGIN_PER_TABLE];
    struct ex_container_schema container_schema;
    int table_id; //ugly
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

static int read_integer_array(char *string, int *array, int size)
{
    int i = 0;
	char *token = NULL, *sub_token = NULL, *saveptr;
	
	for (i = 0, token = string; i < size; token= NULL, i++) {
		sub_token = strtok_r(token, ",", &saveptr);
		if (sub_token == NULL) {
            break;
        }
		
		sscanf(sub_token, "%d", array + i);
	}

	return i;
}

void *plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                        const char *table_name, struct log_handle *logger)
{
    struct plugin_schema *schema = ALLOC(struct plugin_schema, 1);

    schema->logger = logger;

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        log_error(logger, MODULE_PLUGIN, 
                  "[%s:%d]plugin table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }
    schema->table_id = item->valueint;

    /* custom is optional */
    item = cJSON_GetObjectItem(json, "custom");
    if (item != NULL && item->type == cJSON_Object) {
        custom_item = cJSON_GetObjectItem(item, "key");
        if (NULL == custom_item || custom_item->type != cJSON_Number) {
            log_error(logger, MODULE_PLUGIN,
                      "[%s:%d]plugin table:<%s> schema has no key column",
                      __FUNCTION__, __LINE__, table_name);
            goto error;
        }
        schema->key_column = custom_item->valueint;

        custom_item = cJSON_GetObjectItem(item, "key_type");
        if (NULL == custom_item || custom_item->type != cJSON_String) {
            log_error(logger, MODULE_PLUGIN,
                      "[%s:%d]plugin table:<%s> schema has no key_type column",
                      __FUNCTION__, __LINE__, table_name);
            goto error;
        }

        if (strcmp(custom_item->valuestring, "pointer") == 0) {
            schema->key_type = PLUGIN_KEY_TYPE_POINTER;
        } else if (strcmp(custom_item->valuestring, "integer") == 0) {
            schema->key_type = PLUGIN_KEY_TYPE_INTEGER;
            custom_item = cJSON_GetObjectItem(item, "key_len");
            if (NULL == custom_item || custom_item->type != cJSON_Number) {
                log_error(logger, MODULE_PLUGIN,
                          "[%s:%d]plugin table:<%s> schema integer key must"
                          " have key_len column", __FUNCTION__, __LINE__,
                          table_name);
                goto error;
            }
            schema->key_len = custom_item->valueint;
        } else if (strcmp(custom_item->valuestring, "ip_addr") == 0) {
            schema->key_type = PLUGIN_KEY_TYPE_IP_ADDR;
            custom_item = cJSON_GetObjectItem(item, "addr_type");
            if (NULL == custom_item || custom_item->type != cJSON_Number) {
                log_error(logger, MODULE_PLUGIN,
                          "[%s:%d]plugin table:<%s> schema ip_addr key must"
                          " have addr_type column", __FUNCTION__, __LINE__,
                          table_name);
                goto error;
            }
            schema->addr_type_column = custom_item->valueint;
        } else {
            log_error(logger, MODULE_PLUGIN,
                      "[%s:%d]plugin table:<%s> schema key_type:%s is illegal, "
                      "just allow {pointer}, {integer}, {ip_addr}",
                      __FUNCTION__, __LINE__, table_name, custom_item->valuestring);
            goto error;
        }

        custom_item = cJSON_GetObjectItem(item, "tag");
        if (custom_item != NULL && custom_item->type == cJSON_Number) {
            schema->rule_tag_column = custom_item->valueint;
        }

        custom_item = cJSON_GetObjectItem(item, "foreign");
        if (custom_item != NULL) {
            if (custom_item->type == cJSON_String) {
                schema->n_foreign = read_integer_array(custom_item->valuestring,
                                                       schema->foreign_columns,
                                                       MAX_FOREIGN_CLMN_NUM);
            } else if (custom_item->type == cJSON_Array) {
                schema->n_foreign = cJSON_GetArraySize(custom_item);
                for (int i = 0; i < schema->n_foreign; i++) {
                    cJSON *foreign_item = cJSON_GetArrayItem(custom_item, i);
                    assert(foreign_item->type == cJSON_Number);
                    schema->foreign_columns[i] = foreign_item->valueint;
                }
            }
        }
    }

    schema->ref_tbl_mgr = tbl_mgr;
    return schema;
error:
    FREE(schema);
    return NULL;
}

void plugin_schema_free(void *plugin_schema)
{
    if (NULL == plugin_schema) {
        return;
    }

    FREE(plugin_schema);
}

int plugin_table_add_callback(void *plugin_schema, int table_id,
                              maat_start_callback_t *start,
						      maat_update_callback_t *update,
							  maat_finish_callback_t *finish,
							  void *u_para, struct log_handle *logger)
{
    if (NULL == plugin_schema) {
        return -1;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    size_t idx = schema->cb_cnt;

	if (idx == MAX_PLUGIN_PER_TABLE) {
        log_error(logger, MODULE_PLUGIN, 
                  "[%s:%d] the plugin number of table_id: %d exceed maxium:%d", 
                  __FUNCTION__, __LINE__, table_id, MAX_PLUGIN_PER_TABLE);
		return -1;
	}

	schema->cb_cnt++;
	schema->cb[idx].start = start;
	schema->cb[idx].update = update;
	schema->cb[idx].finish = finish;
	schema->cb[idx].u_para = u_para;

    return 0;
}

void plugin_table_all_callback_start(struct plugin_schema *plugin_schema,
                                     int update_type)
{
    for (size_t i = 0; i < plugin_schema->cb_cnt; i++) {
        if (plugin_schema->cb[i].start != NULL) {
            plugin_schema->cb[i].start(update_type, plugin_schema->cb[i].u_para);
        }
    }
}

void plugin_table_all_callback_finish(struct plugin_schema *plugin_schema)
{
    for (size_t i = 0; i < plugin_schema->cb_cnt; i++) {
        if (plugin_schema->cb[i].finish != NULL) {
            plugin_schema->cb[i].finish(plugin_schema->cb[i].u_para);
        }
    }
}

int plugin_table_get_foreign_column(struct plugin_schema *plugin_schema, 
                                    int *foreign_columns)
{
    if (NULL == plugin_schema) {
        return -1;
    }

    int n_foreign = plugin_schema->n_foreign;
    for (int i = 0; i < n_foreign; i++) {
        foreign_columns[i] = plugin_schema->foreign_columns[i];
    }

    return n_foreign;
}

int plugin_table_set_ex_container_schema(void *plugin_schema, int table_id,
                                         maat_ex_new_func_t *new_func,
							             maat_ex_free_func_t *free_func,
							             maat_ex_dup_func_t *dup_func,
                                         void (*custom_data_free)(void *),
							             long argl, void *argp)
{
    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    
    if (1 == schema->container_schema.set_flag) {
        log_error(schema->logger, MODULE_PLUGIN, 
                  "[%s:%d] plugin table(table_id:%d) ex_container_schema"
                  " has been set, can't set again", __FUNCTION__, __LINE__,
                  table_id);
        return -1;
    }

    schema->container_schema.table_id = table_id;
    schema->container_schema.custom_data_free = custom_data_free;
    schema->container_schema.ex_schema.new_func = new_func;
    schema->container_schema.ex_schema.free_func = free_func;
    schema->container_schema.ex_schema.dup_func = dup_func;
    schema->container_schema.ex_schema.argl = argl;
    schema->container_schema.ex_schema.argp = argp;
    schema->container_schema.set_flag = 1;

    return 0;
}

struct ex_container_schema *
plugin_table_get_ex_container_schema(void *plugin_schema)
{
    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;

    return &(schema->container_schema);
}

void *plugin_runtime_new(void *plugin_schema, size_t max_thread_num,
                         struct maat_garbage_bin *garbage_bin, 
                         struct log_handle *logger)
{
    if (NULL == plugin_schema) {
        return NULL;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    struct plugin_runtime *plugin_rt = ALLOC(struct plugin_runtime, 1);
    
    plugin_rt->ex_data_rt = ex_data_runtime_new(schema->table_id, logger);
    if (1 == schema->container_schema.set_flag) {
        ex_data_runtime_set_ex_container_schema(plugin_rt->ex_data_rt,
                                                &(schema->container_schema));
    }

    plugin_rt->ref_garbage_bin = garbage_bin;
    plugin_rt->logger = logger;

    return plugin_rt;
}

void plugin_runtime_free(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    if (plugin_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(plugin_rt->ex_data_rt);
        plugin_rt->ex_data_rt = NULL;
    }

    FREE(plugin_rt);
}

int plugin_runtime_update_row(struct plugin_runtime *plugin_rt, 
                              struct plugin_schema *plugin_schema, 
                              const char *table_name, const char *row, 
                              const char *key, size_t key_len, int is_valid)
{
    int ret = -1;
    struct ex_container_schema *container_schema = &(plugin_schema->container_schema);

    /* already set plugin_table_schema's ex_data_schema */
    if (1 == container_schema->set_flag) {
        if (is_valid == 0) {
            // delete
            ret = ex_data_runtime_del_ex_container(plugin_rt->ex_data_rt, key, key_len);
            if (ret < 0) {
                return -1;
            }
        } else {
            // add
            void *ex_data = ex_data_runtime_row2ex_data(plugin_rt->ex_data_rt, table_name, 
                                                        row, key, key_len);
            struct ex_container *ex_container = ex_container_new(ex_data, NULL);
            ret = ex_data_runtime_add_ex_container(plugin_rt->ex_data_rt, key, key_len,
                                                   ex_container);
            if (ret < 0) {
                return -1;
            }
            plugin_rt->acc_line_num++;
        }
    }

    /* plugin table schema has callback */
    size_t cb_count = plugin_schema->cb_cnt;
    if (cb_count > 0) {
        for (size_t i = 0; i < cb_count; i++) {
            plugin_schema->cb[i].update(plugin_schema->table_id, row,
                                        plugin_schema->cb[i].u_para);
        }
    }
    
    if ((0 == container_schema->set_flag) && (0 == cb_count)) {
        ex_data_runtime_cache_row_put(plugin_rt->ex_data_rt, row);
    }

    return 0;
}

int plugin_accept_tag_match(struct plugin_schema *schema, const char *table_name,
                            const char *line, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    if (schema->rule_tag_column > 0 && n_tag > 0) {
        int ret = get_column_pos(line, schema->rule_tag_column, &column_offset,
                                 &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_PLUGIN,
                      "[%s:%d] table: <%s> has no rule_tag(column_seq:%d) "
                      "in table_line:%s", __FUNCTION__, __LINE__, table_name,
                      schema->rule_tag_column, line);
            return TAG_MATCH_ERR;
        }

        if (column_len > 2) {
            char *tag_str = ALLOC(char, column_len + 1);
            memcpy(tag_str, (line + column_offset), column_len);
            ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag_str);
            FREE(tag_str);
            if (TAG_MATCH_ERR == ret) {
                log_error(logger, MODULE_PLUGIN,
                          "[%s:%d] table: <%s> has invalid tag format in table_line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_ERR;
            }

            if (TAG_MATCH_UNMATCHED == ret) {
                log_error(logger, MODULE_PLUGIN,
                          "[%s:%d] table: <%s> has unmatched tag in table_line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_UNMATCHED;
            }
        }
    }

    return TAG_MATCH_MATCHED;
}

int plugin_table_line_get_key(struct plugin_schema *schema, const char *table_name,
                           const char *line, char *dst_key, size_t *dst_key_len,
                           struct log_handle *logger)
{
    size_t key_offset = 0, key_len = 0;
    
    int ret = get_column_pos(line, schema->key_column, &key_offset, &key_len);
    if (ret < 0) {
        log_error(logger, MODULE_PLUGIN,
                  "[%s:%d] plugin table:<%s> has no key(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  schema->key_column, line);
        return -1;
    }

    const char *common_key = line + key_offset;
    if (schema->key_type == PLUGIN_KEY_TYPE_POINTER) {
        memcpy(dst_key, common_key, key_len);
        *dst_key_len = key_len;
    } else if (schema->key_type == PLUGIN_KEY_TYPE_INTEGER) {
        if (schema->key_len == sizeof(long long)) {
            long long key_ll = atoll(common_key);
            memcpy(dst_key, (char *)&key_ll, schema->key_len);
        } else {
            int key_int = atoi(common_key);
            memcpy(dst_key, (char *)&key_int, schema->key_len);
        }
        *dst_key_len = schema->key_len;
    } else if (schema->key_type == PLUGIN_KEY_TYPE_IP_ADDR) {
        if (key_len >= INET6_ADDRSTRLEN) {
            log_error(logger, MODULE_PLUGIN,
                      "[%s:%d] plugin table:<%s> ip_key too long(illegal) in "
                      "table_line:%s", __FUNCTION__, __LINE__, table_name, line);
            return -1;
        }

        size_t addr_type_offset = 0, addr_type_len = 0;

        ret = get_column_pos(line, schema->addr_type_column, &addr_type_offset,
                             &addr_type_len);
        if (ret < 0) {
            log_error(logger, MODULE_PLUGIN,
                      "[%s:%d] plugin table:<%s> has no addr_type(column seq:%d)"
                      " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                      schema->addr_type_column, line);
            return -1;
        }

        char ip_key[INET6_ADDRSTRLEN] = {0};
        //snprintf() write at most (key_len+1) bytes (including the terminating null{'\0}) to ip_key.
        snprintf(ip_key, key_len + 1, "%s", common_key);

        int addr_type = atoi(line + addr_type_offset);
        if (IPV4 == addr_type) {
            uint32_t ipv4_addr;
            ret = inet_pton(AF_INET, ip_key, &ipv4_addr);
            if (ret <= 0) {
                log_error(logger, MODULE_PLUGIN,
                          "[%s:%d] plugin table:<%s> ipv4 key(column seq:%d)"
                          " illegal in table_line:%s", __FUNCTION__, __LINE__,
                          table_name, schema->key_column, line);
                return -1;
            }

            memcpy(dst_key, (char *)&ipv4_addr, sizeof(ipv4_addr));
            *dst_key_len = sizeof(ipv4_addr);
        } else if (IPV6 == addr_type) {
            uint8_t ipv6_addr[16];
            ret = inet_pton(AF_INET6, ip_key, ipv6_addr);
            if (ret <= 0) {
                log_error(logger, MODULE_PLUGIN,
                          "[%s:%d] plugin table:<%s> ipv6 key(column seq:%d)"
                          " illegal in table_line:%s", __FUNCTION__, __LINE__,
                          table_name, schema->key_column, line);
                return -1;
            }

            memcpy(dst_key, (char *)&ipv6_addr, sizeof(ipv6_addr));
            *dst_key_len = sizeof(ipv6_addr);
        } else {
            log_error(logger, MODULE_PLUGIN,
                      "[%s:%d] plugin table:<%s> addr_type:%d illegal, just"
                      " allow{4, 6}, table_line:%s", __FUNCTION__, __LINE__,
                      table_name, addr_type, line);
            return -1;
        }
    }

    return 0;
}

int plugin_runtime_update(void *plugin_runtime, void *plugin_schema, 
                          const char *table_name, const char *line, 
                          int valid_column)
{
    if (NULL == plugin_runtime || NULL == plugin_schema ||
        NULL == line) {
        return -1;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        log_error(plugin_rt->logger, MODULE_PLUGIN,
                  "[%s:%d] plugin table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        plugin_rt->update_err_cnt++;
        return -1;
    }

    int ret = plugin_accept_tag_match(schema, table_name, line, plugin_rt->logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        plugin_rt->update_err_cnt++;
        return -1;
    }

   char key[MAX_KEYWORDS_STR] = {0};
    size_t key_len = 0;
    ret = plugin_table_line_get_key(schema, table_name, line, key, &key_len,
                                    plugin_rt->logger);
    if (ret < 0) {
        plugin_rt->update_err_cnt++;
        return -1;
    }

    ret = plugin_runtime_update_row(plugin_rt, schema, table_name, line, 
                                    key, key_len, is_valid);
    if (ret < 0) {
        plugin_rt->update_err_cnt++;
        return -1;
    }

    return 0;
}

int plugin_runtime_commit(void *plugin_runtime, const char *table_name,
                          long long maat_rt_version)
{
    if (NULL == plugin_runtime) {
        return -1;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    struct ex_data_runtime *ex_data_rt = plugin_rt->ex_data_rt;
    if (NULL == ex_data_rt) {
        return -1;
    }

    int updating_flag = ex_data_runtime_is_updating(ex_data_rt);
    if (0 == updating_flag) {
        return 0;
    }

    ex_data_runtime_commit(ex_data_rt);
    
    plugin_rt->rule_num = ex_data_runtime_ex_container_count(ex_data_rt);
    if (maat_rt_version != 0) {
        plugin_rt->version = maat_rt_version;
    }
    
    log_info(plugin_rt->logger, MODULE_PLUGIN,
             "table[%s] commit %zu plugin rules, version:%lld", 
             table_name, plugin_rt->rule_num, plugin_rt->version);

    return 0;
}

long long plugin_runtime_rule_count(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return 0;
    }
    
    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    return plugin_rt->rule_num;
}

long long plugin_runtime_update_err_count(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return 0;
    }
    
    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    return plugin_rt->update_err_cnt;
}

struct ex_data_runtime *plugin_runtime_get_ex_data_rt(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return NULL;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    return plugin_rt->ex_data_rt;
}

size_t plugin_runtime_cached_row_count(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return 0;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    if (NULL == plugin_rt->ex_data_rt) {
        return 0;
    }

    return ex_data_runtime_cached_row_count(plugin_rt->ex_data_rt);
}

const char *plugin_runtime_cached_row_get(void *plugin_runtime, size_t index)
{
    if (NULL == plugin_runtime) {
        return NULL;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    if (NULL == plugin_rt->ex_data_rt) {
        return NULL;
    }

    return ex_data_runtime_cached_row_get(plugin_rt->ex_data_rt, index);
}

void *plugin_runtime_get_ex_data(void *plugin_runtime, void *plugin_schema,
                                 const char *key, size_t key_len)
{
    if (NULL == plugin_runtime || NULL == plugin_schema) {
        return NULL;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    if (schema->key_type == PLUGIN_KEY_TYPE_INTEGER &&
        schema->key_len != key_len) {
        return NULL;
    }
    
    return ex_data_runtime_get_ex_data_by_key(plugin_rt->ex_data_rt, key, key_len);    
}
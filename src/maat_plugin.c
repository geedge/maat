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
#include "maat_core.h"
#include "maat_plugin.h"
#include "maat_limits.h"
#include "maat_table.h"
#include "alignment.h"

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
    struct ex_data_runtime *ex_data_rt;
    size_t n_worker_thread;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long rule_num;
    long long update_err_cnt;
    long long *scan_times;
};

enum plugin_key_type {
    PLUGIN_KEY_TYPE_INVALID = 0,
    PLUGIN_KEY_TYPE_POINTER,
    PLUGIN_KEY_TYPE_INTEGER,
    PLUGIN_KEY_TYPE_IP_ADDR,
    PLUGIN_KEY_TYPE_UUID
};

#define	MAX_PLUGIN_PER_TABLE 32
struct plugin_schema {
    enum plugin_key_type key_type;
    int key_len;
    char key_name[MAX_NAME_STR_LEN];
    int gc_timeout_s;
    int n_foreign;
    char foreign_names[MAX_FOREIGN_CLMN_NUM][MAX_FOREIGN_NAME_LEN + 1];
    size_t cb_cnt;
    struct plugin_callback_schema cb[MAX_PLUGIN_PER_TABLE];
    struct ex_container_schema container_schema;
    int table_id;
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

void *plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                        const char *table_name, struct log_handle *logger)
{
    struct plugin_schema *schema = ALLOC(struct plugin_schema, 1);

    schema->logger = logger;

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        log_fatal(logger, MODULE_PLUGIN, 
                  "[%s:%d]plugin table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }
    schema->table_id = item->valueint;

    /* custom is optional */
    item = cJSON_GetObjectItem(json, "custom");
    if (item != NULL && item->type == cJSON_Object) {
        custom_item = cJSON_GetObjectItem(item, "key_name");
        if (NULL == custom_item || custom_item->type != cJSON_String) {
            log_fatal(logger, MODULE_PLUGIN,
                      "[%s:%d]plugin table:<%s> schema has no key_name column",
                      __FUNCTION__, __LINE__, table_name);
            goto error;
        }
        strncpy(schema->key_name, custom_item->valuestring, sizeof(schema->key_name) - 1);

        custom_item = cJSON_GetObjectItem(item, "key_type");
        if (NULL == custom_item || custom_item->type != cJSON_String) {
            log_fatal(logger, MODULE_PLUGIN,
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
                log_fatal(logger, MODULE_PLUGIN,
                          "[%s:%d]plugin table:<%s> schema integer key must"
                          " have key_len column", __FUNCTION__, __LINE__,
                          table_name);
                goto error;
            }
            schema->key_len = custom_item->valueint;
        } else if (strcmp(custom_item->valuestring, "ip_addr") == 0) {
            schema->key_type = PLUGIN_KEY_TYPE_IP_ADDR;
        } else if (strcmp(custom_item->valuestring, "uuid") == 0) {
            schema->key_type = PLUGIN_KEY_TYPE_UUID;
        } else {
            log_fatal(logger, MODULE_PLUGIN,
                      "[%s:%d]plugin table:<%s> schema key_type:%s is illegal, "
                      "just allow {pointer}, {integer}, {ip_addr}",
                      __FUNCTION__, __LINE__, table_name, custom_item->valuestring);
            goto error;
        }

        custom_item = cJSON_GetObjectItem(item, "gc_timeout_s");
        if (custom_item != NULL && custom_item->type == cJSON_Number) {
            schema->gc_timeout_s = custom_item->valueint;
        }

        custom_item = cJSON_GetObjectItem(item, "foreign_names");
        if (custom_item != NULL && custom_item->type == cJSON_Array) {
            schema->n_foreign = cJSON_GetArraySize(custom_item);
            if (schema->n_foreign > MAX_FOREIGN_CLMN_NUM) {
                log_fatal(logger, MODULE_PLUGIN,
                          "[%s:%d]plugin table:<%s> schema foreign_names number"
                          " exceed maxium:%d", __FUNCTION__, __LINE__, table_name,
                          MAX_FOREIGN_CLMN_NUM);
                goto error;
            }

            for (int i = 0; i < schema->n_foreign; i++) {
                cJSON *foreign_item = cJSON_GetArrayItem(custom_item, i);
                if (foreign_item == NULL || foreign_item->type != cJSON_String) {
                    log_fatal(logger, MODULE_PLUGIN,
                              "[%s:%d]plugin table:<%s> schema foreign_names"
                              " has invalid format", __FUNCTION__, __LINE__, table_name);
                    goto error;
                }
                strncpy(schema->foreign_names[i], foreign_item->valuestring, sizeof(schema->foreign_names[i]) - 1);
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
        log_fatal(logger, MODULE_PLUGIN, 
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

int plugin_table_get_foreign_names(struct plugin_schema *plugin_schema, char foreign_names[MAX_FOREIGN_CLMN_NUM][MAX_FOREIGN_NAME_LEN + 1])
{
    if (NULL == plugin_schema) {
        return -1;
    }

    for (int i = 0; i < plugin_schema->n_foreign; i++) {
        strncpy(foreign_names[i], plugin_schema->foreign_names[i], MAX_FOREIGN_NAME_LEN);
    }

    return plugin_schema->n_foreign;
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
        log_fatal(schema->logger, MODULE_PLUGIN, 
                  "[%s:%d] plugin table(table_id:%d) ex_container_schema"
                  " has been set, can't set again", __FUNCTION__, __LINE__,
                  table_id);
        return -1;
    }

    schema->container_schema.table_id = table_id;
    schema->container_schema.table_name = (char *)table_manager_get_table_name(schema->ref_tbl_mgr, table_id);
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
    
    plugin_rt->ex_data_rt = ex_data_runtime_new(schema->table_id,
                                                schema->gc_timeout_s,
                                                logger);
    if (1 == schema->container_schema.set_flag) {
        ex_data_runtime_set_ex_container_schema(plugin_rt->ex_data_rt,
                                                &(schema->container_schema));
    }

    plugin_rt->n_worker_thread = max_thread_num;
    plugin_rt->ref_garbage_bin = garbage_bin;
    plugin_rt->logger = logger;
    plugin_rt->scan_times = alignment_int64_array_alloc(max_thread_num);

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

    if (plugin_rt->scan_times != NULL) {
        alignment_int64_array_free(plugin_rt->scan_times);
        plugin_rt->scan_times = NULL;
    }

    FREE(plugin_rt);
}

static int plugin_runtime_update_row(struct plugin_runtime *plugin_rt, 
                                     struct plugin_schema *plugin_schema, 
                                     const char *table_name, const char *row, 
                                     const char *key, size_t key_len, enum maat_operation op)
{
    int ret = -1;
    struct ex_container_schema *container_schema = &(plugin_schema->container_schema);

    /* already set plugin_table_schema's ex_data_schema */
    if (1 == container_schema->set_flag) {
        if (MAAT_OP_DEL == op) {
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
                log_debug(plugin_rt->logger, MODULE_PLUGIN,
                      "[%s:%d]plugin table:<%s> add key failed, "
                      "key:%s", __FUNCTION__, __LINE__, table_name, key);
                ex_container_free(plugin_rt->ex_data_rt, ex_container);
                //don't return failed, ignore the case of adding duplicate keys
                return 0;
            }
        }
    }

    /* plugin table schema has callback */
    size_t cb_count = plugin_schema->cb_cnt;
    if (cb_count > 0) {
        for (size_t i = 0; i < cb_count; i++) {
            plugin_schema->cb[i].update(table_name, row, op,
                                        plugin_schema->cb[i].u_para);
        }
    }
    
    if (0 == container_schema->set_flag) {
        ex_data_runtime_cache_row_put(plugin_rt->ex_data_rt, row, op);
        plugin_rt->rule_num = ex_data_runtime_cached_row_count(plugin_rt->ex_data_rt);
    }

    return 0;
}

static int plugin_accept_tag_match(struct plugin_schema *schema,
                                   const char *table_name, const char *line,
                                   struct log_handle *logger)
{
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);
    cJSON *tmp_obj = NULL;
    int ret = TAG_MATCH_MATCHED;
    cJSON *json = cJSON_Parse(line);

    tmp_obj = cJSON_GetObjectItem(json, "effective_range");

    if ((tmp_obj != NULL && cJSON_GetArraySize(tmp_obj) > 0) && n_tag > 0) {
        char *tag_str = cJSON_Print(tmp_obj);
        ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag_str);
        FREE(tag_str);
        if (TAG_MATCH_ERR == ret) {
            log_fatal(logger, MODULE_PLUGIN,
                        "[%s:%d] table: <%s> has invalid tag format in table_line:%s",
                        __FUNCTION__, __LINE__, table_name, line);
            goto END;
        }

        if (TAG_MATCH_UNMATCHED == ret) {
            log_fatal(logger, MODULE_PLUGIN,
                        "[%s:%d] table: <%s> has unmatched tag in table_line:%s",
                        __FUNCTION__, __LINE__, table_name, line);
            goto END;
        }
    }

END:
    if (json) {
        cJSON_Delete(json);
    }

    return ret;
}

static int plugin_table_line_get_ip_key(struct plugin_schema *schema,
                                        const char *table_name, const char *line,
                                        const char *src_key, size_t src_key_len,
                                        char *dst_key, size_t *dst_key_len,
                                        struct log_handle *logger)
{
    cJSON *json = cJSON_Parse(line);

    if (src_key_len >= INET6_ADDRSTRLEN) {
        log_fatal(logger, MODULE_PLUGIN,
                  "[%s:%d] plugin table:<%s> ip_key too long exceed maximum:%d in "
                  "table_line:%s", __FUNCTION__, __LINE__, table_name,
                  INET6_ADDRSTRLEN, line);
        goto ERROR;
    }

    cJSON *tmp_obj = NULL;
    int ret = 0;

    tmp_obj = cJSON_GetObjectItem(json, "addr_type");
    if (tmp_obj == NULL || tmp_obj->type != cJSON_Number) {
        log_fatal(logger, MODULE_PLUGIN,
                  "[%s:%d] plugin table:<%s> has no addr_type or not number format in table_line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto ERROR;
    }

    char ip_key[INET6_ADDRSTRLEN] = {0};
    // snprintf() write at most (key_len+1) bytes (including the terminating null{'\0}) to ip_key.
    snprintf(ip_key, src_key_len + 1, "%s", src_key);

    int addr_type = tmp_obj->valueint;
    if (IPV4 == addr_type) {
        uint32_t ipv4_addr;
        ret = inet_pton(AF_INET, ip_key, &ipv4_addr);
        if (ret <= 0) {
            log_fatal(logger, MODULE_PLUGIN,
                      "[%s:%d] plugin table:<%s> ipv4 key"
                      " illegal in table_line:%s",
                      __FUNCTION__, __LINE__, table_name, line);
            goto ERROR;
        }

        memcpy(dst_key, (char *)&ipv4_addr, sizeof(ipv4_addr));
        *dst_key_len = sizeof(ipv4_addr);
    } else if (IPV6 == addr_type) {
        uint8_t ipv6_addr[16];
        ret = inet_pton(AF_INET6, ip_key, ipv6_addr);
        if (ret <= 0) {
            log_fatal(logger, MODULE_PLUGIN,
                      "[%s:%d] plugin table:<%s> ipv6 key"
                      " illegal in table_line:%s",
                      __FUNCTION__, __LINE__, table_name, line);
            goto ERROR;
        }

        memcpy(dst_key, (char *)&ipv6_addr, sizeof(ipv6_addr));
        *dst_key_len = sizeof(ipv6_addr);
    } else {
        log_fatal(logger, MODULE_PLUGIN,
                  "[%s:%d] plugin table:<%s> addr_type:%d illegal, just"
                  " allow{4, 6}, table_line:%s",
                  __FUNCTION__, __LINE__, table_name, addr_type, line);
        goto ERROR;
    }

    if (json) {
        cJSON_Delete(json);
    }
    return 0;
    
ERROR:
    if (json) {
        cJSON_Delete(json);
    }
    return -1;
}

static int plugin_table_line_get_key(struct plugin_schema *schema,
                                     const char *table_name, const char *line,
                                     const char *src_key, size_t src_key_len,
                                     char *dst_key, size_t *dst_key_len,
                                     struct log_handle *logger)
{
    if (schema->key_type == PLUGIN_KEY_TYPE_POINTER || schema->key_type == PLUGIN_KEY_TYPE_UUID) {
        memcpy(dst_key, src_key, src_key_len);
        *dst_key_len = src_key_len;
    } else if (schema->key_type == PLUGIN_KEY_TYPE_INTEGER) {
        memcpy(dst_key, src_key, schema->key_len);
        *dst_key_len = schema->key_len;
    } else {
        //PLUGIN_KEY_TYPE_IP_ADDR
        return plugin_table_line_get_ip_key(schema, table_name, line, src_key,
                                            src_key_len, dst_key, dst_key_len,
                                            logger);
    }

    return 0;
}

int plugin_runtime_update(void *plugin_runtime, void *plugin_schema, 
                          const char *table_name, const char *line, 
                          enum maat_operation op)
{
    if (NULL == plugin_runtime || NULL == plugin_schema ||
        NULL == line) {
        return -1;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    yyjson_doc *doc = yyjson_read(line, strlen(line), 0);
    
    const char *raw_key = NULL;
    int tmp_int_key = 0;
    long long tmp_long_key = 0;
    uuid_t uuid_key;

    if (NULL == doc) {
        log_fatal(plugin_rt->logger, MODULE_PLUGIN,
                  "[%s:%d] plugin table:<%s> line is not json format, line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        return -1;
    }
    yyjson_val *json_root = yyjson_doc_get_root(doc);

    int ret = plugin_accept_tag_match(schema, table_name, line, plugin_rt->logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        plugin_rt->update_err_cnt++;
        goto ERROR;
    }

    size_t raw_key_len = 0;
    yyjson_val *tmp_obj = yyjson_obj_get(json_root, schema->key_name);
    if (tmp_obj == NULL) {
        log_fatal(plugin_rt->logger, MODULE_PLUGIN,
                  "[%s:%d] plugin table:<%s> has no key_name %s in table_line:%s",
                  __FUNCTION__, __LINE__, table_name, schema->key_name, line);
        goto ERROR;
    }

    if (schema->key_type == PLUGIN_KEY_TYPE_INTEGER) {
        if (schema->key_len == sizeof(int)) {
            tmp_int_key = yyjson_get_int(tmp_obj);
            raw_key = (char*)&tmp_int_key;
        } else {
            tmp_long_key = yyjson_get_int(tmp_obj);
            raw_key = (char*)&tmp_long_key;
        }
        raw_key_len = schema->key_len;       
    } else if (schema->key_type == PLUGIN_KEY_TYPE_UUID){
        const char *uuid_str = yyjson_get_str(tmp_obj);
        if (uuid_parse(uuid_str, uuid_key) == -1) {
            log_fatal(plugin_rt->logger, MODULE_PLUGIN,
                    "[%s:%d] plugin table:<%s> uuid key illegal in table_line:%s",
                    __FUNCTION__, __LINE__, table_name, line);
            goto ERROR;
        }
        raw_key = (char*)&uuid_key;
        raw_key_len = sizeof(uuid_t);
    } else {
        raw_key = yyjson_get_str(tmp_obj);
        raw_key_len = strlen(raw_key);

        if (raw_key_len > MAX_KEYWORDS_STR_LEN) {
            log_fatal(plugin_rt->logger, MODULE_PLUGIN,
                    "[%s:%d] plugin table:<%s> key length exceed maxium:%d"
                    " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                    MAX_KEYWORDS_STR_LEN, line); 
            goto ERROR;
        }
    }

    char hash_key[MAX_KEYWORDS_STR_LEN + 1] = {0};
    size_t hash_key_len = 0;

    ret = plugin_table_line_get_key(schema, table_name, line, raw_key, raw_key_len,
                                    hash_key, &hash_key_len, plugin_rt->logger);
    if (ret < 0) {
        plugin_rt->update_err_cnt++;
        goto ERROR;
    }

    ret = plugin_runtime_update_row(plugin_rt, schema, table_name, line, 
                                    hash_key, hash_key_len, op);
    if (ret < 0) {
        plugin_rt->update_err_cnt++;
        goto ERROR;
    }
    
    char print_key[MAX_KEYWORDS_STR_LEN + 1] = {0};
    if (schema->key_type == PLUGIN_KEY_TYPE_INTEGER) {
        if (schema->key_len == sizeof(long long)) {
            snprintf(print_key, sizeof(print_key), "%lld", *(long long*)raw_key);
        } else {
            snprintf(print_key, sizeof(print_key), "%d", *(int*)raw_key);
        }
    } else if(schema->key_type == PLUGIN_KEY_TYPE_UUID) {
        uuid_unparse(uuid_key, print_key);
    } else {
        memcpy(print_key, raw_key, raw_key_len);
    }
    log_debug(plugin_rt->logger, MODULE_PLUGIN,
              "plugin table:<%s> update one line, key:%s, key_len:%zu, maat_operation:%d",
              table_name, print_key, raw_key_len, op);
    
    yyjson_doc_free(doc);
    return 0;

ERROR:
    if (doc) {
        yyjson_doc_free(doc);
    }
    return -1;
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
    
    log_info(plugin_rt->logger, MODULE_PLUGIN,
             "table[%s] commit %zu plugin rules, version:%lld", 
             table_name, plugin_rt->rule_num, maat_rt_version);

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

const struct ex_data_row *plugin_runtime_cached_row_get(void *plugin_runtime, size_t index)
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

void plugin_runtime_scan_times_inc(void *plugin_runtime, int thread_id)
{
    if (NULL == plugin_runtime || thread_id < 0) {
        return;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    alignment_int64_array_add(plugin_rt->scan_times, thread_id, 1);
}

long long plugin_runtime_scan_times(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return 0;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    long long sum = alignment_int64_array_sum(plugin_rt->scan_times,
                                              plugin_rt->n_worker_thread);
    alignment_int64_array_reset(plugin_rt->scan_times,
                                plugin_rt->n_worker_thread);

    return sum;
}
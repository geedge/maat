/*
**********************************************************************************************
*	File: maat_api.cpp
*   Description: maat api entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "maat_utils.h"
#include "json2iris.h"
#include "maat/maat.h"
#include "maat_rule.h"
#include "maat_common.h"
#include "maat_kv.h"
#include "maat_command.h"
#include "maat_ex_data.h"
#include "maat_table_schema.h"
#include "maat_table_runtime.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "maat_hierarchy.h"
#include "alignment.h"

#define MODULE_MAAT_API	 module_name_str("maat.api")

#define	DISTRICT_ANY		-1
#define	DISTRICT_UNKNOWN	-2

struct maat_state {
	struct maat *maat_instance;
	int16_t thread_id;
	unsigned char is_set_district;
	unsigned char is_last_scan;
	int district_id; //-1: Any District; -2: Unkonwn District;
	int scan_cnt;
	struct maat_hierarchy_compile_mid *compile_mid;
};

struct scan_item_hit_wrapper {
	int Nth_scan;
	struct maat_item_inner* wrapped_items[MAX_SCANNER_HIT_NUM];
	size_t n_wrapped_item;
	
	int *virtual_table_ids;
	int virtual_table_id;
	int is_last_item;
};

inline int scan_state_should_compile_NOT(struct maat_state *mid)
{
	if (mid && mid->is_last_scan==1 && mid->compile_mid &&
		maat_hierarchy_compile_mid_has_NOT_clause(mid->compile_mid)) {
		return 1;
	} else {
		return 0;
	}
}

struct maat_options* maat_options_new(void)
{
    struct maat_options *options = ALLOC(struct maat_options, 1);

    options->nr_worker_threads = 1;
    options->deferred_load_on = 0;
    options->rule_effect_interval_ms = 60 * 1000;
    options->rule_update_checking_interval_ms = 1 * 1000;
    options->gc_timeout_ms = 10 * 1000;
    options->input_mode = DATA_SOURCE_NONE;
    options->log_level = 0;

    return options;
}

int maat_options_set_caller_thread_number(struct maat_options *opts, size_t n_thread)
{
    opts->nr_worker_threads = n_thread;
    
    return 0;
}

int maat_options_set_rule_effect_interval_ms(struct maat_options *opts, int interval_ms)
{
    opts->rule_effect_interval_ms = interval_ms;
    
    return 0;
}

int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts, int interval_ms)
{
    opts->rule_update_checking_interval_ms = interval_ms;

    return 0;
}

int maat_options_set_gc_timeout_ms(struct maat_options *opts, int interval_ms)
{
    opts->gc_timeout_ms = interval_ms;

    return 0;
}

int maat_options_set_instance_name(struct maat_options *opts, const char *instance_name, size_t name_len)
{
    memcpy(opts->instance_name, instance_name, name_len);

    return 0;
}

int maat_options_set_deferred_load_on(struct maat_options *opts)
{
    opts->deferred_load_on = 1;

    return 0;
}

int maat_options_set_iris(struct maat_options *opts, const char *full_directory, const char *increment_directory)
{
    if (strlen(full_directory) >= NAME_MAX || strlen(increment_directory) >= NAME_MAX) {
        return -1;
    }

    memcpy(opts->iris_ctx.full_idx_dir, full_directory, strlen(full_directory));
    memcpy(opts->iris_ctx.inc_idx_dir, increment_directory, strlen(increment_directory));
    opts->input_mode = DATA_SOURCE_IRIS_FILE;

    return 0;
}

int maat_options_set_json_file(struct maat_options *opts, const char *json_filename)
{
    strncpy(opts->json_ctx.json_file, json_filename, sizeof(opts->json_ctx.json_file));
    opts->input_mode = DATA_SOURCE_JSON_FILE;

    return 0;
}

int maat_options_set_redis(struct maat_options *opts, const char *redis_ip, uint16_t redis_port, int redis_db)
{
    memcpy(opts->redis_ctx.redis_ip, redis_ip, strlen(redis_ip));
    opts->redis_ctx.redis_port = redis_port;
    opts->redis_ctx.redis_db = redis_db;
    opts->input_mode = DATA_SOURCE_REDIS;

    return 0;
}

int maat_options_set_logger(struct maat_options *opts, void *logger)
{
    opts->logger = (struct log_handle *)logger;

    return 0;
}

void maat_read_full_config(struct maat *maat_instance)
{
    int ret = -1;
    char err_str[NAME_MAX] = {0};
    struct source_redis_ctx *mr_ctx = NULL;

    switch (maat_instance->input_mode) {
        case DATA_SOURCE_REDIS:
            mr_ctx = &(maat_instance->mr_ctx);
            log_info(maat_instance->logger, MODULE_MAAT_API, "Maat initiate from Redis %s:%hu db%d", 
                     mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db);
            mr_ctx->read_ctx = maat_cmd_connect_redis(mr_ctx->redis_ip, mr_ctx->redis_port, 
                                                      mr_ctx->redis_db, maat_instance->logger);
            if (mr_ctx->read_ctx != NULL) {
                redis_monitor_traverse(maat_instance->maat_version, mr_ctx,
									   maat_start_cb, maat_update_cb, maat_finish_cb,
									   maat_instance);
            }

            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "At initiation: NO effective rule in redis %s:%hu db%d",
                          mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db);
            }
            break;
        case DATA_SOURCE_IRIS_FILE:
			config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->iris_ctx.full_idx_dir,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance, maat_instance->logger);
            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "At initiation: NO effective rule in %s",
                          maat_instance->iris_ctx.full_idx_dir);
            }
            break;
        case DATA_SOURCE_JSON_FILE:
            ret = load_maat_json_file(maat_instance, maat_instance->json_ctx.json_file, err_str, sizeof(err_str));
            if (ret < 0) {
                log_error(maat_instance->logger, MODULE_MAAT_API, "Maat re-initiate with JSON file %s failed: %s", 
                          maat_instance->json_ctx.json_file, err_str);
                return;
            }
            
            config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->json_ctx.iris_file,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance, maat_instance->logger);
            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, "At initiation: NO effective rule in %s",
                          maat_instance->json_ctx.iris_file);
            }
            break;
        default:
            break;
    }

    maat_instance->maat_rt = maat_instance->creating_maat_rt;
    maat_instance->creating_maat_rt = NULL;
    maat_instance->is_running = 1;
    if (maat_instance->maat_rt != NULL) {
        maat_instance->maat_version = maat_instance->maat_rt->version;
        maat_instance->last_full_version = maat_instance->maat_rt->version;
    }
}

struct maat *maat_new(struct maat_options *opts, const char *table_info_path)
{
    if (NULL == table_info_path) {
        return NULL;
    }

    int garbage_gc_timeout_s = 0;
    struct maat *maat_instance = ALLOC(struct maat, 1);
    
    if (opts->logger != NULL) {
        maat_instance->logger = opts->logger;
    } else {
        char log_path[1024] = {0};
        if (strlen(maat_instance->instance_name) > 0) {
            snprintf(log_path, sizeof(log_path), "%s.log", maat_instance->instance_name);
        } else {
            snprintf(log_path, sizeof(log_path), "maat.log");
        }
        maat_instance->logger = log_handle_create(log_path, opts->log_level);
    }
    
    maat_instance->table_schema_mgr = table_schema_manager_create(table_info_path, maat_instance->logger);
    if (NULL == maat_instance->table_schema_mgr) {
        goto failed;
    }

    if (opts->compile_tablename != NULL) {
        memcpy(maat_instance->compile_tablename, opts->compile_tablename, strlen(opts->compile_tablename));
    }
    maat_instance->input_mode = opts->input_mode;
    switch (maat_instance->input_mode) {
        case DATA_SOURCE_REDIS:
            memcpy(maat_instance->mr_ctx.redis_ip, opts->redis_ctx.redis_ip, strlen(opts->redis_ctx.redis_ip));
            maat_instance->mr_ctx.redis_port = opts->redis_ctx.redis_port;
            maat_instance->mr_ctx.redis_db = opts->redis_ctx.redis_db;
            break;
        case DATA_SOURCE_IRIS_FILE:
            memcpy(maat_instance->iris_ctx.full_idx_dir, opts->iris_ctx.full_idx_dir, strlen(opts->iris_ctx.full_idx_dir));
            memcpy(maat_instance->iris_ctx.inc_idx_dir, opts->iris_ctx.inc_idx_dir, strlen(opts->iris_ctx.inc_idx_dir));
            break;
        case DATA_SOURCE_JSON_FILE:
            memcpy(maat_instance->json_ctx.json_file, opts->json_ctx.json_file, strlen(opts->json_ctx.json_file));
            break;
        default:
            log_error(maat_instance->logger, MODULE_MAAT_API, "data source unsupported:%d", maat_instance->input_mode);
            goto failed;
    }

    maat_instance->is_running = 0;
    maat_instance->maat_version = 0;
    maat_instance->last_full_version = 0;
    maat_instance->nr_worker_thread = opts->nr_worker_threads;
    maat_instance->rule_effect_interval_ms = opts->rule_effect_interval_ms;
    maat_instance->gc_timeout_ms = opts->gc_timeout_ms;
    maat_instance->deferred_load = opts->deferred_load_on;
    garbage_gc_timeout_s = (maat_instance->rule_effect_interval_ms / 1000) +
                                (maat_instance->gc_timeout_ms / 1000);
    maat_instance->garbage_bin = maat_garbage_bin_new(garbage_gc_timeout_s);

    maat_instance->outer_mid_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);
    maat_instance->compile_mid_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);
    maat_instance->thread_call_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);

    pthread_mutex_init(&(maat_instance->background_update_mutex), NULL);

    if (0 == maat_instance->deferred_load) {
        maat_read_full_config(maat_instance);
    }

    pthread_create(&(maat_instance->cfg_mon_thread), NULL, rule_monitor_loop, (void *)maat_instance);

    return maat_instance;
failed:
    FREE(maat_instance);
    return NULL;
}

void maat_free(struct maat *maat_instance)
{
    if (NULL == maat_instance) {
        return;
    }

    void *ret = NULL;

    maat_instance->is_running = 0;
	pthread_join(maat_instance->cfg_mon_thread, &ret);
}

int maat_table_get_id(struct maat *maat_instance, const char *table_name)
{
    int table_id = -1;

    struct table_schema_manager *table_schema_mgr = maat_instance->table_schema_mgr;
    table_id = table_schema_manager_get_table_id(table_schema_mgr, table_name);
    
    return table_id;
}

inline void maat_runtime_ref_inc(struct maat_runtime *maat_rt, int thread_id)
{
	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, 1);
}

inline void maat_runtime_ref_dec(struct maat_runtime *maat_rt, int thread_id)
{
	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, -1);
}

int maat_table_callback_register(struct maat *maat_instance, int table_id,
								 maat_start_callback_t *start,
								 maat_update_callback_t *update,
								 maat_finish_callback_t *finish,
								 void *u_para)
{
    int ret = -1;

    pthread_mutex_lock(&(maat_instance->background_update_mutex));
    ret = table_schema_add_callback(maat_instance->table_schema_mgr, table_id, 
                                           start, update, finish, u_para, maat_instance->logger);
    if (ret < 0) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return -1;
    }

    if (!maat_instance->maat_rt) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return 0;
    }

    struct table_runtime *table_rt = table_runtime_get(maat_instance->maat_rt->table_rt_mgr, table_id);
    size_t row_count = table_runtime_cached_row_count(table_rt);
    if (row_count > 0) {
        if (start != NULL) {
            start(MAAT_RULE_UPDATE_TYPE_FULL, u_para);
        }

        for (size_t i = 0; i < row_count; i++) {
            const char *line = table_runtime_get_cached_row(table_rt, i);
            if (NULL == line) {
                break;
            }

            update(table_id, line, u_para);
        }

        if (finish != NULL) {
            finish(u_para);
        }
    }

    pthread_mutex_unlock(&(maat_instance->background_update_mutex));

    return 0;
}

int maat_plugin_table_ex_schema_register(struct maat *maat_instance, int table_id,
                                         maat_plugin_ex_new_func_t *new_func,
                                         maat_plugin_ex_free_func_t *free_func,
                                         maat_plugin_ex_dup_func_t *dup_func,
                                         long argl, void *argp)
{
    struct table_schema *table_schema = table_schema_get(maat_instance->table_schema_mgr, table_id);
    pthread_mutex_lock(&(maat_instance->background_update_mutex));
    int ret = table_schema_set_ex_data_schema(table_schema, new_func, free_func, dup_func, 
                                                     argl, argp, maat_instance->logger);
    if (ret < 0) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return -1;
    }
    
    struct table_runtime *table_rt = NULL;
    if (maat_instance->maat_rt != NULL) {
        table_rt = table_runtime_get(maat_instance->maat_rt->table_rt_mgr, table_id);
        table_runtime_commit_ex_data_schema(table_rt, table_schema, maat_instance->nr_worker_thread,
                                            maat_instance->maat_rt->version, maat_instance->logger);
    }
    pthread_mutex_unlock(&(maat_instance->background_update_mutex));

    return 0;
}

void *maat_plugin_table_get_ex_data(struct maat *maat_instance, int table_id, const char *key, size_t key_len)
{
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        return NULL;
    }

    struct table_schema *table_schema  = table_schema_get(maat_instance->table_schema_mgr, table_id);
    if (NULL == table_schema) {
        return NULL;
    }

    struct table_runtime *table_rt = table_runtime_get(maat_rt->table_rt_mgr, table_id);
    if (NULL == table_rt) {
        return NULL;
    }

    struct ex_data_runtime *ex_data_rt = table_runtime_get_ex_data_rt(table_rt);
    if (NULL == ex_data_rt) {
        return NULL;
    }

    return ex_data_runtime_dup_ex_data(ex_data_rt, key, key_len);
}

static void scan_count_inc(struct maat_state *mid)
{
	mid->scan_cnt++;
}

struct maat_state *make_outer_state(struct maat *maat_instance, int thread_id)
{
	struct maat_state *outer_state = NULL;

	outer_state = ALLOC(struct maat_state, 1);
	outer_state->maat_instance = maat_instance;
	outer_state->district_id = DISTRICT_ANY;
	outer_state->thread_id = (signed short)thread_id;

	return outer_state;
}

struct maat_state *grab_mid(struct maat_state **state, struct maat *maat_instance, int thread_id, int is_hit_item)
{
    struct maat_state *mid = *state;

	if (NULL == mid) {
		mid = make_outer_state(maat_instance, thread_id);
        *state = mid;
        //Maat_set_scan_status calls grap_mid() with thread_num=-1.
		if (mid->thread_id >= 0) {
			alignment_int64_array_add(maat_instance->outer_mid_cnt, thread_id, 1);
		}
	}

	if (mid->thread_id < 0 && thread_id >= 0) {
		mid->thread_id = thread_id;		
		alignment_int64_array_add(maat_instance->outer_mid_cnt, thread_id, 1);
	}

	if (is_hit_item == 1) {
		if (NULL == mid->compile_mid) {
			mid->compile_mid = maat_hierarchy_compile_mid_new(maat_instance->maat_rt->hier, thread_id);
			alignment_int64_array_add(maat_instance->compile_mid_cnt, thread_id, 1);
		}
	}
	return mid;
}

void scan_item_hit_wrapper_build(struct scan_item_hit_wrapper* wrapper, struct scan_result* results, size_t n_result, 
                                  int district_id, int is_last_item, int virtual_table_id, int Nth_scan)
{
	size_t i=0;
	struct maat_item_inner *item = NULL;
	wrapper->n_wrapped_item = 0;
	wrapper->virtual_table_id = 0;
	wrapper->virtual_table_ids = NULL;

	for (i = 0; i < n_result; i++) {
		item = (struct maat_item_inner *)(results[i].tag);
		if (item->district_id == district_id || district_id == DISTRICT_ANY) {
			wrapper->wrapped_items[wrapper->n_wrapped_item] = item;
			wrapper->n_wrapped_item++;
		}		
	}
	wrapper->is_last_item = is_last_item;
	wrapper->virtual_table_id = virtual_table_id;
	wrapper->Nth_scan = Nth_scan;
	wrapper->virtual_table_ids = NULL;
}

struct compile_sort_para {
	double evaluation_order;
	int declared_clause_num;
	int compile_id;
	void *user;
};

static void compile_sort_para_set(struct compile_sort_para *para, 
                                  const struct maat_compile_rule *compile_relation, void *user)
{
	para->compile_id=compile_relation->compile_id;
	para->evaluation_order=compile_relation->evaluation_order;
	para->declared_clause_num=compile_relation->declared_clause_num;
	para->user = user;
}

static int compile_sort_para_compare(const struct compile_sort_para *a, const struct compile_sort_para *b)
{
	//If both of compile rule's evaluation order are specified, compile rule with small evaluation order is priority.
	if(a->evaluation_order!=0 && b->evaluation_order!=0)
	{
		if(a->evaluation_order - b->evaluation_order <0)
		{
			return -1;
		}
		else if(a->evaluation_order - b->evaluation_order >0)
		{
			return 1;
		}
	}
	//If one of compile rule's evaluation order is zero, compile rule with big evaluation order is priority.
	else if(a->evaluation_order + b->evaluation_order!= 0)
	{
		return (a->evaluation_order - b->evaluation_order >0) ? -1 : 1;
	}
	//If compile rule's execute sequences are not specified or equal.
	if(a->declared_clause_num!=b->declared_clause_num)
	{
		return (a->declared_clause_num-b->declared_clause_num);
	}
	else
	{
		return (b->compile_id-a->compile_id);
	}

}

static int compare_compile_rule(const void *a, const void *b)
{
	const struct maat_compile_rule *ra=*(const struct Maat_compile_rule **)a;
	const struct maat_compile_rule *rb=*(const struct Maat_compile_rule **)b;
	
	struct compile_sort_para sa, sb;
	compile_sort_para_set(&sa, ra, NULL);
	compile_sort_para_set(&sb, rb, NULL);

	return compile_sort_para_compare(&sa, &sb);
}

int item_compile(struct maat *maat_instance, struct maat_hierarchy_compile_mid *compile_mid, 
                   const struct scan_item_hit_wrapper *item_hit_wrapper, int *result, 
                   int size, int thread_id)
{
	int is_last_item = item_hit_wrapper->is_last_item;
	size_t item_hit_num = item_hit_wrapper->n_wrapped_item;

	int scan_ret=0;
	int i=0;

	struct maat_compile_rule *compile_rule_array[size];
	struct maat_compile_rule *compile_rule = NULL;
	int virtual_table_id = 0;

	struct maat_item_inner *item = NULL;
	
	for (i = 0; (size_t)i < item_hit_num;i++) {
		item = item_hit_wrapper->wrapped_items[i];
		assert(item->magic_num == ITEM_RULE_MAGIC);
		if (item_hit_wrapper->virtual_table_ids) {
			virtual_table_id = item_hit_wrapper->virtual_table_ids[i];
		} else {
			virtual_table_id = item_hit_wrapper->virtual_table_id;
		}
		maat_hierarchy_compile_mid_update(feather->scanner->hier, compile_mid, item->item_id, virtual_table_id, item_hit_wrapper->Nth_scan, i);
	}

	scan_ret = maat_hierarchy_item_compile(feather->scanner->hier, compile_mid, is_last_item, (void **)compile_rule_array, size);
	//Maat_hierarchy is rwlock protected, it always returns non-NULL compile_rule.
	if (scan_ret > 1) {
		qsort(compile_rule_array, scan_ret, sizeof(struct maat_compile_rule *),
			  compare_compile_rule);
	}
	for (i = 0; i < scan_ret && i < size; i++) {
		compile_rule = compile_rule_array[i];
		assert(compile_rule->magic_num == COMPILE_RULE_MAGIC);
        result[i] = compile_rule->compile_id;
		/*
		fill_maat_rule(&(result[i]), &(compile_rule->head), compile_rule->service_defined, 
                       compile_rule->head.serv_def_len);*/
	}	

	if (scan_ret > 0) {
		alignment_int64_array_add(feather->hit_cnt, thread_id, 1);
	}

	if (item_hit_num == 0 && scan_ret > 0) {
		alignment_int64_array_add(feather->not_grp_hit_cnt, thread_id, 1);
	}

	return MIN(scan_ret, size);
}

int maat_scan_integer(struct maat *instance, int table_id, int thread_id,
                      unsigned int intval, int results[], size_t *n_result,
                      struct maat_state **state)
{
    return 0;
}

static int ip_scan_data_set(struct ip_addr *scan_data, struct addr_2tuple *addr, enum component_table_type child_type)
{
    switch (addr->type) {
        case IP_TYPE_V4:
            scan_data->ip_type = IP_TYPE_V4;
            switch (child_type) {
                case COMPONENT_TABLE_TYPE_SIP:
                    scan_data->ipv4 = ntohl(addr->ipv4.sip);
                    break;
                case COMPONENT_TABLE_TYPE_DIP:
                    scan_data->ipv4 = ntohl(addr->ipv4.dip);
                    break;
                default:
                    assert(0);
                    return -1;
            }
            break;
        case IP_TYPE_V6:
            scan_data->ip_type = IP_TYPE_V6;
            switch (child_type) {
                case COMPONENT_TABLE_TYPE_SIP:
                    memcpy(scan_data->ipv6, addr->ipv6.sip, sizeof(addr->ipv6.sip));
                    ipv6_ntoh(scan_data->ipv6);
                    break;
                case COMPONENT_TABLE_TYPE_DIP:
                    memcpy(scan_data->ipv6, addr->ipv6.dip, sizeof(addr->ipv6.dip));
                    ipv6_ntoh(scan_data->ipv6);
                    break;
                default:
                    assert(0);
                    return -1;
            }
            break;
        default:
            assert(0);
            return -1;
    }

    return 0;
}

static int ip_composition_scan(int thread_id, struct addr_2tuple *addr,
                               int parent_table_id, enum component_table_type child_type,
                               int *virtual_table_id,
                               struct table_schema_manager *table_schema_mgr,
                               struct table_runtime_manager *table_rt_mgr, 
                               struct scan_result *item_results, size_t n_result_array)
{
    int child_table_id = 0;

    if (child_type == COMPONENT_TABLE_TYPE_NONE) {
        child_table_id = parent_table_id;
        child_type = COMPONENT_TABLE_TYPE_SESSION;
    } else {
        child_table_id = table_schema_manager_get_child_table_id(table_schema_mgr, parent_table_id, child_type);
    }

    if (child_table_id < 0) {
        return 0;
    }

    struct table_schema *real_table = table_schema_get_by_scan_type(table_schema_mgr, child_table_id, SCAN_TYPE_IP, virtual_table_id);
    if (NULL == real_table) {
        return 0;
    }

    enum table_type table_type = table_schema_get_table_type(real_table);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        return -1;
    }

    int table_id = table_schema_get_table_id(real_table);
    struct table_runtime *table_rt = table_runtime_get(table_rt_mgr, table_id);
    size_t rule_num = table_runtime_rule_count(table_rt);
    if (0 == rule_num) {
        return 0;
    }

    struct ip_addr scan_data;
    memset(&scan_data, 0, sizeof(struct ip_addr));

    ip_scan_data_set(&scan_data, addr, child_type);
    size_t hit_cnt = 0;
    int ret = table_runtime_scan_ip(table_rt, thread_id, &scan_data, item_results, &hit_cnt, n_result_array);
    if (ret < 0) {
        return -1;
    }

    return hit_cnt;
}

int maat_scan_ip(struct maat *maat_instance, int table_id, int thread_id, struct addr_2tuple *addr, 
                 int results[], size_t *n_result, struct maat_state **state)
{
    if ((NULL == maat_instance) || (table_id < 0) || (table_id >= MAX_TABLE_NUM) ||
        (thread_id < 0) || (NULL == addr) || (NULL == results) || (NULL == n_result) ||
        (NULL == state)) {
        return -1;
    }

    struct maat_state *mid = NULL;
    mid = grab_mid(state, maat_instance, thread_id, 0);
    scan_count_inc(mid);
    
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        return 0;
    }

    struct table_runtime_manager *table_rt_mgr = maat_rt->table_rt_mgr;
    struct table_runtime *table_rt = table_runtime_get(table_rt_mgr, table_id);
    enum table_type table_type = table_runtime_get_type(table_rt);
    if (table_type == TABLE_TYPE_INVALID) {
        maat_instance->scan_err_cnt++;
        return -1;
    }

    int item_ret = 0;
    int virtual_table_id = 0;
    struct scan_result *item_result = maat_rt->item_result_buff + thread_id * MAX_SCANNER_HIT_NUM;
    int item_hit_cnt = 0;
    int item_result_virtual_table_ids[MAX_SCANNER_HIT_NUM];
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);
    maat_runtime_ref_inc(maat_rt, thread_id);

    if (table_type == TABLE_TYPE_COMPOSITION) {
        /*
        item_ret = ip_composition_scan(thread_id, addr, table_id, COMPONENT_TABLE_TYPE_SIP, &virtual_table_id,
                                         maat_instance->table_schema_mgr, maat_instance->maat_rt->table_rt_mgr, 
                                         item_result + item_hit_cnt, MAX_SCANNER_HIT_NUM - item_hit_cnt);
        item_hit_cnt += item_ret; */
        enum component_table_type childs[3] = {COMPONENT_TABLE_TYPE_SIP, COMPONENT_TABLE_TYPE_DIP, COMPONENT_TABLE_TYPE_SESSION};                                
        for (int i = 0; i < 3; i++) {
            item_ret = ip_composition_scan(thread_id, addr, table_id, childs[i], &virtual_table_id,
                                         maat_instance->table_schema_mgr, maat_instance->maat_rt->table_rt_mgr, 
                                         item_result + item_hit_cnt, MAX_SCANNER_HIT_NUM - item_hit_cnt);
            if (item_ret < 0) {
                maat_instance->scan_err_cnt++;
            } else {
                for (int j = 0; j < item_ret; j++) {
                    item_result_virtual_table_ids[item_hit_cnt++] = virtual_table_id;
                }
            }
        }
    } else {
        item_ret = ip_composition_scan(thread_id, addr, table_id, COMPONENT_TABLE_TYPE_NONE, &virtual_table_id,
                                         maat_instance->table_schema_mgr, maat_instance->maat_rt->table_rt_mgr, 
                                         item_result + item_hit_cnt, MAX_SCANNER_HIT_NUM - item_hit_cnt);
        if (item_ret < 0) {
            maat_instance->scan_err_cnt++;
        } else {
            item_hit_cnt += item_ret;
        }
    }

    int compile_ret = 0;
    struct scan_item_hit_wrapper item_hit_wrapper;
    if (item_hit_cnt > 0 || scan_state_should_compile_NOT(mid)) {
        mid = grab_mid(state, maat_instance, thread_id, 1);
        scan_item_hit_wrapper_build(&item_hit_wrapper, item_result, item_hit_cnt, -1,
                                     mid->is_last_scan, virtual_table_id, mid->scan_cnt);
        if (table_type == TABLE_TYPE_COMPOSITION) {
            item_hit_wrapper.virtual_table_ids = item_result_virtual_table_ids;
        }

        compile_ret = item_compile(maat_instance, mid->compile_mid,
                                     &item_hit_wrapper,
                                     results, item_hit_cnt,
                                     thread_id);
        assert(mid->is_last_scan < 2);
        if (mid->is_last_scan == 1) {
            mid->is_last_scan = 2;
        }
    }
    maat_runtime_ref_dec(maat_rt, thread_id);

    if (compile_ret == 0 && item_hit_cnt > 0) {
		return -2;
	}
    *n_result = compile_ret;
	return compile_ret;
}

int maat_scan_string(struct maat *maat_instance, int table_id, int thread_id,
                     const char *data, size_t data_len, int results[], size_t *n_result,
                     struct maat_state **state)
{
    if ((NULL == maat_instance) || (table_id < 0) || (table_id >= MAX_TABLE_NUM) ||
        (thread_id < 0) || (NULL == data) || (0 == data_len) || (NULL == results) || 
        (NULL == n_result) || (NULL == state)) {
        return -1;
    }
    
    struct table_runtime_manager *table_rt_mgr = maat_instance->maat_rt->table_rt_mgr;
    struct table_runtime *table_rt = table_runtime_get(table_rt_mgr, table_id);
    
    return table_runtime_scan_string(table_rt, thread_id, data, data_len, results, n_result);
}

struct maat_stream *maat_scan_stream_open(struct maat *instance, int table_id, int thread_id)
{
    return NULL;
}

int maat_scan_stream(struct maat_stream **stream, int thread_id, const char *data, int data_len, 
                     int results[], size_t *n_result, struct maat_state **state)
{
    return 0;
}

void maat_scan_stream_close(struct maat_stream **stream)
{

}

int maat_state_set(struct maat *instance, struct maat_state **mid, enum maat_scan_opt opt, 
                   const void *value, int size)
{

}

//return >=0 if success, return -1 when failed;
int maat_state_get(struct maat *instance, struct maat_state **mid, enum maat_scan_opt opt, 
                   void *value, int size)
{

}

void maat_state_free(struct maat_state **state)
{

}

int maat_matched_compile_id(struct maat *instance, struct maat_matched *matched)
{

}
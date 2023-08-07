/*
**********************************************************************************************
*   Maat: Deep Packet Inspection Policy Framework

*   Maat is the Goddess of truth and justice in ancient Egyptian concept.
*	Her feather was the measure that determined whether the souls (considered 
*	to reside in the heart) of the departed would reach the paradise of afterlife
*	successfully.

*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2023 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_H_
#define _MAAT_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <netinet/in.h>

/* maat instance handle */
struct maat;

struct maat_hit_path {
    int Nth_scan;
    int vtable_id; // 0 is not a virtual table.
	long long item_id;
	long long sub_group_id;
	long long top_group_id;
	long long compile_id;
};

struct maat_hit_group {
    long long item_id;
    long long group_id;
    int vtable_id;
};

enum maat_scan_status {
    MAAT_SCAN_ERR = -1,  //scan error
    MAAT_SCAN_OK,        //scan but not hit(group or compile)
    MAAT_SCAN_HALF_HIT,  //half hit: hit group, not hit compile
    MAAT_SCAN_HIT        //scan hit compile
};

enum maat_update_type {
    MAAT_UPDATE_TYPE_INVALID = 0,
    MAAT_UPDATE_TYPE_FULL,
    MAAT_UPDATE_TYPE_INC
};

enum maat_list_type {
    MAAT_LIST_TYPE_FULL = 1,
    MAAT_LIST_TYPE_INC
};

enum maat_expr_engine {
    MAAT_EXPR_ENGINE_HS = 0, //default engine(hyperscan)
    MAAT_EXPR_ENGINE_RS      //rulescan
};

struct ip_addr {
    int ip_type;             //4: IPv4, 6: IPv6
    union {
        unsigned int ipv4;   //network order
        unsigned int ipv6[4];
    };
};

enum log_level { 
    LOG_LEVEL_TRACE, 
    LOG_LEVEL_DEBUG, 
    LOG_LEVEL_INFO, 
    LOG_LEVEL_WARN, 
    LOG_LEVEL_ERROR, 
    LOG_LEVEL_FATAL 
};

/* update_type: MAAT_UPDATE_TYPE_FULL or MAAT_UPDATE_TYPE_INC */
typedef void maat_start_callback_t(int update_type, void *u_param);

typedef void maat_update_callback_t(int table_id, const char *table_line, void *u_para);

typedef void maat_finish_callback_t(void *u_para);

typedef void maat_ex_new_func_t(const char *table_name, int table_id, const char *key, 
                                const char *table_line, void **ad, long argl, void *argp);

typedef void maat_ex_free_func_t(int table_id, void **ad, long argl, void *argp);

typedef void maat_ex_dup_func_t(int table_id, void **to, void **from, long argl, void *argp);

/* maat_instance options API */
struct maat_options;

struct maat_options *maat_options_new(void);

void maat_options_free(struct maat_options *opts);

/**
 * @brief set maat instance name
 * 
 * @note The maximum length of instance_name is 15 bytes
*/
int maat_options_set_instance_name(struct maat_options *opts, const char *instance_name);

int maat_options_set_caller_thread_number(struct maat_options *opts, size_t n_thread);

int maat_options_set_accept_tags(struct maat_options *opts, const char *accept_tags);

int maat_options_set_rule_effect_interval_ms(struct maat_options *opts, int interval_ms);

int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts, int interval_ms);

int maat_options_set_gc_timeout_ms(struct maat_options *opts, int interval_ms);

int maat_options_set_deferred_load_on(struct maat_options *opts);

int maat_options_set_stat_on(struct maat_options *opts);

int maat_options_set_perf_on(struct maat_options *opts);

int maat_options_set_foreign_cont_dir(struct maat_options *opts, const char *dir);

int maat_options_set_logger(struct maat_options *opts, const char *log_path,
                            enum log_level level);

int maat_options_set_iris(struct maat_options *opts, const char *full_directory, 
                          const char *increment_directory);

int maat_options_set_json_file(struct maat_options *opts, const char *json_filename);

/** 
 * Indicate whether the JSON file is compressed by gzip 
 * flag: 1(compressed) 0(uncompressed)
 * */
int maat_options_set_json_file_gzip_flag(struct maat_options *opts, int flag);

/* Specify the decryption key for the JSON file to be decrypted */
int maat_options_set_json_file_decrypt_key(struct maat_options *opts, const char *decrypt_key);

int maat_options_set_redis(struct maat_options *opts, const char *redis_ip, 
                           uint16_t redis_port, int redis_db);

int maat_options_set_stat_file(struct maat_options *opts, const char *stat_filename);

int maat_options_set_expr_engine(struct maat_options *opts, enum maat_expr_engine engine);

/* maat_instance API */
struct maat *maat_new(struct maat_options *opts, const char *table_info_path);
void maat_free(struct maat *instance);

/* maat helper API */
int maat_helper_read_column(const char *table_line, int Nth_column, 
                            size_t *column_offset, size_t *column_len);
/**
 * verify if regex expression is legal
 * 
 * @param The NULL-terminated expression to parse. 
 * @retval 1(legal) 0(illegal)
 **/                           
int maat_helper_verify_regex_expression(const char *expression);

/* maat table API */
int maat_get_table_id(struct maat *instance, const char *table_name);

/* return 0 if success, otherwise return -1 */
int maat_table_callback_register(struct maat *instance, int table_id,
								 maat_start_callback_t *start,
								 maat_update_callback_t *update,
								 maat_finish_callback_t *finish,
								 void *u_para);

/* maat plugin table API */
int maat_plugin_table_ex_schema_register(struct maat *instance, const char *table_name,
                                         maat_ex_new_func_t *new_func,
                                         maat_ex_free_func_t *free_func,
                                         maat_ex_dup_func_t *dup_func,
                                         long argl, void *argp);
/** 
 *  xx_plugin_table_get_ex_data
 *  returned data is duplicated by dup_func of maat_plugin_table_ex_schema_register, 
 *  caller is responsible to free the data.
 * 
 *  free_func support gargbage collection(gc), gc timeout(default 0) can be configured
 *  in table_info which means maat will not call free_func until the timeout expires
 */

/** 
 *  NOTE: only plugin table support three key type(integer, pointer, ip_addr) 
 *        specified in table_info.conf. If use ip_addr key type, then key should be 
 *        ip address in network order.
*/
void *maat_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                    const char *key, size_t key_len);
                                     
int maat_ip_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                     const struct ip_addr *ip, void **ex_data_array,
                                     size_t n_ex_data);

int maat_fqdn_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                       const char *fqdn, void **ex_data_array, 
                                       size_t n_ex_data);

int maat_bool_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                       unsigned long long *item_ids, size_t n_item,
                                       void **ex_data_array, size_t n_ex_data);
/* maat scan API */
struct maat_state;

/**
 * @param instance:     maat instance created by maat_new()
 * @param table_id:     the id of table which to be scanned
 * @param thread_id:    thread index
 * @param results:      array to store hit compile id
 * @param n_result:     the array size
 * @param n_hit_result: the number of hit compile id
 * @param state:        scan mid status
 * 
 * @retval MAAT_SCAN_ERR
 *         MAAT_SCAN_OK
 *         MAAT_SCAN_HALF_HIT
 *         MAAT_SCAN_HIT       
*/
int maat_scan_flag(struct maat *instance, int table_id,
                   long long flag, long long *results, size_t n_result,
                   size_t *n_hit_result, struct maat_state *state);
int maat_scan_integer(struct maat *instance, int table_id,
                      long long integer, long long *results, size_t n_result,
                      size_t *n_hit_result, struct maat_state *state);

/**
 * @param ip_addr: network ipv4 address
 * @param port:    network port
 * @param protocol: -1(ANY protocol) 1(ICMP) 6(TCP) 17(UDP)
*/
int maat_scan_ipv4(struct maat *instance, int table_id,
                   uint32_t ip_addr, uint16_t port, int protocol,
                   long long *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state *state);

int maat_scan_ipv6(struct maat *instance, int table_id,
                   uint8_t *ip_addr, uint16_t port, int protocol,
                   long long *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state *state);

int maat_scan_string(struct maat *instance, int table_id,
                     const char *data, size_t data_len, long long *results, 
                     size_t n_result, size_t *n_hit_result, 
                     struct maat_state *state);

struct maat_stream;
struct maat_stream *maat_stream_new(struct maat *instance, int table_id,
                                    struct maat_state *state);

int maat_stream_scan(struct maat_stream *stream, const char *data, int data_len, 
                     long long *results, size_t n_result, size_t *n_hit_result,
                     struct maat_state *state);

void maat_stream_free(struct maat_stream *stream);

/* maat state API */
struct maat_state *maat_state_new(struct maat *instance, int thread_id);

void maat_state_reset(struct maat_state *state);

void maat_state_free(struct maat_state *state);

int maat_state_set_scan_district(struct maat_state *state, int table_id, 
                                 const char *district, size_t district_len);

int maat_state_set_last_scan(struct maat_state *state);

int maat_state_set_scan_compile_table(struct maat_state *state, int compile_table_id);

int maat_state_get_compile_table_ids(struct maat_state *state, long long *compile_ids,
                                    size_t n_compile_ids, int *compile_table_ids);

int maat_state_get_hit_paths(struct maat_state *state, struct maat_hit_path *paths, 
                             size_t n_path);
                             
/**
 * @brief get the total number of scans after maat_state_new
*/
size_t maat_state_get_scan_count(struct maat_state *state);

/**
 * @brief get hit groups(full or incremental)
 * 
 * @param type: 
 *          MAAT_LIST_TYPE_FULL => get all hit groups after maat_state_new
 *          MAAT_LIST_TYPE_INC  => get hit groups for this scan
*/
int maat_state_get_hit_groups(struct maat_state *state, enum maat_list_type type,
                              struct maat_hit_group *groups, size_t n_group);

/* return hit object compile_id */
int maat_hit_group_compile_id(struct maat *instance, struct maat_hit_group *group);

#ifdef __cplusplus
}
#endif

#endif

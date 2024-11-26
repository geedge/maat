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
#include <uuid/uuid.h>

#define MAX_FIELD_NAME_LEN  128

/* maat instance handle */
struct maat;

struct maat_hit_path {
    int Nth_scan;
    char field_name[MAX_FIELD_NAME_LEN];    // 0 is not a field.
    int negate_option;     // 1 means negate condition(condition)
    int condition_index; // 0 ~ 7
    uuid_t item_uuid;
    uuid_t sub_object_uuid;
    uuid_t top_object_uuid;
    uuid_t rule_uuid;
};

struct maat_hit_object {
    uuid_t item_uuid;
    uuid_t object_uuid;
    char field_name[MAX_FIELD_NAME_LEN];
};

enum maat_scan_status {
    MAAT_SCAN_ERR = -1,  //scan error
    MAAT_SCAN_OK,        //scan but not hit(object or rule)
    MAAT_SCAN_HALF_HIT,  //half hit: hit object, not hit rule
    MAAT_SCAN_HIT        //scan hit rule
};

enum maat_update_type {
    MAAT_UPDATE_TYPE_INVALID = 0,
    MAAT_UPDATE_TYPE_FULL,
    MAAT_UPDATE_TYPE_INC
};

/**
 * @brief auto means select engine automatically
 *        regex rules always use hyperscan
 *        literal rules: rule_num <= 50k, use hyperscan
 *                       rule_num > 50k, use rulescan
*/
enum maat_expr_engine {
    MAAT_EXPR_ENGINE_HS = 0, //hyperscan
    MAAT_EXPR_ENGINE_RS,     //rulescan
    MAAT_EXPR_ENGINE_AUTO    //default
};

struct ip_addr {
    int ip_type;             //4:IPV4, 6:IPV6
    union {
        unsigned int ipv4;   //network order
        unsigned int ipv6[4];//network order
    };
};

enum maat_operation {
	MAAT_OP_DEL = 0,
	MAAT_OP_ADD
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

typedef void maat_update_callback_t(const char *table_name, const char *table_line, enum maat_operation op, void *u_para);

typedef void maat_finish_callback_t(void *u_para);

typedef void maat_ex_new_func_t(const char *table_name, const char *key, 
                                const char *table_line, void **ad, long argl, void *argp);

typedef void maat_ex_free_func_t(const char *table_name, void **ad, long argl, void *argp);

typedef void maat_ex_dup_func_t(const char *table_name, void **to, void **from, long argl, void *argp);

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

int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts, int interval_ms);

int maat_options_set_gc_timeout_ms(struct maat_options *opts, int interval_ms);

int maat_options_set_deferred_load_on(struct maat_options *opts);

int maat_options_set_stat_on(struct maat_options *opts);

int maat_options_set_perf_on(struct maat_options *opts);

int maat_options_set_foreign_cont_dir(struct maat_options *opts, const char *dir);

int maat_options_set_logger(struct maat_options *opts, const char *log_path,
                            enum log_level level);

int maat_options_set_log_file_max_size(struct maat_options *opts,  size_t max_size_mb);//default is 500MB, 0 for unlimited

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

int maat_options_set_hit_path_enabled(struct maat_options *opts);

int maat_options_set_hit_object_enabled(struct maat_options *opts);

/* maat_instance API */
struct maat *maat_new(struct maat_options *opts, const char *table_info_path);
void maat_free(struct maat *instance);

void maat_reload_log_level(struct maat *instance, enum log_level level);

/**
 * For xx_plugin table, each thread can call this function initially, maat will maintain the
 * thread_id internally and the number of times the xx_plugin_table_get_ex_data interface
 * is called by different threads is counted.
 */
void maat_register_thread(struct maat *instance);

/**
 * verify if regex expression is legal
 * 
 * @param The NULL-terminated expression to parse. 
 * @retval 1(legal) 0(illegal)
 **/                           
int maat_helper_verify_regex_expression(const char *expression);

const char *maat_get_table_schema_tag(struct maat *instance, const char *table_name);

/* return 0 if success, otherwise return -1 */
int maat_table_callback_register(struct maat *instance, const char *table_name,
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
 *        specified in table_info.json. If use ip_addr key type, then key should be 
 *        ip address in network order.
*/
void *maat_plugin_table_get_ex_data(struct maat *instance, const char *table_name,
                                    const char *key, size_t key_len);
                                     
int maat_ip_plugin_table_get_ex_data(struct maat *instance, const char *table_name,
                                     const struct ip_addr *ip_addr,
                                     void **ex_data_array, size_t array_size);

/** 
 * NOTE: @retval -1(ERROR) 0(no ex_data) 1(only one ex_data)
 *      this function return only one ex_data if matched
 */
int maat_ipport_plugin_table_get_ex_data(struct maat *instance, const char *table_name,
                                         const struct ip_addr *ip_addr, uint16_t port,
                                         void **ex_data_array, size_t array_size);

int maat_fqdn_plugin_table_get_ex_data(struct maat *instance, const char *table_name,
                                       const char *fqdn, void **ex_data_array, 
                                       size_t array_size);

int maat_bool_plugin_table_get_ex_data(struct maat *instance, const char *table_name,
                                       unsigned long long *item_ids, size_t n_item,
                                       void **ex_data_array, size_t array_size);
/* maat scan API */
struct maat_state;

/**
 * @param instance:     maat instance created by maat_new()
 * @param table_name:   the name of table which to be scanned
 * @param thread_id:    thread index
 * @param results:      array to store hit rule id
 * @param n_result:     the array size
 * @param n_hit_result: the number of hit rule id
 * @param state:        scan mid status
 * 
 * @retval MAAT_SCAN_ERR
 *         MAAT_SCAN_OK
 *         MAAT_SCAN_HALF_HIT
 *         MAAT_SCAN_HIT       
*/
int maat_scan_flag(struct maat *instance, const char *table_name, const char *field_name, 
                   long long flag, uuid_t *results, size_t n_result, size_t *n_hit_result,
                   struct maat_state *state);

int maat_scan_integer(struct maat *instance, const char *table_name, const char *field_name,
                      long long integer, uuid_t *results, size_t n_result, size_t *n_hit_result,
                      struct maat_state *state);

/**
 * @param ip_addr: ipv4 address in network order
 * @param port:    port in host order. If the port is not specified, use -1. Note that 0 is a valid port.
*/
int maat_scan_ipv4_port(struct maat *instance, const char *table_name, const char *field_name,
                    uint32_t ip_addr, int port, uuid_t *results, size_t n_result, size_t *n_hit_result,
                    struct maat_state *state);

int maat_scan_ipv6_port(struct maat *instance, const char *table_name, const char *field_name,
                    uint8_t *ip_addr, int port, uuid_t *results, size_t n_result, size_t *n_hit_result,
                    struct maat_state *state);
int maat_scan_ipv4(struct maat *instance, const char *table_name, const char *field_name,
                    uint32_t ip_addr, uuid_t *results, size_t n_result, size_t *n_hit_result,
                    struct maat_state *state);

int maat_scan_ipv6(struct maat *instance, const char *table_name, const char *field_name,
                    uint8_t *ip_addr, uuid_t *results, size_t n_result, size_t *n_hit_result,
                    struct maat_state *state);

int maat_scan_string(struct maat *instance, const char *table_name, const char *field_name,
                     const char *data, size_t data_len, uuid_t *results, size_t n_result,
                     size_t *n_hit_result, struct maat_state *state);

int maat_scan_object(struct maat *instance, const char *table_name, const char *field_name,
                    struct maat_hit_object *objects, size_t n_object, uuid_t *results, size_t n_result,
                    size_t *n_hit_result, struct maat_state *state);

int maat_scan_not_logic(struct maat *instance, const char *table_name, const char *field_name,
                        uuid_t *results, size_t n_result, size_t *n_hit_result, struct maat_state *state);

struct maat_stream;
struct maat_stream *maat_stream_new(struct maat *instance, const char *table_name, const char *field_name, struct maat_state *state);

int maat_stream_scan(struct maat_stream *stream, const char *data, int data_len, 
                     uuid_t *results, size_t n_result, size_t *n_hit_result,
                     struct maat_state *state);

void maat_stream_free(struct maat_stream *stream);

/* maat state API */
struct maat_state *maat_state_new(struct maat *instance, int thread_id);

void maat_state_reset(struct maat_state *state);

void maat_state_free(struct maat_state *state);

/**
 * @param rule_uuids:     input rule_uuid array, and also store the result of sorted rule uuids
 * 
 * @retval count of sorted rule_uuids
*/
size_t maat_state_sort_rules(struct maat *maat_inst, const char *table_name, uuid_t *rule_uuids, uuid_t *sorted_rule_uuids, size_t n_rule_uuids);

int maat_state_set_scan_rule_table(struct maat_state *state, const char *rule_table_name);

int maat_state_get_hit_paths(struct maat_state *state, struct maat_hit_path *path_array, 
                             size_t array_size);

int maat_state_get_rule_table_names(struct maat_state *state, uuid_t *rule_ids,
                                    size_t n_rule_ids, char *rule_table_names[]);
                             
/**
 * @brief get the total number of scans after maat_state_new
*/
size_t maat_state_get_scan_count(struct maat_state *state);

/**
 * @brief direct object means object corresponding to item
 * 
 * NOTE: hit objects may be duplicated
 *       
*/
int maat_state_get_direct_hit_objects(struct maat_state *state,
                                     struct maat_hit_object *object_array,
                                     size_t array_size);
size_t maat_state_get_direct_hit_object_cnt(struct maat_state *state);

/**
 * @brief indirect object means superior object
 * 
 * NOTE: hit objects may be duplicated
*/
int maat_state_get_indirect_hit_objects(struct maat_state *state,
                                       struct maat_hit_object *object_array,
                                       size_t array_size);
size_t maat_state_get_indirect_hit_object_cnt(struct maat_state *state);

/**
 * @brief get last scan hit objects(including direct/indirect)
*/
int maat_state_get_last_hit_objects(struct maat_state *state,
                                   struct maat_hit_object *object_array,
                                   size_t array_size);

size_t maat_state_get_last_hit_object_cnt(struct maat_state *state);

#ifdef __cplusplus
}
#endif

#endif

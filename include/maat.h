/*
**********************************************************************************************
*   Maat: Deep Packet Inspection Policy Framework

*   Maat is the Goddess of truth and justice in ancient Egyptian concept.
*	Her feather was the measure that determined whether the souls (considered 
*	to reside in the heart) of the departed would reach the paradise of afterlife
*	successfully.

*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
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
	int item_id;
	int sub_group_id;
	int top_group_id;
	int vtable_id; // 0 is not a virtual table.
	int compile_id;
};

struct maat_hit_object {
    int vtable_id;
    int group_id;
};

enum maat_scan_status {
    MAAT_SCAN_ERR = -1,  //scan error
    MAAT_SCAN_OK,        //scan but not hit(group or compile)
    MAAT_SCAN_HALF_HIT,  //half hit: hit group, not hit compile
    MAAT_SCAN_HIT        //scan hit compile
};

#define	MAX_SERVICE_DEFINE_LEN 128
struct maat_rule {
	int	config_id;
	uint8_t	reserved;
	int	serv_def_len;
	char service_defined[MAX_SERVICE_DEFINE_LEN];
};

struct ip_addr {
    int ip_type;             //4: IPv4, 6: IPv6
    union {
        unsigned int ipv4;   //network order
        unsigned int ipv6[4];
    };
};

typedef void maat_start_callback_t(int update_type, void *u_param);
typedef void maat_update_callback_t(int table_id, const char *table_line, void *u_para);
typedef void maat_finish_callback_t(void *u_para);

typedef void maat_plugin_ex_new_func_t(int table_id, const char *key, const char *table_line, void **ad, long argl, void *argp);
typedef void maat_plugin_ex_free_func_t(int table_id, void **ad, long argl, void *argp);
typedef void maat_plugin_ex_dup_func_t(int table_id, void **to, void **from, long argl, void *argp);

typedef void maat_rule_ex_new_func_t(int idx, const struct maat_rule *rule, const char *srv_def_large,
									 void **ex_data, long argl, void *argp);
typedef void maat_rule_ex_free_func_t(int idx, const struct maat_rule *rule, const char *srv_def_large,
									  void **ex_data, long argl, void *argp);
typedef void maat_rule_ex_dup_func_t(int idx, void **to, void **from, long argl, void *argp);

/* maat_instance options API */
struct maat_options;
struct maat_options *maat_options_new(void);
void maat_options_free(struct maat_options *opts);

int maat_options_set_caller_thread_number(struct maat_options *opts, size_t n_thread);
int maat_options_set_accept_tags(struct maat_options *opts, const char *accept_tags);
int maat_options_set_rule_effect_interval_ms(struct maat_options *opts, int interval_ms);
int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts, int interval_ms);
int maat_options_set_gc_timeout_ms(struct maat_options *opts, int interval_ms);
int maat_options_set_instance_name(struct maat_options *opts, const char *instance_name, size_t name_len);
int maat_options_set_deferred_load_on(struct maat_options *opts);
int maat_options_set_iris(struct maat_options *opts, const char *full_directory, const char *increment_directory);
int maat_options_set_json_file(struct maat_options *opts, const char *json_filename);
int maat_options_set_redis(struct maat_options *opts, const char *redis_ip, uint16_t redis_port, int redis_db);
int maat_options_set_logger(struct maat_options *opts, void *logger);

/* maat_instance API */
struct maat *maat_new(struct maat_options *opts, const char *table_info_path);
void maat_free(struct maat *instance);

/* maat table API */
/* return table_id(>=0) if success,otherwise return -1 */
int maat_table_get_id(struct maat *instance, const char *table_name);
/* return 0 if success, otherwise return -1 */
int maat_table_callback_register(struct maat *instance, int table_id,
								 maat_start_callback_t *start,
								 maat_update_callback_t *update,
								 maat_finish_callback_t *finish,
								 void *u_para);

/* maat compile table API */
int maat_compile_table_ex_schema_register(struct maat *instance, const char *table_name,
                                          maat_rule_ex_new_func_t *new_func,
                                          maat_rule_ex_free_func_t *free_func,
                                          maat_rule_ex_dup_func_t *dup_func,
                                          long argl, void *argp);
void *maat_compile_table_get_ex_data(struct maat *instance, int table_id, int compile_id, size_t idx);

/* maat plugin table API */
int maat_plugin_table_ex_schema_register(struct maat *instance, const char *table_name,
                                         maat_plugin_ex_new_func_t *new_func,
                                         maat_plugin_ex_free_func_t *free_func,
                                         maat_plugin_ex_dup_func_t *dup_func,
                                         long argl, void *argp);
/* returned data is duplicated by dup_func of maat_plugin_table_ex_schema_register, 
   caller is responsible to free the data. */                                     
int maat_ip_plugin_table_get_ex_data(struct maat *instance, const char *table_name,
                                     const struct ip_addr *ip,
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
int maat_scan_flag(struct maat *instance, int table_id, int thread_id,
                   uint64_t flag, int *results, size_t n_result,
                   size_t *n_hit_result, struct maat_state **state);
int maat_scan_integer(struct maat *instance, int table_id, int thread_id,
                      unsigned int intval, int *results, size_t n_result,
                      size_t *n_hit_result, struct maat_state **state);

int maat_scan_ipv4(struct maat *instance, int table_id, int thread_id, 
                   uint32_t ip_addr, int *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state **state);

int maat_scan_ipv6(struct maat *instance, int table_id, int thread_id, 
                   uint8_t *ip_addr, int *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state **state);

int maat_scan_string(struct maat *instance, int table_id, int thread_id,
                     const char *data, size_t data_len, int *results, size_t n_result,
                     size_t *n_hit_result, struct maat_state **state);

struct maat_stream;
struct maat_stream *maat_scan_stream_open(struct maat *instance, int table_id, int thread_id);

int maat_scan_stream(struct maat_stream **stream, int thread_id, const char* data, int data_len, 
                     int results[], size_t *n_result, struct maat_state **state);

void maat_scan_stream_close(struct maat_stream **stream);

/* maat state API */
int maat_state_set_scan_district(struct maat *instance, struct maat_state **state, 
                                 const char *district, size_t district_len);

int maat_state_set_last_scan(struct maat *maat_instance, struct maat_state **state);

int maat_state_set_scan_compile_tables(struct maat *maat_instance, struct maat_state **state, 
                                       const char *compile_table[], size_t n_table);

int maat_state_get_hit_paths(struct maat *instance, struct maat_state **state, 
                             struct maat_hit_path *paths, size_t n_path);

int maat_state_get_hit_objects(struct maat *instance, struct maat_state **state, 
                               struct maat_hit_object *objs, size_t n_obj);

void maat_state_free(struct maat_state **state);

/* return hit object compile_id */
int maat_hit_object_compile_id(struct maat *instance, struct maat_hit_object *obj);

#ifdef __cplusplus
}
#endif

#endif
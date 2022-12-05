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

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdint.h>
#include <netinet/in.h>

/* maat instance handle */
struct maat;

struct maat_rule {
    int rule_id;
};

enum ip_type {
    IP_TYPE_V4,
    IP_TYPE_V6
};

typedef struct ip_data_s {
    enum ip_type type;
    union {
        uint32_t ipv4;
        uint32_t ipv6[4];
    };  
} ip_data_t;

#define	MAAT_RULE_UPDATE_TYPE_FULL	1
#define	MAAT_RULE_UPDATE_TYPE_INC	2

typedef void maat_start_callback_t(int update_type, void *u_param);
typedef void maat_update_callback_t(int table_id, const char *table_line, void *u_para);
typedef void maat_finish_callback_t(void *u_para);

typedef void maat_plugin_ex_new_func_t(int table_id, const char *key, const char *table_line, void **ad, long argl, void *argp);
typedef void maat_plugin_ex_free_func_t(int table_id, void **ad, long argl, void *argp);
typedef void maat_plugin_ex_dup_func_t(int table_id, void **to, void **from, long argl, void *argp);

/* maat_instance options API */
struct maat_options;
struct maat_options* maat_options_new(void);
int maat_options_set_worker_thread_number(struct maat_options *opts, size_t nr_worker_threads);
int maat_options_set_rule_effect_interval_ms(struct maat_options *opts, int interval_ms);
int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts, int interval_ms);
int maat_options_set_gc_timeout_ms(struct maat_options *opts, int interval_ms);
int maat_options_set_instance_name(struct maat_options *opts, const char *instance_name, size_t name_len);
int maat_options_set_deferred_load_on(struct maat_options *opts);
int maat_options_set_iris_full_index_dir(struct maat_options *opts, const char *full_idx_dir);
int maat_options_set_iris_inc_index_dir(struct maat_options *opts, const char *inc_idx_dir);
int maat_options_set_json_file(struct maat_options *opts, const char *json_filename);
int maat_options_set_redis_ip(struct maat_options *opts, const char *redis_ip);
int maat_options_set_redis_port(struct maat_options *opts, uint16_t redis_port);
int maat_options_set_redis_db_index(struct maat_options *opts, int db_index);

/* maat_instance API */
struct maat *maat_new(struct maat_options *opts, const char *table_info_path);
void maat_free(struct maat *instance);

/* maat table API */
int maat_table_get_id(struct maat *instance, const char *table_name);

int maat_table_callback_register(struct maat *instance, int table_id,
								 maat_start_callback_t *start,
								 maat_update_callback_t *update,
								 maat_finish_callback_t *finish,
								 void *u_para);
/* maat plugin table API */
int maat_plugin_table_ex_schema_register(struct maat *instance, int table_id,
                                     maat_plugin_ex_new_func_t *new_func,
                                     maat_plugin_ex_free_func_t *free_func,
                                     maat_plugin_ex_dup_func_t *dup_func,
                                     long argl, void *argp);
                                     
void *maat_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                    const char *key, size_t key_len);
/* maat scan API */
struct maat_state;
int maat_scan_integer(struct maat *instance, int table_id, int thread_id,
                      unsigned int intval, int results[], size_t *n_result,
                      struct maat_state *state);

int maat_scan_ip(struct maat *instance, int table_id, int thread_id, 
                 const ip_data_t *ip, int results[], size_t *n_result, 
                 struct maat_state *state);

int maat_scan_string(struct maat *instance, int table_id, int thread_id,
                     const char *data, size_t data_len, int results[], size_t *n_result,
                     struct maat_state *state);

struct maat_stream;
struct maat_stream *maat_scan_stream_open(struct maat *instance, int table_id, int thread_id);

int maat_scan_stream(struct maat_stream **stream, int thread_id, const char* data, int data_len, 
                     int results[], size_t *n_result, struct maat_state *state);

void maat_scan_stream_close(struct maat_stream **stream);

void maat_state_reset(struct maat_state *state);

#ifdef __cpluscplus
}
#endif

#endif
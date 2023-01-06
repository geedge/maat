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

enum ip_type {
    IP_TYPE_V4,
    IP_TYPE_V6
};

struct maat_hit_path {
    int Nth_scan;
	int item_id;
	int sub_group_id;
	int top_group_id;
	int virtual_table_id; // 0 is not a virtual table.
	int compile_id;
};

struct maat_matched {
    int virtual_table_id;
    int group_id;
};

enum maat_scan_opt
{
	MAAT_SET_SCAN_DISTRICT = 1,		//VALUE is a const char*, SIZE= strlen(string). DEFAULT: no default.
	MAAT_SET_SCAN_LAST_REGION,		//VALUE is NULL, SIZE=0. This option indicates that the follow scan is the last region of current scan combination.
	MAAT_GET_SCAN_HIT_PATH,			//VALUE is struct maat_hit_path*, an array of struct maat_hit_path, SIZE= sizeof(struct maat_hit_path)*N,
									//Maat_get_scan_status returns actual got number.
    MAAT_GET_SCAN_MATCHED           //VALUE is struct maat_matched*, an array of struct maat_matched, SIZE= sizeof(struct maat_matched)*N,                 
};

/* network order */
struct ipv4_2tuple {
    uint32_t sip;
    uint32_t dip;
};

struct ipv6_2tuple {
    uint8_t sip[16];
    uint8_t dip[16];
};

struct addr_2tuple {
    enum ip_type type;
    union {
        struct ipv4_2tuple ipv4;
        struct ipv6_2tuple ipv6;
    };  
};

#define	MAAT_RULE_UPDATE_TYPE_FULL	1
#define	MAAT_RULE_UPDATE_TYPE_INC	2

typedef void maat_start_callback_t(int update_type, void *u_param);
typedef void maat_update_callback_t(int table_id, const char *table_line, void *u_para);
typedef void maat_finish_callback_t(void *u_para);

typedef void maat_plugin_ex_new_func_t(int table_id, const char *key, const char *table_line, void **ad, long argl, void *argp);
typedef void maat_plugin_ex_free_func_t(int table_id, void **ad, long argl, void *argp);
typedef void maat_plugin_ex_dup_func_t(int table_id, void **to, void **from, long argl, void *argp);

typedef void maat_rule_ex_new_func_t(int idx, const struct maat_rule *rule, const char *srv_def_large,
									 void *ex_data, long argl, void *argp);
typedef void maat_rule_ex_free_func_t(int idx, const struct maat_rule *rule, const char *srv_def_large,
									  void *ex_data, long argl, void *argp);
typedef void maat_rule_ex_dup_func_t(int idx, void *to, void *from, long argl, void *argp);

/* maat_instance options API */
struct maat_options;
struct maat_options* maat_options_new(void);
int maat_options_set_caller_thread_number(struct maat_options *opts, size_t n_thread);
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
/* returned data is duplicated by dup_func of maat_plugin_table_ex_schema_register, 
   caller is responsible to free the data. */                                     
void *maat_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                    const char *key, size_t key_len);
/* maat scan API */
struct maat_state;
int maat_scan_integer(struct maat *instance, int table_id, int thread_id,
                      unsigned int intval, int results[], size_t *n_result,
                      struct maat_state **state);

int maat_scan_ip(struct maat *instance, int table_id, int thread_id, 
                 struct addr_2tuple *addr, int results[], size_t *n_result, 
                 struct maat_state **state);

int maat_scan_string(struct maat *instance, int table_id, int thread_id,
                     const char *data, size_t data_len, int results[], size_t *n_result,
                     struct maat_state **state);

struct maat_stream;
struct maat_stream *maat_scan_stream_open(struct maat *instance, int table_id, int thread_id);

int maat_scan_stream(struct maat_stream **stream, int thread_id, const char* data, int data_len, 
                     int results[], size_t *n_result, struct maat_state **state);

void maat_scan_stream_close(struct maat_stream **stream);

/* maat state API */
int maat_state_set(struct maat *instance, struct maat_state **mid, enum maat_scan_opt opt, const void *value, int size);

//return >=0 if success, return -1 when failed;
int maat_state_get(struct maat *instance, struct maat_state **mid, enum maat_scan_opt opt, void *value, int size);

void maat_state_free(struct maat_state **state);

/* return matched compile_id */
int maat_matched_compile_id(struct maat *instance, struct maat_matched *matched);

#ifdef __cpluscplus
}
#endif

#endif
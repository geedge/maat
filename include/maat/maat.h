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

struct ip_data {
    enum ip_type type;
    union {
        uint32_t ipv4;
        uint32_t ipv6[4];
    };  
};

struct maat_options;
struct maat_options* maat_options_new(void);
int maat_options_set_worker_thread_number(struct maat_options *opts, size_t nr_worker_threads);

struct maat *maat_new(struct maat_options options, const char* table_info_path);
void maat_free(struct maat *instance);

int maat_table_get_id(struct maat *instance, const char *table_name);

struct maat_state;
int maat_scan_integer(struct maat *instance, int table_id, int thread_id,
                      unsigned int intval, int results[], size_t *n_result,
                      struct maat_state *state);

int maat_scan_ip(struct maat *instance, int table_id, int thread_id, 
                 const struct ip_data *ip, int results[], size_t *n_result, 
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


#endif
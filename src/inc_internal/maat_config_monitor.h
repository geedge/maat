/*
**********************************************************************************************
*	File: maat_config_monitor.h
*   Description: maat config monitor api
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_CONFIG_MONITOR_H_
#define _MAAT_CONFIG_MONITOR_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include "log/log.h"
#include "maat.h"
#include "maat_utils.h"

void config_monitor_traverse(long long version, const cJSON *json_root,
							void (*start_fn)(long long, int, void *),
							int (*update_fn)(const char *, const char *, void *, enum maat_operation),
							void (*finish_fn)(void *), void *u_param,
							const char *dec_key, struct log_handle *logger);

int load_maat_json_rule_file(struct maat *maat_inst, const char *json_filename, 
                        cJSON *json_root, char *err_str, size_t err_str_sz);
void convert_maat_json_rule(cJSON *json_root, unsigned char *json_buff);

#ifdef __cplusplus
}
#endif

#endif
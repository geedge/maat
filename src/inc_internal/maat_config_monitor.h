/*
**********************************************************************************************
*	File: maat_config_monitor.h
*   Description: maat config monitor api
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_CONFIG_MONITOR_H_
#define _MAAT_CONFIG_MONITOR_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdint.h>

void config_monitor_traverse(long long version, const char *idx_dir,
							void (*start_fn)(long long, int, void *),
							int (*update_fn)(const char *, const char *, void *),
							void (*finish_fn)(void *), void *u_param,
                            struct log_handle *logger);

int load_maat_json_file(struct maat *maat_instance, const char *json_filename, 
                        char *err_str, size_t err_str_sz);

#ifdef __cpluscplus
}
#endif

#endif
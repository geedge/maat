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

#define CONFIG_UPDATE_TYPE_NONE 0
#define CONFIG_UPDATE_TYPE_FULL 1
#define CONFIG_UPDATE_TYPE_INC 2


void config_monitor_traverse(uint64_t version, const char *idx_dir,
							void (*pre_fn)(uint64_t, int, void *),
							int (*update_fn)(const char *, const char *, void *),
							void (*post_fn)(void *),
							void *u_param);

#ifdef __cpluscplus
}
#endif

#endif
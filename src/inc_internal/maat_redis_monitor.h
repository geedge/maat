/*
**********************************************************************************************
*	File: maat_redis_monitor.h
*   Description: maat redis monitor api
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-11-29
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_REDIS_MONITOR_H_
#define _MAAT_REDIS_MONITOR_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "maat_rule.h"

#include <stdint.h>

void redis_monitor_traverse(long long version, struct source_redis_ctx* mr_ctx,
							void (*start_fn)(long long, int, void *),
							int (*update_fn)(const char *, const char *, void *),
							void (*finish_fn)(void *), void *u_param);

#ifdef __cpluscplus
}
#endif

#endif
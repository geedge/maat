/*
**********************************************************************************************
*	File: maat_common.h
*   Description: maat common entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_COMMON_H_
#define _MAAT_COMMON_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stddef.h>

struct maat_options {
    size_t nr_worker_threads;
};

#ifdef __cpluscplus
}
#endif

#endif
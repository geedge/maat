/*
**********************************************************************************************
*	File: maat_ex_data.h
*   Description: ex data
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_EX_DATA_H_
#define _MAAT_EX_DATA_H_

#ifdef __cpluscplus
extern "C"
{
#endif

struct ex_data_runtime;

struct ex_data_runtime *ex_data_runtime_new(void (* data_free)(void *data));

void ex_data_runtime_free(struct ex_data_runtime *ex_data_rt);

#ifdef __cpluscplus
}
#endif

#endif
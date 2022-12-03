/*
**********************************************************************************************
*	File: json2iris.h
*   Description: rule for transform json2iris
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _JSON2IRIS_H_
#define _JSON2IRIS_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "hiredis/hiredis.h"

int json2iris(const char* json_buff, const char* json_filename, const char*compile_tn, 
              const char* group2compile_tn, const char* group2group_tn, redisContext *redis_write_ctx, 
              char* iris_dir_buf, int buf_len, char* encrypt_key, char* encrypt_algo);

#ifdef __cpluscplus
}
#endif

#endif
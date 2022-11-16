/*
**********************************************************************************************
*	File: maat_utils.h
*   Description: maat utils entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_UTILS_H_
#define _MAAT_UTILS_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdlib.h>
#include <stddef.h>

#include "sds/sds.h"

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))

int get_column_pos(sds line, int column_seq, size_t *offset, size_t *len);

#ifdef __cpluscplus
}
#endif

#endif
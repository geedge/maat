/*
**********************************************************************************************
*	File: maat_utils.h
*   Description: maat utils entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _UTILS_H_
#define _UTILS_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdlib.h>

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))

#define FREE(ptr)  \
    {                   \
        if (ptr)        \
        {               \
            free(ptr);  \
            ptr = NULL; \
        }               \
    }

#ifdef __cpluscplus
}
#endif

#endif

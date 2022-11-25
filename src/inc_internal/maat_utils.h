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

#define	TRUE	1
#define	FALSE	0

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

char *maat_strdup(const char *s);

int get_column_pos(const char *line, int column_seq, size_t *offset, size_t *len);

int load_file_to_memory(const char *file_name, unsigned char **pp_out, size_t *out_sz);

char *strtok_r_esc(char *s, const char delim, char **save_ptr);

char *str_unescape_and(char *s);

char *str_unescape(char *s);

#ifdef __cpluscplus
}
#endif

#endif
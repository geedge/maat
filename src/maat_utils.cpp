/*
**********************************************************************************************
*	File: maat_utils.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include "maat_utils.h"

int get_column_pos(sds line, int column_seq, size_t *offset, size_t *len)
{
	const char* seps=" \t";
	char* saveptr=NULL, *subtoken=NULL, *str=NULL;
	sds dup_line = sdsdup(line);
	int i=0, ret=-1;
	for (str = dup_line; ; str = NULL)
	{
		subtoken = strtok_r(str, seps, &saveptr);
		if (subtoken == NULL)
			break;
		if(i==column_seq-1)
		{
			*offset=subtoken-dup_line;
			*len=strlen(subtoken);
			ret=0;
			break;
		}
		i++;
	}
	free(dup_line);
	return ret;
}
/*
**********************************************************************************************
*	File: maat_utils.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "maat_utils.h"

char *maat_strdup(const char *s)
{
	if (NULL == s) {
		return NULL;
	}
    char *d = (char *)malloc(strlen(s) + 1);
	memcpy(d, s, strlen(s) + 1);

	return d;
}

int get_column_pos(const char *line, int column_seq, size_t *offset, size_t *len)
{
	const char *seps=" \t";
	char *saveptr=NULL, *subtoken=NULL, *str=NULL;
	char *dup_line = maat_strdup(line);
	int i = 0, ret = -1;
	for (str = dup_line; ; str = NULL) {
		subtoken = strtok_r(str, seps, &saveptr);
		if (subtoken == NULL)
			break;
		if (i == column_seq - 1) {
			*offset = subtoken - dup_line;
			*len = strlen(subtoken);
			ret = 0;
			break;
		}
		i++;
	}
	free(dup_line);
    
	return ret;
}

int load_file_to_memory(const char *file_name, unsigned char **pp_out, size_t *out_sz)
{
	int ret = 0;
	FILE *fp = NULL;		
	struct stat fstat_buf;
	size_t read_size=0;
	
	ret = stat(file_name, &fstat_buf);
	if (ret != 0) {
		return -1;
	}

	fp = fopen(file_name, "r");
	if (fp == NULL) {
		return -1;
	}

	*out_sz = fstat_buf.st_size;
	*pp_out = (unsigned char *)calloc(1, *out_sz+1);
	read_size = fread(*pp_out, 1, *out_sz, fp);
	if (read_size != *out_sz) {
		free(*pp_out);
		pp_out = NULL;
		return -1;
	}	
	
	fclose(fp);
	fp = NULL;
	return 0;
}

static char *strchr_esc(char *s, const char delim)
{
	char *token = NULL;

	if (NULL == s) {
        return NULL;
    }
	
	for (token = s; *token != '\0'; token++) {
		if (*token == '\\') {
			token++;
			continue;
		}

		if(*token == delim) {
            break;
        }
	}

	if (*token == '\0') { 
		return NULL;
	} else {
		return token;
	}
}

char *strtok_r_esc(char *s, const char delim, char **save_ptr)
{  
    char *token = NULL;  
  
    if (NULL == s) {
        s = *save_ptr; 
    } 
  
    /* Scan leading delimiters.  */
	token = strchr_esc(s,delim);
	if (NULL == token) {
		*save_ptr = token;
		return s;
	}

    /* Find the end of the token.  */  
	*token = '\0';
	token++;
	*save_ptr = token;

    return s;  
} 

char *str_unescape_and(char *s)
{
	size_t i = 0;
    size_t j = 0;

	for (i = 0,j = 0; i < strlen(s); i++) {
		if (s[i] == '\\' && s[i+1] == '&') {
			s[j] = '&';
			i++;
			j++;
		} else {
			s[j] = s[i];
			j++;
		}
	}
	s[j] = '\0';
	return s;
}

char *str_unescape(char *s)
{
	size_t i=0;
    size_t j=0;
	
	for (i = 0, j = 0; i < strlen(s); i++) {
		if (s[i] == '\\') {
			switch (s[i+1]) {
				case '&':
					s[j] = '&';
					break;
				case 'b':
					s[j] = ' ';//space,0x20;
					break;
				case '\\':
					s[j] = '\\';
					break;
				default:
					s[j] = s[i];
					i--;	//undo the followed i++
					break;
			}
			i++;
			j++;
		} else {
			s[j] = s[i];
			j++;
		}
	}
	s[j] = '\0';
	return s;
}

#define MAX_SYSTEM_CMD_LEN	512
int system_cmd_mkdir(const char *path)
{
    char cmd[MAX_SYSTEM_CMD_LEN] = {0};
	snprintf(cmd, sizeof(cmd), "mkdir -p %s", path);
	return system(cmd);
}
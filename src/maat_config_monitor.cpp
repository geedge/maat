/*
**********************************************************************************************
*	File: maat_config_monitor.h
*   Description: maat config monitor api
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

#include "maat_config_monitor.h"
#include "maat_utils.h"

#define CM_MAX_TABLE_NUM 256
#define	MAX_CONFIG_LINE	(1024 * 16)

struct cm_table_info_t
{
	char table_name[NAME_MAX];
	char cfg_path[NAME_MAX];
	int cfg_num;
	char encryp_algorithm[NAME_MAX];
};

/*
	@brief check if rule file updated
	@retval 0 -> CONFIG_UPDATE_TYPE_NONE
			1 -> CONFIG_UPDATE_TYPE_FULL
			2 -> CONFIG_UPDATE_TYPE_INC
*/
int validate_update_happened(uint64_t current_version, const char *idx_dir, char **idx_paths[], size_t *n_idx_paths)
{

}

int cm_read_cfg_index_file(const char* path, struct cm_table_info_t* idx, int size)
{
	int ret = 0;
	int i = 0;
	char line[MAX_CONFIG_LINE];
	struct stat file_info;

	FILE* fp = fopen(path,"r");
	while (!feof(fp)) {
		memset(line, 0, sizeof(line));
		fgets(line, sizeof(line), fp);
		ret=sscanf(line,"%s\t%d\t%s\t%s",idx[i].table_name
								,&(idx[i].cfg_num)
								,idx[i].cfg_path
								,idx[i].encryp_algorithm);
		//jump over empty line
		if (!(ret==3||ret==4)||idx[i].cfg_num==0){
			continue;
		}

		ret = stat(idx[i].cfg_path, &file_info);
		if (ret != 0) {
			//log_error
			fclose(fp);
			return -1;
		}

		i++;
		if (i == size) {
			//log_error
			break;
		}
	}
	fclose(fp);

	return i;
}

const char* path2filename(const char*path)
{
	int i=0;
	for(i=strlen(path);i>0;i--)
	{
		if(path[i]=='/')
		{
			break;
		}
	}
	return path+i+1;
}

char *read_nxt_line_from_buff(const char *buff, size_t buff_size, size_t *offset, char *line, int line_size)
{
	int this_offset=0;
	const char* p;

	//search for CRLF, aka CR '\r'(old Mac), LF '\n'(UNIX) or CRLF"\r\n" (Windows)
	p = (const char*)memchr(buff+*offset, '\n', buff_size-*offset);
	if (p == NULL) { // NOT "\n" or "\r\n"
		p = (const char*)memchr(buff+*offset, '\r', buff_size-*offset);
	}

	if (p != NULL) { //point to next character
		p++;
	} else { //Treat rest buff has no CRLF as a line.
		p = buff + buff_size;
	}

	this_offset = p - (buff + *offset);
	memcpy(line, buff + *offset, MIN(this_offset, line_size-1));

	*offset += this_offset;
	line[MIN(this_offset, line_size - 1)] = '\0';

	return line;
}

int cm_read_table_file(struct cm_table_info_t* index,
						int (*update_fn)(const char *, const char *, void *),
						void* u_param)
{
	int cfg_num = 0,i  =0;
	int ret = 0;
	char error_string[NAME_MAX];
	char line[MAX_CONFIG_LINE]={0};
	char *ret_str=NULL;
	char *table_file_buff=NULL;
	size_t file_sz = 0;
	size_t file_offset = 0;

	ret = load_file_to_memory(index->cfg_path, (unsigned char **)&table_file_buff, &file_sz);
	if (ret < 0) {
		// log_error
		return -1;
	}

	read_nxt_line_from_buff(table_file_buff, file_sz, &file_offset, line, sizeof(line));
	sscanf(line, "%d\n", &cfg_num);

	if(cfg_num != index->cfg_num) {
		//log_error
		return -1;
	}

	for (i = 0; i < cfg_num; i++) {
		line[sizeof(line)-1]='\0';

		ret_str=read_nxt_line_from_buff(table_file_buff, file_sz, &file_offset, line, sizeof(line));
		
		if(ret_str==NULL) {
			//log_error
			break;
		}

		if(line[sizeof(line)-1]!='\0') {
			//log_error
			continue;
		}

		ret = update_fn(index->table_name, line, u_param);
		if (ret<0) {
			break;
		}
	}

	free(table_file_buff);
	
	return 0;
}

void config_monitor_traverse(uint64_t current_version, const char *idx_dir,
							 void (*start_fn)(uint64_t, int, void *),
							 int (*update_fn)(const char *, const char *, void *),
							 void (*finish_fn)(void *),
							 void *u_param)
{
	size_t i = 0;
	uint64_t new_version = 0;
	char **idx_path_array = NULL;
	size_t idx_path_num = 0;
	struct cm_table_info_t table_array[CM_MAX_TABLE_NUM];

	memset(table_array, 0, sizeof(table_array));

	int update_type = validate_update_happened(current_version, idx_dir, &idx_path_array, &idx_path_num);
	if (update_type != CONFIG_UPDATE_TYPE_NONE) {
		for (i = 0; i < idx_path_num; i++) {
			int table_num = cm_read_cfg_index_file(idx_path_array[i], table_array, CM_MAX_TABLE_NUM);
			if (table_num < 0) {
				//log_error
				break;
			}

			char str_not_care[256] = {0};
			const char* table_filename = path2filename(idx_path_array[i]);
			sscanf(table_filename,"%[a-zA-Z]_config_index.%lld", str_not_care, &new_version);
			if (start_fn != NULL) {
				start_fn(new_version, update_type, u_param);
			}

			for (int j = 0; j < table_num; j++) {
				cm_read_table_file(table_array + j, update_fn, u_param);
			}

			if (finish_fn != NULL) {
				finish_fn(u_param);
			}
		}
	}

	for (i = 0; i < idx_path_num; i++) {
		free(idx_path_array[i]);
	}
	
	free(idx_path_array);
}
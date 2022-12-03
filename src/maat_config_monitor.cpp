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
#include <dirent.h>
#include <unistd.h>

#include "utils.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "json2iris.h"
#include "maat_config_monitor.h"

#define CM_MAX_TABLE_NUM 256
#define	MAX_CONFIG_LINE	(1024 * 16)

struct cm_table_info_t
{
	char table_name[NAME_MAX];
	char cfg_path[NAME_MAX];
	int cfg_num;
	char encryp_algorithm[NAME_MAX];
};

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
		if (!(ret == 3 || ret == 4) || idx[i].cfg_num == 0) {
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

const char *path2filename(const char *path)
{
	int i = 0;
	for (i = strlen(path);i > 0;i--) {
		if (path[i]=='/') {
			break;
		}
	}
	return path + i + 1;
}

char *read_nxt_line_from_buff(const char *buff, size_t buff_size, size_t *offset, char *line, int line_size)
{
	int this_offset=0;
	const char* p;

	//search for CRLF, aka CR '\r'(old Mac), LF '\n'(UNIX) or CRLF"\r\n" (Windows)
	p = (const char *)memchr(buff + *offset, '\n', buff_size - *offset);
	if (p == NULL) { // NOT "\n" or "\r\n"
		p = (const char *)memchr(buff + *offset, '\r', buff_size - *offset);
	}

	if (p != NULL) { //point to next character
		p++;
	} else { //Treat rest buff has no CRLF as a line.
		p = buff + buff_size;
	}

	this_offset = p - (buff + *offset);
	memcpy(line, buff + *offset, MIN(this_offset, line_size - 1));

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
		line[sizeof(line) - 1] = '\0';

		ret_str = read_nxt_line_from_buff(table_file_buff, file_sz, &file_offset, line, sizeof(line));
		if (ret_str == NULL) {
			//log_error
			break;
		}

		if(line[sizeof(line) - 1] != '\0') {
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

//replacement of glibc scandir, to adapt dictator malloc wrap
#define	ENLARGE_STEP	1024
int my_scandir(const char *dir, struct dirent ***namelist,
              int(*filter)(const struct dirent *),
              int(*compar)(const void *, const void *))
{
	int n = 0;
	int DIR_ENT_SIZE = ENLARGE_STEP;
	struct dirent entry, *result;

	if ((NULL == dir) || (NULL == namelist)) {
        return -1;
    }

	DIR *od = opendir(dir);
	if (NULL == od) {
        return -1;
    }
    
    struct dirent **list = ALLOC(struct dirent *, DIR_ENT_SIZE);
	while (0 == readdir_r(od, &entry, &result)) {
		if (NULL == result) {
			break;
		}

		if (filter && !filter(&entry)) {
            continue;
        }
		
        struct dirent *p = ALLOC(struct dirent, 1);
		memcpy((void *)p, (void *)(&entry), sizeof(struct dirent));
		list[n] = p;

		n++;
		if (n >= DIR_ENT_SIZE) {
			DIR_ENT_SIZE += ENLARGE_STEP;
			list = (struct dirent **)realloc((void*)list, DIR_ENT_SIZE * sizeof(struct dirent *));
		}
	} 

	closedir(od); 
	*namelist = list;

	if (compar) {
        qsort((void *)*namelist, n, sizeof(struct dirent *), compar); 
    }
	
	return n; 
}

int filter_fn(const struct dirent *ent)
{
    return (strncmp(ent->d_name,"full_config_index",strlen("full_config_index")) == 0 ||
   	        strncmp(ent->d_name,"inc_config_index",strlen("inc_config_index")) == 0);
}

int get_new_idx_path(long long current_version, const char *file_dir, char ***idx_path, size_t *idx_num)
{
	struct dirent **namelist = NULL;
	int update_type = CM_UPDATE_TYPE_NONE;
	
	int n = my_scandir(file_dir, &namelist, filter_fn, (int (*)(const void*, const void*))alphasort);
	if (n < 0) {
		//log_error("scan dir error");
		return update_type;
	}

    long long latest_full_version = 0;
    long long latest_inc_version = 0;
    int full_file_idx = 0;
    int *inc_file_idx = ALLOC(int, n);
	int inc_idx_num = 0;
    int i = 0;
	for (i = 0; i < n; i++) {
		long long config_seq = 0;
        char update_str[32] = {0};
        
		if ((strcmp(namelist[i]->d_name, ".") == 0) || (strcmp(namelist[i]->d_name, "..") == 0)) {
			continue;
		}

		if (strlen(namelist[i]->d_name) > 42) {
			fprintf(stderr, "config file %s filename too long,should like full_config_index.00000000000000000001", 
                            namelist[i]->d_name);
			continue;
		}

		int ret = sscanf(namelist[i]->d_name,"%[a-zA-Z]_config_index.%lld", update_str, &config_seq);
		if (ret != 2) {
			fprintf(stderr, "config file %s filename error,should like full_config_index.00000000000000000001",
                            namelist[i]->d_name);
			continue;
		}

		if (strncasecmp(update_str, "full", strlen(update_str)) == 0) {
			if (config_seq > latest_full_version) {
				latest_full_version = config_seq;
				full_file_idx = i;
			}
		} else if(strncasecmp(update_str,"inc",strlen(update_str))==0) {
			if (config_seq > current_version) {
				inc_file_idx[inc_idx_num] = i;
				inc_idx_num++;
				if (config_seq > latest_inc_version) {
					latest_inc_version = config_seq;
				}
			}
		} else {
			fprintf(stderr, "config file %s,not full or inc config", namelist[i]->d_name);
		}
	}

    size_t path_len = 0;
	//full update
	if (latest_full_version > current_version) {
        *idx_path = (char **)malloc(sizeof(char **));
		path_len = strlen(file_dir) + strlen(namelist[full_file_idx]->d_name) + 1 + 1;
		(*idx_path)[0] = (char *)malloc(path_len);
		snprintf((*idx_path)[0], path_len, "%s/%s", file_dir, namelist[full_file_idx]->d_name);
		*idx_num = 1;
		update_type = CM_UPDATE_TYPE_FULL;
	} else if (latest_inc_version > current_version) {
		//inc update,it's possible that do inc after full update in this function,but we'll process it at next loop.
		*idx_path = (char **)malloc(sizeof(char **) * inc_idx_num);
		for (i = 0; i < inc_idx_num; i++) {
			path_len = strlen(file_dir) + strlen(namelist[inc_file_idx[i]]->d_name) + 1 + 1;
			(*idx_path)[i] = (char *)malloc(path_len);
			snprintf((*idx_path)[i], path_len, "%s/%s", file_dir, namelist[inc_file_idx[i]]->d_name);
		}
		*idx_num = inc_idx_num;
		update_type = CM_UPDATE_TYPE_INC;
	} else {
		update_type = CM_UPDATE_TYPE_NONE;
	}

	free(inc_file_idx);
	for (i = 0; i < n; i++) {
		free(namelist[i]);
	}
	free(namelist);

	return update_type;
}

void config_monitor_traverse(long long current_version, const char *idx_dir,
							 void (*start_fn)(long long, int, void *),
							 int (*update_fn)(const char *, const char *, void *),
							 void (*finish_fn)(void *),
							 void *u_param)
{
	size_t i = 0;
	long long new_version = 0;
	char **idx_path_array = NULL;
	size_t idx_path_num = 0;
	struct cm_table_info_t table_array[CM_MAX_TABLE_NUM];

	memset(table_array, 0, sizeof(table_array));

	int update_type = get_new_idx_path(current_version, idx_dir, &idx_path_array, &idx_path_num);
	if (update_type != CM_UPDATE_TYPE_NONE) {
		for (i = 0; i < idx_path_num; i++) {
			int table_num = cm_read_cfg_index_file(idx_path_array[i], table_array, CM_MAX_TABLE_NUM);
			if (table_num < 0) {
				fprintf(stderr, "load %s failed, abandon udpate.", idx_path_array[i]);
				break;
			}

			char str_not_care[256] = {0};
			const char *table_filename = path2filename(idx_path_array[i]);
			sscanf(table_filename, "%[a-zA-Z]_config_index.%lld", str_not_care, &new_version);
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

int load_maat_json_file(struct maat *maat_instance, const char *json_filename, char *err_str, size_t err_str_sz)
{
	int ret = 0;
	struct stat fstat_buf;
	unsigned char *json_buff = NULL; 
    unsigned char *decrypted_buff = NULL; 
    unsigned char *uncompressed_buff = NULL;
	size_t json_buff_sz = 0;
    size_t decrypted_buff_sz = 0; 
    size_t uncompressed_buff_sz = 0;

	fprintf(stdout, "Maat initial with JSON file %s, formating..", json_filename);

	if (strlen(maat_instance->decrypt_key) && strlen(maat_instance->decrypt_algo)) {
		ret = decrypt_open(json_filename, maat_instance->decrypt_key, maat_instance->decrypt_algo, 
                            (unsigned char **)&decrypted_buff, &decrypted_buff_sz, err_str, err_str_sz);
		if (ret < 0) {
			fprintf(stderr, "Decrypt Maat JSON file %s failed.", json_filename);
			return -1;
		}

		json_buff=decrypted_buff;
		json_buff_sz=decrypted_buff_sz;
	}
    
	if (maat_instance->maat_json_is_gzipped) {
		ret = gzip_uncompress(json_buff, json_buff_sz, &uncompressed_buff, &uncompressed_buff_sz);
		free(json_buff);
		if (ret < 0) {
			fprintf(stderr, "Uncompress Maat JSON file %s failed.", json_filename);
			return -1;
		}

		json_buff = uncompressed_buff;
		json_buff_sz = uncompressed_buff_sz;
	}

    //decryption failed or no decryption
	if (NULL == json_buff) {	
		ret = load_file_to_memory(json_filename, &json_buff, &json_buff_sz);
		if (ret < 0) {
			fprintf(stderr, "Read Maat JSON file %s failed.", json_filename);
			return -1;
		}
	}

	ret = json2iris((const char*)json_buff, json_filename,
			maat_instance->compile_tn, maat_instance->group2compile_tn, maat_instance->group2group_tn,
			NULL,
			maat_instance->json_ctx.iris_file,
			sizeof(maat_instance->json_ctx.iris_file),
			strlen(maat_instance->decrypt_key) ? maat_instance->decrypt_key : NULL,
			strlen(maat_instance->decrypt_algo) ? maat_instance->decrypt_algo : NULL);

	free(json_buff);
	json_buff = NULL;
	if (ret < 0) {
		return -1;
	}

	if (!maat_instance->is_running) {
		strncpy(maat_instance->json_ctx.json_file, json_filename, sizeof(maat_instance->json_ctx.json_file));
	}
	
	ret=stat(json_filename, &fstat_buf);
	maat_instance->json_ctx.last_md5_time = fstat_buf.st_ctim;
	
	md5_file(maat_instance->json_ctx.json_file, maat_instance->json_ctx.effective_json_md5);
	fprintf(stdout, "JSON file %s md5: %s, generate index file %s OK.",
					maat_instance->json_ctx.json_file,
					maat_instance->json_ctx.effective_json_md5,
					maat_instance->json_ctx.iris_file);
	maat_instance->input_mode = DATA_SOURCE_JSON_FILE;

	return 0;	
}
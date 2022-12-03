#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "cJSON/cJSON.h"
#include "maat_config_monitor.h"
#include "json2iris.h"
#include "hiredis/hiredis.h"

const char *redis_dump_dir = "./redis_dump";
const char *default_table_info = "./table_info.conf";

void maat_tool_print_usage(void)
{
	printf("maat_redis_tool manipulate rules from redis.\n");
	printf("Usage:\n");
	printf("\t-h [host], redis IP, 127.0.0.1 as default.\n");
	printf("\t-p [port], redis port, 6379 as default.\n");
	printf("\t-n [db], redis db, 0 as default.\n");
	printf("\t-d [dir], dump rules from redis to [dir], %s as default.\n",redis_dump_dir);
	printf("\t-v [version], dump specific [version] from redis, dump latest version as default.\n");
	printf("\t-j [payload.json], add or delete rules as maat json. Must have field compile_table field, and plugin table's valid flag must be in the last column.\n");
	printf("\t-t [timeout], timeout config after t seconds, default is 0 which means never timeout.\n");	
	printf("example: ./maat_redis_tool -h 127.0.0.1 -p 6379 -d %s\n",redis_dump_dir);
	printf("	./maat_redis_tool -h 127.0.0.1 -p 6379 -j payload.json -t 300\n");
}

static int compare_serial_rule(const void *a, const void *b)
{
	struct serial_rule *ra=(struct serial_rule *)a;
	struct serial_rule *rb=(struct serial_rule *)b;

	int ret = strcmp(ra->table_name, rb->table_name);
	if (0 == ret) {
		ret = ra->rule_id - rb->rule_id;
	}

	return ret;
}

int set_file_rulenum(const char *path, int rule_num)
{
	FILE* fp=NULL;
	if (0 == rule_num) {
		fp = fopen(path, "w");
	} else {
		fp = fopen(path, "r+");
	}

	if (NULL == fp) {
		fprintf(stderr, "fopen %s failed %s at set rule num.", path, strerror(errno));
		return -1;
	}

	fprintf(fp, "%010d\n", rule_num);
	fclose(fp);

	return 0;
}

void read_rule_from_redis(redisContext *c, long long desire_version, const char* output_path)
{
	struct serial_rule *rule_list;
	int line_count=0;
	int i=0,ret=0;
	int update_type = CM_UPDATE_TYPE_INC;
	long long version=0;
	const char* cur_table=NULL;
    char foreign_files_dir[256] = {0};
	char table_path[256],index_path[256];
	FILE *table_fp=NULL, *index_fp=NULL;

	int rule_num = maat_cmd_get_rm_key_list(c, 0, desire_version, &version, NULL, &rule_list, &update_type, 0);
	if (0 == rule_num) {
		if (desire_version != 0) {
			printf("Read desired version %lld failed.\n", desire_version);
		} else {
			printf("No Effective Rules.\n");
		}
		return;
	}

	if (rule_num < 0) {
		printf("Read Redis Error.\n");
		return;
	}

	assert(update_type == CM_UPDATE_TYPE_FULL);
	printf("MAAT Version: %lld, key number: %d\n", version, rule_num);
	if (0 == rule_num) {
		goto clean_up;
	}

	printf("Reading value: \n");
	ret = maat_cmd_get_redis_value(c, rule_list, rule_num, 1);
	if (ret < 0) {
		goto clean_up;
	}

	printf("Sorting.\n");
	qsort(rule_list, rule_num, sizeof(struct serial_rule), compare_serial_rule);
	if ((access(output_path, F_OK)) <0) {	
        if ((mkdir(output_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) < 0) {
            printf("mkdir %s error\n", output_path);
        }
	}

	snprintf(foreign_files_dir, sizeof(foreign_files_dir), "%s/foreign_files/",output_path);

	if ((access(foreign_files_dir, F_OK)) <0) {	
        if((mkdir(foreign_files_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) < 0) {
            printf("mkdir %s error\n", foreign_files_dir);
        }
	}

	ret = maat_cmd_get_foreign_keys_by_prefix(c, rule_list, rule_num, foreign_files_dir);
	if (ret > 0) {
		printf("%d lines has foreign content.\n", ret);
		maat_cmd_get_foreign_conts(c, rule_list, rule_num, 1);
	}

	snprintf(index_path,sizeof(index_path),"%s/full_config_index.%020lld",output_path,version);
	index_fp = fopen(index_path, "w");
	if (NULL == index_fp) {
		printf("Open %s failed.\n",index_path);
		goto clean_up;
	}

	for (i = 0; i < rule_num; i++) {
		if (rule_list[i].n_foreign > 0) {
			maat_cmd_rewrite_table_line_with_foreign(rule_list+i);
		}

		if (NULL == cur_table || 0 != strcmp(cur_table,rule_list[i].table_name)) {
			if (table_fp != NULL) {
				fprintf(index_fp, "%s\t%d\t%s\n", cur_table, line_count, table_path);
				fclose(table_fp);
				table_fp = NULL;
				set_file_rulenum(table_path, line_count);
				line_count = 0;
				printf("Written table %s\n",table_path);
			}

			snprintf(table_path, sizeof(table_path), "%s/%s.%020lld", output_path, 
                                                     rule_list[i].table_name, version);
			set_file_rulenum(table_path, 0);

			table_fp = fopen(table_path, "a");
			if (NULL == table_fp) {
				printf("Open %s failed.\n", table_path);
				goto clean_up;
			}
			
			cur_table = rule_list[i].table_name;
		}
		fprintf(table_fp, "%s\tkey=%ld\n", rule_list[i].table_line, rule_list[i].rule_id);
		line_count++;
	}

	fclose(table_fp);
	table_fp = NULL;

	fprintf(index_fp, "%s\t%d\t%s\n", cur_table, line_count, table_path);
	set_file_rulenum(table_path, line_count);
	printf("Written table %s\n", table_path);
	printf("Written complete: %s\n", index_path);

clean_up:
	for (i = 0; i < rule_num; i++) {
		maat_cmd_empty_serial_rule(rule_list+i);
	}

	free(rule_list);
	rule_list = NULL;

	if (c != NULL) {
		redisFree(c);
	}

	if (index_fp != NULL) {
		fclose(index_fp);
	}

	if (table_fp != NULL) {
		fclose(table_fp);
	}
}

int count_line_num(const char *table_name,const char *line, void *u_para)
{
	(*((unsigned int *)u_para))++;
	return 0;
}

int line_idx = 0;
long long absolute_expire_time=0;
int make_serial_rule(const char *table_name, const char *line,void *u_para)
{
	struct serial_rule *s_rule=(struct serial_rule *)u_para;
	int rule_id=0,is_valid=0;
	char *buff = ALLOC(char, strlen(line) + 1);
    
    memcpy(buff, line, strlen(line) + 1);

	while (buff[strlen(buff) - 1] == '\n' || buff[strlen(buff) - 1] == '\t') {
		buff[strlen(buff) - 1] = '\0';
	}

    int j = 0;
    char *str1 = NULL;
    char *token = NULL;
    char *saveptr1 = NULL;
    char *last1 =NULL;
	for (j = 0,str1 = buff; ; j++, str1 = NULL) {
		 token = strtok_r(str1, "\t ", &saveptr1);
		 if (token == NULL)
			 break;
		 if(j==0)
		 {
			sscanf(token,"%d",&rule_id);
		 }
		 last1=token;
 	 }
	sscanf(last1,"%d",&is_valid);
	
	memcpy(buff,line, strlen(line)+1);
	while(buff[strlen(buff)-1]=='\n'||buff[strlen(buff)-1]=='\t')
	{
		buff[strlen(buff)-1]='\0';
	}
	//printf("Writing table %s, rule_id=%d, timeout=%lld, is_valid=%d\n", table_name, rule_id,absolute_expire_time,is_valid);
	maat_cmd_set_serial_rule(s_rule + line_idx, (enum maat_operation)is_valid, rule_id, table_name, buff, absolute_expire_time);
	line_idx++;
	free(str1);

	return 0;
}

#define	WORK_MODE_DUMP	0
#define WORK_MODE_JSON	1
int main(int argc, char * argv[])
{
	int oc=0,ret=0;
	int model=0;
	char redis_ip[64];
	int redis_port=6379;
	int redis_db=0;
	strncpy(redis_ip, "127.0.0.1", sizeof(redis_ip));
	char dump_dir[128], json_file[128], tmp_iris_path[128];
	strncpy(dump_dir,redis_dump_dir,sizeof(dump_dir));
	redisContext * ctx=NULL;
	unsigned int total_line_cnt=0, success_cnt=0, i=0;
	int timeout=0;
	FILE* json_fp=NULL;
	cJSON *json=NULL, *tmp_obj=NULL;
	struct stat fstat_buf;
	unsigned long json_file_size=0,read_size=0;
	long long desired_version=0;
	char* json_buff=NULL;
	size_t json_buff_sz=0;
    char compile_table_name[128] = {0};

	while ((oc = getopt(argc,argv,"h:p:n:d:v:f:j:t:")) != -1) {
		switch (oc) {
			case 'h':
				strncpy(redis_ip, optarg, sizeof(redis_ip));
				break;
			case 'p':
				sscanf(optarg, "%d", &redis_port);
				break;
			case 'n':
				sscanf(optarg, "%d", &redis_db);
				break;
			case 'd':
				model = WORK_MODE_DUMP;
				strncpy(dump_dir, optarg, sizeof(dump_dir));
				if (dump_dir[strlen(dump_dir)-1] == '/') {
					dump_dir[strlen(dump_dir)-1] = '\0';
				}
				break;
			case 'v':
				sscanf(optarg, "%lld", &desired_version);
				break;
			case 'j':
				strncpy(json_file, optarg, sizeof(json_file));
				model = WORK_MODE_JSON;
				ret = stat(json_file, &fstat_buf);
				if (ret != 0) {
					printf("fstat file %s error.\n", json_file);
					return -1;
				}

				json_fp = fopen(json_file, "r");
				if (NULL == json_fp) {
					printf("fopen file %s error %s.\n", json_file, strerror(errno));
					return -1;
				}

				json_file_size = fstat_buf.st_size;
				json_buff = ALLOC(char, json_file_size);
				read_size = fread(json_buff, 1, json_file_size, json_fp);
				if (read_size != json_file_size) {
					printf("fread file %s error.\n", json_file);
					return -1;
				}

				json = cJSON_Parse(json_buff);
				if (!json) {
					printf("%s format is error before: %-200.200s\n", json_file, cJSON_GetErrorPtr());
					return -1;
				}

				tmp_obj=cJSON_GetObjectItem(json, "compile_table");
				if (NULL == tmp_obj) {
					printf("No \"compile_table\" in %s.\n",json_file);
					return -1;
				}
				strncpy(compile_table_name, tmp_obj->valuestring, sizeof(compile_table_name));
				free(json_buff);
				cJSON_Delete(json);
				fclose(json_fp);
				break;
			case 't':
				sscanf(optarg,"%d",&timeout);
				break;
			case '?':
			default:
				maat_tool_print_usage();
				return 0;
				break;
		}
	}

	ctx = maat_cmd_connect_redis(redis_ip, redis_port, redis_db);
	if (NULL == ctx) {
		return -1;
	}

	if (model == WORK_MODE_DUMP) {
		printf("Reading key list from %s:%d db%d.\n", redis_ip, redis_port, redis_db);
		read_rule_from_redis(ctx, desired_version, dump_dir);
	} else if(model == WORK_MODE_JSON) {
		ret = load_file_to_memory(json_file, (unsigned char**)&json_buff, &json_buff_sz);
		if (ret < 0) {
			printf("open %s failed.\n", json_file);
		}

		ret = json2iris(json_buff, json_file, NULL, NULL, NULL, ctx, tmp_iris_path, sizeof(tmp_iris_path), NULL, NULL);
		if (ret < 0) {
			printf("Invalid json format.\n");
		}

		total_line_cnt = 0;
		config_monitor_traverse(0, tmp_iris_path, NULL, count_line_num, NULL, &total_line_cnt);
		printf("Serialize %s to %d lines, write temp file to %s .\n",json_file, total_line_cnt, tmp_iris_path);

		struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
		long long server_time = maat_cmd_redis_server_time_s(ctx);
		if (!server_time) {
			printf("Get Redis Time failed.\n");
		}

		if (timeout > 0) {
			absolute_expire_time = server_time + timeout;
		}

		config_monitor_traverse(0, tmp_iris_path, NULL, make_serial_rule, NULL, s_rule);
		printf("Timeout = %lld\n", absolute_expire_time);

		ret = 0;
		do {
			success_cnt = maat_cmd_exec_serial_rule(ctx, s_rule, total_line_cnt, server_time);
		} while(success_cnt < 0);

		if (success_cnt != total_line_cnt) {
			printf("Only Add %d of %d, rule id maybe conflicts.\n", success_cnt, total_line_cnt);
		}

		for (i = 0; i < total_line_cnt; i++) {
			maat_cmd_empty_serial_rule(s_rule+i);
		}
		free(s_rule);	
		redisFree(ctx);
	}

	return 0;
}
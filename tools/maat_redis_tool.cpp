#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "cJSON/cJSON.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "json2iris.h"
#include "hiredis/hiredis.h"

#define MODULE_REDIS_TOOL	 module_name_str("maat.redis_tool")

const char *redis_dump_dir = "./redis_dump";
const char *default_table_info = "./table_info.conf";

void maat_tool_print_usage(void)
{
	printf("maat_redis_tool manipulate rules from redis.\n");
	printf("Usage:\n");
	printf("\t-h [host], redis IP, 127.0.0.1 as default.\n");
	printf("\t-p [port], redis port, 6379 as default.\n");
	printf("\t-n [db], redis db, 0 as default.\n");
	printf("\t-d [dir], dump rules from redis to [dir], %s as default.\n", redis_dump_dir);
    printf("\t-u [json_file], flush redis and upload all rules to redis, confirm the risk before proceeding\n");
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
		fprintf(stderr, "fopen %s failed %s at set rule num\n", path, strerror(errno));
		return -1;
	}

	fprintf(fp, "%010d\n", rule_num);
	fclose(fp);

	return 0;
}

void read_rule_from_redis(redisContext *c, const char *output_path, struct log_handle *logger)
{
	int i = 0;
    int ret = 0;
    int line_count = 0;
	int update_type = MAAT_UPDATE_TYPE_INC;
	long long version = 0;
	const char *cur_table = NULL;
    char foreign_files_dir[NAME_MAX] = {0};
	char table_path[PATH_MAX] = {0};
    char index_path[PATH_MAX] = {0};
	FILE *table_fp = NULL; 
    FILE *index_fp = NULL;
    struct serial_rule *rule_list = NULL;

	int rule_num = maat_get_rm_key_list(c, 0, &version, NULL, &rule_list, &update_type, 0, logger);
	if (0 == rule_num) {
		printf("No Effective Rules.\n");
		return;
	}

	if (rule_num < 0) {
		printf("Read Redis Error.\n");
		return;
	}

	assert(update_type == MAAT_UPDATE_TYPE_FULL);
	printf("MAAT Version: %lld, key number: %d\n", version, rule_num);
	if (0 == rule_num) {
		goto clean_up;
	}

	printf("Reading value: \n");
	ret = maat_get_redis_value(c, rule_list, rule_num, 1, logger);
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

	ret = maat_get_foreign_keys_by_prefix(c, rule_list, rule_num, foreign_files_dir, logger);
	if (ret > 0) {
		printf("%d lines has foreign content.\n", ret);
		maat_get_foreign_conts(c, rule_list, rule_num, 1, NULL);
	}

	snprintf(index_path,sizeof(index_path), "%s/full_config_index.%020lld", output_path, version);
	index_fp = fopen(index_path, "w");
	if (NULL == index_fp) {
		printf("Open %s failed.\n", index_path);
		goto clean_up;
	}

	for (i = 0; i < rule_num; i++) {
		if (rule_list[i].n_foreign > 0) {
			maat_rewrite_table_line_with_foreign(rule_list+i);
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

        size_t line_len = strlen(rule_list[i].table_line);
        if (rule_list[i].table_line[line_len - 1] == '\n') {
            rule_list[i].table_line[line_len - 1] = '\0';
        }
        
		fprintf(table_fp, "%s\tkey=%lld\n", rule_list[i].table_line, rule_list[i].rule_id);
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
		maat_clear_rule_cache(rule_list+i);
	}

	FREE(rule_list);

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

int count_line_num_cb(const char *table_name, const char *line, void *u_para)
{
	(*((unsigned int *)u_para))++;
	return 0;
}

int line_idx = 0;
int make_serial_rule(const char *table_name, const char *line, void *u_para)
{
	struct serial_rule *s_rule=(struct serial_rule *)u_para;
    redisContext *ctx = s_rule->ref_ctx;
    long long absolute_expire_time = s_rule->timeout;
	char *buff = ALLOC(char, strlen(line) + 1);

    memcpy(buff, line, strlen(line) + 1);
	while(buff[strlen(line) - 1] == '\n' || buff[strlen(line) - 1] == '\t') {
		buff[strlen(line) - 1] = '\0';
	}
	
    const char *redis_rule_key = "TEST_RULE_KEY";
    redisReply *reply = maat_wrap_redis_command(ctx, "INCRBY %s %d", redis_rule_key, 1);
	if (reply->type == REDIS_REPLY_NIL) {
		printf("incrby redis_rule_key:%s failed.", redis_rule_key);
        return -1;
	} else {
		s_rule->rule_id = maat_read_redis_integer(reply);
		freeReplyObject(reply);
		reply = NULL;
	}

	maat_set_serial_rule(s_rule + line_idx, MAAT_OP_ADD, s_rule->rule_id, table_name, 
                         buff, absolute_expire_time);
    (s_rule + line_idx)->ref_ctx = ctx;
	line_idx++;
    FREE(buff);

	return 0;
}

int write_config_to_redis(redisContext *c, char *json_filename, struct log_handle *logger)
{
    char tmp_iris_path[128] = {0};
    char *json_buff = NULL;
    size_t json_buff_sz = 0;

    snprintf(tmp_iris_path, sizeof(tmp_iris_path), "%s_iris_tmp", json_filename);

    int ret = load_file_to_memory(json_filename, (unsigned char **)&json_buff, &json_buff_sz);
    if (ret < 0) {
        return -1;
    }

    ret = json2iris(json_buff, json_filename, c, tmp_iris_path, sizeof(tmp_iris_path), NULL, NULL, logger);
    FREE(json_buff);
    if (ret < 0) {
        return -1;
    }

    size_t total_line_cnt = 0;
    config_monitor_traverse(0, tmp_iris_path, NULL, count_line_num_cb, NULL, &total_line_cnt, NULL, logger);

    struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
    s_rule->ref_ctx = c;
    long long server_time = maat_redis_server_time_s(c);
    if (server_time < 0) {
        return -1;
    }

    s_rule->timeout = server_time + 300;
    config_monitor_traverse(0, tmp_iris_path, NULL, make_serial_rule, NULL, s_rule, NULL, logger);
    s_rule->ref_ctx = NULL;
    line_idx = 0;

    int success_cnt = 0;
    do {
        success_cnt = maat_cmd_write_rule(c, s_rule, total_line_cnt, server_time, logger);
    } while (success_cnt < 0);

    assert(success_cnt == (int)total_line_cnt);

    for (size_t i = 0; i < total_line_cnt; i++) {
        maat_clear_rule_cache(s_rule + i);
    }

    FREE(s_rule);
    
    return 0;
}

int rollback_redis_version(redisContext *c, struct log_handle *logger)
{
    redisReply *reply = maat_wrap_redis_command(c, "SET MAAT_VERSION 0");
    if (NULL == reply) {
        log_fatal(logger, MODULE_REDIS_TOOL, 
                  "[%s:%d] set MAAT_VERSION failed, Redis Communication error: %s", 
                  __FUNCTION__, __LINE__, c->errstr);
        return -1;
    }
    freeReplyObject(reply);
    reply = NULL;

    return 0;
}

int clear_config_in_redis(redisContext *c, struct log_handle *logger)
{
    long long redis_version = 0;
    redisReply *reply = maat_wrap_redis_command(c, "GET MAAT_VERSION");
    if (reply != NULL) {
		if (reply->type == REDIS_REPLY_NIL || reply->type == REDIS_REPLY_ERROR) {
			log_fatal(logger, MODULE_REDIS_TOOL, 
                      "[%s:%d] GET MAAT_VERSION failed, maybe Redis is busy",
                      __FUNCTION__, __LINE__);
			freeReplyObject(reply);
			reply = NULL;
			return -1;
		}
	} else {
		log_fatal(logger, MODULE_REDIS_TOOL, 
                  "[%s:%d] GET MAAT_VERSION failed with NULL reply, error: %s",
                  __FUNCTION__, __LINE__, c->errstr);
		return -1;
	}

    redis_version = maat_read_redis_integer(reply);
	if (redis_version < 0) {
		if (reply->type == REDIS_REPLY_ERROR) {
			log_fatal(logger, MODULE_REDIS_TOOL, 
                      "[%s:%d] Redis Communication error: %s", 
                      __FUNCTION__, __LINE__, reply->str);
		}
        freeReplyObject(reply);
	    reply = NULL;
		return -1;
	}

	freeReplyObject(reply);
	reply = NULL;

    reply = maat_wrap_redis_command(c, "MULTI");
	freeReplyObject(reply);
	reply = NULL;
	
    int append_cmd_cnt = 0;
	redisAppendCommand(c, "FLUSHDB");
	append_cmd_cnt++;
	redisAppendCommand(c, "SET MAAT_VERSION %lld", redis_version);
	append_cmd_cnt++;
	redisAppendCommand(c, "SET MAAT_PRE_VER %lld", redis_version);
	append_cmd_cnt++;
	redisAppendCommand(c, "SET %s 1", mr_region_id_var);
	append_cmd_cnt++;
	redisAppendCommand(c, "SET %s 1", mr_group_id_var);
	append_cmd_cnt++;
	redisAppendCommand(c, "EXEC");
	append_cmd_cnt++;

    int redis_transaction_success = 1;
    for (int i = 0; i < append_cmd_cnt; i++) {
		int ret = maat_wrap_redis_get_reply(c, &reply);
		if (ret == REDIS_OK) {
			if (reply->type == REDIS_REPLY_NIL) {
				redis_transaction_success = 0;
			}
			freeReplyObject(reply);
			reply = NULL;
		}
	}

    if (0 == redis_transaction_success) {
		return -1;
	}

    return 0;
}

#define	WORK_MODE_DUMP	0
#define WORK_MODE_JSON	1
#define WORK_MODE_UPLOAD 2

int main(int argc, char * argv[])
{
	int oc = 0;
	int mode = 0;
	char redis_ip[64] = {0};
	int redis_port = 6379;
	int redis_db = 0;
    char dump_dir[128] = {0};
    char json_file[128] = {0};
    char upload_file[128] = {0};
    char log_path[128] = "./maat_redis_tool.log";
    int timeout = 0;

	strncpy(redis_ip, "127.0.0.1", sizeof(redis_ip));
	strncpy(dump_dir, redis_dump_dir, sizeof(dump_dir));
	struct log_handle *logger = log_handle_create(log_path, 0);

	while ((oc = getopt(argc,argv,"h:p:n:d:f:j:t:u:")) != -1) {
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
				mode = WORK_MODE_DUMP;
				strncpy(dump_dir, optarg, sizeof(dump_dir));
				if (dump_dir[strlen(dump_dir)-1] == '/') {
					dump_dir[strlen(dump_dir)-1] = '\0';
				}
				break;
			case 'j':
				strncpy(json_file, optarg, sizeof(json_file));
				mode = WORK_MODE_JSON;
				break;
			case 't':
				sscanf(optarg,"%d", &timeout);
				break;
            case 'u':
                strncpy(upload_file, optarg, sizeof(upload_file));
                mode = WORK_MODE_UPLOAD;
                break;
			case '?':
			default:
				maat_tool_print_usage();
				return 0;
				break;
		}
	}

	redisContext *c = maat_connect_redis(redis_ip, redis_port, redis_db, logger);
	if (NULL == c) {
		return -1;
	}

    char tmp_iris_path[128] = {0};
	if (mode == WORK_MODE_DUMP) {
		log_info(logger, MODULE_REDIS_TOOL, "Reading key list from %s:%d db%d.", 
                 redis_ip, redis_port, redis_db);
		read_rule_from_redis(c, dump_dir, logger);
	} else if(mode == WORK_MODE_JSON) {
        char *json_buff = NULL;
        size_t json_buff_sz = 0;
		int ret = load_file_to_memory(json_file, (unsigned char**)&json_buff, &json_buff_sz);
		if (ret < 0) {
			log_fatal(logger, MODULE_REDIS_TOOL, "open file:%s failed.", json_file);
            return -1;
		}

		ret = json2iris(json_buff, json_file, c, tmp_iris_path, sizeof(tmp_iris_path), NULL, NULL, logger);
		FREE(json_buff);
        if (ret < 0) {
			log_fatal(logger, MODULE_REDIS_TOOL, "Invalid json format.");
            return -1;
		}

		size_t total_line_cnt = 0;
		config_monitor_traverse(0, tmp_iris_path, NULL, count_line_num_cb, NULL, &total_line_cnt, NULL, logger);
		log_fatal(logger, MODULE_REDIS_TOOL, "Serialize %s to %zu lines, write temp file to %s .", 
                  json_file, total_line_cnt, tmp_iris_path);

		struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
        s_rule->ref_ctx = c;
		long long server_time = maat_redis_server_time_s(c);
		if (!server_time) {
			log_fatal(logger, MODULE_REDIS_TOOL, "Get Redis Time failed.");
            FREE(s_rule);
            return -1;
		}

		if (timeout > 0) {
			s_rule->timeout = server_time + timeout;
		}
        log_info(logger, MODULE_REDIS_TOOL, "Timeout = %lld\n", s_rule->timeout);
        config_monitor_traverse(0, tmp_iris_path, NULL, make_serial_rule, NULL, s_rule, NULL, logger);
        s_rule->ref_ctx = NULL;

        int success_cnt = 0;
		do {
			success_cnt = maat_cmd_write_rule(c, s_rule, total_line_cnt, server_time, logger);
		} while(success_cnt < 0);

		if (success_cnt != (int)total_line_cnt) {
			log_fatal(logger, MODULE_REDIS_TOOL, "Only Add %d of %zu, rule id maybe conflicts.", 
                      success_cnt, total_line_cnt);
		}

		for (size_t i = 0; i < total_line_cnt; i++) {
			maat_clear_rule_cache(s_rule+i);
		}
		FREE(s_rule);	
		redisFree(c);
	} else if (mode == WORK_MODE_UPLOAD) {
        int ret = clear_config_in_redis(c, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_REDIS_TOOL, "clear config in redis failed.");
            return -1;
        }

        ret = write_config_to_redis(c, upload_file, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_REDIS_TOOL, "write config to redis failed.");
            return -1;
        }

        ret = rollback_redis_version(c, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_REDIS_TOOL, "rollback redis version failed.");
            return -1;
        }
        redisFree(c);
    }

	return 0;
}
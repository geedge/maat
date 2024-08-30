#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "maat_core.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "cJSON/cJSON.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "json2iris.h"
#include "../test/test_utils.h"
#include "hiredis/hiredis.h"

#define MODULE_REDIS_TOOL	 module_name_str("maat.redis_tool")

#define	WORK_MODE_DUMP	0
#define WORK_MODE_UPLOAD 1
#define WORK_MODE_TEST_TRANS 2

const char *redis_dump_dir = "./redis_dump";
const char *default_table_info = "./table_info.json";

static void maat_tool_print_usage(void)
{
	printf("maat_redis_tool manipulate rules from redis.\n");
	printf("Usage:\n");
	printf("\t-h [host], redis IP, 127.0.0.1 as default.\n");
	printf("\t-p [port], redis port, 6379 as default.\n");
	printf("\t-n [db], redis db, 0 as default.\n");
	printf("\t-d [dir], dump rules from redis to [dir], %s as default.\n", redis_dump_dir);
	printf("\t-k, try to execute the 'keys EFFECTIVE_RULE:*' transaction, and give a specific reason if an error occurs\n");
    printf("\t-u [json_file], flush redis and upload all rules to redis, confirm the risk before proceeding\n");
	printf("\t-v [version], dump specific [version] from redis, dump latest version as default.\n");
	printf("\t-t [timeout], timeout config after t seconds, default is 0 which means never timeout.\n");	
	printf("example: ./maat_redis_tool -h 127.0.0.1 -p 6379 -d %s\n",redis_dump_dir);
	printf("    ./maat_redis_tool -h 127.0.0.1 -p 6379 -k\n");
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

static int set_file_rulenum(const char *path, int rule_num)
{
	FILE* fp=NULL;

	if (0 == rule_num) {
		fp = fopen(path, "w");
	} else {
		fp = fopen(path, "r+");
	}

	if (NULL == fp) {
		fprintf(stderr, "fopen %s failed %s at set rule num\n",
				path, strerror(errno));
		return -1;
	}

	fprintf(fp, "%010d\n", rule_num);
	fclose(fp);

	return 0;
}

static void read_rule_from_redis(redisContext *c, const char *output_path,
						  		 struct log_handle *logger)
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

	int rule_num = maat_get_rm_key_list(c, 0, &version, NULL, &rule_list,
										&update_type, logger);
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

	snprintf(foreign_files_dir, sizeof(foreign_files_dir),
			 "%s/foreign_files/", output_path);

	if ((access(foreign_files_dir, F_OK)) <0) {	
        if((mkdir(foreign_files_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) < 0) {
            printf("mkdir %s error\n", foreign_files_dir);
        }
	}

	ret = maat_get_foreign_keys_by_prefix(c, rule_list, rule_num,
										  foreign_files_dir, logger);
	if (ret > 0) {
		printf("%d lines has foreign content.\n", ret);
		maat_get_foreign_conts(c, rule_list, rule_num, 1, NULL);
	}

	snprintf(index_path,sizeof(index_path), "%s/full_config_index.%020lld",
			 output_path, version);

	index_fp = fopen(index_path, "w");
	if (NULL == index_fp) {
		printf("Open %s failed.\n", index_path);
		goto clean_up;
	}

	for (i = 0; i < rule_num; i++) {
		if (rule_list[i].n_foreign > 0) {
			maat_rewrite_table_line_with_foreign(rule_list+i);
		}

		if (NULL == cur_table ||
			0 != strcmp(cur_table,rule_list[i].table_name)) {
			if (table_fp != NULL) {
				fprintf(index_fp, "%s\t%d\t%s\n", cur_table, line_count, table_path);
				fclose(table_fp);
				table_fp = NULL;
				set_file_rulenum(table_path, line_count);
				line_count = 0;
				printf("Written table %s\n",table_path);
			}

			snprintf(table_path, sizeof(table_path), "%s/%s.%020lld",
					 output_path, rule_list[i].table_name, version);
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
        
		fprintf(table_fp, "%s\tkey=%lld\n", rule_list[i].table_line,
				rule_list[i].rule_id);
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

	if (index_fp != NULL) {
		fclose(index_fp);
	}

	if (table_fp != NULL) {
		fclose(table_fp);
	}
}

static int exec_keys_transaction(redisContext *c, struct log_handle *logger)
{
	printf("Ready to execute [keys EFFECTIVE_RULE:*] transaction...\n");
	struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    size_t append_cmd_cnt = 0;
    int ret = redisAppendCommand(c, "MULTI");
	if (ret < 0) {
		printf("redisAppendCommand(MULTI) failed.\n");
		return -1;
	}
    append_cmd_cnt++;
	
    ret = redisAppendCommand(c, "GET MAAT_VERSION");
	if (ret < 0) {
		printf("redisAppendCommand(GET MAAT_VERSION) failed.\n");
		return -1;
	}
    append_cmd_cnt++;

    ret = redisAppendCommand(c, "KEYS EFFECTIVE_RULE:*");
	if (ret < 0) {
		printf("redisAppendCommand(KEYS EFFECTIVE_RULE:*) failed.\n");
		return -1;
	}
    append_cmd_cnt++;

    size_t i = 0;
	redisReply *reply = NULL;

    //consume reply "OK" and "QUEUED".
    for (i = 0; i < append_cmd_cnt; i++) {
        maat_wrap_redis_get_reply(c, &reply);
        freeReplyObject(reply);
        reply = NULL;
    }

    reply = maat_wrap_redis_command(c, logger, "EXEC");
    if (NULL == reply) {
        printf("[%s:%d] execute exec failed.: %s, "
			   "check the log file to find the cause of the error.\n",
               __FUNCTION__, __LINE__, c->errstr);
        return -1;
    }

    if (reply->type != REDIS_REPLY_ARRAY) {
        printf("[%s:%d] Invalid Redis Key List type %d\n",
                __FUNCTION__, __LINE__, reply->type);
        freeReplyObject(reply);
        reply = NULL;
        return -1;
    }

	redisReply *sub_reply = reply->element[1];
	clock_gettime(CLOCK_MONOTONIC, &end);
	long long time_elapse_s = (end.tv_sec - start.tv_sec) +
                              (end.tv_nsec - start.tv_nsec) / 1000000000;
    printf("success!!! consume time:%llds, rule_num:%zu\n",
		   time_elapse_s, sub_reply->elements);

    return 0;
}

int main(int argc, char * argv[])
{
	int opt = 0;
	int mode = 0;
	char redis_ip[64] = {0};
	int redis_port = 6379;
	int redis_db = 0;
    char dump_dir[128] = {0};
    char upload_file[128] = {0};
    char log_path[128] = "./maat_redis_tool.log";
    int timeout = 0;

	strncpy(redis_ip, "127.0.0.1", sizeof(redis_ip));
	strncpy(dump_dir, redis_dump_dir, sizeof(dump_dir));
	struct log_handle *logger = log_handle_create(log_path, 0);

	while ((opt = getopt(argc,argv,"h:p:n:d:f:t:u:k")) != -1) {
		switch (opt) {
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
			case 'k':
				mode = WORK_MODE_TEST_TRANS;
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

	if (mode == WORK_MODE_UPLOAD) {
		return write_json_to_redis(upload_file, redis_ip, redis_port,
								   redis_db, logger);
	}

	redisContext *c = maat_connect_redis(redis_ip, redis_port, redis_db, logger);
	if (NULL == c) {
		return -1;
	}

	int ret = 0;
	if (mode == WORK_MODE_DUMP) {
		log_info(logger, MODULE_REDIS_TOOL, "Reading key list from %s:%d db%d.", 
                 redis_ip, redis_port, redis_db);
		read_rule_from_redis(c, dump_dir, logger);
    } else if (mode == WORK_MODE_TEST_TRANS) {
		ret = exec_keys_transaction(c, logger);
		if (ret < 0) {
			printf("[ERROR]: execute 'KEYS EFFECTIVE_RULE:*' failed.");
		}
	}

	redisFree(c);
	return ret;
}
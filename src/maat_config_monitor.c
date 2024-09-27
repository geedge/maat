/*
**********************************************************************************************
*	File: maat_config_monitor.c
*   Description: maat config monitor api
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include "maat_core.h"
#include "maat_config_monitor.h"

#define MODULE_CONFIG_MONITOR	 module_name_str("maat.config_monitor")

#define	MAX_CONFIG_LINE	(1024 * 16)

struct cm_table_info_t {
	char table_name[MAX_NAME_STR_LEN];
	char cfg_path[NAME_MAX];
	int cfg_num;
	char encrypt_algo[NAME_MAX];
};

//replacement of glibc scandir, to adapt dictator malloc wrap
#define	ENLARGE_STEP	1024
int my_scandir(const char *dir, struct dirent ***namelist,
              int(*filter)(const struct dirent *),
              int(*compare)(const void *, const void *))
{
	if ((NULL == dir) || (NULL == namelist)) {
        return -1;
    }

	DIR *od = opendir(dir);
	if (NULL == od) {
        return -1;
    }

	int num = 0;
	int DIR_ENT_SIZE = ENLARGE_STEP;
    struct dirent *entry = NULL;
    struct dirent **list = ALLOC(struct dirent *, DIR_ENT_SIZE);

    while ((entry = readdir(od)) != NULL) {
        if (filter && !filter(entry)) {
            continue;
        }

        struct dirent *p = ALLOC(struct dirent, 1);
        memcpy((void *)p, (void *)entry, sizeof(struct dirent));
        list[num] = p;

        num++;
        if (num >= DIR_ENT_SIZE) {
            DIR_ENT_SIZE += ENLARGE_STEP;
            struct dirent **tmp_list = (struct dirent **)realloc((void *)list,
										DIR_ENT_SIZE * sizeof(struct dirent *));
            if (tmp_list != NULL) {
                list = tmp_list;
            } else {
                FREE(list);
                closedir(od);
                return -1;
            }
        }
        entry = readdir(od);
    }

    closedir(od); 
	*namelist = list;

	if (compare) {
        qsort((void *)*namelist, num, sizeof(struct dirent *), compare); 
    }
	
	return num; 
}

static void config_load_json_content(const cJSON *json_root, const char *table_name, const char *key, void *u_param,
									int (*update_fn)(const char *, const char *, void *, enum maat_operation))
{
	cJSON *array_item = NULL;
	int i;

	array_item = cJSON_GetObjectItem(json_root, key);
	if (array_item != NULL) {
		for (i = 0; i < cJSON_GetArraySize(array_item); i++) {
			cJSON *rule = cJSON_GetArrayItem(array_item, i);
			if (rule == NULL) {
				continue;
			}
			cJSON *rule_table = cJSON_GetObjectItem(rule, "rule_table_name");

			char *rule_str = cJSON_PrintUnformatted(rule);
			if (rule_str == NULL) {
				continue;
			}

			if (rule_table != NULL) {
				update_fn(rule_table->valuestring, rule_str, u_param, MAAT_OP_ADD);
			} else {
				update_fn(table_name, rule_str, u_param, MAAT_OP_ADD);
			}

			FREE(rule_str);
		}
	}
}

void config_monitor_traverse(long long current_version, const cJSON *json_root,
							 void (*start_fn)(long long, int, void *),
							 int (*update_fn)(const char *, const char *, void *, enum maat_operation),
							 void (*finish_fn)(void *), void *u_param,
							 const char *dec_key, struct log_handle *logger)
{
	size_t i = 0;
	long long new_version = 0;
	int update_type = MAAT_UPDATE_TYPE_FULL;

	if (start_fn != NULL) {
		start_fn(new_version, update_type, u_param);
	}
	
	cJSON *tmp_obj = NULL;
	cJSON *rule_table = cJSON_GetObjectItem(json_root, "rule_table");
	cJSON *object2object_table = cJSON_GetObjectItem(json_root, "object2object_table");
	cJSON *plugin_table = cJSON_GetObjectItem(json_root, "plugin_table");

	tmp_obj = cJSON_GetObjectItem(json_root, "items");
	if (tmp_obj != NULL) {
		for (i = 0; i < cJSON_GetArraySize(tmp_obj); i++) {
			cJSON *object = cJSON_GetArrayItem(tmp_obj, i);
			if (object == NULL) {
				continue;
			}

			cJSON *table_name = cJSON_GetObjectItem(object, "table_name");
			if (table_name == NULL) {
				continue;
			}

			cJSON *table_content = cJSON_GetObjectItem(object, "table_content");
			if (table_content == NULL) {
				continue;
			}

			char *table_content_str = cJSON_PrintUnformatted(table_content);

			update_fn(table_name->valuestring, table_content_str, u_param, MAAT_OP_ADD);
			FREE(table_content_str);
		}
	}
	
	if (object2object_table) {
		config_load_json_content(json_root, object2object_table->valuestring, "object_groups", u_param, update_fn);
	}
	if (rule_table) {
		config_load_json_content(json_root, rule_table->valuestring, "rules", u_param, update_fn);
	}
	if (plugin_table) {
		cJSON *plugin_item;
		cJSON_ArrayForEach(plugin_item, plugin_table) {
			cJSON *table_name = cJSON_GetObjectItem(plugin_item, "table_name");
			config_load_json_content(plugin_item, table_name->valuestring, "table_content", u_param, update_fn);
		}
	}

	if (finish_fn != NULL) {
		finish_fn(u_param);
	}
}

void convert_maat_json_rule(cJSON **json_root, unsigned char *json_buff)
{
	*json_root = cJSON_Parse((const char *)json_buff);
	cJSON *top_items = cJSON_GetObjectItem(*json_root, "items");
	cJSON *top_objects = cJSON_GetObjectItem(*json_root, "objects");
	cJSON *rules = cJSON_GetObjectItem(*json_root, "rules");
	uuid_t tmp_uuid;

	if (top_items == NULL) {
		top_items = cJSON_CreateArray();
		cJSON_AddItemToObject(*json_root, "items", top_items);
	}

	/*
	"objects": [																	"items": [
        {																				{
            "object_name": "ASN1234",														"table_name": "AS_NUMBER",
            "uuid": 1,																	"table_content": {
            "items": [																				"uuid": "1",
                {																					"object_uuid": "1",
                    "table_name": "AS_NUMBER",    -------------------->								"keywords": "^AS1234$",
                    "table_type": "expr",															"expr_type": "and"
                    "table_content": {														}
                        "keywords": "^AS1234$",											}
                        "expr_type": "and"											]
                    }
                }
            ]
        }
	]
	*/
	cJSON *tmp_node = NULL;
	cJSON_ArrayForEach(tmp_node, top_objects) {
		cJSON *object_id_obj = cJSON_GetObjectItem(tmp_node, "uuid");
		cJSON *items = cJSON_GetObjectItem(tmp_node, "items");
		cJSON *tmp_item = NULL;
		cJSON_ArrayForEach(tmp_item, items) {
			cJSON *table_name = cJSON_GetObjectItem(tmp_item, "table_name");
			cJSON *table_content = cJSON_GetObjectItem(tmp_item, "table_content");
			cJSON *new_item = cJSON_CreateObject();
			cJSON *new_table_content = cJSON_Duplicate(table_content, 0);

			if (object_id_obj == NULL) {
				char uuid_str[UUID_STR_LEN];
				uuid_generate(tmp_uuid);
				uuid_unparse(tmp_uuid, uuid_str);
				cJSON_AddStringToObject(new_table_content, "object_uuid", uuid_str);
			} else {
				cJSON_AddStringToObject(new_table_content, "object_uuid", object_id_obj->valuestring);
			}

			if (cJSON_GetObjectItem(table_content, "uuid") == NULL) {
				char uuid_str[UUID_STR_LEN];
				uuid_generate(tmp_uuid);
				uuid_unparse(tmp_uuid, uuid_str);
				cJSON_AddStringToObject(new_table_content, "uuid", uuid_str);
			}

			cJSON_AddStringToObject(new_item, "table_name", table_name->valuestring);
			cJSON_AddItemToObject(new_item, "table_content", new_table_content);
			cJSON_AddItemToArray(top_items, new_item);
		}
	}

	/*
	"rules": [																		"items":[
    {																					{
      "uuid": "201",																		"table_name": "ATTR_APP_ID",
      "conditions": [																		"table_content": {
        {																						"uuid": "1",	
          "attribute_name": "ATTR_APP_ID",														"object_uuid": "1",
          "objects": [																			"interval": "4001"
            {
			 "items":[											-------------->     		}
              "table_name": "APP_ID_DICT",												}
              "table_type": "interval",												]
              "interval": "4001"
			  ]													
            }																		"rules": [{
          ]																				"uuid": "201",
        }																				"conditions": [
      ],																					{
      "misc": "blah, blah"																		"attribute_name": "ATTR_APP_ID",
    }																							"object_uuids": ["1"]
  ]																							}		
																						]
																						"misc": "blah, blah"
																					  }
																					]
	*/	
	cJSON *tmp_rule = NULL;
	cJSON_ArrayForEach(tmp_rule, rules) {
		cJSON *tmp_condition = NULL;
		cJSON *condition_array = cJSON_GetObjectItem(tmp_rule, "conditions");
		cJSON_ArrayForEach(tmp_condition, condition_array) {
			cJSON *tmp_object = NULL;
			cJSON *object_uuid_array = cJSON_CreateArray();
			cJSON *object_array = cJSON_GetObjectItem(tmp_condition, "objects");

			if (object_array == NULL) {
				continue;
			}

			cJSON *negate_option = cJSON_GetObjectItem(tmp_condition, "negate_option");
			if (negate_option == NULL) {
				cJSON_AddBoolToObject(tmp_condition, "negate_option", 0);
			}

			cJSON_ArrayForEach(tmp_object, object_array) {
				//find items, generate item_id and object_id
				cJSON *object_id_obj = cJSON_GetObjectItem(tmp_object, "uuid");
				cJSON *items = cJSON_GetObjectItem(tmp_object, "items");
				cJSON *item = NULL;
				char obj_uuid_str[UUID_STR_LEN];
				memset(obj_uuid_str, 0, sizeof(obj_uuid_str));
				if (object_id_obj != NULL) {
					snprintf(obj_uuid_str, sizeof(obj_uuid_str), "%s", object_id_obj->valuestring);
				} else {
					uuid_generate(tmp_uuid);
					uuid_unparse(tmp_uuid, obj_uuid_str);
				}

				cJSON_ArrayForEach(item, items) {
					cJSON *table_name = cJSON_GetObjectItem(item, "table_name");
					cJSON *tmp_item = cJSON_CreateObject();
					cJSON_AddItemToObject(tmp_item, "table_name", cJSON_CreateString(table_name->valuestring));

					cJSON *dup = cJSON_Duplicate(cJSON_GetObjectItem(item, "table_content"), 1);

					if (cJSON_GetObjectItem(dup, "uuid") == NULL) {
						char uuid_str[UUID_STR_LEN];
						uuid_generate(tmp_uuid);
						uuid_unparse(tmp_uuid, uuid_str);
						cJSON_AddStringToObject(dup, "uuid", uuid_str);
					}
					cJSON_AddStringToObject(dup, "object_uuid", obj_uuid_str);

					cJSON_AddItemToObject(tmp_item, "table_content", dup);
					cJSON_AddItemToArray(top_items, tmp_item);
				}

				cJSON_AddItemToArray(object_uuid_array, cJSON_CreateString(obj_uuid_str));
			}
			//replace object content with object_id
			cJSON_DeleteItemFromObject(tmp_condition, "objects");
			cJSON_AddItemToObject(tmp_condition, "object_uuids", object_uuid_array);
		}
			
	}
}

int load_maat_json_rule_file(struct maat *maat_inst, const char *json_filename, 
                        cJSON **json_root, char *err_str, size_t err_str_sz)
{
	int ret = 0;
	unsigned char *json_buff = NULL; 
    unsigned char *decrypted_buff = NULL; 
    unsigned char *uncompressed_buff = NULL;
	size_t json_buff_sz = 0;
    size_t decrypted_buff_sz = 0; 
    size_t uncompressed_buff_sz = 0;

	log_info(maat_inst->logger, MODULE_CONFIG_MONITOR, 
            "Maat initial with JSON file %s, formating...", 
            json_filename);

	if (strlen(maat_inst->opts.decrypt_key) &&
		strlen(maat_inst->opts.decrypt_algo)) {
		ret = decrypt_open(json_filename, maat_inst->opts.decrypt_key, 
                           maat_inst->opts.decrypt_algo,
                           &decrypted_buff, &decrypted_buff_sz, 
                           err_str, err_str_sz);
		if (ret < 0) {
			log_fatal(maat_inst->logger, MODULE_CONFIG_MONITOR, 
                      "[%s:%d] Decrypt Maat JSON file %s failed", 
                      __FUNCTION__, __LINE__, json_filename);
			return -1;
		}

		json_buff = decrypted_buff;
		json_buff_sz = decrypted_buff_sz;
	}
    
	if (maat_inst->opts.maat_json_is_gzipped) {
		ret = gzip_uncompress(json_buff, json_buff_sz, &uncompressed_buff, 
                              &uncompressed_buff_sz);
		FREE(json_buff);
		if (ret < 0) {
			log_fatal(maat_inst->logger, MODULE_CONFIG_MONITOR, 
                      "[%s:%d] Uncompress Maat JSON file %s failed", 
                      __FUNCTION__, __LINE__, json_filename);
			return -1;
		}

		json_buff = uncompressed_buff;
		json_buff_sz = uncompressed_buff_sz;
	}

    //decryption failed or no decryption
	if (NULL == json_buff) {	
		ret = load_file_to_memory(json_filename, &json_buff, &json_buff_sz);
		if (ret < 0) {
			log_fatal(maat_inst->logger, MODULE_CONFIG_MONITOR, 
                      "[%s:%d] Read Maat JSON file %s failed", 
                      __FUNCTION__, __LINE__, json_filename);
			return -1;
		}
	}
	maat_inst->opts.input_mode = DATA_SOURCE_JSON_FILE;
	
	convert_maat_json_rule(json_root, json_buff);

	return 0;	
}
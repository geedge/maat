/*
**********************************************************************************************
*	File: maat_command.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_COMMAND_H_
#define _MAAT_COMMAND_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <limits.h>

#include "maat.h"

struct maat_cmd_line {
	const char *table_name;
	const char *table_line;
	long long rule_id;		// for MAAT_OP_DEL, only rule_id and table_name are necessary.
	int expire_after;	//expired after $timeout$ seconds, set to 0 for never timeout.
};

/**
 * @brief write one line to redis
 * 
 * @retval 
 *      success: number of successfully updated rule.
 *      failed: -1
*/
int maat_cmd_set_line(struct maat *maat_instance, const struct maat_cmd_line *line_rule, enum maat_operation op);

int maat_cmd_set_file(struct maat *maat_instance, const char *key, const char *value, 
                      size_t size, enum maat_operation op);
                      
long long maat_cmd_incrby(struct maat *maat_instance, const char *key, int increment);

int maat_cmd_flushDB(struct maat *maat_instance);

#ifdef __cplusplus
}
#endif

#endif
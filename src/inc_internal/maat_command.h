/*
**********************************************************************************************
*	File: maat_command.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_COMMAND_H_
#define _MAAT_COMMAND_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "maat.h"

enum maat_operation {
	MAAT_OP_DEL = 0,
	MAAT_OP_ADD,
	MAAT_OP_RENEW_TIMEOUT	//Rule expire time is changed to now+cmd->expire_after
};

struct maat_cmd_line
{
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
int maat_cmd_set_line(struct maat *maat_instance, const struct maat_cmd_line *line_rule);

long long maat_cmd_incrby(struct maat *maat_instance, const char *key, int increment);

#ifdef __cplusplus
}
#endif

#endif
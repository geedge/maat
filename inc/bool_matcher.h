/*
 *
 * Copyright (c) 2018
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2018-12-31
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef INCLUDE_BOOL_MATCHER_H
#define INCLUDE_BOOL_MATCHER_H
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif
	#define MAX_ITEMS_PER_BOOL_EXPR   8

	/*not_flag=0表示布尔项item_id必须出现；not_flag=1表示布尔项item_id不能出现*/
	struct bool_item
	{
		unsigned long long item_id;
		unsigned char      not_flag;
	};

	/*注意：不支持布尔项全“非”的情形*/
	struct bool_expr
	{
		void * user_tag;
		size_t item_num;
		struct bool_item items[MAX_ITEMS_PER_BOOL_EXPR];
	};

	struct bool_matcher;

	/*注意：本函数调用会交换bool_exprs中元素的位置*/
	struct bool_matcher * bool_matcher_new(struct bool_expr * exprs, size_t expr_num, unsigned int max_thread_num, size_t * mem_size);

	int bool_matcher_match(struct bool_matcher * matcher, unsigned int thread_id, const unsigned long long * item_ids, size_t item_num, void ** result, size_t size);

	void bool_matcher_free(struct bool_matcher * matcher);

#ifdef __cplusplus
}
#endif

#endif

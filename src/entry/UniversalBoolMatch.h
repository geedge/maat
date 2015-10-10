/*
 *
 * Copyright (c) 2014
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2014-12-09
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_UNIVERSAL_BOOL_MATCH_H
#define H_UNIVERSAL_BOOL_MATCH_H

#ifdef __cplusplus
extern "C"
{
#endif

    #define MAX_ITEMS_PER_BOOL_EXPR   8

	typedef struct _universal_bool_expr_t
	{
		void *       bool_expr_id;
		unsigned int bool_item_num;
		unsigned int bool_item_ids[MAX_ITEMS_PER_BOOL_EXPR];
	}universal_bool_expr_t;

	/*注意：本函数调用会交换bool_exprs中元素的位置*/
	void * boolexpr_initialize(universal_bool_expr_t * bool_exprs, unsigned int bool_expr_num, unsigned int max_thread_num, unsigned int * mem_size);

	int    boolexpr_match(void * instance, unsigned int thread_id, unsigned int * item_ids, unsigned int item_num, void ** result, unsigned int size);

	void   boolexpr_destroy(void * instance);

#ifdef __cplusplus
}
#endif

#endif

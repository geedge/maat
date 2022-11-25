/*
 *
 * Copyright (c) 2020
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LU YUHAI    (luyuhai@iie.ac.cn)
 * Last modification: 2020-04-20
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_IP_MATCHER_H
#define H_IP_MATCHER_H
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

	 enum IP_TYPE
	{
		IPv4,
		IPv6
	};

	/* 带掩码的单点IPv4规则 */
	struct ipv4_range
	{
		unsigned int	start_ip;     /* IP范围下界 */
		unsigned int	end_ip;     /* IP范围上界 */
	};

	/* 带掩码的单点IPv6规则 */
	struct ipv6_range
	{
		unsigned int	start_ip[4];  /* IP范围下界 */
		unsigned int	end_ip[4];  /* IP范围上界 */
	};

	/* 通用的ip规则类型 */
	struct ip_rule
	{
		enum IP_TYPE type;           /* 规则类型，ipv4或ipv6 */
		unsigned int rule_id;		 /* 规则ID */
		void* user_tag;              /* 用户自定义数据，命中时随匹配结果返回 */
		union								
		{
			struct ipv4_range ipv4_rule;  /*带掩码的单点IPv4规则*/
			struct ipv6_range ipv6_rule;  /*带掩码的单点IPv6规则*/
		};
	};

	/* 通用的待扫描数据类型 */
	struct ip_data
	{
		enum IP_TYPE type;			/* 规则类型，ipv4或ipv6 */
		union                       /* 根据rule_type决定数据负载是ipv4还是ipv6 */
		{
			unsigned int ipv4;		/* ipv4数据*/
			unsigned int ipv6[4];	/* ipv6数据*/
		};
	};


		/* 布尔表达式的扫描结果类型 */
	struct scan_result
	{
		unsigned int  rule_id;	/* 规则的ID */		
		void *        tag;		/* 用户自定义数据，命中时随匹配结果返回 */
	};


	struct ip_matcher;

	/* 
	功能：根据输入的规则生成扫描器 
	参数：
		rules[in]：一组ip规则
		rule_num[in]：输入的规则数量
		mem_use[out]：内存消耗量
	返回值：
		ip扫描器,返回空指针生成扫描器失败
	*/
	struct ip_matcher* ip_matcher_new(struct ip_rule * rules, size_t rule_num, size_t * mem_use);

	/*
	功能：调用ip扫描器对输入的ip数据进行扫描
	参数：
		matcher[in]：ip扫描器
		data[in]：输入的待扫描ip数据
		result[in]：返回结果存储数组
		size[in]：结果数组的大小
	返回值：
		命中结果的数量（<=size）；返回值为-1表示出错。
		
	*/
	int ip_matcher_match(struct ip_matcher* matcher, struct ip_data * data, struct scan_result* result, size_t size);

	/*
	功能：销毁一个ip扫描器
	参数：
		matcher[in]：待销毁的ip扫描器指针
	*/
	void ip_matcher_free(struct ip_matcher* matcher);

#ifdef __cplusplus
}
#endif

#endif /* !defined(H_IP_MATCHER_H) */

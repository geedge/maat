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

#include "../../deps/log/log.h"

#ifdef __cplusplus
extern "C"
{
#endif

	 enum IP_TYPE
	{
		IPv4=4,
		IPv6=6
	};

	/* ������ĵ���IPv4���� */
	struct ipv4_range
	{
		unsigned int	start_ip;   /* IP��Χ�½� */
		unsigned int	end_ip;     /* IP��Χ�Ͻ� */
	};

	/* ������ĵ���IPv6���� */
	struct ipv6_range
	{
		unsigned int	start_ip[4];  /* IP��Χ�½磬�� Big-Endian ģʽ�洢 */
		unsigned int	end_ip[4];    /* IP��Χ�Ͻ磬�� Big-Endian ģʽ�洢 */
	};

	/* ͨ�õ�ip�������� */
	struct ip_rule
	{
		enum IP_TYPE type;           /* �������ͣ�ipv4��ipv6 */
		long long rule_id;		    /* ����ID */
		void* user_tag;              /* �û��Զ������ݣ�����ʱ��ƥ�������� */
		union								
		{
			struct ipv4_range ipv4_rule;  /*������ĵ���IPv4����*/
			struct ipv6_range ipv6_rule;  /*������ĵ���IPv6����*/
		};
	};

	/* ͨ�õĴ�ɨ���������� */
	struct ip_data
	{
		enum IP_TYPE type;			/* �������ͣ�ipv4��ipv6 */
		union                       /* ����rule_type�������ݸ�����ipv4����ipv6 */
		{
			unsigned int ipv4;		/* ipv4����*/
			unsigned int ipv6[4];	/* ipv6���ݣ��� Big-Endian ģʽ�洢*/
		};
	};


		/* ��������ʽ��ɨ�������� */
	struct scan_result
	{
		long long  rule_id;	/* �����ID */		
		void *        tag;		/* �û��Զ������ݣ�����ʱ��ƥ�������� */
	};


	struct ip_matcher;

	/* 
	���ܣ���������Ĺ��������?���� 
	������
		rules[in]��һ��ip����
		rule_num[in]������Ĺ�������?
		mem_use[out]���ڴ�������
	����ֵ��
		ipɨ����,���ؿ�ָ������ɨ����ʧ��
	*/
	struct ip_matcher* ip_matcher_new(struct ip_rule * rules, size_t rule_num, size_t * mem_use);

	/*
	���ܣ�����ipɨ�����������ip���ݽ���ɨ��
	������
		matcher[in]��ipɨ����
		data[in]������Ĵ��?��ip����
		result[in]�����ؽ����?����
		size[in]���������Ĵ�С
	����ֵ��
		���н����������?<=size��������ֵΪ-1��ʾ������
		
	*/
	int ip_matcher_match(struct ip_matcher* matcher, struct ip_data * data, 
                         struct scan_result* result, size_t size);

	/*
	���ܣ�����һ��ipɨ����
	������
		matcher[in]�������ٵ�ipɨ����ָ��
	*/
	void ip_matcher_free(struct ip_matcher* matcher);

#ifdef __cplusplus
}
#endif

#endif /* !defined(H_IP_MATCHER_H) */

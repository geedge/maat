/*
 *
 * Copyright (c) 2014
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2016-06-05
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_RULE_SCAN_H
#define H_RULE_SCAN_H

#ifdef __cplusplus
extern "C"
{
#endif

	/* rulescan_set_param函数可设置的参数类型 */
	enum RULESCAN_PARA_NAME
	{
		RULESCAN_DETAIL_RESULT=1,		/* 本标志位表示：返回详细命中位置等信息, optval设为NULL，optlen设为0。默认不返回详细信息*/
		RULESCAN_REGEX_GROUP  =2,		/* 本标志位表示：返回正则表达式匹配的分组信息；开启本字段，需要先设置RULESCAN_DETAIL_RESULT标志位,optval设为NULL，optlen设为0。默认不返回分组信息 */
		RULESCAN_QUICK_SCAN			    /* 设置需要快速扫描模式的sub_type, 由用户自己定义，optval的值为0-4096，optlen设为4。默认设置是普通扫描模式。*/
	};

	#define MAX_REGEX_GROUP_NUM 5		 /* 对于正则表达式，所支持的最大分组的个数 */	

	#define MAX_EXPR_ITEM_NUM  (1U<<3)   /* 每条与表达式最多由MAX_EXPR_ITEM_NUM个规则组成 */
	#define MAX_MATCH_POS_NUM  1024      /* 每条规则最多允许返回的命中位置的个数 */
	#define MATCH_POS_NUM_INC  64		 /* 每条规则允许返回的命中位置的个数初始值与增量值 */

	/* 定义不同的规则类型  */
	const unsigned int RULETYPE_STR  = 0; /* 字符串或二进制规则 */
	const unsigned int RULETYPE_REG  = 1; /* 正则表达式规则 */
	const unsigned int RULETYPE_INT  = 2; /* 数值区间规则 */
	const unsigned int RULETYPE_IPv4 = 3; /* IPv4规则 */
	const unsigned int RULETYPE_IPv6 = 4; /* IPv6规则 */

	const unsigned int MAX_RULETYPE     = 5;          /* 规则类型数量 */
	const unsigned int MAX_SUB_RULETYPE = 4096;        /* 规则子类型数量 */

	/* 字符串类型规则（可表示文本字符串、二进制字符串、正则表达式） */
	typedef struct _string_rule_t
	{
		char *        str;            /* 字符串内容；如果是正则表达式，须以'\0'结束，可不指定长度 */
		unsigned int  len;            /* 字符串长度 */
		unsigned char case_sensitive; /* 是否大小写敏感匹配（1：敏感；0：不敏感） */
		unsigned char match_mode;     /* 匹配模式：子串匹配（0），完整匹配（1）；仅对精确串匹配有效 */
		int  l_offset;                /* 表示模式串只能在文本范围[l_offset, r_offset]中出现，-1表示无限制,-2表示左匹配；仅对精确串匹配有效 */
		int  r_offset;                /* 表示模式串只能在文本范围[l_offset, r_offset]中出现，-1表示无限制,-2表示右匹配；仅对精确串匹配有效 */
	}string_rule_t;

	/* 整数数值区间规则，表示整数区间[lb, ub] */
	typedef struct _interval_rule_t
	{
		unsigned int lb; /* 数据区间的下界（包含lb），无限制默认为0 */
		unsigned int ub; /* 数据区间的下界（包含ub），无限制默认为0 */
	}interval_rule_t;

	/* 带掩码的IPv4规则 */
	typedef struct _ipv4_rule_t
	{
		unsigned int       saddr;     /* 源IP地址；0表示忽略本字段 */
		unsigned int       smask;     /* 源IP地址掩码；0表示固定IP=saddr */
		unsigned int       daddr;     /* 目的IP地址；0表示忽略本字段 */
		unsigned int       dmask;     /* 目的IP地址掩码；0表示固定IP=daddr */
		unsigned short int min_sport; /* 源端口范围下界；0表示忽略本字段 */
		unsigned short int max_sport; /* 源端口范围上界；0表示固定端口=min_sport */
		unsigned short int min_dport; /* 目的端口范围下界；0表示忽略本字段 */
		unsigned short int max_dport; /* 目的端口范围上界；0表示固定端口=min_dport */
		unsigned short int proto;     /* 传输层协议，6表示TCP，17表示UDP；0表示忽略本字段 */
		unsigned short int direction; /* 方向，0表示双向，1表示单向 */
	}ipv4_rule_t;

	/* 带掩码的IPv6规则 */
	typedef struct _ipv6_rule_t
	{
		unsigned int       saddr[4];  /* 源IP地址；0表示忽略本字段 */
		unsigned int       smask[4];  /* 源IP地址掩码；0表示固定IP=saddr */
		unsigned int       daddr[4];  /* 目的IP地址；0表示忽略本字段 */
		unsigned int       dmask[4];  /* 目的IP地址掩码；0表示固定IP=daddr */
		unsigned short int min_sport; /* 源端口范围下界；0表示忽略本字段 */
		unsigned short int max_sport; /* 源端口范围上界；0表示固定端口=min_sport */
		unsigned short int min_dport; /* 目的端口范围下界；0表示忽略本字段 */
		unsigned short int max_dport; /* 目的端口范围上界；0表示固定端口=min_dport */
		unsigned short int proto;     /* 传输层协议，6表示TCP，17表示UDP，无限制默认为0 */
		unsigned short int direction; /* 方向，0表示双向，1表示单向 */
	}ipv6_rule_t;

	/* 通用的规则类型 */
	typedef struct _scan_rule_t
	{
		unsigned int rule_type;              /* 规则类型，必须为上述枚举规则类型之一 */
		unsigned int sub_type;               /* 子类类型，用户自定义，但子类型个数不允许超过MAX_SUB_RULETYPE（见前文定义） */
		union                                /* 根据rule_type决定规则是字符串、数值区间、还是IP规则 */
		{
			string_rule_t    string_rule;    /* 字符串规则（字符串、二进制、正则表达式） */
			interval_rule_t  interval_rule;  /* 整数数值区间规则 */
			ipv4_rule_t      ipv4_rule;      /* 带掩码的IPv4规则 */
			ipv6_rule_t      ipv6_rule;      /* 带掩码的IPv6规则 */
		};
	}scan_rule_t;

	/* 一条与表达式规则 */
	typedef struct _boolean_expr_t
	{
		unsigned int  expr_id;   /* 与表达式的ID */
		unsigned int  operation; /* 对与表达式执行的操作：0表示增加，1表示删除 */
		unsigned int  rnum;      /* 该与表达式包含多少个项；如果operation=1，置rnum=0即可 */
		scan_rule_t * rules;     /* 组成与表达式的项；如果operation=1，置rules=NULL即可 */
		void *        tag;       /* 用户自定义数据，命中时随匹配结果返回 */
	}boolean_expr_t;


	/* 待扫描的文本数据类型 */
	typedef struct _text_data_t
	{
		const char * text;   /* 文本数据内容 */
		unsigned int tlen;   /* 文本数据长度 */
		int			 toffset;/* 本段文本数据在整个流数据中的偏移量，流式扫描情况下有效，由用户传入，其它情况置为0(这个必须置为0) */  
	}text_data_t;

	/* 待扫描的IPv4元组 */
	typedef struct _ipv4_data_t
	{
		unsigned int       saddr; /* 源IP地址 */
		unsigned int       daddr; /* 目的IP地址 */
		unsigned short int sport; /* 源端口 */
		unsigned short int dport; /* 目的端口 */
		unsigned short int proto; /* 传输层协议，6表示TCP，17表示UDP */
	}ipv4_data_t;

	/* 待扫描的IPv6元组 */
	typedef struct _ipv6_data_t
	{
		unsigned int       saddr[4]; /* 源IP地址 */
		unsigned int       daddr[4]; /* 目的IP地址 */
		unsigned short int sport;    /* 源端口 */
		unsigned short int dport;    /* 目的端口 */
		unsigned short int proto;    /* 传输层协议，6表示TCP，17表示UDP */
	}ipv6_data_t;

	/* 通用的待扫描数据类型 */
	typedef struct _scan_data_t
	{
		unsigned int rule_type;     /* 规则类型，必须为上述枚举规则类型之一 */
		unsigned int sub_type;      /* 子类类型，用户自定义，但子类型个数不允许超过MAX_SUB_RULETYPE（见前文定义） */
		union                       /* 根据rule_type决定数据负载是字符串、数值、还是IP元组 */
		{
			text_data_t  text_data; /* 待扫描文本数据（可匹配字符串、二进制、正则表达式） */
			unsigned int int_data;  /* 整数数值（可匹配数值区间） */
			ipv4_data_t  ipv4_data; /* 待扫描的IPv4元组 */
			ipv6_data_t  ipv6_data; /* 待扫描的IPv6元组 */
		};
	}scan_data_t;

	/*
	   扫描结果类型scan_result_t和rule_result_t说明：
	1、对于命中的每个布尔表达式，一条表达式对应一条scan_result_t结果，该布尔表达式包含rnum个规则，每个规则均对应于一个结果scan_result_t::result[k]（0<=k<rnum）。

	2、对于精确字符串，结果数组position和length释义如下：
	命中的精确字符串包含result_num个匹配结果，第i（0<=i<result_num）个匹配结果的起始位置和长度分别是：
	   (position[i], length[i])

	3、对于正则表达式，结果数组position和length释义如下：
	命中的正则表达式包含result_num个匹配结果，每个匹配结果包含group_num+1个数组元素。对于第i（0<=i<result_num）个匹配结果：
	（a）整条正则表达式匹配的起始位置和长度分别是：
	   (position[(group_num+1)*i],     length[(group_num+1)*i])
	（b）第j（0<=j<group_num）个分组的起始位置和长度分别是：
	   (position[(group_num+1)*i+j+1], length[(group_num+1)*i+j+1])
	*/

	/* 规则的扫描结果类型 */
	typedef struct _rule_result_t
	{
		unsigned int rule_type;                   /* 规则的类型，必须为上述枚举规则类型之一 */
		unsigned int group_num;                   /* 对于正则表达式类型规则，本字段表示捕获分组（capturing group）的个数；否则设置为0 */
		unsigned int result_num;                  /* 该规则所有命中结果的个数 */
		unsigned int position[MAX_MATCH_POS_NUM]; /* 该规则所有命中结果的起始位置 */
		unsigned int length[MAX_MATCH_POS_NUM];   /* 该规则所有命中结果的长度；如果该命中结果是在以前的数据包中命中的，则设置对应的length=0, 对于整数区间与IP类，长度置为0*/
	}rule_result_t;

	/* 布尔表达式的扫描结果类型，quick模式下只有expr_id以及tag两项有效 */
	typedef struct _scan_result_t
	{
		unsigned int  expr_id;                     /* 与表达式的ID */
		unsigned int  rnum;                        /* 该与表达式包含多少个规则 */
		rule_result_t result[MAX_EXPR_ITEM_NUM];  /* 布尔表达式中每个规则对应的扫描结果 */
		void *        tag;                         /* 用户自定义数据，命中时随匹配结果返回 */
	}scan_result_t;

	/*
	功能：扫描器初始化，生成扫描器对象。
	参数：
		max_thread_num [in]: 扫描器可并行执行的线程数。
	返回值：
		扫描器句柄；返回值为NULL时，表示初始化失败。
	*/
	void * rulescan_initialize(unsigned int max_thread_num);

	/*
	功能：
		设置扫描参数，本函数在rulescan_update之前可多次调用，每次设置一种扫描类型。Rulescan中默认不返回命中位置等详细信息
	参数：
		instance[in]:			扫描器对象指针；
		optname [in]:           参数类型；
		optval [in]:            optval和optlen表示参数的具体内容；
		optlen [in]:            optval和optlen表示参数的具体内容。
	返回值：
		1：正确设置，-1：设置失败。
	*/
	int rulescan_set_param(void * instance, enum RULESCAN_PARA_NAME optname, const void * optval, unsigned int optlen);

	/*
	功能：动态注册一组与表达式，更新扫描器对象。对于同一个instance句柄，不允许同时有多个更新线程。
	参数：
		instance[in]:		扫描器对象指针；
		expr_array[in]:		一组与表达式；
		epxr_num[in]:		与表达式的个数；
		failed_ids[out]:	非法规则的id；failed_ids[0]表示非法id的个数，failed_ids[1...failed_ids[0]]记录非法id，目前只对含一个正则规则的这类布尔表达式有效；
		failed_size[in]:	failed_ids数组的大小。
	返回值：
		返回值为1时，表示注册成功；返回值为-1时，表示出错。
	*/
	int rulescan_update(void * instance, boolean_expr_t * expr_array, unsigned int expr_num, unsigned int * failed_ids, unsigned int failed_size);

	/*
	功能：释放扫描器对象；本函数仅调用一次。
	参数：
		instance [in]: 扫描器指针。
	返回值：
		无。
	*/
	void rulescan_destroy(void * instance);

	/*
	功能：启动一次流式扫描，申请保存流状态的参数。
	参数：
		instance [in]:  扫描器指针；
		thread_id [in]: 当前执行扫描的线程id，必须在范围[0, max_thread_num-1]之内。
	返回值：
		返回保存流状态的参数；返回值为NULL时，表示失败。
	*/
	void * rulescan_startstream(void * instance, unsigned int thread_id);

	/*
	功能：流式扫描接口，扫描一段数据scan_data，并将中间扫描结果保存在流状态stream_param中；
		本函数支持两种扫描模式：
		（1）presults不为NULL：本段流数据扫描结束后立即通过*presults返回一组此次的命中结果；
		（2）presults为NULL  ：完全扫描模式，表示等待整个流扫描结束后，再计算并返回整个流的全部命中结果，
			 详见rulescan_computeresult函数。
	参数：
		stream_param [in]: 保存流状态的参数；
		scan_data [in]:    待扫描数据；
		presults [out]:    如果presults不为NULL，则存的是本次命中的一组扫描结果；
		size [in]:		   结果数组presults的大小。
	返回值：
		如果是流式的完全扫描（presults为NULL），则返回值为本次扫描命中的关键词（数值区间、IP规则等）的个数；
		如果presult不为NULL，则返回值为本次扫描命中的与表达式的个数，-1表示出错。
	*/
	int rulescan_searchstream(void * stream_param,  scan_data_t * scan_data, scan_result_t * presults, unsigned int size);

	/*
	功能：数据流扫描结束后，计算扫描结果。
	参数：
		stream_param [in]: 保存流状态的指针；
		presults [out]:    结果数组，保存所有命中的与表达式规则id；
		size [in]:         结果数组presults的大小。
	返回值：
		命中与表达式规则的数量（<=size）；返回值为-1表示出错。
	*/
	int rulescan_computeresult(void * stream_param, scan_result_t * presults, unsigned int size);

	/*
	功能：结束流式扫描，释放流参数。正常流程情况下调用该接口释放流参数，正常流程指在结束流扫描之前还没有调用
		  rulescan_destroy销毁rulescan句柄。
	参数：
		stream_param [in]: 流参数指针。
	返回值：
		无。
	*/ 
	void rulescan_endstream(void * stream_param);

	/*
	功能：结束流式扫描，释放流参数。对于先调用rulescan_destroy销毁了rulescan句柄之后再结束流扫描的情况，
		  需要调用rulescan_endstream_simple来释放流参数，仅限于这种情况下才调用该接口。
	参数：
		stream_param [in]: 流参数指针。
	返回值：
		无。
	*/ 
	void rulescan_endstream_simple(void * stream_param);

	/*
	功能：非流式扫描接口，扫描结束后返回所有命中结果。
	参数：
		instance [in]:	   扫描器指针；
		thread_id [in]:	   当前执行扫描的线程id，必须在范围[0, max_thread_num-1]之内；
		scan_data [in]:    待扫描数据；
		presults [out]:    结果数组，保存所有命中的与表达式规则id；
		size [in]:         结果数组presults的大小。
	返回值：
		命中与表达式规则的数量（<=size）；返回值为-1表示出错。
	*/
	int rulescan_search(void * instance, unsigned int thread_id, scan_data_t * scan_data, scan_result_t * presults, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif /* !defined(H_RULE_SCAN_H) */


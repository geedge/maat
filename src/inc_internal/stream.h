#ifndef _APP_STREAM_H_
#define _APP_STREAM_H_ 

/*************************************************************************************
Update Log:
2014-09-17 LiJia:
	(1)保留原有struct ipaddr结构体, 与新平台结构struct layer_addr在内存分布上兼容;
	(2)增加新接口:
		int MESA_kill_tcp_synack(struct streaminfo *stream, const void *raw_pkt);
		用于HMD模式下的FD.

2014-09-10 LiJia:
	(1)增加新接口:
		int MESA_inject_pkt(struct streaminfo *stream, const char *payload, 
						 int payload_len, const void *raw_pkt, UCHAR snd_routedir);
		用于应用层插件发送数据, 比原有MESA_fakepacket_send_tcp()减少了很多参数, 便于使用.
**************************************************************************************/

#include <sys/types.h>
#include <netinet/in.h>            
#include <netinet/ip.h>            
#include <netinet/ip6.h>   
#include <netinet/tcp.h>   
#include <netinet/udp.h>   
#include <stdlib.h>
#include <string.h>

#define USE_MESA_STREAM_HASH			(1) /* 使用基于隧道模式新的HASH表 */

extern int MESA_PLATFORM_VERSION_20140917; /* 平台版本号 */

#define ADDR_UNSYMMETRY	(0) /* 2014-04-25, 针对从XinJing捕获的包, 临时解决VLAN地址不对称问题, 此宏不应长期存在 */

#if 0
#define FOR_863				(0) /* for 863项目用户标签模块 */
#define FOR_108				(0)
#define RAW_IP_FRAG_PKT          (0) /* 2013-08-21 LiJia add, 保存全部原始IP分片包 */
#endif

#ifndef UINT8
typedef unsigned char		UINT8;
#endif
#ifndef UCHAR
typedef unsigned char		UCHAR;
#endif
#ifndef UINT16
typedef unsigned short		UINT16;
#endif
#ifndef UINT32
typedef unsigned int			UINT32;
#endif
#ifndef UINT64
typedef unsigned long long	UINT64;
#endif

//流的方向定义
#define DIR_C2S 			0x01
#define DIR_S2C 			0x02
#define DIR_DOUBLE 		0x03

//单包的方向定义
#define DIR_ROUTE_UP		0x00
#define DIR_ROUTE_DOWN 	0x01

//地址类型定义
enum addr_type_t{
	__ADDR_TYPE_INIT = 0,
	ADDR_TYPE_IPV4,				/* 1, 基于IPv4地址的四元组信息 */
	ADDR_TYPE_IPV6,				/* 2, 基于IPv6地址的四元组信息 */
	ADDR_TYPE_VLAN,				/* 3 */
	ADDR_TYPE_MAC,				/* 4 */
	ADDR_TYPE_ARP = 5,				/* 5 */
	ADDR_TYPE_GRE,					/* 6 */
	ADDR_TYPE_MPLS,				/* 7 */
	ADDR_TYPE_PPPOE_SES,			/* 8 */
	ADDR_TYPE_TCP,					/* 9 */
	ADDR_TYPE_UDP = 10,			/* 10 */
	ADDR_TYPE_L2TP,				/* 11 */
	//ADDR_TYPE_STREAM_TUPLE4_V4, 	 /* 12, 混合地址类型, 基于IPv4地址的四元组信息 */
	//ADDR_TYPE_STREAM_TUPLE4_V6,	 /* 13, 混合地址类型, 基于IPv6地址的四元组信息 */	
	__ADDR_TYPE_IP_PAIR_V4,		/* 14, 纯IPv4地址对 */
	__ADDR_TYPE_IP_PAIR_V6,		/* 15, 纯IPv6地址对 */
	__ADDR_TYPE_MAX,				/* 16 */
};


#define TCP_TAKEOVER_STATE_FLAG_OFF	0
#define TCP_TAKEOVER_STATE_FLAG_ON	1

//应用层看到的链接状态定义
#define OP_STATE_PENDING   0
#define OP_STATE_REMOVE_ME 1
#define OP_STATE_CLOSE     2
#define OP_STATE_DATA      3

//应用层返回结果定义
#define APP_STATE_GIVEME   0x00
#define APP_STATE_DROPME   0x01
#define APP_STATE_FAWPKT   0x00
#define APP_STATE_DROPPKT  0x10

//流的类型定义
enum stream_type_t{
	STREAM_TYPE_NON = 0, /* 无流的概念, 如VLAN, IP层等 */
	STREAM_TYPE_TCP,
	STREAM_TYPE_UDP,
	STREAM_TYPE_SOCKS4,
	STREAM_TYPE_SOCKS5,
	STREAM_TYPE_HTTP_PROXY,
	STREAM_TYPE_PPPOE,
};

#define PROXY_STATE_SEL 0
#define PROXY_STATE_LINK_IN 1


/* 原始包结构 */
typedef struct {
	enum addr_type_t low_layer_type;	/* 原始包最底层协议的类型, 可能是MAC(pcap捕包), 也可能是IPv4(pag捕包) */
	int raw_pkt_len;			/* 原始包总长度 */
	const void *raw_pkt_data;	/* 原始包头指针, 根据low_layer_type判断协议类型 */
	struct timeval raw_pkt_ts;	/* 原始包捕获时间戳, 如果全为0则不支持此功能(如pag模式) */
}raw_pkt_t;

//	代理信息
struct proxy_node
{	
	UINT16 iType;		//	代理类型, 0 表示无效
	UINT16  uiPort;		//	代理服务器端口
	UINT16	uiUserLen;
	UINT16  uiPwdLen;
	UINT16  uiApendLen;
	
	UCHAR  opstate;		//当前链接所处状态
	UCHAR  dealstate;	//代理处理状态	
	UINT32  uiIP;		//	代理服务器IP地址v4, 按网络字节序
	UCHAR	*pIpv6;		//	代理服务器IP地址, v6地址
	UCHAR	*pUser;		//    代理用户名
	UCHAR   *pPwd;		//    代理密码
	UCHAR 	*append;	//   其它附属信息，比如url
	
	void 	*apme;	//   其它附属信息，比如url
	struct proxy_node *pnext;
} ;


typedef struct raw_ipfrag_list{
    void *frag_packet;
    int pkt_len;
    int type; /* IPv4 or IPv6 */
    struct raw_ipfrag_list *next;
}raw_ipfrag_list_t;


struct buf_unorder
{
    struct buf_unorder *next;
    struct buf_unorder *prev;
    void *data;
    UINT32 len;
    UINT32 tcpdatalen;
    UINT32 urg_ptr;
    char fin;
    char urg;
    char rst;   
    unsigned char pad;
    UINT32 seq;
    UINT32 ack;
    raw_ipfrag_list_t *ipfrag_list;
    raw_pkt_t raw_pkt; /* 乱序包存储原始包 */
};

/*半流结构体定义：*/
struct half_tcpstream
{
  UCHAR *data;
  UINT32 offset;           /*data中第一个字节在TCP数据流中的偏移量*/
  UINT32 count;           /*从连接建立起到现在为止，到达的数据总长度字节数*/
  UINT32 count_new;        /*本次新到的数据字节数*/
  UINT32 count_ideal;      /*从连接建立起到现在为止，理论上应该到达的数据总长度*/
  UINT32 pktcout;          /*本侧累计到达的包个数*/
  UINT32 totallost;        /*本侧累计丢包长度*/
  UINT32 seq;              /*本侧数据期待的seq序号*/
  UINT32 first_data_seq;   /*本侧数据起始的的seq序号*/
  UINT32 ack_seq;          /*本侧数据最后使用的应答号*/
  UINT16 window;           /*本侧数据滑动窗口大小*/
  UCHAR maxunorder;      /*最大乱序数目*/
  UCHAR finstate;		    /*fin状态*/
  UINT32 pktcout_new;      /*本次新到达的包个数*/
  UINT32 unorder_cnt;
  struct buf_unorder *unorderlist;	/*乱序包的链表*/
  struct buf_unorder *unorderlisttail;	/*乱序包的链表尾部指针*/

};

/* 兼容papp */
struct tuple4 {
  u_int saddr;
  u_int daddr;
  u_short source;
  u_short dest;
};

struct tuple6
{
	UCHAR saddr[16] ;
	UCHAR daddr[16] ;
	UINT16 source;
	UINT16 dest;
};

/* network-order */
struct stream_tuple4_v4{
	UINT32 saddr;	/* network order */
	UINT32 daddr;	/* network order */
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};


#ifndef IPV6_ADDR_LEN
#define IPV6_ADDR_LEN	(sizeof(struct in6_addr))
#endif

struct stream_tuple4_v6
{
	UCHAR saddr[IPV6_ADDR_LEN] ;
	UCHAR daddr[IPV6_ADDR_LEN] ;
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};



#define GRE_TAG_LEN 		(4)
struct layer_addr_gre
{
	UINT16 gre_id;
};


#define VLAN_ID_MASK		(0x0FFF)
#define VLAN_TAG_LEN 		(4)
struct layer_addr_vlan
{
	UINT16 vlan_id;	/* network order */
};

struct layer_addr_pppoe_session
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ver:4;   
	unsigned int type:4;  
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned int type:4; 
	unsigned int ver:4; 
#endif
  	unsigned char code;
	unsigned short session_id;
};

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN		(6)
#endif

struct layer_addr_mac
{
	UCHAR src_mac[MAC_ADDR_LEN]; /* network order */
	UCHAR dst_mac[MAC_ADDR_LEN]; /* network order */
};

struct layer_addr_ipv4
{
	UINT32 saddr; 	/* network order */
	UINT32 daddr; 	/* network order */
	/* 2014-04-21 lijia add, 
	   为了空间、易用性、和效率, 不强制按协议层次处理,
	   IP层存储完整的四元组信息, TCP层只需指针指向此块内存, 
	   插件获取四元组时, 不再需要get_tuple4()函数.
	   对于隧道外层IP, 端口信息为0;
	*/
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};

struct layer_addr_ipv6
{
	UCHAR saddr[IPV6_ADDR_LEN] ; /* network order */
	UCHAR daddr[IPV6_ADDR_LEN] ; /* network order */
	/* 2014-04-21 lijia add, 
	   为了空间、易用性、和效率, 不强制按协议层次处理,
	   IP层存储完整的四元组信息, TCP层只需指针指向此块内存, 
	   插件获取四元组时, 不再需要get_tuple4()函数.
	   对于隧道外层IP, 端口信息为0;
	*/
	UINT16 source;/* network order */
	UINT16 dest;/* network order */
};

struct layer_addr_tcp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};

struct layer_addr_udp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};

struct layer_addr_l2tp
{
	UINT32 tunnelid; /* network order */
	UINT32 sessionid; /* network order */
};

struct layer_addr
{
	UCHAR addrtype; /* 地址类型, 详见 enum addr_type_t */
	/* 为了方便应用插件取地址, 此处使用联合体, 省去指针类型强制转换步骤 */
	union
	{
		struct stream_tuple4_v4 *tuple4_v4;
		struct stream_tuple4_v6 *tuple4_v6;
		struct layer_addr_ipv4	*ipv4;
		struct layer_addr_ipv6	*ipv6;
		struct layer_addr_vlan	*vlan;
		struct layer_addr_mac	*mac;
		struct layer_addr_gre	*gre;
		struct layer_addr_tcp	*tcp;
		struct layer_addr_udp	*udp;
		struct layer_addr_pppoe_session *pppoe_ses;		
		struct layer_addr_l2tp	*l2tp;
		void 					*paddr;
	};
	UCHAR addrlen; /* 地址结构长度 */
};

/* 保留此结构用于和papp兼容, 用作指针时, 可与struct layer_addr强转. */
struct ipaddr
{
	 UCHAR addrtype;
     union
     {
         struct stream_tuple4_v4 *v4;
         struct stream_tuple4_v6 *v6;
     }paddr;
 //  struct tuple4  *paddr;
};


/* to do:
   变量地址对齐问题;
   变量隐藏, 内部变量对外不可见, 将stream.h拆分, 外部插件看到的是stream.h的部分只读视图;
 */
struct streaminfo
{
	struct layer_addr addr;      //本层协议地址信息
	struct streaminfo *pfather;//上层流结构体
	UCHAR type;				   // 链接类型
	UCHAR threadnum;	       // 所属线程
	UCHAR  dir:2;              /*  流的生存期内有效, 流的单、双方向情况0x01:c-->s; 0x02:s-->c;  0x03 c<-->s;  */
	UCHAR  curdir:2;           /* 单包有效, 当前来包上层流的逻辑方向, 0x01:c-->s;  0x02:s-->c */
	UCHAR  layer_dir:2;   /* 单包有效, 当前层的地址是否和默认规则"大端口是客户端"相同 */	
	UCHAR  stream_dir:2; /* 流的生存期内有效, 流的存储的地址是否和默认规则"大端口是客户端"相同  */	
	UCHAR  dirreverse;	     /* 建立连接时是否进行了ip地址反转, 即与"大端口是客户端"规则相反 */
	UCHAR  opstate;		//当前链接所处状态
	UCHAR  pktstate;		//链接的包序列
	UCHAR  routedir;	     /* 物理包方向, 单包有效, 纯人工指定, 仅用于发包时标记是否与来包方向是否相同, 别无他意, 0:上行; 1:下行 */
	UCHAR addr_use_as_hash; /* 本层的addr是否做为HASH计算和比较的参数, 如:MAC地址不参与计算 */

	UCHAR stream_killed_flag; /* 2014-08-22 lijia add, 串联模式下, 已经被插件Kill, 之后此流可直接Drop或Kill, 无需再给上层插件 */
	UCHAR  __pad__[7];		//整体8字节对齐
   	void   *pproject;		//每个工程可以自定义使用；
	void   *pdetail;		//流的详细信息
	const void *p_layer_header; /* 指向本层包头的指针, 用于构造包时获取相关参数 */
	
#if 0 //FOR_108,  ->pproject
	unsigned long stream_id;
#endif

#if 0 //RAW_IP_FRAG_PKT, ->pproject
    raw_ipfrag_list_t *ipfrag_list; /* 2013-08-21 LiJia add, 原始分片包链表 */
#endif

#if 0 //FOR_863,  ->pproject	
	char   terminal_tag[40]; /* 用户标签 */ 
#endif
 };


struct tcpdetail
{

	void  *pdata;		      //数据
	UINT32 datalen;			  //数据长度
	UINT32 lostlen;
	UCHAR  multisynflag:4;	  // multi syn
	UCHAR  needackflag:2;	  //需要上传ack报文
	UCHAR  takeoverflag:2;
	UCHAR  tcpstateflag;	   // 用于记录tcp的会话SYN相关状态
	UCHAR  link_state;		   // 链接的状态
	UCHAR  creat_mod;
	UINT32 regionid;			//地域信息
	
	struct half_tcpstream *pclient;  //到client的TCP连接信息
	struct half_tcpstream *pserver;  //到 server的TCP连接信息
	UINT32 serverpkt;
	UINT32 clientpkt;
	UINT32 servercount;
	UINT32 clientcount;
	UINT64 creattime; 
	UINT64 lastmtime;
	
	UINT32 iserverseq;	  //链接建立时临时存储seq
	UINT32 iclientseq;	  //链接建立时临时存储seq
	void   *apme;		  //应用层上下文
	void   *pAllpktpme;   //无状态的tcp管理上下文
	struct proxy_node    *pproxylist;    //代理的链表,具体代理解析模块负责申请和释放
	
};
struct udpdetail
{
   	  void *pdata;		      //数据
   	  UINT32 datalen;			  //数据长度
	  UINT32 regionid;			//地域信息
	  UINT32 serverpkt;
	  UINT32 clientpkt;
	  UINT32 servercount;
	  UINT32 clientcount;
	  UINT64 creattime; 
	  UINT64 lastmtime;
	  void	 *apme; 					   //应用层上下文
};


//业务层调用解析层时session_state状态
#define SESSION_STATE_PENDING	0x01
#define SESSION_STATE_DATA		0x02
#define SESSION_STATE_CLOSE	0x04

//解析层调用业务层时的返回值；
#define PROT_STATE_GIVEME   	0x01
#define PROT_STATE_DROPME		0x02
#define PROT_STATE_KILLME		0x04

//解析层插件调用业务层插件时传入参数
typedef struct _plugin_session_info
{
	unsigned short  plugid;			//plugid，平台分配
	char session_state;	//会话状态，PENDING,DATA,CLOSE
	char _pad_;			//补齐
	int buflen;			//当前字段长度
	long long prot_flag;	//当前字段的flag值
	void *buf;			//当前字段
	void* app_info;		//解析层上下文信息
}stSessionInfo;
#ifdef __cplusplus
extern "C" {
#endif


/*
	args:
		[IN]:
			stream:流结构体指针;
		[OUT]
			addr_type:四元组类型, ADDR_TYPE_IPV4 or ADDR_TYPE_IPV6;
			
	return value:
		NULL		: error;
		NON-NULL	: 指向四元组结构体的指针;
*/
struct layer_addr *get_stream_tuple4(struct streaminfo *this_stream);
int get_thread_count(void);

typedef char (*STREAM_CB_FUN_T)(struct streaminfo *pstream,void **pme, int thread_seq,const void *raw_pkt);
typedef char (*IPv4_CB_FUN_T)(struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *raw_pkt);
typedef char (*IPv6_CB_FUN_T)(struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *raw_pkt);

/*参数描述：
	a_*：		本流上下文信息;
	f_*:		本包所对应的父流信息;
	raw_pkt:	原始包指针, 实际类型为'raw_pkt_t';
	pme:		私有数据指针，将来扩展用，暂时为NULL;
	thread_seq：线程序号;

函数返回值描述：为下面四个值的运算

	APP_STATE_GIVEME：继续向本函数送包。
	APP_STATE_DROPME：不再向本函数送包。
	APP_STATE_FAWPKT：回注该数据包
	APP_STATE_DROPPKT：不回注该数据包
*/
char IPv4_ENTRY_EXAMPLE( struct streaminfo *f_stream,unsigned char routedir,int thread_seq, const void *raw_pkt);
char IPv6_ENTRY_EXAMPLE( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,const void *raw_pkt);
char TCP_ENTRY_EXAMPLE(struct streaminfo *a_tcp,  void **pme, int thread_seq,const void *raw_pkt);
char UDP_ENTRY_EXAMPLE(struct streaminfo *a_udp,  void **pme, int thread_seq,const void *raw_pkt);

int stream_register_tcp_allpkt (STREAM_CB_FUN_T fun);
int stream_register_tcp_takeover (STREAM_CB_FUN_T fun);

int stream_register_tcp (STREAM_CB_FUN_T fun);
int stream_register_udp (STREAM_CB_FUN_T fun);
int stream_register_ip (IPv4_CB_FUN_T fun);
int stream_register_ipv6 (IPv6_CB_FUN_T fun);


void *dictator_malloc(int thread_seq,size_t size);
void dictator_free(int thread_seq,void *pbuf);
void *dictator_realloc(int thread_seq, void* pbuf, size_t size);

char PROT_PROCESS(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,void *a_packet);

/* 用于应用层插件获取本流中对应的用户标签 */
//int terminal_tag_probe(struct streaminfo *stream, struct mesa_tcp_hdr *this_tcphdr,void *rawippkt);
const unsigned char *get_terminal_tag(struct streaminfo *stream);
//int MESA_kill_tcp(struct streaminfo *stream, struct ip *a_packet);
int MESA_kill_tcp(struct streaminfo *stream, const void *raw_pkt);
int MESA_kill_tcp_synack(struct streaminfo *stream, const void *raw_pkt);

/*
	ARG:
		stream: 流结构体指针;
		payload: 要发送的数据指针;
		payload_len: 要发送的数据负载长度;
		raw_pkt: 原始包指针;
		snd_routedir: 要发送数据的方向, 原始包方向为:stream->routedir , 
			 如果与原始包同向, snd_dir = stream->routedir, 
			 如果与原始包反向, snd_dir = stream->routedir ^ 3(即1<--->2,  2<--->1的数学转换);
	return value:
		-1: error.
		>0: 发送的数据包实际总长度(payload_len + 底层包头长度);
*/
int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, const void *raw_pkt, UCHAR snd_routedir);

/* 2014-07-31 LiJia add, for set one stream unorder number */
int tcp_set_single_stream_max_unorder(struct streaminfo *stream, UCHAR dir, UCHAR unorder_num);

raw_ipfrag_list_t *get_raw_frag_list(struct streaminfo *stream);
//void frags_list_free_one(raw_ipfrag_list_t *frags_list, int);
//raw_ipfrag_list_t *frags_list_merge(raw_ipfrag_list_t *new_merge_list, raw_ipfrag_list_t *old_list);
//raw_ipfrag_list_t *raw_ip_frag_list_attach(int thread_num);
//void raw_ip_frag_list_detach(int thread_num);


unsigned long get_stream_id(struct streaminfo *stream);

void MESA_stream_list_free(struct streaminfo *heap_stream);
struct streaminfo *MESA_stream_list_dup(struct streaminfo *stack_stream, int reverse);
int MESA_stream_list_cmp(struct streaminfo *stream1, struct streaminfo *stream2);

#ifdef __cplusplus
}
#endif



#endif


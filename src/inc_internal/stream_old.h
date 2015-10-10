#ifndef _APP_STREAM_H_
#define _APP_STREAM_H_ 

#include <sys/types.h>
#include <netinet/in.h>            
#include <netinet/ip.h>            
#include <netinet/ip6.h>   
#include <netinet/tcp.h>   
#include <netinet/udp.h>   
#include <stdlib.h>
#include <string.h>

#define FOR_863				(0) /* for 863项目用户标签模块 */
#define FOR_108				(0)
#define RAW_IP_FRAG_PKT          (0) /* 2013-08-21 LiJia add, 保存全部原始IP分片包 */

typedef unsigned char      UINT8;
typedef unsigned long long UINT64;
typedef unsigned int       UINT32;
typedef unsigned short     UINT16;
typedef unsigned char      UCHAR;

//流的方向定义
#define DIR_C2S 0x01
#define DIR_S2C 0x02
#define DIR_DOUBLE 0x03

//单包的方向定义
#define DIR_ROUTE_UP   0x00
#define DIR_ROUTE_DOWN 0x01

//地址类型定义
#define ADDR_TYPE_IPV4			1
#define ADDR_TYPE_IPV6			2
#define ADDR_TYPE_VLAN			3

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
#define STREAM_TYPE_TCP				1
#define STREAM_TYPE_UDP				2
#define STREAM_TYPE_VLAN			3
#define STREAM_TYPE_SOCKS4			4
#define STREAM_TYPE_SOCKS5			5
#define STREAM_TYPE_HTTP_PROXY		6

#define STREAM_TYPE_MPLS			7

#define PROXY_STATE_SEL 0
#define PROXY_STATE_LINK_IN 1


//	代理信息
struct proxy_node
{	
	UINT16 iType;		//	代理类型, 0 表示无效
	UINT16  uiPort;		//	代理的真实服务器端口
	UINT16	uiUserLen;
	UINT16  uiPwdLen;
	UINT16  uiApendLen;
	
	UCHAR  opstate;		//当前链接所处状态
	UCHAR  dealstate;	//代理处理状态	
	UINT32  uiIP;		//	代理的真实服务器IP地址v4, 按网络字节序
	UCHAR	*pIpv6;		//	代理的真实服务器IP地址, v6地址
	UCHAR	*pUser;		//    代理用户名
	UCHAR   *pPwd;		//    代理密码
	UCHAR 	*append;	//   其它附属信息，比如url
	
	void 	*apme;	//   其它附属信息，比如url
	struct proxy_node *pnext;
} ;


#if RAW_IP_FRAG_PKT
typedef struct raw_ipfrag_list{
    void *frag_packet;
    int pkt_len;
    int type; /* IPv4 or IPv6 */
    struct raw_ipfrag_list *next;
}raw_ipfrag_list_t;
#endif

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
#if RAW_IP_FRAG_PKT
    raw_ipfrag_list_t *ipfrag_list;
#endif
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

#ifndef STRUCT_TUPLE4_DEFINED
#define STRUCT_TUPLE4_DEFINED (1)
struct tuple4 {
  UINT32 saddr;
  UINT32 daddr;
  UINT16 source;
  UINT16 dest;
};
#endif

struct tuple6
{
	UCHAR saddr[16] ;
	UCHAR daddr[16] ;
	UINT16 source;
	UINT16 dest;
};

#define VLAN_ID_LEN 4
struct tuplevlan
{
	UCHAR vlan_id[VLAN_ID_LEN];
};

struct tupell2tp
{
	UINT32 tunnelid;
	UINT32 sessionid;
};
struct ipaddr
{
	UCHAR addrtype; //地址类型 ipv6 or ipv4
	union
	{
		struct tuple4	*v4;
		struct tuple6	*v6;
	}paddr;
//	struct tuple4  *paddr;
};

struct streaminfo
{
	struct ipaddr addr;      //ip端口信息
	struct streaminfo *pfather;//上层流结构体
	UCHAR type;				   // 链接类型
	UCHAR threadnum;	       // 所属线程
	UCHAR  dir:2;              //  流的方向情况0x01 c-->s  0x02  s-->c  0x03 c<-->s
	UCHAR  curdir:2;           //  当前来包0x01 c-->s  0x02  s-->c
	UCHAR  dirreverse:4;	     //建立连接时是否进行了ip地址反转  
	UCHAR  opstate;		//当前链接所处状态
	UCHAR  pktstate;		//链接的包序列
	UCHAR  routedir;	     //最高位为1表示上行，为0表示下行; 在串联模式下,低7位表示特殊设备ID
	UCHAR  __pad__[2];		//整体8字节对齐
   	void   *pproject;		//每个工程可以自定义使用；
	void   *pdetail;		//流的详细信息
#if FOR_108
	unsigned long stream_id;
#endif
#if RAW_IP_FRAG_PKT
    raw_ipfrag_list_t *ipfrag_list; /* 2013-08-21 LiJia add, 原始分片包链表 */
#endif

#if FOR_863	
	char   terminal_tag[40]; /* 用户标签 */ 
#endif
 };


struct tcpdetail
{

	void  *pdata;		      //数据
	UINT32 datalen;			  //数据长度	
	UINT32 lostlen;			  //丢包数据长度
	
	UCHAR  multisynflag:4;	  // multi syn
	UCHAR  needackflag:2;	  //需要上传ack报文
	UCHAR  takeoverflag:2;
	UCHAR  tcpstateflag;	   // 用于记录tcp的会话SYN相关状态
	UCHAR  link_state;		   // 链接的状态
	UCHAR  pad[5];
	
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
	  UINT32 pad;
	  UINT32 serverpkt;
	  UINT32 clientpkt;
	  UINT32 servercount;
	  UINT32 clientcount;
	  UINT64 creattime; 
	  UINT64 lastmtime;
	  void	*apme; 					   //应用层上下文
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

/*参数描述：
a_*：		本流上下文信息；
f_*:		本包所对应的父流信息；
a_packet:	原始ip包；
pme:		私有数据指针，将来扩展用，暂时为NULL
thread_seq：并行分析的时候分析当前连接的线程序号

函数返回值描述：为下面四个值的运算

	APP_STATE_GIVEME：继续向本函数送包。
	APP_STATE_DROPME：不再向本函数送包。
	APP_STATE_FAWPKT：回注该数据包
	APP_STATE_DROPPKT：不回注该数据包
*/
char IP_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet);
char IPv6_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip6_hdr *a_packet);
char TCP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet);
char UDP_ENTRY(struct streaminfo *a_udp,  void **pme, int thread_seq,void *a_packet);

int stream_register_tcp_allpkt (char (*x)(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet));
int stream_register_tcp_takeover (char (*x)(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet));

int stream_register_tcp (char (*x)(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet));
int stream_register_udp (char (*x)(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet));
//int stream_register_ip (char (*x)(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet));
int stream_register_ip (char (*x)(struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet));
int stream_register_ipv6 (char (*x)(struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip6_hdr *a_packet));

char * printaddr (struct ipaddr *paddrinfo,int threadindex);


void *dictator_malloc(int thread_seq,int size);
void dictator_free(int thread_seq,void *pbuf);

char PROT_PROCESS(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,void *a_packet);


/* 用于应用层插件获取本流中对应的用户标签 */
int terminal_tag_probe(struct streaminfo *stream, struct tcphdr *this_tcphdr,void *rawippkt);
const unsigned char *get_terminal_tag(struct streaminfo *stream);
int MESA_kill_tcp(struct streaminfo *stream, struct ip *a_packet);

#if RAW_IP_FRAG_PKT
extern raw_ipfrag_list_t **G_IP_FRAG_LIST;
void frags_list_free(raw_ipfrag_list_t *frags_list);
raw_ipfrag_list_t *frags_list_merge(raw_ipfrag_list_t *new_merge_list, raw_ipfrag_list_t *old_list);
#endif

#if FOR_108
unsigned long papp_get_streamid();
#endif


#ifdef __cplusplus
}
#endif



#endif

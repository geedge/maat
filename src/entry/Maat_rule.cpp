#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>//tolower
#include <iconv.h>
#include <sys/types.h>		//inet_pton
#include <sys/socket.h>	//inet_pton
#include <arpa/inet.h>		//inet_pton
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/MESA_handle_logger.h>

#include "Maat_rule.h"
#include "Maat_rule_internal.h"
#include "json2iris.h"
#include "dynamic_array.h"
#include "config_monitor.h"
#include "map_str2int.h"
#include "rulescan.h"
#include "UniversalBoolMatch.h"

int MAAT_FRAME_VERSION_1_2_20151113=0;
const char *maat_module="MAAT Frame";
const char* CHARSET_STRING[]={"CHARSET_NONE","GBK","BIG5","UNICODE","UTF-8"};

int converHextoint(char srctmp)
{
	if(isdigit(srctmp))
	{
		return srctmp-'0';
	}
	else
	{
		char temp=toupper(srctmp);
		temp=temp-'A'+10;
		return temp;
	}
}
int  hex2bin(char *hex,int hex_len,char *binary,int size)
{
	int i=0;
	int resultlen=0;
	int high,low;
	for(i=0;i<hex_len&&size>resultlen; i+=2,resultlen++)
	{
		high=converHextoint(hex[i]);
		low=converHextoint(hex[i+1]);
		binary[resultlen]=high*16+low;
	}
	size=resultlen;
	binary[resultlen]='\0';
	return resultlen;
}
iconv_t maat_iconv_open(struct _Maat_scanner_t* scanner,enum MAAT_CHARSET to,enum MAAT_CHARSET from)
{
	const char *from_s=CHARSET_STRING[from];
	const char *to_s=CHARSET_STRING[to];
	iconv_t cd;
	if(from==CHARSET_GBK&&to==CHARSET_BIG5)
	{
		from_s="gb2312";
	}
	if(from>=MAX_CHARSET_NUM||to>=MAX_CHARSET_NUM)
	{
		return (iconv_t)-1;
	}

	if(scanner->iconv_handle[to][from]==NULL)
	{
		scanner->iconv_handle[to][from]=iconv_open(to_s, from_s);
	}
	cd=scanner->iconv_handle[to][from];
	return cd;
}
int iconv_convert(struct _Maat_scanner_t* scanner,enum MAAT_CHARSET from,enum MAAT_CHARSET to,char *src,int srclen,char *dst,int *dstlen)
{
	size_t ret;
	int copy_len=0;
	char* copy_buf=NULL;
	if(srclen==0||src==NULL)
	{
		return -1;
	}
	iconv_t cd=maat_iconv_open(scanner,to, from);
	if(cd!=(iconv_t)-1)
	{
		char * pInBuff=src;
		size_t iInBuffLen=srclen;

		size_t iOutBuffLen=10*iInBuffLen;
		char * pOutBuff=(char *)malloc(iOutBuffLen);

		char * pLeftBuff=pOutBuff;
		size_t iLeftLen=iOutBuffLen;

		ret=iconv(cd, &pInBuff, &iInBuffLen, &pLeftBuff, &iLeftLen);
		if(ret!=(size_t)(-1))
		{
			
			if(to==CHARSET_UNICODE)//jump unicode 2 bytes head 0xFF 0xFE
			{
				copy_len=iOutBuffLen-iLeftLen-2;
				copy_buf=pOutBuff+2;
			}
			else
			{
				copy_len=iOutBuffLen-iLeftLen;
				copy_buf=pOutBuff;
			}
			assert(copy_len<=*dstlen);
			*dstlen=copy_len;
			memcpy(dst,copy_buf,*dstlen);
			
			free(pOutBuff);
			return 1;
		}
		else
		{
			free(pOutBuff);
			return -1;
		}
	}
	else
	{
		return -1;
	}

}

char* strlwr(char* string)
{
	int i=0;
	for(i=0;i<(int)strlen(string);i++)
	{
		string[i]=(char)tolower(string[i]);
	}
	return string;
}
char * strchr_esc(char* s,const char delim)
{
	char *token;
	if(s==NULL)
		return NULL;
	for(token=s;*token!='\0';token++)
	{
		if(*token=='\\')
		{
			token++;
			continue;
		}
		if(*token==delim)
			break;
	}
	if (*token == '\0')
	{ 
		return NULL;
	}
	else
	{
		return token;
	}
}
char *strtok_r_esc(char *s, const char delim, char **save_ptr) {  
    char *token;  
  
    if (s == NULL) s = *save_ptr;  
  
    /* Scan leading delimiters.  */
	token=strchr_esc(s,delim);
	if(token==NULL)
	{
		*save_ptr=token;
		return s;
	}
    /* Find the end of the token.  */  
	*token='\0';
	token++;
	*save_ptr=token;

    return s;  
}   
char *str_unescape_and(char*s)
{
	int i=0,j=0;
	for(i=0,j=0;i<(int)strlen(s);i++)
	{
		if(s[i]=='\\'&&s[i+1]=='&')
		{
			s[j]='&';
			i++;
			j++;
		}
		else{
			s[j]=s[i];
			j++;
		}
	}
	s[j]='\0';
	return s;
}
int cnt_maskbits(struct in6_addr mask)
{
	unsigned int i=0;
	int bits_cnt=0;
	unsigned char* p=(unsigned char*)&mask;
	for(i=0;i<sizeof(mask);i++)
	{
		for(;p[i]>0;p[i]=p[i]/2)
		{
			bits_cnt++;
		}
	}
	return bits_cnt;
}
inline void ipv6_ntoh(unsigned int *v6_addr)
{
	unsigned int i=0;
	for(i=0;i<4;i++)
	{
		v6_addr[i]=ntohl(v6_addr[i]);
	}
	return;
}
int aligment_int_array_sum(int * array,int size)
{	
	int sum=0,i=0;
	int offset=0;
	for(i=0;i<size;i++)
	{
		offset=(CPU_CACHE_ALIGMENT/sizeof(int))*i;
		sum+=array[offset];
	}
	return sum;
}
int lqueue_destroy_cb(void *data, long data_len, void *arg)
{
	assert(0);
}
void * HASH_fetch_by_id(MESA_htable_handle hash,int id)
{
	return MESA_htable_search(hash,(unsigned char*)&(id),sizeof(id));
}
int HASH_add_by_id(MESA_htable_handle hash,int id,void*data)
{
	int ret=0;
	ret=MESA_htable_add(hash
					,(unsigned char*)&(id)
					,sizeof(id)
					,data);
	return ret;
}
int HASH_delete_by_id(MESA_htable_handle hash,int id)
{
	//destroy function had been initialized when hash create.
	int ret=-1;
	ret=MESA_htable_del(hash,(unsigned char*)&id, sizeof(id), NULL);
	return ret;
}
int read_table_info(struct _Maat_table_info_t** p_table_info,int num,const char* table_info_path)
{
	FILE*fp=NULL;
	char line[MAX_TABLE_LINE_SIZE];
	int i=0,j=0,ret[4]={0},table_cnt=0;
	char table_type[16],src_charset[16],dst_charset[64],merge[4];
	MESA_htable_handle string2int_map=map_create();
	char *token=NULL,*sub_token=NULL,*saveptr;
	struct _Maat_table_info_t*p=NULL;
	
	map_register(string2int_map,"expr", TABLE_TYPE_EXPR);
	map_register(string2int_map,"ip", TABLE_TYPE_IP);
	map_register(string2int_map,"compile", TABLE_TYPE_COMPILE);
	map_register(string2int_map,"plugin", TABLE_TYPE_PLUGIN);
	map_register(string2int_map,"intval", TABLE_TYPE_INTVAL);
	map_register(string2int_map,"group", TABLE_TYPE_GROUP);
	map_register(string2int_map,"bin", CHARSET_NONE);
	map_register(string2int_map,"gbk", CHARSET_GBK);
	map_register(string2int_map,"big5", CHARSET_BIG5);
	map_register(string2int_map,"unicode", CHARSET_UNICODE);
	map_register(string2int_map,"utf8", CHARSET_UTF8);
	map_register(string2int_map,"yes", 1);
	map_register(string2int_map,"no", 0);
	
	fp=fopen(table_info_path,"r");
	if(fp==NULL)
	{
		fprintf(stderr,"Maat read table info %s error.\n",table_info_path);
	}
	while(NULL!=fgets(line,sizeof(line),fp))
	{
		i++;

		if(line[0]=='#'||line[0]==' '||line[0]=='\t'||strlen(line)<4)
		{
			continue;
		}
		p=(struct _Maat_table_info_t*)calloc(sizeof(struct _Maat_table_info_t),1);
		p->cross_cache_size=0;
		sscanf(line,"%hu\t%s\t%s\t%s\t%s\t%s\t%d",&(p->table_id)
											,p->table_name
											,table_type
											,src_charset
											,dst_charset
											,merge
											,&(p->cross_cache_size));
		ret[0]=map_str2int(string2int_map,strlwr(table_type),(int*)&(p->table_type));
		ret[1]=map_str2int(string2int_map,strlwr(src_charset),(int*)&(p->src_charset));
		ret[2]=map_str2int(string2int_map,strlwr(merge),&(p->do_charset_merge));
		for(j=0;j<3;j++)
		{
			if(ret[j]<0)
			{
				fprintf(stderr,"Maat read table info %s line %d error.\n",table_info_path,i);
				goto error_jump;
			}
		}
		j=0;
		for (token = dst_charset; ; token= NULL)
		{
			sub_token= strtok_r(token,"/", &saveptr);
			if (sub_token == NULL)
				break;
			ret[3]=map_str2int(string2int_map,strlwr(sub_token),(int*)&(p->dst_charset[j]));
			if(ret[3]>0)
			{
				if(p->dst_charset[j]==p->src_charset)
				{
					p->src_charset_in_dst=TRUE;
				}
				j++;
			}
			else
			{
				fprintf(stderr,"Maat read table info %s line %d error.\n",table_info_path,i);
				goto error_jump;
			}
			
		}
		if(p->table_id>=num)
		{
			fprintf(stderr,"Maat read table info %s line %d error: table id %uh > %d.\n",table_info_path,i,p->table_id,num);
			goto error_jump;
		}
		if(p_table_info[p->table_id]!=NULL)
		{
			fprintf(stderr,"Maat read table info %s line %d error:duplicated table id %d.\n",table_info_path,i,p->table_id);
			goto error_jump;
		}
		if(p->table_type==TABLE_TYPE_PLUGIN)
		{
			p->cb_info=(struct _plugin_table_info*)calloc(sizeof(struct _plugin_table_info),1);
			p->cb_info->cache_lines=dynamic_array_create(1024,1024);
		}
		p_table_info[p->table_id]=p;
		table_cnt++;
		continue;
error_jump:
		free(p);
		p=NULL;
	}
	fclose(fp);
	map_destroy(string2int_map);
	return table_cnt;
}
struct _Maat_group_rule_t* create_group_rule(int group_id)
{
	struct _Maat_group_rule_t* group=(struct _Maat_group_rule_t*)malloc(sizeof(struct _Maat_group_rule_t));
	group->group_id=group_id;
	group->region_cnt=0;
	group->region_boundary=0;
	group->ref_cnt=0;
	group->region_rules=dynamic_array_create(1,8);
	group->compile_shortcut=NULL;
	pthread_mutex_init(&(group->mutex), NULL);
	return group;
}
void destroy_group_rule(struct _Maat_group_rule_t* group)
{

	if(group->ref_cnt>0||group->region_cnt>0)
	{
		return;
	}

	dynamic_array_destroy(group->region_rules,free);
	group->region_cnt=0;
	group->region_boundary=0;
	group->region_rules=NULL;
	group->ref_cnt=0;
	group->group_id=-1;
	pthread_mutex_destroy(&(group->mutex));
	free(group);

}
void make_group_set(const struct _Maat_compile_rule_t* compile_rule,universal_bool_expr_t* a_set)
{
	int i=0,j=0;
	a_set->bool_expr_id=(void*)compile_rule;
	struct _Maat_group_rule_t*group=NULL;
	assert(MAAT_MAX_EXPR_ITEM_NUM<=MAX_ITEMS_PER_BOOL_EXPR);
	for(i=0,j=0;i<MAAT_MAX_EXPR_ITEM_NUM&&j<MAX_ITEMS_PER_BOOL_EXPR;i++)
	{
		group=(struct _Maat_group_rule_t*)dynamic_array_read(compile_rule->groups,i);
		if(group==NULL)
		{
			continue;
		}
		a_set->bool_item_ids[j]=group->group_id;
		j++;
	}
	assert(j==compile_rule->group_cnt);
	a_set->bool_item_num=j;
}
void walk_compile_hash(const uchar * key, uint size, void * data, void * user)
{
	universal_bool_expr_t* one_set=NULL;
	struct _Maat_compile_rule_t* compile_rule=(struct _Maat_compile_rule_t*)data;
	MESA_lqueue_head update_q=(MESA_lqueue_head)user;
	if(compile_rule->db_c_rule==NULL)
	{
		return;
	}
	//make sure compile rule's each group has loadded.
	if((compile_rule->group_cnt==compile_rule->db_c_rule->declare_grp_num
		||compile_rule->db_c_rule->declare_grp_num==0)//for compatible old version
		&&compile_rule->group_cnt>0)
	{
		one_set=(universal_bool_expr_t*)malloc(sizeof(universal_bool_expr_t));
		//reading compile rule is safe in update thread, mutex lock called when modified
		make_group_set(compile_rule, one_set);
		MESA_lqueue_join_tail(update_q,&one_set, sizeof(void*));//put the pointer into queue
	}
	return;
}
void* create_bool_matcher(MESA_htable_handle compile_hash,int thread_num,void* logger)
{
	void* bool_matcher=NULL;
	MESA_lqueue_head update_q=MESA_lqueue_create(0,0);;
	long data_size=0;
	unsigned int mem_size=0;
	MESA_queue_errno_t q_ret=MESA_QUEUE_RET_OK; 	
	data_size=sizeof(void*);
	universal_bool_expr_t* one_set=NULL;
	universal_bool_expr_t* set_array=NULL;
	int i=0;
	MESA_htable_iterate(compile_hash, walk_compile_hash, update_q);
	
	const long q_cnt=MESA_lqueue_get_count(update_q);
	set_array=(universal_bool_expr_t*)malloc(sizeof(universal_bool_expr_t)*q_cnt);
	for(i=0;i<q_cnt;i++)
	{
		q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(update_q,&one_set,&data_size);
		assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
		memcpy(set_array+i,one_set,sizeof(universal_bool_expr_t));
		free(one_set);
		one_set=NULL;
	}
	bool_matcher=boolexpr_initialize(set_array, q_cnt, thread_num, &mem_size);
	if(bool_matcher!=NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module,
								"build bool matcher contain %ld compile rule, use %u memory",
								q_cnt,mem_size);
	}
	else
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module,
								"build bool matcher failed!",
								q_cnt,mem_size);
	}
	free(set_array);
	set_array=NULL;
	MESA_lqueue_destroy(update_q,lqueue_destroy_cb,NULL);
	return bool_matcher;

}
void destroy_bool_matcher(void * bool_matcher)
{
	boolexpr_destroy(bool_matcher);
	return;

}
void EMPTY_FREE(void*p)
{
	return;
}
struct _Maat_compile_rule_t * create_compile_rule(int compile_id)
{
	struct _Maat_compile_rule_t* p=NULL;
	p=(struct _Maat_compile_rule_t*)calloc(sizeof(struct _Maat_compile_rule_t),1);
	p->compile_id=compile_id;
	p->group_cnt=0;
	p->groups=dynamic_array_create(1, 1);
	pthread_rwlock_init(&(p->rwlock), NULL);
	return p;
}
void destroy_compile_rule(struct _Maat_compile_rule_t * p)
{
	int i=0;
	struct _Maat_compile_rule_t* p_group=NULL;
	assert(p->group_cnt==0);
	for(i=0;i<MAAT_MAX_EXPR_ITEM_NUM;i++)
	{
		p_group=(struct _Maat_compile_rule_t*)dynamic_array_read(p->groups,i);
		assert(p_group==NULL);
	}
	p->compile_id=-1;
	dynamic_array_destroy(p->groups,NULL);
	if(p->db_c_rule!=NULL)
	{
		free(p->db_c_rule);
	}
	pthread_rwlock_destroy(&(p->rwlock));
	free(p);
}
scan_rule_t* create_rs_str_rule(unsigned int sub_type,enum MAAT_MATCH_METHOD match_method,int is_case_sensitive,const char* string,int len,int l_offset,int r_offset)
{
	scan_rule_t* p_rule=(scan_rule_t* )calloc(sizeof(scan_rule_t),1);
	p_rule->rule_type=RULETYPE_STR;
	p_rule->sub_type=sub_type;
	
	p_rule->string_rule.case_sensitive=is_case_sensitive;
	p_rule->string_rule.match_mode=0;
	p_rule->string_rule.l_offset=-1;
	p_rule->string_rule.r_offset=-1;
	switch(match_method)
	{
		case MATCH_METHOD_FULL:
			p_rule->string_rule.match_mode=1;
			break;
		case MATCH_METHOD_LEFT:
			p_rule->string_rule.l_offset=-2;
			break;
		case MATCH_METHOD_RIGHT:
			p_rule->string_rule.r_offset=-2;
			break;
		case MATCH_METHOD_SUB:
			p_rule->string_rule.l_offset=l_offset;
			p_rule->string_rule.r_offset=r_offset;			
			break;
		default:
			assert(0);
			break;	
	}
	p_rule->string_rule.len=len;
	p_rule->string_rule.str=(char*)calloc(sizeof(char),len);
	memcpy(p_rule->string_rule.str,string,len);
	return p_rule;

}
void destroy_rs_str_rule(scan_rule_t* p_rule)
{
	free(p_rule->string_rule.str);
	free(p_rule);
}
scan_rule_t* create_rs_ip_rule(unsigned int sub_type,struct db_ip_rule_t *db_ip_rule)
{
	scan_rule_t *p_rule=(scan_rule_t*)calloc(sizeof(scan_rule_t),1);
	if(db_ip_rule->addr_type==4)
	{
		p_rule->rule_type=RULETYPE_IPv4;
		memcpy(&(p_rule->ipv4_rule),&(db_ip_rule->ipv4_rule),sizeof(p_rule->ipv4_rule));
	}
	else
	{
		p_rule->rule_type=RULETYPE_IPv6;
		memcpy(&(p_rule->ipv6_rule),&(db_ip_rule->ipv6_rule),sizeof(p_rule->ipv6_rule));
	}
	p_rule->sub_type=sub_type;
	return p_rule;
}
void destroy_rs_ip_rule(scan_rule_t* p)
{
	free(p);
}
scan_rule_t* create_rs_intval_rule(unsigned int sub_type,struct db_intval_rule_t *intval_rule)
{
	scan_rule_t *p_rule=(scan_rule_t*)calloc(sizeof(scan_rule_t),1);
	p_rule->rule_type=RULETYPE_INT;
	p_rule->sub_type=sub_type;
	p_rule->interval_rule.lb=intval_rule->intval.lb;
	p_rule->interval_rule.ub=intval_rule->intval.ub;
	return p_rule;
}
void destroy_rs_intval_rule(scan_rule_t* p)
{
	free(p);
}

struct op_expr_t* create_op_expr(unsigned int expr_id,int operation,void* u_para)
{
	struct op_expr_t* op_expr=NULL;
	op_expr=(struct op_expr_t*)calloc(sizeof(struct op_expr_t),1);
	op_expr->p_expr=(boolean_expr_t*)calloc(sizeof(boolean_expr_t),1);
	op_expr->p_expr->expr_id=expr_id;
	op_expr->p_expr->operation=operation;
	op_expr->p_expr->rnum=0;
	op_expr->p_expr->rules=NULL;
	op_expr->p_expr->tag=u_para;
	return op_expr;
}
void destroy_op_expr(struct op_expr_t*  op_expr)
{
	unsigned int i=0;
	for(i=0;i<op_expr->p_expr->rnum;i++)
	{
		switch(op_expr->p_rules[i]->rule_type)
		{
			case RULETYPE_STR:
			case RULETYPE_REG:
				destroy_rs_str_rule(op_expr->p_rules[i]);
				break;
			case RULETYPE_IPv4:
			case RULETYPE_IPv6:
				destroy_rs_ip_rule(op_expr->p_rules[i]);
				break;
			case RULETYPE_INT:
				destroy_rs_intval_rule(op_expr->p_rules[i]);
				break;
			default:
				assert(0);
				break;
		}
		op_expr->p_rules[i]=NULL;
	}
	free(op_expr->p_expr);
	op_expr->p_expr=NULL;
	free(op_expr);
}
void op_expr_add_rule(struct op_expr_t* op_expr,scan_rule_t* p_rule)
{
	int idx=op_expr->p_expr->rnum;
	op_expr->p_rules[idx]=p_rule;
	op_expr->p_expr->rnum++;
	return;
}

struct _Maat_scanner_t* create_maat_scanner(unsigned int version,int scan_thread_num,MESA_lqueue_head tomb)
{
	
	MESA_htable_create_args_t hargs;
	memset(&hargs,0,sizeof(hargs));
	hargs.thread_safe=0;
	hargs.hash_slot_size = 1024*1024;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_LRU;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;
	hargs.recursive = 0; 
//	hargs.data_free = _void_destroy_compile_rule;
	hargs.data_free = EMPTY_FREE;

	hargs.data_expire_with_condition = NULL;

	struct _Maat_scanner_t* scanner=NULL;
	scanner=(struct _Maat_scanner_t*)calloc(sizeof(struct _Maat_scanner_t),1);

	scanner->compile_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(scanner->compile_hash,0);


	hargs.data_free=EMPTY_FREE;
	scanner->group_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(scanner->group_hash,0);


	scanner->region_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(scanner->group_hash,0);
	
	scanner->version=version;
	scanner->cfg_num=0;
	scanner->max_thread_num=scan_thread_num;
	//optimized for CPU cache_alignment 64
	scanner->ref_cnt=(int*)calloc(CPU_CACHE_ALIGMENT,scan_thread_num);
	scanner->region_update_q=MESA_lqueue_create(0,0);
	scanner->region=rulescan_initialize(scan_thread_num);
	scanner->tomb_ref=tomb;
	scanner->region_rslt_buff=(scan_result_t*)malloc(sizeof(scan_result_t)*MAX_SCANNER_HIT_NUM*scan_thread_num);

	return scanner;
}



void destroy_maat_scanner(struct _Maat_scanner_t*scanner)
{
	long q_cnt=0,data_size=0;
	int i=0,j=0,q_ret=0;
	struct op_expr_t* op_expr=NULL;
	rulescan_destroy(scanner->region);
	MESA_htable_destroy(scanner->compile_hash,NULL);
	MESA_htable_destroy(scanner->group_hash, NULL);
	MESA_htable_destroy(scanner->region_hash, NULL);

	destroy_bool_matcher((void*)scanner->expr_compiler);
	q_cnt=MESA_lqueue_get_count(scanner->region_update_q);
	for(i=0;i<q_cnt;i++)
	{
		data_size=sizeof(struct op_expr_t*);
		q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(scanner->region_update_q,&op_expr,&data_size);
		assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
		destroy_op_expr(op_expr);
	}	
	MESA_lqueue_destroy(scanner->region_update_q, lqueue_destroy_cb, NULL);
	free(scanner->region_rslt_buff);
	scanner->region_rslt_buff=NULL;
	free(scanner->ref_cnt);
	scanner->ref_cnt=NULL;
	for(i=0;i<MAX_CHARSET_NUM;i++)
	{
		for(j=0;j<MAX_CHARSET_NUM;j++)
		{
			if(scanner->iconv_handle[i][j]!=NULL)
			{
				iconv_close(scanner->iconv_handle[i][j]);
			}
		}
	}
	free(scanner);
	return;
}


inline unsigned int make_sub_type(unsigned short table_id,enum MAAT_CHARSET charset,int do_charset_merge)
{
	unsigned int sub_type=0;
	if(do_charset_merge==TRUE)
	{
		sub_type=table_id<<4|CHARSET_NONE;
	}
	else
	{
		sub_type=table_id<<4|charset;
	}
	assert(sub_type<MAX_SUB_RULETYPE);
	return sub_type;
}


void destroy_ip_expr(boolean_expr_t*p)
{
	free(p->rules);
	free(p);
	return;
}


void batch_update(rule_scanner_t scanner,MESA_lqueue_head expr_queue,void*logger)
{
	long i=0,data_size=0;
	int j=0,ret=0;
	unsigned int failed_ids[MAX_FAILED_NUM];
	char failed_info[512],*p=NULL;
	MESA_queue_errno_t q_ret=MESA_QUEUE_RET_OK; 
	memset(failed_ids,0,sizeof(failed_ids));
	memset(failed_info,0,sizeof(failed_info));
	const long q_cnt=MESA_lqueue_get_count(expr_queue);
	if(q_cnt==0)
	{
		return;
	}
	boolean_expr_t* to_update_expr=(boolean_expr_t*)calloc(sizeof(boolean_expr_t),q_cnt);
	struct op_expr_t* op_expr=NULL;
	for(i=0;i<q_cnt;i++)
	{
		data_size=sizeof(void*);
		q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(expr_queue,&op_expr,&data_size);
		assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
		memcpy(&(to_update_expr[i]),op_expr->p_expr,sizeof(boolean_expr_t));
		//make a whole memory chunk
		to_update_expr[i].rules=(scan_rule_t*)calloc(sizeof(scan_rule_t),op_expr->p_expr->rnum);
		for(j=0;j<(int)op_expr->p_expr->rnum;j++)
		{
			memcpy(&(to_update_expr[i].rules[j]),op_expr->p_rules[j],sizeof(scan_rule_t));
			if(to_update_expr[i].rules[j].rule_type==RULETYPE_REG||to_update_expr[i].rules[j].rule_type==RULETYPE_STR)
			{
				to_update_expr[i].rules[j].string_rule.str=(char*)calloc(sizeof(char),to_update_expr[i].rules[j].string_rule.len);
				memcpy(to_update_expr[i].rules[j].string_rule.str
					,op_expr->p_rules[j]->string_rule.str
					,to_update_expr[i].rules[j].string_rule.len);
			}
		}
		destroy_op_expr(op_expr);
		op_expr=NULL;
	}
	ret=rulescan_update(scanner, to_update_expr,q_cnt, failed_ids,MAX_FAILED_NUM);

	if(ret!=1)
	{
		p=failed_info;
		for(i=0;i<failed_ids[0]&&i<MAX_FAILED_NUM-1&&sizeof(failed_info)-(p-failed_info)>10;i++)
		{
			p+=snprintf(p,sizeof(failed_info)-(p-failed_info),"%d,",failed_ids[i+1]);
		}
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"rulescan_update error,when batch update %ld rules,regex error %u.",q_cnt,failed_ids[0]);
	}
	for(i=0;i<q_cnt;i++)
	{
		for(j=0;j<(int)to_update_expr[i].rnum;j++)
		{
			if(to_update_expr[i].rules[j].rule_type==RULETYPE_REG||to_update_expr[i].rules[j].rule_type==RULETYPE_STR)
			{
				free(to_update_expr[i].rules[j].string_rule.str);
			}
		}
		free(to_update_expr[i].rules);
	}
	free(to_update_expr);
}



struct _Maat_group_rule_t* add_region_to_group(struct _Maat_group_rule_t* group,int region_id,int expr_id,enum MAAT_TABLE_TYPE region_type)
{
	struct _Maat_region_rule_t* region_rule=(struct _Maat_region_rule_t*)malloc(sizeof(struct _Maat_region_rule_t));
	region_rule->region_id=region_id;
	region_rule->expr_id=expr_id;
	region_rule->region_type=region_type;
	pthread_mutex_lock(&(group->mutex));
	dynamic_array_write(group->region_rules,group->region_boundary,region_rule);
	group->region_cnt++;
	group->region_boundary++;
	pthread_mutex_unlock(&(group->mutex));
	return group;
}
unsigned int del_region_from_group(struct _Maat_group_rule_t* group,int region_id,unsigned int *output_expr_id,int output_size)
{
	int i=0,j=0;
	struct _Maat_region_rule_t* region_rule=NULL;
	pthread_mutex_lock(&(group->mutex));
	for(i=0;i<group->region_boundary;i++)
	{
		region_rule=(struct _Maat_region_rule_t*)dynamic_array_read(group->region_rules, i);
		if(region_rule==NULL)
		{
			continue;
		}
		if(region_rule->region_id==region_id)
		{
			dynamic_array_write(group->region_rules, i, NULL);
			output_expr_id[j]=region_rule->expr_id;
			j++;
			assert(j<=output_size);
			
			free(region_rule);
			region_rule=NULL;
			
			group->region_cnt--;
		}
	}
	pthread_mutex_unlock(&(group->mutex));
	return j;
}

int add_group_to_compile(struct _Maat_compile_rule_t*a_compile_rule,struct _Maat_group_rule_t* a_rule_group)
{
	int i=0,ret=-1;
	struct _Maat_group_rule_t* p=NULL;
	pthread_rwlock_wrlock(&(a_compile_rule->rwlock));
	if(a_compile_rule->db_c_rule!=NULL
		&&a_compile_rule->group_cnt>=a_compile_rule->db_c_rule->declare_grp_num
		&&a_compile_rule->db_c_rule->declare_grp_num!=0)
	{
		ret=-1;
	}
	else
	{
		for(i=0;i<MAAT_MAX_EXPR_ITEM_NUM;i++)
		{
			p=(struct _Maat_group_rule_t*)dynamic_array_read(a_compile_rule->groups,i);
			if(p==NULL)
			{
				dynamic_array_write(a_compile_rule->groups,i, a_rule_group);
				a_compile_rule->group_cnt++;
				a_rule_group->ref_cnt++;
				//variable compile_shortcut may set to NULL and compile rule pointer repeatly,until rule build finish.
				if(a_rule_group->ref_cnt==1&&a_compile_rule->group_cnt==1)
				{
					a_rule_group->compile_shortcut=a_compile_rule;
				}
				else
				{
					a_rule_group->compile_shortcut=NULL;
				}
				ret=1;
				break;
			}
			else
			{
				if(p->group_id==a_rule_group->group_id)//duplicate group
				{
					ret=-1;
					
				}
			}
		}
		if(i==MAAT_MAX_EXPR_ITEM_NUM)
		{
			ret=-1;
		}
		//update group's shortcut when compile has more than one group.
		if(a_compile_rule->group_cnt!=1)
		{
			for(i=0;i<MAAT_MAX_EXPR_ITEM_NUM;i++)
			{
				p=(struct _Maat_group_rule_t*)dynamic_array_read(a_compile_rule->groups,i);
				if(p!=NULL)
				{
					p->compile_shortcut=NULL;
				}
			}
		}
	}
	pthread_rwlock_unlock(&(a_compile_rule->rwlock));

	return ret;
}
struct _Maat_group_rule_t* del_group_from_compile(struct _Maat_compile_rule_t*a_compile_rule,int group_id)
{
	int i=0;
	struct _Maat_group_rule_t* group_rule=NULL;
	pthread_rwlock_wrlock(&(a_compile_rule->rwlock));
	for(i=0;i<MAAT_MAX_EXPR_ITEM_NUM;i++)
	{
		group_rule=(struct _Maat_group_rule_t*)dynamic_array_read(a_compile_rule->groups,i);
		if(group_rule==NULL)
		{
			continue;
		}
		if(group_rule->group_id==group_id)
		{
			group_rule->ref_cnt--;
			dynamic_array_write(a_compile_rule->groups,i,NULL);
			a_compile_rule->group_cnt--;
			pthread_rwlock_unlock(&(a_compile_rule->rwlock));
			return group_rule;
		}
	}
	pthread_rwlock_unlock(&(a_compile_rule->rwlock));
	return NULL;
}
int MAAT_MAGIC=0xaaaa;
int sync_region(MESA_htable_handle region_hash,int region_id,const char* table_name,int is_valid,void*logger)
{
	int ret=-1;
	if(is_valid==TRUE)
	{
		ret=HASH_add_by_id(region_hash,region_id,&MAAT_MAGIC);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
								"region id %d of table %s is not unique.",region_id,table_name);
			return -1;
		}
		
	}
	else
	{
		ret=HASH_delete_by_id(region_hash,region_id);
		if(ret==-1)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
								"region delete error,id %d in table %s does not exisit."
								,region_id
								,table_name);
			return -1;
		}
	}
	return 1;
}
int add_expr_rule(struct _Maat_table_info_t* table,struct db_str_rule_t* db_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	unsigned int i=0,j=0;
	char* p=NULL,*saveptr=NULL,*region_string=NULL;
	int region_str_len=0,ret=0,k=0;
	int expr_id=0;
	
	scan_rule_t*p_rule=NULL;
	struct _Maat_group_rule_t* group_rule=NULL;
	enum MAAT_CHARSET dst_charset=CHARSET_NONE;
	char *sub_key_array[MAAT_MAX_EXPR_ITEM_NUM];
	int key_left_offset[MAAT_MAX_EXPR_ITEM_NUM]={-1},key_right_offset[MAAT_MAX_EXPR_ITEM_NUM]={-1};
	for(i=0;i<MAAT_MAX_EXPR_ITEM_NUM;i++)
	{
		key_left_offset[i]=-1;
		key_right_offset[i]=-1;
	}
	int sub_expr_cnt=0;
	struct op_expr_t *op_expr=NULL;
	struct _Maat_group_rule_t* u_para=NULL;
	
	group_rule=(struct _Maat_group_rule_t*)HASH_fetch_by_id(scanner->group_hash, db_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(db_rule->group_id);
		HASH_add_by_id(scanner->group_hash, db_rule->group_id, group_rule);
	}
	switch(db_rule->expr_type)
	{
		case EXPR_TYPE_AND:
			if(db_rule->match_method!=MATCH_METHOD_SUB)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
				"Table %s region cfg %d is EXPR_TYPE_AND,but match method is not MATCH_METHOD_SUB,force fixed.",
				table->table_name,db_rule->region_id);
				db_rule->match_method=MATCH_METHOD_SUB;
					
			}
			for(i=0,p=db_rule->keywords;;i++,p=NULL)
			{
				if(i>=MAAT_MAX_EXPR_ITEM_NUM)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d too many expr.",table->table_name,db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=strtok_r_esc(p,'&',&saveptr);
				if(sub_key_array[i]==NULL)
				{
					break;
				}
				sub_key_array[i]=str_unescape_and(sub_key_array[i]);
			}
			sub_expr_cnt=i;
			table->expr_rule_cnt++;
			break;
		case EXPR_TYPE_OFFSET:
			for(i=0,p=db_rule->keywords;;i++,p=NULL)
			{
				if(i>=MAAT_MAX_EXPR_ITEM_NUM)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d too many expr.",table->table_name,db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=strtok_r_esc(p,'&',&saveptr);
				if(sub_key_array[i]==NULL)
				{
					break;
				}
				sscanf(sub_key_array[i],"%d-%d:",&(key_left_offset[i]),&(key_right_offset[i]));
				if(!(key_left_offset[i]>=0&&key_right_offset[i]>0&&key_left_offset[i]<key_right_offset[i]))
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d invalid offset.",table->table_name,db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=(char*)memchr(sub_key_array[i],':',strlen(sub_key_array[i]));
				if(sub_key_array[i]==NULL)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d invalid keywords format.",table->table_name,db_rule->region_id);
					return -1;
				}
				sub_key_array[i]++;//jump over ':'
				sub_key_array[i]=str_unescape_and(sub_key_array[i]);
			}
			sub_expr_cnt=i;
			table->expr_rule_cnt++;
			break;
		case EXPR_TYPE_REGEX://it's easy,no need to charset convert
			expr_id=scanner->exprid_generator++;
			u_para=add_region_to_group(group_rule,db_rule->region_id,expr_id,TABLE_TYPE_EXPR);
			if(u_para==NULL)
			{
				return -1;
			}
			op_expr=create_op_expr(expr_id
						,0
						,u_para);
			for(i=0,p=db_rule->keywords;;i++,p=NULL)
			{
				if(i>=MAAT_MAX_EXPR_ITEM_NUM)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d too many expr.",table->table_name,db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=strtok_r_esc(p,'&',&saveptr);
				if(sub_key_array[i]==NULL)
				{
					break;
				}
				sub_key_array[i]=str_unescape_and(sub_key_array[i]);
				p_rule=create_rs_str_rule(make_sub_type(table->table_id,CHARSET_NONE,0)
										,MATCH_METHOD_SUB//not care db_rule->match_method
										,db_rule->is_case_sensitive
										,sub_key_array[i]
										,strlen(sub_key_array[i])
										,-1
										,-1);
				p_rule->rule_type=RULETYPE_REG;
				op_expr_add_rule(op_expr, p_rule);
			
			}
			MESA_lqueue_join_tail(scanner->region_update_q,&op_expr, sizeof(void*));
			table->regex_rule_cnt++;
			return 0;//yes,we returned.
			break;
		case EXPR_TYPE_STRING:
			sub_expr_cnt=1;
			sub_key_array[0]=db_rule->keywords;
			sub_key_array[0]=str_unescape_and(sub_key_array[0]);
			table->expr_rule_cnt++;
			break;
		default:
			break;
	}
	for(k=0;k<sub_expr_cnt;k++)
	{
		if(strlen(sub_key_array[k])==0)// keyword like "aa&&cc" or "aa&bb&" will cause strlen==0
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
					"Table %s region cfg %d has an empty sub string.",
					table->table_name,db_rule->region_id);
			//this sub string will jump over before iconv_convert
		}
	}
	if(db_rule->is_hexbin==FALSE)
	{
		for(j=0;j<MAX_CHARSET_NUM;j++)
		{
			dst_charset=table->dst_charset[j];
			if(dst_charset==CHARSET_NONE)
			{
				break;
			}
			expr_id=scanner->exprid_generator++;
			u_para=add_region_to_group(group_rule, db_rule->region_id,expr_id, TABLE_TYPE_EXPR);
			if(u_para==NULL)//duplicate
			{
				return -1;
			}
			op_expr=create_op_expr(expr_id
									,0	//add
									,u_para
									);
			for(k=0;k<sub_expr_cnt;k++)
			{
				if(strlen(sub_key_array[k])==0)
				{
						continue;
				}
				region_str_len=strlen(sub_key_array[k])*2+1;
				region_string=(char*)calloc(sizeof(char),region_str_len);
				if(table->src_charset!=dst_charset)//need convert
				{

					ret=iconv_convert(scanner,table->src_charset, dst_charset, 
										sub_key_array[k],strlen(sub_key_array[k]),
										region_string, &region_str_len);
					if(ret<0)
					{
						MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
								"Table %s region cfg %d charset convert from %s to %s failed.",table->table_name
																					,db_rule->region_id
																					,CHARSET_STRING[table->src_charset]
																					,CHARSET_STRING[dst_charset]);
						free(region_string);
						continue;
					}
					//if convert take no effect
					if(region_str_len==(int)strlen(sub_key_array[k])&&
						0==memcmp(sub_key_array[k],region_string,region_str_len)&&
						TRUE==table->src_charset_in_dst)
					{
						free(region_string);
						continue;
					}
				}
				else
				{
					memcpy(region_string,sub_key_array[k],strlen(sub_key_array[k]));
					region_str_len=strlen(sub_key_array[k]);
				}
				p_rule=create_rs_str_rule(make_sub_type(table->table_id,dst_charset,table->do_charset_merge)
										,db_rule->match_method
										,db_rule->is_case_sensitive
										,region_string
										,region_str_len
										,key_left_offset[k]
										,key_right_offset[k]);
				op_expr_add_rule(op_expr, p_rule);
				free(region_string);
				region_string=NULL;
			}
			MESA_lqueue_join_tail(scanner->region_update_q,&op_expr, sizeof(void*));
		}
	
	}
	else
	{
		expr_id=scanner->exprid_generator++;
		u_para=add_region_to_group(group_rule, db_rule->region_id,expr_id, TABLE_TYPE_EXPR);
		if(u_para==NULL)
		{
			return -1;
		}
		op_expr=create_op_expr(expr_id
								,0	//add
								,u_para
								);
		for(k=0;k<sub_expr_cnt;k++)
		{
			region_str_len=strlen(sub_key_array[0])+1;
			region_string=(char*)calloc(sizeof(char),region_str_len);
			region_str_len=hex2bin(sub_key_array[0], strlen(sub_key_array[0]),region_string,region_str_len);
			
			p_rule=create_rs_str_rule(make_sub_type(table->table_id,dst_charset,table->do_charset_merge)
									,db_rule->match_method
									,db_rule->is_case_sensitive
									,region_string
									,region_str_len
									,key_left_offset[k]
									,key_right_offset[k]);
			op_expr_add_rule(op_expr,p_rule);
			free(region_string);
			region_string=NULL;
		}
		MESA_lqueue_join_tail(scanner->region_update_q,&op_expr, sizeof(void*));
	}
	return 0;
}
int add_ip_rule(struct _Maat_table_info_t* table,struct db_ip_rule_t* db_ip_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_group_rule_t* group_rule=NULL;
	scan_rule_t* p_rule=NULL;
	struct op_expr_t* op_expr=NULL;
	struct _Maat_group_rule_t* u_para=NULL;
	int expr_id=0;

	group_rule=(struct _Maat_group_rule_t*)HASH_fetch_by_id(scanner->group_hash, db_ip_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(db_ip_rule->group_id);
		HASH_add_by_id(scanner->group_hash, db_ip_rule->group_id, group_rule);
	}

	expr_id=scanner->exprid_generator++;
	u_para=add_region_to_group(group_rule,db_ip_rule->region_id,expr_id,TABLE_TYPE_IP);
	if(u_para==NULL)
	{
		return -1;
	}
	op_expr=create_op_expr(expr_id
						,0
						,u_para
						);
	p_rule=create_rs_ip_rule(make_sub_type(table->table_id,CHARSET_NONE,0)
						,db_ip_rule);
	op_expr_add_rule(op_expr,p_rule);
	MESA_lqueue_join_tail(scanner->region_update_q, &op_expr, sizeof(void*));
	return 0;
}
int add_intval_rule(struct _Maat_table_info_t* table,struct db_intval_rule_t* intval_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_group_rule_t* group_rule=NULL;
	scan_rule_t* p_rule=NULL;
	struct op_expr_t* op_expr=NULL;
	struct _Maat_group_rule_t* u_para=NULL;
	int expr_id=0;

	group_rule=(struct _Maat_group_rule_t*)HASH_fetch_by_id(scanner->group_hash, intval_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(intval_rule->group_id);
		HASH_add_by_id(scanner->group_hash, intval_rule->group_id, group_rule);
	}
	expr_id=scanner->exprid_generator++;
	u_para=add_region_to_group(group_rule,intval_rule->region_id,expr_id,TABLE_TYPE_INTVAL);
	if(u_para==NULL)
	{
		return -1;
	}
	op_expr=create_op_expr(expr_id
						,0
						,u_para
						);
	p_rule=create_rs_intval_rule(make_sub_type(table->table_id,CHARSET_NONE,0)
						,intval_rule);
	op_expr_add_rule(op_expr,p_rule);
	MESA_lqueue_join_tail(scanner->region_update_q, &op_expr, sizeof(void*));
	return 0;
}
int del_region_rule(struct _Maat_table_info_t* table,int region_id,int group_id,struct _Maat_scanner_t *maat_scanner,void* logger)
{
	int i=0;
	unsigned int expr_id[MAAT_MAX_EXPR_ITEM_NUM*MAX_CHARSET_NUM]={0};
	int expr_num=0;
	struct _Maat_group_rule_t* group_rule=NULL;
	struct op_expr_t* op_expr=NULL;
	
	group_rule=(struct _Maat_group_rule_t*)HASH_fetch_by_id(maat_scanner->group_hash, group_id);
	if(group_rule==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,table %s group id %u not exist,while delete region id %d."
							,table->table_name
							,group_id
							,region_id);
		return -1;
	}
	assert(group_id==group_rule->group_id);
	expr_num=del_region_from_group(group_rule,region_id, expr_id, sizeof(expr_id)/sizeof(unsigned int));
	if(expr_num==0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"region delete error,id %d table %s region not in  group id %d."
							,region_id
							,table->table_name
							,group_id);
		return -1;
	}
	for(i=0;i<expr_num;i++)
	{
		op_expr=create_op_expr(expr_id[i],1,NULL);//del expr
		MESA_lqueue_join_tail(maat_scanner->region_update_q,&op_expr, sizeof(void*));
	}
	
	if(group_rule->region_cnt==0&&group_rule->region_cnt==0)
	{
		HASH_delete_by_id(maat_scanner->group_hash,group_id);
		garbage_bagging(GARBAGE_GROUP_RULE, group_rule, maat_scanner->tomb_ref);
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"last region rule of group id %d in table %s region id %d has been delete."
							,group_id
							,table->table_name
							,region_id);
	}
	return 1;
}
int add_group_rule(struct _Maat_table_info_t* table,struct db_group_rule_t* db_group_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_group_rule_t* group_rule=NULL;
	struct _Maat_compile_rule_t*compile_rule=NULL;
	int ret=0;
	group_rule=(struct _Maat_group_rule_t*)HASH_fetch_by_id(scanner->group_hash, db_group_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(db_group_rule->group_id);
		ret=HASH_add_by_id(scanner->group_hash, db_group_rule->group_id,group_rule);
		assert(ret>=0);
	}
	
	compile_rule=(struct _Maat_compile_rule_t*)HASH_fetch_by_id(scanner->compile_hash, db_group_rule->compile_id);
	if(compile_rule==NULL)
	{
		compile_rule=create_compile_rule(db_group_rule->compile_id);
		ret=HASH_add_by_id(scanner->compile_hash,db_group_rule->compile_id, compile_rule);
		assert(ret>=0);
	}
	ret=add_group_to_compile(compile_rule,group_rule);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module,
							"update error,add %s group %d to compile %d error,compile rule is full or duplicate group."
																	,table->table_name
																	,db_group_rule->group_id
																	,db_group_rule->compile_id);
		return -1;
	}
	return 0;
	
}
void del_group_rule(struct _Maat_table_info_t* table,struct db_group_rule_t* db_group_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_compile_rule_t*compile_rule=NULL;
	struct _Maat_group_rule_t* group_rule=NULL;
	compile_rule=(struct _Maat_compile_rule_t*)HASH_fetch_by_id(scanner->compile_hash, db_group_rule->compile_id);
	if(compile_rule==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,delete %s group rule error : compile id %d does not exisit."
																	,table->table_name
																	,db_group_rule->compile_id);
		return;
	}
	group_rule=del_group_from_compile(compile_rule, db_group_rule->group_id);
	if(group_rule==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,delete %s group rule error : group id %d not in compile id %d."
																	,table->table_name
																	,db_group_rule->group_id
																	,db_group_rule->compile_id);
		return;
	}
	if(compile_rule->group_cnt==0&&compile_rule->db_c_rule==NULL)
	{
		HASH_delete_by_id(scanner->compile_hash, db_group_rule->compile_id);
		garbage_bagging(GARBAGE_COMPILE_RULE, compile_rule, scanner->tomb_ref);
	}
	if(group_rule->ref_cnt==0&&group_rule->region_cnt==0)
	{
		HASH_delete_by_id(scanner->group_hash,db_group_rule->group_id);
		garbage_bagging(GARBAGE_GROUP_RULE, group_rule, scanner->tomb_ref);
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"table %s group id %d been eternal delete."
							,table->table_name
							,db_group_rule->group_id);
	}
	return;
}
int add_compile_rule(struct _Maat_table_info_t* table,struct db_compile_rule_t* db_compile_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_compile_rule_t *compile_rule=NULL;
	struct _head_Maat_rule_t *p_maat_rule_head=&(db_compile_rule->m_rule_head);
	compile_rule=(struct _Maat_compile_rule_t*)HASH_fetch_by_id(scanner->compile_hash, p_maat_rule_head->config_id);
	if(compile_rule==NULL)
	{
		compile_rule=create_compile_rule(p_maat_rule_head->config_id);
		HASH_add_by_id(scanner->compile_hash,p_maat_rule_head->config_id,compile_rule);
	}
	if(compile_rule->db_c_rule!=NULL)//duplicate config
	{
		return -1;
	}
	compile_rule->db_c_rule=db_compile_rule;
	return 0;
	
}
int del_compile_rule(struct _Maat_table_info_t* table,struct db_compile_rule_t* db_compile_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_compile_rule_t *compile_rule=NULL;
	compile_rule=(struct _Maat_compile_rule_t*)HASH_fetch_by_id(scanner->compile_hash, db_compile_rule->m_rule_head.config_id);
	if(compile_rule==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,delete %s  compile rule error : congfig id %d does not exisit."
																	,table->table_name
																	,db_compile_rule->m_rule_head.config_id);
		return -1;
	}
	pthread_rwlock_wrlock(&(compile_rule->rwlock));
	free(compile_rule->db_c_rule->service_defined);
	free(compile_rule->db_c_rule);
	compile_rule->db_c_rule=NULL;
	pthread_rwlock_unlock(&(compile_rule->rwlock));

	if(compile_rule->group_cnt==0)
	{
		HASH_delete_by_id(scanner->compile_hash, compile_rule->compile_id);
		garbage_bagging(GARBAGE_COMPILE_RULE,compile_rule, scanner->tomb_ref);
	}
	return 1;
}
void update_group_rule(struct _Maat_table_info_t* table,const char* table_line,struct _Maat_scanner_t *scanner,void* logger)
{
	struct db_group_rule_t db_group_rule;
	int ret=0;
	ret=sscanf(table_line,"%d\t%d\t%d",&(db_group_rule.group_id)
										,&(db_group_rule.compile_id)
										,&(db_group_rule.is_valid));
	assert(ret==3);
	if(db_group_rule.is_valid==FALSE)
	{
		del_group_rule(table, &db_group_rule,scanner,logger);
		table->cfg_num--;
	}
	else
	{
		ret=add_group_rule(table,&db_group_rule, scanner,logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of group table %s group_id %d compile_id %d.",table->table_name
																							,db_group_rule.group_id
																							,db_group_rule.compile_id);

		}
		else
		{
			//no need to free db_group_rule,it was saved in scanner->compile_hash
			table->cfg_num++;
		}
	}
	
	return;	
}
void compatible_group_udpate(struct _Maat_table_info_t* table,int region_id,int compile_id,int is_valid,struct _Maat_scanner_t *scanner,void* logger)
{
	char virtual_group_line[256];
	snprintf(virtual_group_line,sizeof(virtual_group_line),
				"%d\t%d\t%d",region_id,compile_id,is_valid);
	update_group_rule(table, virtual_group_line,scanner,logger);
	return;
}

void update_expr_rule(struct _Maat_table_info_t* table,const char* table_line,struct _Maat_scanner_t *scanner,void* logger,int group_mode_on)
{
	struct db_str_rule_t* maat_str_rule=(struct db_str_rule_t*)malloc(sizeof(struct db_str_rule_t));
	int ret=0,db_hexbin=0;
	ret=sscanf(table_line,"%d\t%d\t%s\t%d\t%d\t%d\t%d",&(maat_str_rule->region_id)
													,&(maat_str_rule->group_id)
													,maat_str_rule->keywords
													,(int*)&(maat_str_rule->expr_type)
													,(int*)&(maat_str_rule->match_method)
													,&db_hexbin
													,&(maat_str_rule->is_valid));
	if(ret!=7)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,invalid format of expr table %s:%s",table->table_name,table_line);
		free(maat_str_rule);
		maat_str_rule=NULL;	
		return;
	}
	switch(db_hexbin)
	{
		case	0:
			maat_str_rule->is_hexbin=FALSE;
			maat_str_rule->is_case_sensitive=FALSE;
			break;
		case	1:
			maat_str_rule->is_hexbin=TRUE;
			maat_str_rule->is_case_sensitive=FALSE;
			break;
		case	2:
			maat_str_rule->is_hexbin=FALSE;
			maat_str_rule->is_case_sensitive=TRUE;
			break;
		default:
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
								"update error,invalid hexbin value of expr table %s:%s",table->table_name,table_line);
			goto error_out;
	}
	ret=sync_region(scanner->region_hash
					,maat_str_rule->region_id
					,table->table_name
					,maat_str_rule->is_valid,logger);
	if(ret<0)
	{
		goto error_out;
	}
	if(group_mode_on==FALSE)//for compatible old version
	{
		compatible_group_udpate(table
								,maat_str_rule->region_id
								,maat_str_rule->group_id
								,maat_str_rule->is_valid
								,scanner
								,logger);
		maat_str_rule->group_id=maat_str_rule->region_id;
	}

	if(maat_str_rule->is_valid==FALSE)
	{
		ret=del_region_rule(table,maat_str_rule->region_id,maat_str_rule->group_id, scanner, logger);
		if(ret>0)
		{
			table->cfg_num--;
		}
	}
	else
	{

		ret=add_expr_rule(table, maat_str_rule,scanner, logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of expr table %s region_id=%d",table->table_name,maat_str_rule->region_id);
			
		}
		else
		{
			table->cfg_num++;
		}
	}
error_out:
	free(maat_str_rule);
	maat_str_rule=NULL;
}
void update_ip_rule(struct _Maat_table_info_t* table,const char* table_line,struct _Maat_scanner_t *scanner,void* logger,int group_mode_on)
{
	struct db_ip_rule_t* ip_rule=(struct db_ip_rule_t*)calloc(sizeof(struct db_ip_rule_t),1);
	char src_ip[40],mask_src_ip[40],dst_ip[40],mask_dst_ip[40];

	unsigned short i_src_port,i_sport_mask,i_dst_port,i_dport_mask;
	struct in6_addr v6_src_mask,v6_dst_mask;
	int protocol=0,direction=0;
	int ret=0;
	int ret_array[8]={1},i=0;
	ret=sscanf(table_line,"%d\t%d\t%d\t%s\t%s\t%hu\t%hu\t%s\t%s\t%hu\t%hu\t%d\t%d\t%d"
													,&(ip_rule->region_id)
													,&(ip_rule->group_id)
													,&(ip_rule->addr_type)
													,src_ip
													,mask_src_ip
													,&i_src_port
													,&i_sport_mask
													,dst_ip
													,mask_dst_ip
													,&i_dst_port
													,&i_dport_mask
													,&protocol
													,&direction
													,&(ip_rule->is_valid));
	if(ret!=14||(ip_rule->addr_type!=4&&ip_rule->addr_type!=6)
			||protocol>65535||protocol<0
			||(direction!=0&&direction!=1))
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,invalid format of ip table %s:%s",table->table_name,table_line);
		goto error_out;
	}
	if(ip_rule->addr_type==4)
	{
		ret_array[0]=inet_pton(AF_INET,src_ip,&(ip_rule->ipv4_rule.saddr));
		ip_rule->ipv4_rule.saddr=ntohl(ip_rule->ipv4_rule.saddr);
		ret_array[1]=inet_pton(AF_INET,mask_src_ip,&(ip_rule->ipv4_rule.smask));
		ip_rule->ipv4_rule.smask=ntohl(ip_rule->ipv4_rule.smask);
		
		ret_array[2]=inet_pton(AF_INET,dst_ip,&(ip_rule->ipv4_rule.daddr));
		ip_rule->ipv4_rule.daddr=ntohl(ip_rule->ipv4_rule.daddr);
		ret_array[3]=inet_pton(AF_INET,mask_dst_ip,&(ip_rule->ipv4_rule.dmask));
		ip_rule->ipv4_rule.dmask=ntohl(ip_rule->ipv4_rule.dmask);
		
		ip_rule->ipv4_rule.min_sport=i_src_port&i_sport_mask;
		ip_rule->ipv4_rule.max_sport=(i_src_port&i_sport_mask)+(~i_sport_mask);
		
		ip_rule->ipv4_rule.min_dport=i_dst_port&i_dport_mask;
		ip_rule->ipv4_rule.max_dport=(i_dst_port&i_dport_mask)+(~i_dport_mask);
		
		ip_rule->ipv4_rule.proto=protocol;
		ip_rule->ipv4_rule.direction=direction;
	}
	else
	{
		ret_array[0]=inet_pton(AF_INET6,src_ip,&(ip_rule->ipv6_rule.saddr));
		ipv6_ntoh(ip_rule->ipv6_rule.saddr);
		ret_array[1]=inet_pton(AF_INET6,mask_src_ip,&(v6_src_mask));
		ip_rule->ipv6_rule.smask_bits=128-cnt_maskbits(v6_src_mask);
		
		ret_array[2]=inet_pton(AF_INET6,dst_ip,&(ip_rule->ipv6_rule.daddr));
		ipv6_ntoh(ip_rule->ipv6_rule.daddr);
		ret_array[3]=inet_pton(AF_INET6,mask_dst_ip,&(v6_dst_mask));
		ip_rule->ipv6_rule.dmask_bits=128-cnt_maskbits(v6_dst_mask);
		
		ip_rule->ipv6_rule.min_sport=i_src_port&i_sport_mask;
		ip_rule->ipv6_rule.max_sport=(i_src_port&i_sport_mask)+(~i_sport_mask);
		
		ip_rule->ipv6_rule.min_dport=i_dst_port&i_dport_mask;
		ip_rule->ipv6_rule.max_dport=(i_dst_port&i_dport_mask)+~(i_dport_mask);
		
		ip_rule->ipv6_rule.proto=protocol;
		ip_rule->ipv6_rule.direction=direction;
	}
	for(i=0;i<4;i++)
	{
		if(ret_array[i]<=0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
								"update error,invalid format of ip table %s:%s",table->table_name,table_line);
			goto error_out;
		}
	}
	ret=sync_region(scanner->region_hash
					,ip_rule->region_id
					,table->table_name
					,ip_rule->is_valid,logger);
	if(ret<0)
	{
		goto error_out;
	}
	if(group_mode_on==FALSE)//for compatible old version
	{
		compatible_group_udpate(table
								,ip_rule->region_id
								,ip_rule->group_id
								,ip_rule->is_valid
								,scanner
								,logger);
		ip_rule->group_id=ip_rule->region_id;
	}
	if(ip_rule->is_valid==FALSE)
	{
		ret=del_region_rule(table,ip_rule->region_id,ip_rule->group_id, scanner, logger);
		if(ret>0)
		{
			table->cfg_num--;
		}
	}
	else
	{

		ret=add_ip_rule(table, ip_rule,scanner, logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of ip table %s config_id=%d",table->table_name,ip_rule->region_id);
			
		}
		else
		{
			table->cfg_num++;
		}
	}
error_out:
	free(ip_rule);
	ip_rule=NULL;	
}

void update_intval_rule(struct _Maat_table_info_t* table,const char* table_line,struct _Maat_scanner_t *scanner,void* logger,int group_mode_on)
{
	struct db_intval_rule_t* intval_rule=(struct db_intval_rule_t*)calloc(sizeof(struct db_intval_rule_t),1);
	int ret=0;
	ret=sscanf(table_line,"%d\t%d\t%u\t%u\t%d",&(intval_rule->region_id)
											,&(intval_rule->group_id)
											,&(intval_rule->intval.lb)
											,&(intval_rule->intval.ub)
											,&(intval_rule->is_valid));

	if(ret!=5||intval_rule->intval.ub<intval_rule->intval.lb)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,invalid format  of interval table %s:%s",table->table_name,table_line);
		goto error_out;
	}
	ret=sync_region(scanner->region_hash
					,intval_rule->region_id
					,table->table_name
					,intval_rule->is_valid,logger);
	if(ret<0)
	{
		goto error_out;
	}
	if(group_mode_on==FALSE)//for compatible old version
	{
		compatible_group_udpate(table
								,intval_rule->region_id
								,intval_rule->group_id
								,intval_rule->is_valid
								,scanner
								,logger);
		intval_rule->group_id=intval_rule->region_id;
	}

	if(intval_rule->is_valid==FALSE)
	{
		ret=del_region_rule(table,intval_rule->region_id,intval_rule->group_id, scanner, logger);
		if(ret>0)
		{
			table->cfg_num--;
		}
	}
	else
	{
		ret=add_intval_rule(table, intval_rule,scanner,logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of intval table %s config_id=%d",table->table_name,intval_rule->region_id);
		}
		else
		{
			table->cfg_num++;
		}
	}
error_out:
	free(intval_rule);
	intval_rule=NULL;		
}

void update_compile_rule(struct _Maat_table_info_t* table,const char* table_line,struct _Maat_scanner_t *scanner,void* logger)
{
	struct db_compile_rule_t *p_compile=(struct db_compile_rule_t*)calloc(sizeof(struct db_compile_rule_t ),1);
	struct _head_Maat_rule_t* p_m_rule=&(p_compile->m_rule_head);
	char user_region[128*2]={0};
	int ret=0;
	p_compile->declare_grp_num=0;
	ret=sscanf(table_line,"%d\t%d\t%hhd\t%hhd\t%hhd\t%lld\t%s\t%d\t%d",&(p_m_rule->config_id)
													,&(p_m_rule->service_id)
													,&(p_m_rule->action)
													,&(p_m_rule->do_blacklist)
													,&(p_m_rule->do_log)
													,&(p_compile->effective_range)
													,user_region
													,&(p_compile->is_valid)
													,&(p_compile->declare_grp_num));
	if((ret!=8&&ret!=9)||strlen(user_region)>MAX_SERVICE_DEFINE_LEN||p_compile->declare_grp_num>MAAT_MAX_EXPR_ITEM_NUM)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,invalid format of compile table %s:%s",table->table_name,table_line);
		free(p_compile);
		p_compile=NULL;
		return;
	}
	
	p_m_rule->serv_def_len=strlen(user_region)+1;
	p_compile->service_defined=(char*)malloc(p_m_rule->serv_def_len*sizeof(char));
	memcpy(p_compile->service_defined,user_region,p_m_rule->serv_def_len);
	if(p_compile->is_valid==FALSE)
	{
		ret=del_compile_rule(table,p_compile,scanner, logger);
		if(ret>0)
		{
			table->cfg_num--;
		}
		free(p_compile->service_defined);
		p_compile->service_defined=NULL;
		free(p_compile);
		p_compile=NULL;
	}
	else
	{
		ret=add_compile_rule(table, p_compile, scanner,logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of compile table %s config_id=%d",table->table_name,p_m_rule->config_id);
			free(p_compile->service_defined);
			p_compile->service_defined=NULL;
			free(p_compile);
			p_compile=NULL;

		}
		else
		{
			//no need to free p_compile,it was saved in scanner->compile_hash
			table->cfg_num++;
		}
	}
	
	return;	
}

void garbage_bagging(enum maat_garbage_type type,void *p,MESA_lqueue_head garbage_q)
{
	struct _maat_garbage_t* bag=(struct _maat_garbage_t*)malloc(sizeof(struct _maat_garbage_t));
	bag->raw=p;
	bag->type=type;
	bag->create_time=time(NULL);
	bag->ok_times=0;
	MESA_lqueue_join_tail(garbage_q,&bag,sizeof(void*));
	return;
}
void garbage_bury(MESA_lqueue_head garbage_q,void *logger)
{
	MESA_queue_errno_t q_ret=MESA_QUEUE_RET_OK;
	_maat_garbage_t* bag=NULL;
	long data_size=0;
	const long q_cnt=MESA_lqueue_get_count(garbage_q);
	int i=0,bury_cnt=0;
	int ref_cnt=0;
	int have_timeout=0;
	time_t now=time(NULL);
	for(i=0;i<q_cnt;i++)
	{
		data_size=sizeof(void*);
		q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(garbage_q,&bag,&data_size);
		assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
		if(now-bag->create_time<10)
		{
			MESA_lqueue_join_tail(garbage_q,&bag,sizeof(void*));
			continue;
		}
		have_timeout=1;
		switch(bag->type)
		{
			case GARBAGE_COMPILE_RULE:
				destroy_compile_rule(bag->compile_rule);
				break;
			case GARBAGE_GROUP_RULE:
				destroy_group_rule(bag->group_rule);
				break;
			case GARBAGE_SCANNER:
				ref_cnt=aligment_int_array_sum(bag->scanner->ref_cnt,bag->scanner->max_thread_num);
				
				if(ref_cnt==0)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module,
							"scanner %p version %d has no reference peacefully destroyed.",bag->scanner,bag->scanner->version);
				}
				else
				{
					MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module,
							"scanner %p version %d force destroyed,ref_cnt %d.",
							bag->scanner,bag->scanner->version,ref_cnt);
					
				}
				destroy_maat_scanner(bag->scanner);
				break;
			case GARBAGE_BOOL_MATCHER:
				destroy_bool_matcher(bag->bool_matcher);
				break;
			default:
				assert(0);
		}
		free(bag);
		bag=NULL;
		bury_cnt++;
	}
	if(q_cnt>0&&have_timeout==1)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module,
							"Garbage queue size %ld, bury %d",
							q_cnt,bury_cnt);
	}
}
void plugin_table_callback(struct _Maat_table_info_t* table,const char* table_line,void* logger)
{
	int i=0;
	unsigned int len=strlen(table_line)+1;
	struct _plugin_table_info* p_table_cb=table->cb_info;
	for(i=0;i<p_table_cb->cb_plug_cnt;i++)
	{
		p_table_cb->cb_plug[i].update(table->table_id,table_line,p_table_cb->cb_plug[i].u_para);
	}
	char *p=(char*)calloc(len,1);
	memcpy(p,table_line,len);
	p_table_cb->cache_size+=len;
	dynamic_array_write(p_table_cb->cache_lines,p_table_cb->line_num,p);
	p_table_cb->line_num++;
}
void maat_start_cb(unsigned int new_version,int update_type,void*u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para; 
	struct _Maat_table_info_t* p_table=NULL;
	struct _plugin_table_info* p_table_cb=NULL;
	int i=0,j=0;
	if(update_type==CM_UPDATE_TYPE_FULL)
	{
		feather->update_tmp_scanner=create_maat_scanner(new_version,feather->scan_thread_num,feather->garbage_q);
		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Full config version %u -> %u update start",
								feather->maat_version,new_version);
	}
	else
	{

		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Inc config version %u -> %u update start",
								feather->maat_version,new_version);
		feather->maat_version=new_version;
	}
	for(i=0;i<feather->table_cnt;i++)
	{
		p_table=feather->p_table_info[i];
		if(p_table==NULL||p_table->table_type!=TABLE_TYPE_PLUGIN)
		{
			continue;
		}
		p_table_cb=p_table->cb_info;
		for(j=0;j<p_table_cb->cb_plug_cnt;j++)
		{
			p_table_cb->cb_plug[j].start(update_type,p_table_cb->cb_plug[j].u_para);
		}
	}
	return;
}
void do_increase_update(struct _Maat_feather_t *feather)
{
	void *tmp1=NULL,*tmp2=NULL;
	tmp1=create_bool_matcher(feather->scanner->compile_hash,
											feather->scan_thread_num,
											feather->logger);
	tmp2=feather->scanner->expr_compiler;
	
	//assume pinter = operation is thread safe 
	feather->scanner->expr_compiler=tmp1;
	garbage_bagging(GARBAGE_BOOL_MATCHER, tmp2, feather->garbage_q);
	
	batch_update(feather->scanner->region,
		feather->scanner->region_update_q,
		feather->logger);
	feather->scanner->last_update_time=time(NULL);

	return;

}
void maat_finish_cb(void* u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para; 
	struct _Maat_table_info_t* p_table=NULL;
	struct _plugin_table_info* p_table_cb=NULL;
	int i=0,j=0,total=0;
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		p_table=feather->p_table_info[i];
		if(p_table!=NULL)
		{
			total+=p_table->cfg_num;
		}
	}
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		p_table=feather->p_table_info[i];
		
		if(p_table==NULL||p_table->table_type!=TABLE_TYPE_PLUGIN)
		{
			continue;
		}
		p_table_cb=p_table->cb_info;
		for(j=0;j<p_table_cb->cb_plug_cnt;j++)
		{
			p_table_cb->cb_plug[j].finish(p_table_cb->cb_plug[j].u_para);
		}
	}
	if(feather->update_tmp_scanner!=NULL)
	{
		feather->update_tmp_scanner->cfg_num=total;
		feather->update_tmp_scanner->expr_compiler=create_bool_matcher(feather->update_tmp_scanner->compile_hash,
																		feather->scan_thread_num,
																		feather->logger);
		batch_update(feather->update_tmp_scanner->region,
			feather->update_tmp_scanner->region_update_q,
			feather->logger);
		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Full config version %u load %d entries complete.",
								feather->update_tmp_scanner->version,feather->update_tmp_scanner->cfg_num);	
		feather->update_tmp_scanner->last_update_time=time(NULL);
	}
	else
	{
		feather->scanner->cfg_num=total;
		feather->scanner->version=feather->maat_version;
		if(time(NULL)-feather->scanner->last_update_time>60)
		{
			do_increase_update(feather);
			MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
									"Inc config version %u build complete,%d entries in total.",
									feather->scanner->version,feather->scanner->cfg_num);
		}
		else
		{
			MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
									"Postpone config version %u %d entries load to rulescan.",
									feather->scanner->version,feather->scanner->cfg_num);
		}
	}
	return;
}
void maat_update_cb(const char* table_name,const char* line,void *u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para; 
	int ret=-1;
	int table_id=-1;
	_Maat_scanner_t* scanner=NULL;
	if(feather->update_tmp_scanner!=NULL)
	{
		scanner=feather->update_tmp_scanner;
	}
	else
	{
		scanner=feather->scanner;
	}
	ret=map_str2int(feather->map_tablename2id,table_name,&table_id);
	if(ret<0)
	{
		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module ,"update warning,unknown table name %s",table_name);
		return;	
	}
	switch(feather->p_table_info[table_id]->table_type)
	{
		case	TABLE_TYPE_EXPR:
			update_expr_rule(feather->p_table_info[table_id], line, scanner,feather->logger,feather->GROUP_MODE_ON);
			break;
		case	TABLE_TYPE_IP:
			update_ip_rule(feather->p_table_info[table_id], line, scanner,feather->logger,feather->GROUP_MODE_ON);
			break;
		case	TABLE_TYPE_INTVAL:
			update_intval_rule(feather->p_table_info[table_id], line, scanner,feather->logger,feather->GROUP_MODE_ON);
			break;
		case	TABLE_TYPE_COMPILE:
			update_compile_rule(feather->p_table_info[table_id], line, scanner,feather->logger);
			break;
		case	TABLE_TYPE_GROUP:
			update_group_rule(feather->p_table_info[table_id], line, scanner,feather->logger);
			break;
		case	TABLE_TYPE_PLUGIN:
			plugin_table_callback(feather->p_table_info[table_id], line,feather->logger);
			break;
		default:
			break;
	
	}
	return;
}
void *thread_rule_monitor(void *arg)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)arg;
	const char* inc_cfg_dir=(const char*)feather->inc_dir;
	struct _Maat_scanner_t* old_scanner=NULL;
	long expr_wait_q_cnt=0;
	while(feather->still_working)
	{
		usleep(feather->scan_interval_ms*1000);
		config_monitor_traverse(feather->maat_version,
								inc_cfg_dir, 
								maat_start_cb,
								maat_update_cb,
								maat_finish_cb,
								feather,
								feather->logger);
		if(feather->update_tmp_scanner!=NULL)
		{
			old_scanner=feather->scanner;
			//__sync_lock_test_and_set not work in some OS.
			//feather->scanner=__sync_lock_test_and_set(&(feather->scanner),feather->update_tmp_scanner);
			feather->scanner=feather->update_tmp_scanner;
			if(old_scanner!=NULL)
			{
				assert(feather->scanner->version>old_scanner->version);
				assert(old_scanner->tomb_ref==feather->garbage_q);
				garbage_bagging(GARBAGE_SCANNER, old_scanner, feather->garbage_q);
			}
			feather->update_tmp_scanner=NULL;
			feather->maat_version=feather->scanner->version;
		}
		if(feather->scanner!=NULL)
		{
			expr_wait_q_cnt=MESA_lqueue_get_count(feather->scanner->region_update_q);
			if(expr_wait_q_cnt>0&&time(NULL)-feather->scanner->last_update_time>feather->effect_interval_ms*1000)
			{
				do_increase_update(feather);
				MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
										"Actual udpate config version %u %d entries load to rulescan after postpone.",
										feather->scanner->version,feather->scanner->cfg_num);
			}
		}
		garbage_bury(feather->garbage_q,feather->logger);
	}
	
	MESA_htable_destroy(feather->map_tablename2id,free);
	destroy_maat_scanner(feather->scanner);
	garbage_bury(feather->garbage_q,feather->logger);
	MESA_lqueue_destroy(feather->garbage_q,lqueue_destroy_cb,NULL);

	int i=0,j=0;
	struct dynamic_array_t* d_array=NULL;
	char* lines=NULL;
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		if(feather->p_table_info[i]==NULL)
		{
			continue;
		}
		if(feather->p_table_info[i]->table_type==TABLE_TYPE_PLUGIN)
		{
			d_array=feather->p_table_info[i]->cb_info->cache_lines;
			for(j=0;j<feather->p_table_info[i]->cb_info->line_num;j++)
			{
				lines=(char*)dynamic_array_read(d_array, j);
				free(lines);
			}
		}
		free(feather->p_table_info[i]);
		feather->p_table_info[i]=NULL;
	}
	free(feather);
	return NULL;
}
//return 1 if insert a unique id
//return 0 if id is duplicated
//return -1 if set is full
int insert_set_id(unsigned int **set,int* size,int cnt,unsigned int id)
{
	int i=0;
	for(i=0;i<cnt;i++)
	{
		if((*set)[i]==id)
		{
			break;
		}
	}
	if(i==cnt)
	{
		if(cnt==*size)
		{
			*size+=16;
			*set=(unsigned int*)realloc(*set,(*size)*sizeof(unsigned int));
		}
		(*set)[cnt]=id;
		return 1;
	}
	else
	{
		return 0;
	}
}
int pickup_hit_region_from_compile(universal_bool_expr_t *compile_hit,const unsigned int* hitted_id,int hit_cnt,int* region_pos,int size)
{
	int i=0,j=0;
	int k=0;
	for(i=0;i<hit_cnt;i++)
	{
		for(j=0;j<(int)(compile_hit->bool_item_num);j++)
		{
			if(hitted_id[i]==compile_hit->bool_item_ids[j])
			{
				region_pos[k]=i;
				k++;
			}
		}
	}
	return k;
}
int region_compile(struct _scan_status_t *_mid,scan_result_t* region_hit,int region_hit_num,struct Maat_rule_t* result,_compile_result_t *rs_result, int size)
{

	int scan_ret=0,result_cnt=0;
	int ret=0,i=0,j=0;
	int r_in_c_cnt=0;
	void* expr_compiler=_mid->feather->scanner->expr_compiler;
	int shortcut_avilable_cnt=0;
	struct _Maat_group_rule_t* group_rule=NULL;
	struct _Maat_compile_rule_t* array_mi_rule[MAX_SCANNER_HIT_NUM];
	struct _Maat_compile_rule_t* _mi_rule=NULL;
	int region_pos[MAX_SCANNER_HIT_NUM];

	_mid->cur_hit_cnt=0;
	for(i=0;i<region_hit_num;i++)
	{
		group_rule=(struct _Maat_group_rule_t*)(region_hit[i].tag);
		if(group_rule->group_id<0)
		{
			continue;
		}
		if(group_rule->compile_shortcut!=NULL&&group_rule->ref_cnt==1&&shortcut_avilable_cnt<MAX_SCANNER_HIT_NUM)
		{			
			array_mi_rule[shortcut_avilable_cnt]=(struct _Maat_compile_rule_t*)(group_rule->compile_shortcut);
			shortcut_avilable_cnt++;
		}
		_mid->cur_hit_id[_mid->cur_hit_cnt]=(int)group_rule->group_id;
		_mid->cur_hit_cnt++;
		ret=insert_set_id(&(_mid->hitted_group_id),
									&(_mid->hit_group_size),
									_mid->hit_group_cnt,
									(unsigned int)group_rule->group_id);
		_mid->hit_group_cnt+=ret;
	}
	if(shortcut_avilable_cnt==region_hit_num||shortcut_avilable_cnt==MAX_SCANNER_HIT_NUM)
	{
		//short cut for rules contains one group
		scan_ret=shortcut_avilable_cnt;
	}
	else
	{
		scan_ret=boolexpr_match(expr_compiler,_mid->thread_num, 
										_mid->hitted_group_id,_mid->hit_group_cnt,
										(void **)array_mi_rule, MAX_SCANNER_HIT_NUM);
	}
	for(i=0,j=0;i<scan_ret&&result_cnt<size;i++)
	{
		_mi_rule=array_mi_rule[i];
		if(_mi_rule==NULL||_mi_rule->db_c_rule==NULL)
		{
			continue;
		}
		
		if(0==pthread_rwlock_tryrdlock(&(_mi_rule->rwlock)))
		{
			make_group_set(_mi_rule,&(rs_result[result_cnt].group_set));
			r_in_c_cnt=pickup_hit_region_from_compile(&(rs_result[result_cnt].group_set),_mid->cur_hit_id,_mid->cur_hit_cnt,
										region_pos, MAX_SCANNER_HIT_NUM);
			if(r_in_c_cnt>0)//compile config hitted becasue of new reigon
			{
				memcpy(&(result[result_cnt]),&(_mi_rule->db_c_rule->m_rule_head),sizeof(struct _head_Maat_rule_t));
				memcpy(result[result_cnt].service_defined
						,_mi_rule->db_c_rule->service_defined
						,_mi_rule->db_c_rule->m_rule_head.serv_def_len);
				rs_result[result_cnt].compile_id=_mi_rule->compile_id;
				result_cnt++;
			}
			pthread_rwlock_unlock(&(_mi_rule->rwlock));

		}
		
	}	
	return result_cnt;
}

int exprid2region_id(struct _Maat_group_rule_t* group_rule,int expr_id)
{
	int i=0,region_id=-1;;
	struct _Maat_region_rule_t* region_rule=NULL;
	assert(group_rule->group_id>=0);
	pthread_mutex_lock(&(group_rule->mutex));
	for(i=0;i<group_rule->region_boundary;i++)
	{
		region_rule=(struct _Maat_region_rule_t*)dynamic_array_read(group_rule->region_rules, i);
		if(region_rule==NULL)
		{
			continue;
		}
		if(region_rule->expr_id==expr_id)
		{
			region_id=region_rule->region_id;
		}
	}
	pthread_mutex_unlock(&(group_rule->mutex));
	return region_id;
}


int fill_regex_pos(struct regex_pos_t *regex_pos,int size,rule_result_t *rs_result,const char* buff)
{
	int i=0,j=0;
	int group_num=rs_result->group_num;
	unsigned int * position=rs_result->position;
	unsigned int * length=rs_result->length;
	regex_pos->group_num=group_num;
	for(i=0;i<(int)rs_result->result_num&&i<size;i++)
	{
		if((group_num+1)*i>MAX_MATCH_POS_NUM)
		{
			break;
		}
		regex_pos[i].hitting_regex_pos=buff+position[(group_num+1)*i];
		regex_pos[i].hitting_regex_len=length[(group_num+1)*i];
		for(j=0;j<group_num&&j<MAAT_MAX_REGEX_GROUP_NUM;j++)
		{
			if((group_num+1)*i+j+1>MAAT_MAX_REGEX_GROUP_NUM)
			{
				break;
			}
			regex_pos[i].grouping_pos[j]=buff+position[(group_num+1)*i+j+1];
			regex_pos[i].grouping_len[j]=length[(group_num+1)*i+j+1];
		}
	}
	return i;
}
int fill_substr_pos(struct str_pos_t* str_pos,int size,rule_result_t *rs_result,const char* buff)
{
	int i=0;
	unsigned int * position=rs_result->position;
	unsigned int * length=rs_result->length;
	for(i=0;i<(int)rs_result->result_num&&i<size;i++)
	{
		if(i>MAX_MATCH_POS_NUM)
		{
			break;
		}
		str_pos[i].hit_pos=buff+position[i];
		str_pos[i].hit_len= length[i];
	}
	return i;
}
int hit_pos_RS2Maat(struct sub_item_pos_t* maat_sub_item,int size,rule_result_t* rs_result,int rs_cnt,const char* buff)
{
	int k=0;
	for(k=0;k<rs_cnt&&k<size;k++)
	{
		switch(rs_result[k].rule_type)
		{

			case	RULETYPE_STR:
				maat_sub_item[k].ruletype=MAAT_POSTYPE_EXPR;
				maat_sub_item[k].hit_cnt=fill_substr_pos(maat_sub_item[k].substr_pos, MAAT_MAX_HIT_POS_NUM, &(rs_result[k]),buff);
				break;
			case	RULETYPE_REG:
				maat_sub_item[k].ruletype=MAAT_POSTYPE_REGEX;
				maat_sub_item[k].hit_cnt=fill_regex_pos(maat_sub_item[k].regex_pos, MAAT_MAX_HIT_POS_NUM, &(rs_result[k]),buff);
				break;
			default:
				assert(0);

		}
	}
	return k;
}
int fill_region_hit_detail(const char* scan_buff,const _scan_status_t* _mid,
							scan_result_t *region_hit,int region_cnt,
							_compile_result_t *compile_hit,int compile_cnt,
							struct Maat_hit_detail_t *hit_detail,int detail_num)
{
	int i=0,j=0,k=0;
	char r_in_c_flag[region_cnt];
	int region_pos[MAX_SCANNER_HIT_NUM],pos=0;
	int r_in_c_cnt=0;
	int region_id=-1;
	memset(r_in_c_flag,0,sizeof(r_in_c_flag));
	memset(region_pos,0,sizeof(region_pos));
	
	struct _Maat_group_rule_t* group_rule=NULL;
	//for each hitted compile cfg,find its region_ids
	for(i=0;i<compile_cnt&&i<detail_num;i++)
	{
		hit_detail[i].config_id=compile_hit[i].compile_id;
		r_in_c_cnt=pickup_hit_region_from_compile(&(compile_hit[i].group_set),_mid->cur_hit_id,_mid->cur_hit_cnt,
												region_pos, MAX_SCANNER_HIT_NUM);
		assert(r_in_c_cnt>0);//previous hitted compile was elimited in region_compile
		for(j=0,k=0;j<r_in_c_cnt&&k<MAAT_MAX_HIT_RULE_NUM;j++)
		{
			pos=region_pos[j];
			r_in_c_flag[pos]=1;
			group_rule=(struct _Maat_group_rule_t*)(region_hit[pos].tag);
			region_id=exprid2region_id(group_rule,region_hit[pos].expr_id);
			if(region_id<0)
			{
				continue;
			}
			hit_detail[i].region_pos[k].region_id=region_id;
			hit_detail[i].region_pos[k].sub_item_num=region_hit[pos].rnum;
			hit_pos_RS2Maat(hit_detail[i].region_pos[k].sub_item_pos,MAAT_MAX_EXPR_ITEM_NUM,
							region_hit[pos].result, region_hit[pos].rnum,scan_buff);
			k++;
		}		
		hit_detail[i].hit_region_cnt=k;

	}
	//for each region_ids, if belongs to no compile cfg, fill hit_detail as a half hit cfg
	for(k=0,j=i;k<region_cnt&&j<region_cnt&&j<detail_num;k++)
	{
		if(r_in_c_flag[k]==0)
		{
			group_rule=(struct _Maat_group_rule_t*)(region_hit[k].tag);
	 		hit_detail[j].config_id=-2;
			hit_detail[j].hit_region_cnt=1;
			hit_detail[j].region_pos[0].region_id=exprid2region_id(group_rule,region_hit[k].expr_id);
			hit_detail[j].region_pos[0].sub_item_num=region_hit[k].rnum;
			hit_pos_RS2Maat(hit_detail[j].region_pos[0].sub_item_pos,MAAT_MAX_EXPR_ITEM_NUM,
						region_hit[k].result,region_hit[k].rnum,scan_buff);
			j++;
		}
	}
	return j;
}
struct _scan_status_t* _Maat_make_status(struct _Maat_feather_t* feather,int thread_num)
{
	struct _scan_status_t* _mid=NULL;
	_mid=(struct _scan_status_t*)calloc(sizeof(struct _scan_status_t),1);
	_mid->feather=feather;
	_mid->thread_num=thread_num;
	_mid->cur_hit_cnt=0;
	_mid->hit_group_cnt=0;
	_mid->hit_group_size=4;
	_mid->hitted_group_id=(unsigned int*)malloc(sizeof(unsigned int)*_mid->hit_group_size);
	return _mid;
}

int detain_last_data(char* buff,int buff_size,int detained_len,const char* data,int data_len)
{
	int to_copy_size=0,foward_offset=0;
	int ret_len;
	if(data_len<=buff_size-detained_len)
	{
		to_copy_size=data_len;
		memcpy(buff+detained_len,data,data_len);
		ret_len=detained_len+data_len;
	}
	else if(data_len>buff_size-detained_len&&data_len<buff_size)
	{
		foward_offset=detained_len+data_len-buff_size;
		to_copy_size=buff_size-data_len;
		memmove(buff,buff+foward_offset,to_copy_size);
		
		memcpy(buff+to_copy_size,data,data_len);
		ret_len=buff_size;
	}
	else//data_len>=buff_size
	{
		memcpy(buff,data+data_len-buff_size,buff_size);
		ret_len=buff_size;
	}
	return ret_len;
}
Maat_feather_t Maat_summon_feather(int max_thread_num,
									const char* table_info_path,
									const char* ful_cfg_dir,
									const char* inc_cfg_dir,
									void* logger)
{

	_Maat_feather_t* feather=(_Maat_feather_t*)calloc(sizeof(struct _Maat_feather_t),1);
	feather->table_cnt=read_table_info(feather->p_table_info, MAX_TABLE_NUM,table_info_path);
	feather->map_tablename2id=map_create();
	int i=0;
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		if(feather->p_table_info[i]!=NULL)
		{
			if(feather->p_table_info[i]->table_type==TABLE_TYPE_GROUP)
			{
				feather->GROUP_MODE_ON=1;
			}
			map_register(feather->map_tablename2id,feather->p_table_info[i]->table_name,feather->p_table_info[i]->table_id);
		}
	}
	memcpy(feather->inc_dir,inc_cfg_dir,strlen(inc_cfg_dir));
	memcpy(feather->full_dir,ful_cfg_dir,strlen(ful_cfg_dir));
	feather->logger=logger;
	feather->scan_thread_num=max_thread_num;
	feather->garbage_q=MESA_lqueue_create(0,0);
	config_monitor_traverse(feather->maat_version,
							ful_cfg_dir, 
							maat_start_cb,
							maat_update_cb,
							maat_finish_cb,
							feather,
							logger);
	if(feather->update_tmp_scanner==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"At initiation: no valid index file in %s",ful_cfg_dir);
	}
	feather->scanner=feather->update_tmp_scanner;
	feather->update_tmp_scanner=NULL;
	feather->still_working=1;
	if(feather->scanner!=NULL)
	{
		feather->maat_version=feather->scanner->version;
	}
	feather->effect_interval_ms=60*1000;
	feather->scan_interval_ms=1*1000;
	pthread_t cfg_mon_t;
	pthread_create(&cfg_mon_t, NULL, thread_rule_monitor, (void*)feather);
	return feather;
}
Maat_feather_t Maat_summon_feather_json(int max_thread_num,
									const char* table_info_path,
									const char* json_rule,
									void* logger)
{
	Maat_feather_t feather;
	char full_index_dir[256]={0};
	int ret=-1;
	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"Maat initial with JSON file %s.",json_rule);

	ret=json2iris(json_rule, full_index_dir,sizeof(full_index_dir),logger);
	if(ret<0)
	{
		return NULL;
	}
	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"generate index file %s OK.",full_index_dir);
	feather=Maat_summon_feather(max_thread_num,table_info_path, full_index_dir, full_index_dir,logger);
	return feather;
}
int Maat_set_feather_opt(Maat_feather_t feather,int type,void* value,int size)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	int intval=0;
	switch(type)
	{
		case MAAT_OPT_EFFECT_INVERVAL_MS:
			intval=*(int*)value;
			if(size!=sizeof(int)||intval<=0)
			{
				return -1;
			}
			_feather->effect_interval_ms=intval;
			break;
		case MAAT_OPT_SCANDIR_INTERVAL_MS:
			intval=*(int*)value;
			if(size!=sizeof(int)||intval<0)
			{
				return -1;
			}
			_feather->scan_interval_ms=intval;
			break;
		default:
			return -1;
	}
	return 0;
}
void Maat_burn_feather(Maat_feather_t feather)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	_feather->still_working=0;//destroy will proceed in thread_rule_monitor
	return;
}
int Maat_table_register(Maat_feather_t feather,const char* table_name)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	int table_id=-1,ret=0;
	ret=map_str2int(_feather->map_tablename2id, table_name,&table_id);
	if(ret>0)
	{
		return table_id;
	}
	else
	{
		return -1;
	}
}
int Maat_table_callback_register(Maat_feather_t feather,short table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	int idx=0,i=0;
	_Maat_table_info_t *p_table=_feather->p_table_info[table_id];
	const char* lines=NULL;
	if(p_table==NULL)
	{
		return -1;
	}
	if(p_table->table_type!=TABLE_TYPE_PLUGIN)
	{
		return -1;
	}
	idx=p_table->cb_info->cb_plug_cnt;
	if(idx==MAX_PLUGING_NUM)
	{
		return -1;
	}
	p_table->cb_info->cb_plug_cnt++;
	p_table->cb_info->cb_plug[idx].start=start;
	p_table->cb_info->cb_plug[idx].update=update;
	p_table->cb_info->cb_plug[idx].finish=finish;
	p_table->cb_info->cb_plug[idx].u_para=u_para;
	if(p_table->cb_info->line_num>0)
	{
		start(MAAT_RULE_UPDATE_TYPE_FULL,u_para);
		for(i=0;i<p_table->cb_info->line_num;i++)
		{
			lines=(const char*)dynamic_array_read(p_table->cb_info->cache_lines,i);
			if(lines==NULL)
			{
				break;
			}
			update(table_id,lines,u_para);
		}
		finish(u_para);
	}
	return 1;
}
int Maat_full_scan_string_detail(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
						,int* detail_ret,scan_status_t* mid,int thread_num)
{
	int region_ret=0,compile_ret=0,hit_region_cnt=0;
	unsigned int sub_type=0;
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _scan_status_t* _mid=NULL;

	scan_result_t *region_result=NULL;
	_compile_result_t compile_result[rule_num];//dynamic array
	
	struct _Maat_table_info_t *p_table=NULL;
	p_table=_feather->p_table_info[table_id];
	if(data==NULL||data_len==0)
	{
		return 0;
	}
	if(p_table->cfg_num==0)
	{
		return 0;
	}
	if(p_table==NULL||p_table->table_type!=TABLE_TYPE_EXPR)
	{
		return -1;
	}
	if(p_table->do_charset_merge==1)
	{
		sub_type=make_sub_type(table_id,CHARSET_NONE,0);
	}
	else
	{
		sub_type=make_sub_type(table_id,charset,0);
	}
	
	scan_data_t scan_data;
	scan_data.text_data.text=data;
	scan_data.text_data.tlen=data_len;
	scan_data.text_data.toffset=0;
	_Maat_scanner_t* my_scanner=NULL;
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	assert(thread_num<_feather->scan_thread_num);
	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	int offset=(CPU_CACHE_ALIGMENT/sizeof(int))*thread_num;
	my_scanner->ref_cnt[offset]++;
	if(p_table->expr_rule_cnt>0)
	{
		scan_data.rule_type=RULETYPE_STR;
		scan_data.sub_type=sub_type;
		region_ret=rulescan_search(my_scanner->region, thread_num, &scan_data, region_result, MAX_SCANNER_HIT_NUM);
		if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}
	}
	if(p_table->regex_rule_cnt>0)
	{
		scan_data.rule_type=RULETYPE_REG;
		scan_data.sub_type=make_sub_type(table_id,CHARSET_NONE,0);
		region_ret=rulescan_search(my_scanner->region, thread_num, &scan_data, region_result+hit_region_cnt, MAX_SCANNER_HIT_NUM-hit_region_cnt);
		if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}

	}
	if(hit_region_cnt>0)
	{
		if(*mid==NULL)
		{
			_mid=_Maat_make_status(_feather,thread_num);
			*mid=_mid;
		}
		else
		{
			_mid=(struct _scan_status_t*)(*mid);
		}
		compile_ret=region_compile(_mid,region_result,hit_region_cnt,result,compile_result,rule_num);
		if(hit_detail!=NULL)
		{
			*detail_ret=fill_region_hit_detail(data,_mid,										
											region_result,hit_region_cnt,
											compile_result,compile_ret, 
											hit_detail,detail_num);
		}
	}
	my_scanner->ref_cnt[offset]--;
	if(compile_ret==0&&hit_region_cnt>0)
	{
		return -2;
	}
	return compile_ret;
}
int Maat_full_scan_string(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int* found_pos,int rule_num
						,scan_status_t* mid,int thread_num)
{
	int detail_ret=0,compile_ret=0;
	compile_ret=Maat_full_scan_string_detail(feather,table_id,
											charset, data,data_len,
											result, rule_num,
											NULL, 0, &detail_ret,mid,thread_num);
	return compile_ret;
}
int Maat_scan_intval(Maat_feather_t feather,int table_id
						,unsigned int intval
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num)
{
	int region_ret=0,compile_ret=0;
	struct _scan_status_t* _mid=NULL;
	scan_data_t intval_scan_data;
	scan_result_t *region_result=NULL;
	_compile_result_t compile_result[rule_num];
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _Maat_scanner_t* my_scanner=NULL;
	intval_scan_data.rule_type=RULETYPE_INT;
	intval_scan_data.sub_type=make_sub_type(table_id,CHARSET_NONE, 0);
	intval_scan_data.int_data=intval;
	if(_feather->p_table_info[table_id]==NULL||_feather->p_table_info[table_id]->table_type!=TABLE_TYPE_INTVAL)
	{
		return -1;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	if(_feather->p_table_info[table_id]->cfg_num==0)
	{
		return 0;
	}
	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	
	int offset=(CPU_CACHE_ALIGMENT/sizeof(int))*thread_num;
	my_scanner->ref_cnt[offset]++;
	region_ret=rulescan_search(my_scanner->region, thread_num, &intval_scan_data, region_result, MAX_SCANNER_HIT_NUM);
	if(region_ret<0)
	{
		return -1;
	}
	else if(region_ret>0)
	{
		if(*mid==NULL)
		{
			_mid=_Maat_make_status(_feather,thread_num);
			*mid=_mid;
		}
		else
		{
			_mid=(struct _scan_status_t*)(*mid);
		}
		compile_ret=region_compile(_mid,region_result,region_ret,result,compile_result,rule_num);
	}
	
	my_scanner->ref_cnt[offset]--;
	if(compile_ret==0&&region_ret>0)
	{
		return -2;
	}
	return compile_ret;

}

int Maat_scan_proto_addr(Maat_feather_t feather,int table_id
						,struct ipaddr* addr,unsigned short int proto
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num)
{
	int region_ret=0,compile_ret=0;
	struct _scan_status_t* _mid=NULL;
	scan_data_t ip_scan_data;
	scan_result_t *region_result=NULL;
	_compile_result_t compile_result[rule_num];
	
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _Maat_scanner_t* my_scanner=NULL;
	if(_feather->p_table_info[table_id]==NULL||_feather->p_table_info[table_id]->table_type!=TABLE_TYPE_IP)
	{
		return -1;
	}
	if(_feather->p_table_info[table_id]->cfg_num==0)
	{
		return 0;
	}
	ip_scan_data.rule_type=RULETYPE_IPv4;
	ip_scan_data.sub_type=make_sub_type(table_id,CHARSET_NONE, 0);
	switch(addr->addrtype)
	{
		case ADDR_TYPE_IPV4:
			ip_scan_data.ipv4_data.saddr=ntohl(addr->paddr.v4->saddr);
			ip_scan_data.ipv4_data.daddr=ntohl(addr->paddr.v4->daddr);
			ip_scan_data.ipv4_data.sport=ntohs(addr->paddr.v4->source);
			ip_scan_data.ipv4_data.dport=ntohs(addr->paddr.v4->dest);
			ip_scan_data.ipv4_data.proto=proto;
			break;
		case ADDR_TYPE_IPV6:
			ip_scan_data.rule_type=RULETYPE_IPv6;
			memcpy(ip_scan_data.ipv6_data.saddr,addr->paddr.v6->saddr,sizeof(ip_scan_data.ipv6_data.saddr));
			ipv6_ntoh(ip_scan_data.ipv6_data.saddr);
			memcpy(ip_scan_data.ipv6_data.daddr,addr->paddr.v6->daddr,sizeof(ip_scan_data.ipv6_data.daddr));
			ipv6_ntoh(ip_scan_data.ipv6_data.daddr);
			ip_scan_data.ipv6_data.sport=ntohs(addr->paddr.v6->source);
			ip_scan_data.ipv6_data.dport=ntohs(addr->paddr.v6->dest);
			ip_scan_data.ipv6_data.proto=proto;
			break;
		default:
			return -1;
			break;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	int offset=(CPU_CACHE_ALIGMENT/sizeof(int))*thread_num;
	my_scanner->ref_cnt[offset]++;
	region_ret=rulescan_search(my_scanner->region, thread_num, &ip_scan_data, region_result, MAX_SCANNER_HIT_NUM);
	if(region_ret<0)
	{
		return -1;
	}
	else if(region_ret>0)
	{
		if(*mid==NULL)
		{
			_mid=_Maat_make_status(_feather,thread_num);
			*mid=_mid;
		}
		else
		{
			_mid=(struct _scan_status_t*)(*mid);
		}
		compile_ret=region_compile(_mid,region_result,region_ret,result,compile_result,rule_num);
	}
	
	my_scanner->ref_cnt[offset]--;
	if(compile_ret==0&&region_ret>0)
	{
		return -2;
	}
	return compile_ret;
}
int Maat_scan_addr(Maat_feather_t feather,int table_id
						,struct ipaddr* addr
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num)
{
	int compile_ret=0;
	compile_ret=Maat_scan_proto_addr(feather,table_id,
								addr, 0,
								result, rule_num,
								mid,thread_num);
	return compile_ret;
}
stream_para_t Maat_stream_scan_string_start(Maat_feather_t feather,int table_id,int thread_num)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _Maat_scanner_t* scanner=NULL;

	struct _Maat_table_info_t *p_table=NULL;
	assert(thread_num<_feather->scan_thread_num);
	if(_feather->p_table_info[table_id]==NULL)
	{
		return NULL;
	}
	p_table=_feather->p_table_info[table_id];
	if(p_table==NULL||p_table->table_type!=TABLE_TYPE_EXPR)
	{
		return NULL;
	}
	struct _stream_para_t* sp=(struct _stream_para_t*)calloc(sizeof(struct _stream_para_t),1);
	scanner=_feather->scanner;
	sp->feather=_feather;
	sp->version=_feather->maat_version;
	sp->acc_scan_len=0;
	if(scanner==NULL)
	{
		return sp;
	}
	int offset=(CPU_CACHE_ALIGMENT/sizeof(int))*thread_num;
	scanner->ref_cnt[offset]++;
	assert(table_id<256);
	sp->table_id=table_id;
	sp->thread_num=thread_num;
	sp->max_cross_size=p_table->cross_cache_size;
	sp->caching_size=0;
	sp->scan_buff=NULL;
	sp->last_cache=NULL;
	if(p_table->do_charset_merge==1)
	{
		sp->do_merge=1;
	}
	if(p_table->expr_rule_cnt>0)
	{
		sp->do_expr=1;
	}
	if(p_table->regex_rule_cnt>0)
	{
		sp->do_regex=1;
	}
	sp->rs_stream_para=rulescan_startstream(_feather->scanner->region,thread_num);
	return sp;
}

int Maat_stream_scan_string_detail(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
									,int* detail_ret,scan_status_t* mid)
{
	struct _stream_para_t* sp=(struct _stream_para_t*)(*stream_para);
	struct _Maat_scanner_t* scanner=sp->feather->scanner;

	int sub_type=0;
	int region_ret=0,hit_region_cnt=0,compile_ret=0;
	struct _scan_status_t* _mid=(struct _scan_status_t*)(*mid);
	scan_result_t *region_result;
	_compile_result_t compile_result[rule_num];//dynamic array
	scan_data_t region_scan_data;
	if(data==NULL||data_len==0)
	{
		return 0;
	}
	if(scanner==NULL)
	{
		return 0;
	}
	if(sp->version!=sp->feather->maat_version)
	{
		return 0;
	}
	if(sp->feather->p_table_info[sp->table_id]->cfg_num==0)
	{
		return 0;
	}
	region_result=scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*sp->thread_num;
	*detail_ret=0;
	if(sp->do_merge==1)
	{
		sub_type=make_sub_type(sp->table_id,CHARSET_NONE,0);
	}
	else
	{
		sub_type=make_sub_type(sp->table_id,charset,0);
	}
	if(sp->max_cross_size>0&&sp->caching_size>0)
	{
		if(sp->scan_buff!=NULL)
		{
			free(sp->scan_buff);
			sp->scan_buff=NULL;
		}
		sp->scan_buff=(char*)malloc(sp->caching_size+data_len);
		memcpy(sp->scan_buff,sp->last_cache,sp->caching_size);
		memcpy(sp->scan_buff+sp->caching_size,data,data_len);
		region_scan_data.text_data.text=sp->scan_buff;
		region_scan_data.text_data.tlen=sp->caching_size+data_len;
	}
	else
	{
		region_scan_data.text_data.text=data;
		region_scan_data.text_data.tlen=data_len;
	}

	if(sp->last_cache==NULL&&sp->max_cross_size>0)
	{
		assert(sp->caching_size==0);
		sp->last_cache=(char*)malloc(sizeof(char)*sp->max_cross_size);
	}
	if(sp->max_cross_size>0)
	{
		sp->caching_size=detain_last_data(sp->last_cache,sp->max_cross_size,sp->caching_size,data,data_len);
	}

	region_scan_data.text_data.toffset=(int)MIN(0xffffffff/2, sp->acc_scan_len);//longger then int
	sp->acc_scan_len+=data_len;
	if(sp->do_expr==1)
	{
		region_scan_data.rule_type=RULETYPE_STR;
		region_scan_data.sub_type=sub_type;
		region_ret=rulescan_searchstream(sp->rs_stream_para, &region_scan_data, region_result, MAX_SCANNER_HIT_NUM);
		if(region_ret<0)
		{
			return -1;
		}
		else if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}
	}
	if(sp->do_regex==1)
	{
		region_scan_data.rule_type=RULETYPE_REG;
		region_scan_data.sub_type=make_sub_type(sp->table_id,CHARSET_NONE,0);
		region_ret=rulescan_searchstream(sp->rs_stream_para, &region_scan_data, region_result+hit_region_cnt, MAX_SCANNER_HIT_NUM-hit_region_cnt);
		if(region_ret<0)
		{
			return -1;
		}
		else if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}
	}
	if(hit_region_cnt>0)
	{
		if(*mid==NULL)
		{
			_mid=_Maat_make_status(sp->feather,sp->thread_num);
			*mid=_mid;
		}
		else
		{
			_mid=(struct _scan_status_t*)(*mid);
		}
		compile_ret=region_compile(_mid,region_result,hit_region_cnt,result,compile_result,rule_num);
		if(hit_detail!=NULL)
		{
			if(sp->scan_buff!=NULL)
			{
				*detail_ret=fill_region_hit_detail(sp->scan_buff,_mid,
												region_result,hit_region_cnt,
												compile_result,compile_ret,
												hit_detail,detail_num);
			}
			else
			{
				*detail_ret=fill_region_hit_detail(data,_mid,
												region_result,hit_region_cnt,
												compile_result,compile_ret,
												hit_detail,detail_num);
			}
		}
	}
	if(*detail_ret==0)
	{
		free(sp->scan_buff);
		sp->scan_buff=0;
	}
	if(compile_ret==0&&hit_region_cnt>0)
	{
		return -2;
	}
	return compile_ret;
}
int Maat_stream_scan_string(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int* found_pos,int rule_num
									,scan_status_t* mid)

{

	int compile_ret=0;
	int detail_ret=0;
	compile_ret=Maat_stream_scan_string_detail(stream_para, charset,data,data_len,
										result,rule_num, NULL, 0,&detail_ret,mid);
	return compile_ret;
}
void Maat_stream_scan_string_end(stream_para_t* stream_para)
{
	struct _stream_para_t* sp=(struct _stream_para_t*)(*stream_para);
	struct _Maat_scanner_t* scanner=sp->feather->scanner;
	int offset=(CPU_CACHE_ALIGMENT/sizeof(int))*sp->thread_num;

	if(scanner!=NULL)
	{
		if(sp->version==sp->feather->maat_version)
		{
			scanner->ref_cnt[offset]--;
		}

		rulescan_endstream(sp->rs_stream_para);
		
	}
	if(sp->last_cache!=NULL)
	{
		free(sp->last_cache);
		sp->last_cache=NULL;
		sp->caching_size=0;
	}
	if(sp->scan_buff!=NULL)
	{
		free(sp->scan_buff);
		sp->scan_buff=NULL;
	}
	free(sp);
	*stream_para=NULL;
	return;
}
void Maat_clean_status(scan_status_t* mid)
{
	struct _scan_status_t* _mid=NULL;
	if(*mid==NULL)
	{
		return;
	}
	_mid=(struct _scan_status_t*)(*mid);
	free(_mid->hitted_group_id);
	free(_mid);
	*mid=NULL;
	return;
}


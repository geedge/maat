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
#include <time.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/field_stat2.h>

#include "Maat_rule.h"
#include "Maat_rule_internal.h"
#include "json2iris.h"
#include "dynamic_array.h"
#include "aligment_int64.h"
#include "config_monitor.h"

#include "map_str2int.h"
#include "rulescan.h"
#include "UniversalBoolMatch.h"
#include "stream_fuzzy_hash.h"
#include "gram_index_engine.h"

int MAAT_FRAME_VERSION_2_1_20171107=1;

const char* CHARSET_STRING[]={"NONE","gbk","big5","unicode","utf8","bin",
							"unicode_ascii_esc","unicode_ascii_aligned","unicode_ncr_dec","unicode_ncr_hex","url_encode_gb2312","url_encode_utf8",""};
pid_t gettid()
{
	return syscall(SYS_gettid);
}
const char*	module_name_str(const char*name)
{
	static __thread char module[64];
	snprintf(module,sizeof(module),"%s(%d)", name, gettid());
	return module;
}

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
//functioned as strdup, for dictator compatible.
char* _maat_strdup(const char* s)
{
	char*d=NULL;
	if(s==NULL)
	{
		return NULL;
	}
	d=(char*)malloc(strlen(s)+1);
	memcpy(d,s,strlen(s)+1);
	return d;
}
int is_valid_expr_type(enum MAAT_EXPR_TYPE expr_type)
{
	switch(expr_type)
	{
		case EXPR_TYPE_STRING:
		case EXPR_TYPE_AND:
		case EXPR_TYPE_REGEX:
		case EXPR_TYPE_OFFSET:
			return 1;
		default:
			return 0;
	}
}
int is_valid_match_method(enum MAAT_MATCH_METHOD match_method)
{
	switch(match_method)
	{
		case MATCH_METHOD_SUB:
		case MATCH_METHOD_RIGHT:
		case MATCH_METHOD_LEFT:
		case MATCH_METHOD_COMPLETE:
			return 1;
		default:
			return 0;
	}
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
			
			if(to==CHARSET_UNICODE&&
				(*(unsigned short*)pOutBuff==0xFFFE||*(unsigned short*)pOutBuff==0XFEFF))//jump unicode 2 bytes BOM, 0xFF 0xFE
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
int URLEncode(const char* str, const int strSize, char* result, const int resultSize)  
{  
	int i;  
	int j = 0;//for result index  
	char ch;  

	if ((str==NULL) || (result==NULL) || (strSize<=0) || (resultSize<=0)) 
	{  
		return -1;  
	}  

	for ( i=0; (i<strSize)&&(j<resultSize); ++i)
	{  
		ch = str[i];  
		if (((ch>='A') && (ch<='Z')) ||  
			((ch>='a') && (ch<='z')) ||  
			((ch>='0') && (ch<='9')))
		{  
			result[j++] = ch;  
		} 
		else if (ch == ' ')
		{  
			result[j++] = '+';  
		}
		else if (ch == '.' || ch == '-' || ch == '_' || ch == '*')
		{  
			result[j++] = ch;  
		}
		else 
		{  
			if (j+3 < resultSize)
			{  
				sprintf(result+j, "%%%02X", (unsigned char)ch);  
				j += 3;  
			} 
			else
			{  
				return -1;  
			}  
		}  
	}  

	result[j] = '\0';  
	return j;  
}  
int uni2ascii(const char* fmt,const char* src, const int srclen, char* dst, const int dstsize) 
{
	int i=0,j=0;
	assert(srclen%2==0);//unicode must be 2 bytes aligned.
	while(i<srclen&&j<dstsize)
	{
		if(*(unsigned short*)(src+i)<0x7f)
		{
			dst[j]=*(unsigned short*)(src+i);
			j++;
		}
		else
		{
			j+=snprintf(dst+j,dstsize-j,fmt,*(unsigned short*)(src+i));
		}
		i+=2;
	}
	return j;
}
int universal_charset_convert(struct _Maat_scanner_t* scanner,enum MAAT_CHARSET from,enum MAAT_CHARSET to,char *src,int srclen,char *dst,int *dstlen)
{
	int ret=0;
	char* tmp_buff=NULL;
	int tmp_buff_size=0;
	MAAT_CHARSET tmp_dst_code=CHARSET_NONE;
	const char* fmt=NULL;
	switch(to)
	{
		case CHARSET_GBK:
		case CHARSET_BIG5:
		case CHARSET_UNICODE:
		case CHARSET_UTF8:
			ret=iconv_convert(scanner,from,to,src,srclen,dst,dstlen);
			return ret;
			break;
		case CHARSET_UNICODE_ASCII_ESC:
			tmp_dst_code=CHARSET_UNICODE;
			fmt="\\u%x;";
			break;
		case CHARSET_UNICODE_ASCII_ALIGNED:
			tmp_dst_code=CHARSET_UNICODE;
			fmt="\\u%04x";
			break;
		case CHARSET_UNICODE_NCR_DEC:	
			tmp_dst_code=CHARSET_UNICODE;
			fmt="&#%u;";
			break;
		case CHARSET_UNICODE_NCR_HEX:
			tmp_dst_code=CHARSET_UNICODE;
			fmt="&#x%x;";
			break;
		case CHARSET_URL_ENCODE_GB2312:	
			tmp_dst_code=CHARSET_GBK;
			fmt=NULL;
			break;
		case CHARSET_URL_ENCODE_UTF8:
			tmp_dst_code=CHARSET_UTF8;
			fmt=NULL;
			break;
		default:
			return -1;
			break;
	}
	tmp_buff_size=*dstlen;
	tmp_buff=(char*)malloc(tmp_buff_size);
	ret=iconv_convert(scanner,from,tmp_dst_code,src,srclen,tmp_buff,&tmp_buff_size);
	if(ret<0)
	{
		goto error_out;
	}
	if(fmt!=NULL)
	{
		ret=uni2ascii(fmt, tmp_buff, tmp_buff_size, dst,*dstlen);
	}
	else
	{
		ret=URLEncode(tmp_buff,tmp_buff_size,dst,*dstlen);
	}
	*dstlen=ret;
error_out:

	free(tmp_buff);
	tmp_buff=NULL;
	
	return ret;
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
char* str_unescape(char* s)
{
	int i=0,j=0;
	int len=strlen(s);
	for(i=0,j=0;i<len;i++)
	{
		if(s[i]=='\\')
		{
			switch(s[i+1])
			{
				case '&':
					s[j]='&';
					break;
				case 'b':
					s[j]=' ';//space,0x20;
					break;
				case '\\':
					s[j]='\\';
					break;
				default:
					s[j]=s[i];
					i--;	//undo the followed i++
					break;
			}
			i++;
			j++;
		}
		else
		{
			s[j]=s[i];
			j++;
		}
	}
	s[j]='\0';
	return s;
}
char* Maat_str_escape(char* dst,int size,const char*src)
{
	int i=0,j=0;
	int len=strlen(src);
	for(i=0,j=0;i<len&&j<size;i++)
	{
		switch(src[i])
		{
			case '&':
				dst[j]='\\';
				dst[j+1]='&';
				j+=2;
				break;
			case ' ':
				dst[j]='\\';
				dst[j+1]='b';//space,0x20;
				j+=2;
				break;
			case '\\':
				dst[j]='\\';
				dst[j+1]='\\';
				j+=2;
				break;
			default:
				dst[j]=src[i];
				j++;	//undo the followed i++
				break;

		}
	}
	dst[j]='\0';
	return dst;
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
_Maat_table_info_t* create_table_info(int max_thread_num)
{
	struct _Maat_table_info_t*p=NULL;
	p=(struct _Maat_table_info_t*)calloc(sizeof(struct _Maat_table_info_t),1);
	p->conj_cnt=1;
	p->scan_cnt=aligment_int64_array_alloc(max_thread_num);
	p->scan_cpu_time=aligment_int64_array_alloc(max_thread_num);
	p->input_bytes=aligment_int64_array_alloc(max_thread_num);
	p->stream_num=aligment_int64_array_alloc(max_thread_num);
	p->hit_cnt=aligment_int64_array_alloc(max_thread_num);
	p->cross_cache_size=0;
	p->quick_expr_switch=0;
	return p;
}
void destroy_table_info(struct _Maat_table_info_t*p)
{
	aligment_int64_array_free(p->scan_cnt);
	aligment_int64_array_free(p->scan_cpu_time);
	aligment_int64_array_free(p->input_bytes);
	aligment_int64_array_free(p->stream_num);
	aligment_int64_array_free(p->hit_cnt);
	if(p->cb_info!=NULL)
	{
		dynamic_array_destroy(p->cb_info->cache_lines, free);
		p->cb_info->cache_lines=NULL;
		free(p->cb_info);
		p->cb_info=NULL;
	}
	free(p);
	return;
}
int read_expr_table_info(const char* line,int line_num,struct _Maat_table_info_t* p,MESA_htable_handle string2int_map)
{
	int j=0,ret[4]={0};
	char table_type[16],src_charset[256],dst_charset[256],merge[4],quick_str_scan[32]={0};
	char *token=NULL,*sub_token=NULL,*saveptr;

	sscanf(line,"%hu\t%s\t%s\t%s\t%s\t%s\t%d\t%s",&(p->table_id)
											,p->table_name[0]
											,table_type
											,src_charset
											,dst_charset
											,merge
											,&(p->cross_cache_size)
											,quick_str_scan);
	memset(ret,0,sizeof(ret));
	ret[0]=map_str2int(string2int_map,strlwr(table_type),(int*)&(p->table_type));
	ret[1]=map_str2int(string2int_map,strlwr(src_charset),(int*)&(p->src_charset));
	ret[2]=map_str2int(string2int_map,strlwr(merge),&(p->do_charset_merge));
	if(strlen(quick_str_scan)>0)
	{
		ret[3]=map_str2int(string2int_map,strlwr(quick_str_scan),&(p->quick_expr_switch));
	}
	memset(quick_str_scan,0,sizeof(quick_str_scan));

	for(j=0;j<4;j++)
	{
		if(ret[j]<0)
		{
			return -1;
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
			return -1;
		}
		
	}
	return 0;
}
int read_table_info(struct _Maat_table_info_t** p_table_info,int num,const char* table_info_path,int max_thread_num,void* logger)
{
	FILE*fp=NULL;
	char line[MAX_TABLE_LINE_SIZE];
	int i=0,ret=0,table_cnt=0;
	char table_type_str[16],not_care[256];
	MESA_htable_handle string2int_map=map_create();
	struct _Maat_table_info_t*p=NULL;
	struct _Maat_table_info_t*conj_table=NULL;
	
	map_register(string2int_map,"expr", TABLE_TYPE_EXPR);
	map_register(string2int_map,"ip", TABLE_TYPE_IP);
	map_register(string2int_map,"compile", TABLE_TYPE_COMPILE);
	map_register(string2int_map,"plugin", TABLE_TYPE_PLUGIN);
	map_register(string2int_map,"intval", TABLE_TYPE_INTERVAL);
	map_register(string2int_map,"digest", TABLE_TYPE_DIGEST);
	map_register(string2int_map,"expr_plus", TABLE_TYPE_EXPR_PLUS);
	map_register(string2int_map,"group", TABLE_TYPE_GROUP);
	map_register(string2int_map,"similar", TABLE_TYPE_SIMILARITY);
	map_register(string2int_map,"quickoff",0);
	map_register(string2int_map,"quickon",1);
	for(i=0;i<MAX_CHARSET_NUM;i++)
	{
		if(strlen(CHARSET_STRING[i])>0)
		{
			map_register(string2int_map,CHARSET_STRING[i], i);
		}
		else
		{
			break;
		}
	}

	map_register(string2int_map,"yes", 1);
	map_register(string2int_map,"no", 0);
	
	fp=fopen(table_info_path,"r");
	if(fp==NULL)
	{
		fprintf(stderr,"Maat read table info %s error.\n",table_info_path);
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
								"Maat read table info %s error.\n",table_info_path);
	}
	i=0;
	while(NULL!=fgets(line,sizeof(line),fp))
	{
		i++;

		if(line[0]=='#'||line[0]==' '||line[0]=='\t'||strlen(line)<4)
		{
			continue;
		}
		p=create_table_info(max_thread_num);

		sscanf(line,"%hu\t%s\t%s\t%s",&(p->table_id)
											,p->table_name[0]
											,table_type_str
											,not_care);
		ret=map_str2int(string2int_map,strlwr(table_type_str),(int*)&(p->table_type));
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
						"Maat read table info %s line %d error:invalid table type.",table_info_path,i);
			goto error_jump;
		}
		switch(p->table_type)
		{
			case TABLE_TYPE_EXPR:
			case TABLE_TYPE_EXPR_PLUS:
				ret=read_expr_table_info(line, i, p, string2int_map);
				if(ret<0)
				{
					fprintf(stderr,"Maat read table info %s line %d error:unknown column.\n",table_info_path,i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
									"Maat read table info %s line %d error:unknown column.",table_info_path,i);
					goto error_jump;
				}
				break;
			case TABLE_TYPE_PLUGIN:
				p->cb_info=(struct _plugin_table_info*)calloc(sizeof(struct _plugin_table_info),1);
				p->cb_info->cache_lines=dynamic_array_create(1024,1024);
				ret=sscanf(not_care,"%d",&(p->valid_flag_column));
				if(ret==0||ret==EOF)
				{
					p->valid_flag_column=-1;
				}
				break;
			default:
				break;
		}

		if(p->table_id>=num)
		{
			fprintf(stderr,"Maat read table info %s:%d error: table id %uh > %d.\n",table_info_path,i,p->table_id,num);
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
				"Maat read table info %s line %d error: table id %uh > %d.\n",table_info_path,i,p->table_id,num);

			goto error_jump;
		}
		if(p_table_info[p->table_id]!=NULL)//duplicate table_id,means conjunction table;
		{
			conj_table=p_table_info[p->table_id];
			if(conj_table->conj_cnt==MAX_CONJUNCTION_TABLE_NUM)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
								"Maat read table info %s line %d error:reach tableid %d conjunction upper limit."
								,table_info_path,i,p->table_id);
				goto error_jump;
			}
			memcpy(conj_table->table_name[conj_table->conj_cnt],p->table_name[0],MAX_TABLE_NAME_LEN);
			conj_table->conj_cnt++;
			MESA_handle_runtime_log(logger, RLOG_LV_INFO,maat_module,
								"Maat read table info %s:%d:conjunction %s with %s (id=%d,total=%d)."
								,table_info_path,i,p->table_name[0]
								,conj_table->table_name[0],conj_table->table_id,conj_table->conj_cnt);
			//use goto to free the conjunctioned table_info
			goto error_jump;
		}

		p_table_info[p->table_id]=p;
		table_cnt++;
		continue;
error_jump:
		destroy_table_info(p);
		p=NULL;
	}
	fclose(fp);
	map_destroy(string2int_map);
	return table_cnt;
}
struct _Maat_group_inner_t* create_group_rule(int group_id)
{
	struct _Maat_group_inner_t* group=(struct _Maat_group_inner_t*)malloc(sizeof(struct _Maat_group_inner_t));
	group->group_id=group_id;
	group->region_cnt=0;
	group->region_boundary=0;
	group->ref_cnt=0;
	group->regions=dynamic_array_create(1,8);
	group->compile_shortcut=NULL;
	group->table_id=0;
	group->group_name=NULL;
	pthread_mutex_init(&(group->mutex), NULL);
	return group;
}
void destroy_group_rule(struct _Maat_group_inner_t* group)
{

	if(group->ref_cnt>0||group->region_cnt>0)
	{
		return;
	}

	dynamic_array_destroy(group->regions,free);
	group->region_cnt=0;
	group->region_boundary=0;
	group->regions=NULL;
	group->ref_cnt=0;
	group->group_id=-1;
	group->table_id=-1;
	free(group->group_name);
	group->group_name=NULL;
	pthread_mutex_destroy(&(group->mutex));
	free(group);

}
void make_group_set(const struct _Maat_compile_inner_t* compile_rule,universal_bool_expr_t* a_set)
{
	int i=0,j=0;
	a_set->bool_expr_id=(void*)compile_rule;
	struct _Maat_group_inner_t*group=NULL;
	assert(compile_rule->group_cnt<=MAX_ITEMS_PER_BOOL_EXPR);
	for(i=0,j=0;i<compile_rule->group_boundary&&j<MAX_ITEMS_PER_BOOL_EXPR;i++)
	{
		group=(struct _Maat_group_inner_t*)dynamic_array_read(compile_rule->groups,i);
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
	struct _Maat_compile_inner_t* compile_rule=(struct _Maat_compile_inner_t*)data;
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
	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module,
								"build bool matcher start contain %ld compile rule",
								q_cnt);	
	bool_matcher=boolexpr_initialize(set_array, q_cnt, thread_num, &mem_size);
	if(bool_matcher!=NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module,
								"build bool matcher use %u memory",mem_size);
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
struct _Maat_compile_inner_t * create_compile_rule(int compile_id)
{
	struct _Maat_compile_inner_t* p=NULL;
	p=(struct _Maat_compile_inner_t*)calloc(sizeof(struct _Maat_compile_inner_t),1);
	p->compile_id=compile_id;
	p->group_cnt=0;
	p->table_id=0;
	p->group_boundary=1;
	p->groups=dynamic_array_create(1, 1);
	pthread_rwlock_init(&(p->rwlock), NULL);
	return p;
}
void destroy_compile_rule(struct _Maat_compile_inner_t * p)
{
	int i=0;
	struct _Maat_compile_inner_t* p_group=NULL;
	assert(p->group_cnt==0);
	for(i=0;i<p->group_boundary;i++)
	{
		p_group=(struct _Maat_compile_inner_t*)dynamic_array_read(p->groups,i);
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
		case MATCH_METHOD_COMPLETE:
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

struct op_expr_t* create_op_expr(unsigned int expr_id,int operation,void* u_para,int table_id)
{
	struct op_expr_t* op_expr=NULL;
	op_expr=(struct op_expr_t*)calloc(sizeof(struct op_expr_t),1);
	op_expr->no_effect_convert_cnt=0;
	op_expr->convert_failed=0;
	op_expr->p_expr=(boolean_expr_t*)calloc(sizeof(boolean_expr_t),1);
	op_expr->p_expr->expr_id=expr_id;
	op_expr->p_expr->operation=operation;
	op_expr->p_expr->rnum=0;
	op_expr->p_expr->rules=NULL;
	op_expr->p_expr->tag=u_para;
	op_expr->table_id=table_id;
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
	op_expr->rule_type=p_rule->rule_type;
	return;
}
GIE_digest_t* create_digest_rule(unsigned int id,short op,const char* digest,
						short cfds_lvl,struct _Maat_group_inner_t* tag)
{
	GIE_digest_t* rule=(GIE_digest_t*)calloc(sizeof(GIE_digest_t),1);
	int digest_len=0;
	rule->id=id;
	rule->operation=op;
	if(digest!=NULL)
	{
		digest_len=strlen(digest);
		rule->sfh=(char*)calloc(sizeof(char),digest_len+1);
		memcpy(rule->sfh,digest,digest_len);

	}
	rule->sfh_length=digest_len;
	rule->cfds_lvl=cfds_lvl;
	rule->tag=(void*)tag;
	return rule;
}
void destroy_digest_rule(GIE_digest_t*rule)
{
	if(rule->sfh!=NULL)
	{
		free(rule->sfh);
		rule->sfh=NULL;
	}
	free(rule);
	rule=NULL;
	return;
}
struct _Maat_scanner_t* create_maat_scanner(unsigned int version,_Maat_feather_t *feather)
{
	int scan_thread_num=feather->scan_thread_num;
	MESA_lqueue_head tomb=feather->garbage_q;
//	int rs_scan_type=feather->rule_scan_type;
	struct _Maat_table_info_t ** pp_table=feather->p_table_info;

	int i=0,j=0;
	unsigned int sub_type=0;
	int ret=0;
	
	MESA_htable_create_args_t hargs;
	memset(&hargs,0,sizeof(hargs));
	hargs.thread_safe=0;
	hargs.hash_slot_size = 1024*1024;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;
	hargs.recursive = 0; 
//	hargs.data_free = _void_destroy_compile_rule;
	hargs.data_free = EMPTY_FREE;

	hargs.data_expire_with_condition = NULL;

	struct _Maat_scanner_t* scanner=NULL;
	scanner=(struct _Maat_scanner_t*)calloc(sizeof(struct _Maat_scanner_t),1);

	//Function Maat_cmd_append will access compile_hash in user thread.
	hargs.thread_safe=1;
	scanner->compile_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(scanner->compile_hash,0);

	hargs.thread_safe=1;
	hargs.data_free=EMPTY_FREE;
	scanner->group_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(scanner->group_hash,0);

	hargs.thread_safe=0;
	scanner->region_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(scanner->region_hash,0);

	scanner->district_map=map_create();
	
	scanner->version=version;
	scanner->cfg_num=0;
	scanner->dedup_expr_num=0;
	scanner->max_thread_num=scan_thread_num;
	//optimized for CPU cache_alignment 64
	scanner->ref_cnt=aligment_int64_array_alloc(scan_thread_num);
	scanner->region_update_q=MESA_lqueue_create(0,0);
	scanner->region=rulescan_initialize(scan_thread_num);
	
	//For best performance test:
	//1.Do NOT set this option,rulescan return no hit detail as default;
	//2.Set necessary STR rule to QUICK;
	if(feather->rule_scan_type==1)
	{
		rulescan_set_param(scanner->region,RULESCAN_DETAIL_RESULT,NULL,0);
	}
	else if(feather->rule_scan_type==2)
	{
		rulescan_set_param(scanner->region,RULESCAN_DETAIL_RESULT,NULL,0);
		rulescan_set_param(scanner->region,RULESCAN_REGEX_GROUP,NULL,0);
	}
	scanner->tomb_ref=tomb;
	scanner->region_rslt_buff=(scan_result_t*)malloc(sizeof(scan_result_t)*MAX_SCANNER_HIT_NUM*scan_thread_num);

	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		if(pp_table[i]==NULL)
		{
			continue;
		}
		switch(pp_table[i]->table_type)
		{
			case TABLE_TYPE_DIGEST:
			case TABLE_TYPE_SIMILARITY:
				scanner->gie_aux[i].table_type=pp_table[i]->table_type;
				scanner->gie_aux[i].update_q=MESA_lqueue_create(0,0);
				break;
			case TABLE_TYPE_EXPR:
			case TABLE_TYPE_EXPR_PLUS:
				if(pp_table[i]->quick_expr_switch==1)
				{
					for(j=0;j<MAX_CHARSET_NUM&& pp_table[i]->dst_charset[j]!=CHARSET_NONE;j++)
					{
						sub_type=make_sub_type(pp_table[i]->table_id, pp_table[i]->dst_charset[j], pp_table[i]->do_charset_merge);
						ret=rulescan_set_param(scanner->region,RULESCAN_QUICK_SCAN,&sub_type,sizeof(sub_type));
						assert(ret==1);
						if(pp_table[i]->do_charset_merge==1)
						{
							break;
						}
					}
				}
				break;
			default:
				break;
		}
	}
	return scanner;
}



void destroy_maat_scanner(struct _Maat_scanner_t*scanner)
{
	long q_cnt=0,data_size=0;
	int i=0,j=0,q_ret=0;
	struct op_expr_t* op_expr=NULL;
	GIE_digest_t* digest_rule=NULL;
	if(scanner==NULL)
	{
		return;
	}
	rulescan_destroy(scanner->region);
	MESA_htable_destroy(scanner->compile_hash,NULL);
	MESA_htable_destroy(scanner->group_hash, NULL);
	MESA_htable_destroy(scanner->region_hash, NULL);
	map_destroy(scanner->district_map);
	scanner->district_map=NULL;
	assert(scanner->tmp_district_map==NULL);
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
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		if(scanner->gie_aux[i].gie_handle!=NULL)
		{
			GIE_destory(scanner->gie_aux[i].gie_handle);
		}
		if(scanner->gie_aux[i].update_q==NULL)
		{
			continue;
		}
		q_cnt=MESA_lqueue_get_count(scanner->gie_aux[i].update_q);
		for(j=0;j<q_cnt;j++)
		{
			data_size=sizeof(GIE_digest_t*);
			q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(scanner->gie_aux[i].update_q,&digest_rule,&data_size);
			assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
			destroy_digest_rule(digest_rule);
		}
		MESA_lqueue_destroy(scanner->gie_aux[i].update_q, lqueue_destroy_cb, NULL);
	}
	free(scanner);
	return;
}


unsigned int make_sub_type(unsigned short table_id,enum MAAT_CHARSET charset,int do_charset_merge)
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
void count_rs_region(struct op_expr_t* op_expr,struct _region_stat_t* region_stat, int size)
{
	assert(op_expr->table_id<size);
	int op=0;
	if(op_expr->p_expr->operation==0)//add
	{
		op=1;
	}
	else if(op_expr->p_expr->operation==1)//delete
	{
		op=-1;
	}
	else
	{
		assert(0);
	}
	region_stat[op_expr->table_id].cfg_num+=op;
	switch(op_expr->rule_type)
	{
		case RULETYPE_STR:
			region_stat[op_expr->table_id].expr_rule_cnt+=op;
			break;
		case RULETYPE_REG:
			region_stat[op_expr->table_id].regex_rule_cnt+=op;
			break;
		case RULETYPE_INT:
			break;
		case RULETYPE_IPv4:
			region_stat[op_expr->table_id].ipv4_rule_cnt+=op;
			break;
		case RULETYPE_IPv6:
			region_stat[op_expr->table_id].ipv6_rule_cnt+=op;
			break;
		default:
			assert(0);
			break;
	}
	return;
}

void rulescan_batch_update(rule_scanner_t rs_handle,MESA_lqueue_head expr_queue,void*logger,struct _Maat_scanner_t* maat_scanner)
{
	long i=0,data_size=0;
	int j=0,ret=0;
	unsigned int failed_ids[MAX_FAILED_NUM];
	char failed_info[512],*p=NULL;
	MESA_queue_errno_t q_ret=MESA_QUEUE_RET_OK; 
	memset(failed_ids,0,sizeof(failed_ids));
	memset(failed_info,0,sizeof(failed_info));
	const long q_cnt=MESA_lqueue_get_count(expr_queue);
	struct timespec start,end;
	unsigned long long update_interval=0;
	struct _region_stat_t region_counter[MAX_TABLE_NUM];
	if(q_cnt==0)
	{
		return;
	}
	memset(region_counter,0,sizeof(region_counter));
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
		count_rs_region(op_expr,region_counter,MAX_TABLE_NUM);
		destroy_op_expr(op_expr);
		op_expr=NULL;
	}
	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"rs_handle %p rulescan_update %ld rules.",rs_handle,q_cnt);
	clock_gettime(CLOCK_MONOTONIC,&start);
	ret=rulescan_update(rs_handle, to_update_expr,q_cnt, failed_ids,MAX_FAILED_NUM);
	clock_gettime(CLOCK_MONOTONIC,&end);
	if(ret!=1)
	{
		p=failed_info;
		for(i=0;i<failed_ids[0]&&i<MAX_FAILED_NUM-1&&sizeof(failed_info)-(p-failed_info)>10;i++)
		{
			p+=snprintf(p,sizeof(failed_info)-(p-failed_info),"%d,",failed_ids[i+1]);
		}
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"rulescan_update error,when batch update %ld rules,regex error %u.",q_cnt,failed_ids[0]);
		assert(0);
	}
	update_interval=(end.tv_sec-start.tv_sec)*1000000000+end.tv_nsec-start.tv_nsec;
	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"rs_handle %p rulescan_update with %2.2e (%llu) ns."
							,rs_handle
							,(double)update_interval
							,update_interval);
	//update scanner's region cnt;
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		maat_scanner->region_counter[i].cfg_num+=region_counter[i].cfg_num;
		maat_scanner->region_counter[i].expr_rule_cnt+=region_counter[i].expr_rule_cnt;
		maat_scanner->region_counter[i].regex_rule_cnt+=region_counter[i].regex_rule_cnt;
		assert(maat_scanner->region_counter[i].cfg_num>=0);
		assert(maat_scanner->region_counter[i].expr_rule_cnt>=0);
		assert(maat_scanner->region_counter[i].regex_rule_cnt>=0);
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

void digest_batch_update(GIE_handle_t* handle,MESA_lqueue_head update_q,void*logger,struct _Maat_scanner_t* maat_scanner,int table_id)
{
	long i=0,data_size=0;
	int ret=0;
	GIE_digest_t* digest_rule=NULL;
	GIE_digest_t** update_array=NULL;
	MESA_queue_errno_t q_ret=MESA_QUEUE_RET_OK; 
	const long q_cnt=MESA_lqueue_get_count(update_q);
	if(q_cnt==0)
	{
		return;
	}
	struct _region_stat_t region_counter[MAX_TABLE_NUM];
	memset(region_counter,0,sizeof(region_counter));
	update_array=(GIE_digest_t** )calloc(sizeof(GIE_digest_t*),q_cnt);
	for(i=0;i<q_cnt;i++)
	{
		data_size=sizeof(void*);
		q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(update_q,&digest_rule,&data_size);
		assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
		update_array[i]=digest_rule;
		digest_rule=NULL;
	}
	ret=GIE_update(handle,update_array, (int)q_cnt);
	if(ret!=(int)q_cnt)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"GIE_update error,when batch update %d/%ld rules.",ret,q_cnt);

	}
	for(i=0;i<q_cnt;i++)
	{
		if(update_array[i]->operation==GIE_INSERT_OPT)
		{
			maat_scanner->region_counter[table_id].cfg_num++;
		}
		else
		{
			maat_scanner->region_counter[table_id].cfg_num--;
		}
		destroy_digest_rule(update_array[i]);
		update_array[i]=NULL;
	}
	free(update_array);
	update_array=NULL;
	return;
}
struct _Maat_group_inner_t* add_region_to_group(struct _Maat_group_inner_t* group,int table_id,int region_id,int district_id,int expr_id,enum MAAT_TABLE_TYPE region_type)
{
	int i=0;
	struct _Maat_region_inner_t* region_rule=NULL;
	for(i=0;i<group->region_boundary;i++)
	{
		region_rule=(struct _Maat_region_inner_t*)dynamic_array_read(group->regions, i);
		if(region_rule==NULL)
		{
			continue;
		}
		if(region_rule->region_id==region_id)
		{
			break;
		}
	}
	if(i==group->region_boundary)//new region
	{
		region_rule=(struct _Maat_region_inner_t*)malloc(sizeof(struct _Maat_region_inner_t));
		region_rule->region_id=region_id;
		region_rule->expr_id_cnt=1;
		region_rule->expr_id_ub=region_rule->expr_id_lb=expr_id;
		region_rule->district_id=district_id;
		region_rule->table_type=region_type;
		region_rule->table_id=table_id;
		pthread_mutex_lock(&(group->mutex));
		dynamic_array_write(group->regions,group->region_boundary,region_rule);
		group->region_cnt++;
		group->region_boundary++;
		pthread_mutex_unlock(&(group->mutex));
	}
	else
	{
		assert(expr_id==region_rule->expr_id_ub+1);
		region_rule->expr_id_ub=expr_id;
		region_rule->expr_id_cnt++;
	}
	return group;
}
void cancel_last_region_from_group(struct _Maat_group_inner_t* group,int region_id,int expr_id)
{
	struct _Maat_region_inner_t* region_rule=NULL;
	pthread_mutex_lock(&(group->mutex));
	region_rule=(struct _Maat_region_inner_t*)dynamic_array_read(group->regions,group->region_boundary-1);
	assert(region_rule->expr_id_ub==expr_id&&region_rule->region_id==region_id);
	if(region_rule->expr_id_cnt==1)
	{
		free(region_rule);
		dynamic_array_write(group->regions,group->region_boundary,NULL);
		group->region_cnt--;
		group->region_boundary--;
	}
	else
	{
		region_rule->expr_id_ub--;
		region_rule->expr_id_cnt--;
	}
	pthread_mutex_unlock(&(group->mutex));
	return;
}
unsigned int del_region_from_group(struct _Maat_group_inner_t* group,int region_id,unsigned int *output_expr_id,int output_size)
{
	int i=0,j=0;
	struct _Maat_region_inner_t* region_rule=NULL;
	pthread_mutex_lock(&(group->mutex));
	for(i=0;i<group->region_boundary;i++)
	{
		region_rule=(struct _Maat_region_inner_t*)dynamic_array_read(group->regions, i);
		if(region_rule==NULL)
		{
			continue;
		}
		if(region_rule->region_id==region_id)
		{
			dynamic_array_write(group->regions, i, NULL);
			for(j=0;j<region_rule->expr_id_cnt;j++)
			{
				output_expr_id[j]=region_rule->expr_id_lb+j;
				assert(output_expr_id[j]>=0);
			}
			assert(j<=output_size);	
			region_rule->region_id=0;
			free(region_rule);
			region_rule=NULL;
			group->region_cnt--;
			break;
		}
	}
	pthread_mutex_unlock(&(group->mutex));
	return j;
}

int add_group_to_compile(struct _Maat_compile_inner_t*a_compile_rule,struct _Maat_group_inner_t* a_rule_group)
{
	int i=0,ret=-1;
	int write_pos=-1;
	struct _Maat_group_inner_t* p=NULL;
	pthread_rwlock_wrlock(&(a_compile_rule->rwlock));
	if(a_compile_rule->db_c_rule!=NULL
		&&a_compile_rule->group_cnt>=a_compile_rule->db_c_rule->declare_grp_num
		&&a_compile_rule->db_c_rule->declare_grp_num!=0)
	{
		ret=-1;
		goto error_out;
	}

	for(i=0;i<a_compile_rule->group_boundary;i++)
	{
		p=(struct _Maat_group_inner_t*)dynamic_array_read(a_compile_rule->groups,i);
		if(p==NULL)
		{
			write_pos=i;
		}
		else
		{
			if(p->group_id==a_rule_group->group_id)//duplicate group
			{
				ret=-1;
				goto error_out;
			}
		}
	}
	if(write_pos<0&&a_compile_rule->group_boundary==MAX_EXPR_ITEM_NUM)
	{
		ret=-1;
		goto error_out;
	}
	if(write_pos<0)
	{
		write_pos=a_compile_rule->group_boundary;
		a_compile_rule->group_boundary++;
	}
	dynamic_array_write(a_compile_rule->groups,write_pos, a_rule_group);
	a_compile_rule->group_cnt++;
	a_rule_group->ref_cnt++;
	//member group->compile_shortcut may set to NULL and compile rule pointer repeatly,until rule build finish.
	if(a_rule_group->ref_cnt==1&&a_compile_rule->group_cnt==1)
	{
		a_rule_group->compile_shortcut=a_compile_rule;
	}
	else
	{
		a_rule_group->compile_shortcut=NULL;
	}
		
	//update group's shortcut when compile has more than one group.
	if(a_compile_rule->group_cnt!=1)
	{
		for(i=0;i<a_compile_rule->group_boundary;i++)
		{
			p=(struct _Maat_group_inner_t*)dynamic_array_read(a_compile_rule->groups,i);
			if(p!=NULL)
			{
				p->compile_shortcut=NULL;
			}
		}
	}
	ret=1;
error_out:
	pthread_rwlock_unlock(&(a_compile_rule->rwlock));

	return ret;
}
struct _Maat_group_inner_t* del_group_from_compile(struct _Maat_compile_inner_t*a_compile_rule,int group_id)
{
	int i=0;
	struct _Maat_group_inner_t* group_rule=NULL;
	pthread_rwlock_wrlock(&(a_compile_rule->rwlock));
	for(i=0;i<MAAT_MAX_EXPR_ITEM_NUM;i++)
	{
		group_rule=(struct _Maat_group_inner_t*)dynamic_array_read(a_compile_rule->groups,i);
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
int get_district_id(_Maat_scanner_t *scanner,const char* district_str)
{
	int map_ret=0,district_id=-1;
	map_ret=map_str2int(scanner->district_map, district_str,&district_id);
	if(map_ret<0)
	{
		if(scanner->tmp_district_map==NULL)
		{
			scanner->tmp_district_map=map_duplicate(scanner->district_map);
		}
		map_ret=map_str2int(scanner->tmp_district_map, district_str,&district_id);
		if(map_ret<0)
		{
			district_id= scanner->district_num;
			map_register(scanner->tmp_district_map,district_str, district_id);
			scanner->district_num++;
		}
	}
	return district_id;
}
int add_expr_rule(struct _Maat_table_info_t* table,struct db_str_rule_t* db_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	unsigned int i=0,j=0;
	char* p=NULL,*saveptr=NULL,*region_string=NULL;
	int region_str_len=0,ret=0,k=0;
	int expr_id=0,district_id=-1;
	
	scan_rule_t*p_rule=NULL;
	struct _Maat_group_inner_t* group_rule=NULL;
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
	struct _Maat_group_inner_t* u_para=NULL;

	if(table->table_type==TABLE_TYPE_EXPR_PLUS)
	{
		assert(strlen(db_rule->district)>0);
		district_id=get_district_id(scanner, db_rule->district);
	}
	group_rule=(struct _Maat_group_inner_t*)HASH_fetch_by_id(scanner->group_hash, db_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(db_rule->group_id);
		HASH_add_by_id(scanner->group_hash, db_rule->group_id, group_rule);
	}
	switch(db_rule->expr_type)
	{
		case EXPR_TYPE_AND:
			for(i=0,p=db_rule->keywords;;i++,p=NULL)
			{
				if(i>=MAAT_MAX_EXPR_ITEM_NUM)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d too many expr.",table->table_name[table->updating_name],db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=strtok_r_esc(p,'&',&saveptr);
				if(sub_key_array[i]==NULL)
				{
					break;
				}
				sub_key_array[i]=str_unescape(sub_key_array[i]);
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
							"Table %s region cfg %d too many expr.",table->table_name[table->updating_name],db_rule->region_id);
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
							"Table %s region cfg %d invalid offset.",table->table_name[table->updating_name],db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=(char*)memchr(sub_key_array[i],':',strlen(sub_key_array[i]));
				if(sub_key_array[i]==NULL)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d invalid keywords format.",table->table_name[table->updating_name],db_rule->region_id);
					return -1;
				}
				sub_key_array[i]++;//jump over ':'
				sub_key_array[i]=str_unescape(sub_key_array[i]);
			}
			sub_expr_cnt=i;
			table->expr_rule_cnt++;
			break;
		case EXPR_TYPE_REGEX://it's easy,no need to charset convert
			expr_id=scanner->exprid_generator++;
			u_para=add_region_to_group(group_rule,table->table_id,db_rule->region_id,district_id,expr_id,TABLE_TYPE_EXPR);
			if(u_para==NULL)
			{
				return -1;
			}
			op_expr=create_op_expr(expr_id
						,0
						,u_para
						,table->table_id);
			for(i=0,p=db_rule->keywords;;i++,p=NULL)
			{
				if(i>=MAAT_MAX_EXPR_ITEM_NUM)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d too many expr.",table->table_name[table->updating_name],db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=strtok_r_esc(p,'&',&saveptr);
				if(sub_key_array[i]==NULL)
				{
					break;
				}
				sub_key_array[i]=str_unescape_and(sub_key_array[i]);//regex remain use str_unescape_and
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
			sub_key_array[0]=str_unescape(sub_key_array[0]);
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
					table->table_name[table->updating_name],db_rule->region_id);
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
			u_para=add_region_to_group(group_rule,table->table_id, db_rule->region_id,district_id,expr_id, table->table_type);
			if(u_para==NULL)//duplicate
			{
				return -1;
			}
			op_expr=create_op_expr(expr_id
									,0	//add
									,u_para
									,table->table_id
									);
			for(k=0;k<sub_expr_cnt;k++)
			{
				if(strlen(sub_key_array[k])==0)
				{
						continue;
				}
				region_str_len=strlen(sub_key_array[k])*8+1; // 1 byte map to 8 bytes maximum, e.g. "&#x0627;" or "\u63221;"
				region_string=(char*)calloc(sizeof(char),region_str_len);
				if(table->src_charset!=dst_charset)//need convert
				{

					ret=universal_charset_convert(scanner,table->src_charset, dst_charset, 
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
						op_expr->convert_failed++;
						table->iconv_err_cnt++;
						break;
					}
					if(region_str_len==(int)strlen(sub_key_array[k])&&
						0==memcmp(sub_key_array[k],region_string,region_str_len))
					{
						op_expr->no_effect_convert_cnt++;
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
			//if each sub string's convert take no effect and src charset is one of the dst.
			//if any sub expr convert failed
			if((TRUE==table->src_charset_in_dst&&op_expr->no_effect_convert_cnt==sub_expr_cnt)||
				op_expr->convert_failed>0)
			{
				scanner->dedup_expr_num++;
				cancel_last_region_from_group(group_rule,db_rule->region_id,op_expr->p_expr->expr_id);
				destroy_op_expr(op_expr);
				//redeem expr_id
				scanner->exprid_generator--;
				op_expr=NULL;
			}
			else
			{
				MESA_lqueue_join_tail(scanner->region_update_q,&op_expr, sizeof(void*));
			}
		}
	
	}
	else
	{
		expr_id=scanner->exprid_generator++;
		u_para=add_region_to_group(group_rule, table->table_id, db_rule->region_id,district_id,expr_id, table->table_type);
		if(u_para==NULL)
		{
			return -1;
		}
		op_expr=create_op_expr(expr_id
								,0	//add
								,u_para
								,table->table_id
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
	struct _Maat_group_inner_t* group_rule=NULL;
	scan_rule_t* p_rule=NULL;
	struct op_expr_t* op_expr=NULL;
	struct _Maat_group_inner_t* u_para=NULL;
	int expr_id=0,district_id=-1;

	group_rule=(struct _Maat_group_inner_t*)HASH_fetch_by_id(scanner->group_hash, db_ip_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(db_ip_rule->group_id);
		HASH_add_by_id(scanner->group_hash, db_ip_rule->group_id, group_rule);
	}

	expr_id=scanner->exprid_generator++;
	u_para=add_region_to_group(group_rule, table->table_id,db_ip_rule->region_id,district_id,expr_id,TABLE_TYPE_IP);
	if(u_para==NULL)
	{
		return -1;
	}
	op_expr=create_op_expr(expr_id
						,0
						,u_para
						,table->table_id
						);
	p_rule=create_rs_ip_rule(make_sub_type(table->table_id,CHARSET_NONE,0)
						,db_ip_rule);
	op_expr_add_rule(op_expr,p_rule);
	MESA_lqueue_join_tail(scanner->region_update_q, &op_expr, sizeof(void*));
	return 0;
}
int add_intval_rule(struct _Maat_table_info_t* table,struct db_intval_rule_t* intval_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_group_inner_t* group_rule=NULL;
	scan_rule_t* p_rule=NULL;
	struct op_expr_t* op_expr=NULL;
	struct _Maat_group_inner_t* u_para=NULL;
	int expr_id=0,district_id=-1;
	
	group_rule=(struct _Maat_group_inner_t*)HASH_fetch_by_id(scanner->group_hash, intval_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(intval_rule->group_id);
		HASH_add_by_id(scanner->group_hash, intval_rule->group_id, group_rule);
	}
	expr_id=scanner->exprid_generator++;
	u_para=add_region_to_group(group_rule, table->table_id,intval_rule->region_id,district_id,expr_id,TABLE_TYPE_INTERVAL);
	if(u_para==NULL)
	{
		return -1;
	}
	op_expr=create_op_expr(expr_id
						,0
						,u_para
						,table->table_id
						);
	p_rule=create_rs_intval_rule(make_sub_type(table->table_id,CHARSET_NONE,0)
						,intval_rule);
	op_expr_add_rule(op_expr,p_rule);
	MESA_lqueue_join_tail(scanner->region_update_q, &op_expr, sizeof(void*));
	return 0;
}
int add_digest_rule(struct _Maat_table_info_t* table,struct db_digest_rule_t* db_digest_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_group_inner_t* group_rule=NULL;
	GIE_digest_t* digest_rule=NULL;
	struct _Maat_group_inner_t* u_para=NULL;
	int expr_id=0,district_id=-1;

	group_rule=(struct _Maat_group_inner_t*)HASH_fetch_by_id(scanner->group_hash, db_digest_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(db_digest_rule->group_id);
		HASH_add_by_id(scanner->group_hash, db_digest_rule->group_id, group_rule);
	}
	expr_id=scanner->exprid_generator++;
	u_para=add_region_to_group(group_rule,table->table_id,db_digest_rule->region_id,district_id,expr_id,TABLE_TYPE_DIGEST);
	if(u_para==NULL)
	{
		return -1;
	}
	if(table->table_type==TABLE_TYPE_SIMILARITY)
	{
		db_digest_rule->digest_string=str_unescape(db_digest_rule->digest_string);
	}
	digest_rule=create_digest_rule(expr_id, GIE_INSERT_OPT
								,db_digest_rule->digest_string
								,db_digest_rule->confidence_degree
								,group_rule);
	MESA_lqueue_join_tail(scanner->gie_aux[table->table_id].update_q, &digest_rule, sizeof(void*));
	scanner->gie_total_q_size++;
	return 0;
}
int del_region_rule(struct _Maat_table_info_t* table,int region_id,int group_id,int rule_type,struct _Maat_scanner_t *maat_scanner,void* logger)
{
	int i=0;
	unsigned int expr_id[MAAT_MAX_EXPR_ITEM_NUM*MAX_CHARSET_NUM]={0};
	int expr_num=0;
	struct _Maat_group_inner_t* group_rule=NULL;
	struct op_expr_t* op_expr=NULL;
	GIE_digest_t* digest_rule=NULL;
	group_rule=(struct _Maat_group_inner_t*)HASH_fetch_by_id(maat_scanner->group_hash, group_id);
	if(group_rule==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,table %s group id %u not exist,while delete region id %d."
							,table->table_name[table->updating_name]
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
							,table->table_name[table->updating_name]
							,group_id);
		return -1;
	}
	switch(table->table_type)
	{
		case	TABLE_TYPE_IP:
		case	TABLE_TYPE_EXPR:
		case	TABLE_TYPE_EXPR_PLUS:
		case	TABLE_TYPE_INTERVAL:
			for(i=0;i<expr_num;i++)
			{
				op_expr=create_op_expr(expr_id[i],1,NULL,table->table_id);//del expr
				op_expr->rule_type=rule_type;
				MESA_lqueue_join_tail(maat_scanner->region_update_q,&op_expr, sizeof(void*));
			}
			break;
		case	TABLE_TYPE_SIMILARITY:
		case	TABLE_TYPE_DIGEST:
			assert(expr_num==1);
			digest_rule=create_digest_rule(expr_id[0], GIE_DELETE_OPT	//del digest
									,NULL
									,0
									,NULL);
			MESA_lqueue_join_tail(maat_scanner->gie_aux[table->table_id].update_q,&digest_rule, sizeof(void*));
			maat_scanner->gie_total_q_size++;
			break;
		default:
			assert(0);
			break;
	}
	if(group_rule->region_cnt==0&&group_rule->region_cnt==0)
	{
		HASH_delete_by_id(maat_scanner->group_hash,group_id);
		garbage_bagging(GARBAGE_GROUP_RULE, group_rule, maat_scanner->tomb_ref);
		MESA_handle_runtime_log(logger,RLOG_LV_DEBUG,maat_module ,
							"Indirectly delete group %d,last region rule has been delete,table %s region id %d ."
							,group_id
							,table->table_name[table->updating_name]
							,region_id);
	}
	return 1;
}
int add_group_rule(struct _Maat_table_info_t* table,struct db_group_rule_t* db_group_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_group_inner_t* group_rule=NULL;
	struct _Maat_compile_inner_t*compile_rule=NULL;
	int ret=0;
	group_rule=(struct _Maat_group_inner_t*)HASH_fetch_by_id(scanner->group_hash, db_group_rule->group_id);
	if(group_rule==NULL)
	{
		group_rule=create_group_rule(db_group_rule->group_id);
		group_rule->table_id=table->table_id;
			
		ret=HASH_add_by_id(scanner->group_hash, db_group_rule->group_id,group_rule);
		assert(ret>=0);
	}
	
	compile_rule=(struct _Maat_compile_inner_t*)HASH_fetch_by_id(scanner->compile_hash, db_group_rule->compile_id);
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
																	,table->table_name[table->updating_name]
																	,db_group_rule->group_id
																	,db_group_rule->compile_id);
		return -1;
	}
	return 0;
	
}
void del_group_rule(struct _Maat_table_info_t* table,struct db_group_rule_t* db_group_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_compile_inner_t*compile_rule=NULL;
	struct _Maat_group_inner_t* group_rule=NULL;
	compile_rule=(struct _Maat_compile_inner_t*)HASH_fetch_by_id(scanner->compile_hash, db_group_rule->compile_id);
	if(compile_rule==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,delete %s group rule error : compile id %d does not exisit."
																	,table->table_name[table->updating_name]
																	,db_group_rule->compile_id);
		return;
	}
	group_rule=del_group_from_compile(compile_rule, db_group_rule->group_id);
	if(group_rule==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,delete %s group rule error : group id %d not in compile id %d."
																	,table->table_name[table->updating_name]
																	,db_group_rule->group_id
																	,db_group_rule->compile_id);
		return;
	}
	if(compile_rule->group_cnt==0&&compile_rule->db_c_rule==NULL)
	{
		HASH_delete_by_id(scanner->compile_hash, db_group_rule->compile_id);
		garbage_bagging(GARBAGE_COMPILE_RULE, compile_rule, scanner->tomb_ref);
	}
	//Directly delete group id will not destroyp group_rule,it 'll be destroyed when delete this group's last region.
	if(group_rule->ref_cnt==0&&group_rule->region_cnt==0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"Directly delete table %s group id %d, do this when delete its last region."
							,table->table_name[table->updating_name]
							,db_group_rule->group_id);
	}
	return;
}
int add_compile_rule(struct _Maat_table_info_t* table,struct db_compile_rule_t* db_compile_rule,struct _Maat_scanner_t *scanner,void* logger)
{
	struct _Maat_compile_inner_t *compile_rule=NULL;
	struct _head_Maat_rule_t *p_maat_rule_head=&(db_compile_rule->m_rule_head);
	compile_rule=(struct _Maat_compile_inner_t*)HASH_fetch_by_id(scanner->compile_hash, p_maat_rule_head->config_id);
	if(compile_rule==NULL)
	{
		compile_rule=create_compile_rule(p_maat_rule_head->config_id);
		compile_rule->table_id=table->table_id;
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
	struct _Maat_compile_inner_t *compile_rule=NULL;
	compile_rule=(struct _Maat_compile_inner_t*)HASH_fetch_by_id(scanner->compile_hash, db_compile_rule->m_rule_head.config_id);
	if(compile_rule==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,delete %s  compile rule error : congfig id %d does not exisit."
																	,table->table_name[table->updating_name]
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
		//leave no trace when compatible_group_update calling
		if(table->table_type==TABLE_TYPE_GROUP)
		{
			table->cfg_num--;
		}
	}
	else
	{
		ret=add_group_rule(table,&db_group_rule, scanner,logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of group table %s group_id %d compile_id %d.",table->table_name[table->conj_cnt]
																							,db_group_rule.group_id
																							,db_group_rule.compile_id);

		}
		else
		{
			//no need to free db_group_rule,it was saved in scanner->compile_hash
			if(table->table_type==TABLE_TYPE_GROUP)
			{
				table->cfg_num++;
			}
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
	int ret=0,db_hexbin=0,rule_type=0;
	switch(table->table_type)
	{
		case	TABLE_TYPE_EXPR:
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
									"abandon config: invalid format of expr table %s:%s",table->table_name[table->updating_name],table_line);
				free(maat_str_rule);
				maat_str_rule=NULL;	
				table->udpate_err_cnt++;
				return;
			}
			break;
		case	TABLE_TYPE_EXPR_PLUS:
			ret=sscanf(table_line,"%d\t%d\t%s\t%s\t%d\t%d\t%d\t%d",&(maat_str_rule->region_id)
															,&(maat_str_rule->group_id)
															,maat_str_rule->district
															,maat_str_rule->keywords
															,(int*)&(maat_str_rule->expr_type)
															,(int*)&(maat_str_rule->match_method)
															,&db_hexbin
															,&(maat_str_rule->is_valid));
			if(ret!=8)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
									"abandon config: invalid format of expr_plus table %s:%s",table->table_name[table->updating_name],table_line);
				free(maat_str_rule);
				maat_str_rule=NULL;	
				table->udpate_err_cnt++;
				return;
			}
			break;
		default:
			assert(0);
			break;
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
								"abandon config %d:update error,invalid hexbin value of expr table %s:%s"
								,maat_str_rule->region_id
								,table->table_name[table->updating_name],table_line);
			table->udpate_err_cnt++;
			goto error_out;
	}
	if(!is_valid_match_method(maat_str_rule->match_method))
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"abandon config %d:update error,invalid match method=%d in expr table %s:%s"
							,maat_str_rule->region_id
							,maat_str_rule->match_method
							,table->table_name[table->updating_name],table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}
	if(!is_valid_expr_type(maat_str_rule->expr_type))
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"abandon config %d:update error,invalid expr type=%d in expr table %s:%s"
							,maat_str_rule->region_id
							,maat_str_rule->expr_type
							,table->table_name[table->updating_name],table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}
	ret=sync_region(scanner->region_hash
					,maat_str_rule->region_id
					,table->table_name[table->updating_name]
					,maat_str_rule->is_valid,logger);
	if(ret<0)
	{
		table->udpate_err_cnt++;
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
		if(maat_str_rule->expr_type==EXPR_TYPE_REGEX)
		{
			rule_type=RULETYPE_REG;
		}
		else
		{
			rule_type=RULETYPE_STR;
		}
		ret=del_region_rule(table
							,maat_str_rule->region_id,maat_str_rule->group_id,rule_type
							,scanner, logger);
		if(ret>0)
		{
			table->cfg_num--;
		}
		else
		{
			table->udpate_err_cnt++;
		}
	}
	else
	{
		if(maat_str_rule->expr_type==EXPR_TYPE_AND
			&&maat_str_rule->match_method!=MATCH_METHOD_SUB)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
			"table %s region cfg %d is EXPR_TYPE_AND,but match method is not MATCH_METHOD_SUB,force fixed.",
			table->table_name[table->updating_name],maat_str_rule->region_id);
			maat_str_rule->match_method=MATCH_METHOD_SUB;
				
		}
		if(maat_str_rule->expr_type==EXPR_TYPE_STRING
			&&table->quick_expr_switch==1
			&&maat_str_rule->match_method!=MATCH_METHOD_SUB)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
			"abandon config: table %s scan mode is quickon, only support MATCH_METHOD_SUB, conflict with match method of region %d.",
			table->table_name[table->updating_name],maat_str_rule->region_id);
			table->udpate_err_cnt++;
			goto error_out;
		}
		ret=add_expr_rule(table, maat_str_rule,scanner, logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of expr table %s region_id=%d"
							,table->table_name[table->updating_name],maat_str_rule->region_id);
			table->udpate_err_cnt++;
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
	int protocol=0,direction=0;
	int ret=0,rule_type=0;
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
							"update error,invalid format of ip table %s:%s"
							,table->table_name[table->updating_name],table_line);
		table->udpate_err_cnt++;
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
		rule_type=RULETYPE_IPv4;
	}
	else
	{
		ret_array[0]=inet_pton(AF_INET6,src_ip,&(ip_rule->ipv6_rule.saddr));
		ipv6_ntoh(ip_rule->ipv6_rule.saddr);
		ret_array[1]=inet_pton(AF_INET6,mask_src_ip,&(ip_rule->ipv6_rule.smask));
		ipv6_ntoh(ip_rule->ipv6_rule.smask);

		ret_array[2]=inet_pton(AF_INET6,dst_ip,&(ip_rule->ipv6_rule.daddr));
		ipv6_ntoh(ip_rule->ipv6_rule.daddr);
		ret_array[3]=inet_pton(AF_INET6,mask_dst_ip,&(ip_rule->ipv6_rule.dmask));
		ipv6_ntoh(ip_rule->ipv6_rule.dmask);
		
		ip_rule->ipv6_rule.min_sport=i_src_port&i_sport_mask;
		ip_rule->ipv6_rule.max_sport=(i_src_port&i_sport_mask)+(~i_sport_mask);
		
		ip_rule->ipv6_rule.min_dport=i_dst_port&i_dport_mask;
		ip_rule->ipv6_rule.max_dport=(i_dst_port&i_dport_mask)+~(i_dport_mask);
		
		ip_rule->ipv6_rule.proto=protocol;
		ip_rule->ipv6_rule.direction=direction;
		rule_type=RULETYPE_IPv6;
	}
	for(i=0;i<4;i++)
	{
		if(ret_array[i]<=0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
								"update error,invalid format of ip table %s:%s"
								,table->table_name[table->updating_name],table_line);
			table->udpate_err_cnt++;
			goto error_out;
		}
	}
	ret=sync_region(scanner->region_hash
					,ip_rule->region_id
					,table->table_name[table->updating_name]
					,ip_rule->is_valid,logger);
	if(ret<0)
	{
		table->udpate_err_cnt++;
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
		ret=del_region_rule(table
							,ip_rule->region_id,ip_rule->group_id,rule_type
							,scanner, logger);
		if(ret>0)
		{
			table->cfg_num--;
			if(ip_rule->addr_type==4)
			{
				table->ipv4_rule_cnt--;
			}
			else
			{
				table->ipv6_rule_cnt--;
			}
		}
		else
		{
			table->udpate_err_cnt++;
		}
	}
	else
	{

		ret=add_ip_rule(table, ip_rule,scanner, logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of ip table %s config_id=%d"
							,table->table_name[table->updating_name],ip_rule->region_id);
			table->udpate_err_cnt++;
		}
		else
		{
			table->cfg_num++;
			if(ip_rule->addr_type==4)
			{
				table->ipv4_rule_cnt++;
			}
			else
			{
				table->ipv6_rule_cnt++;
			}
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
							"update error,invalid format  of interval table %s:%s"
							,table->table_name[table->updating_name],table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}
	ret=sync_region(scanner->region_hash
					,intval_rule->region_id
					,table->table_name[table->updating_name]
					,intval_rule->is_valid,logger);
	if(ret<0)
	{
		table->udpate_err_cnt++;
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
		ret=del_region_rule(table
							,intval_rule->region_id,intval_rule->group_id,RULETYPE_INT
							,scanner, logger);
		if(ret>0)
		{
			table->cfg_num--;
		}
		else
		{
			table->udpate_err_cnt++;
		}
	}
	else
	{
		ret=add_intval_rule(table, intval_rule,scanner,logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of intval table %s config_id=%d"
							,table->table_name[table->updating_name],intval_rule->region_id);
			table->udpate_err_cnt++;
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
							"update error,invalid format of compile table %s:%s"
							,table->table_name[table->updating_name],table_line);
		free(p_compile);
		p_compile=NULL;
		table->udpate_err_cnt++;
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
							"duplicate config of compile table %s config_id=%d"
							,table->table_name[table->updating_name],p_m_rule->config_id);
			free(p_compile->service_defined);
			p_compile->service_defined=NULL;
			free(p_compile);
			p_compile=NULL;
			table->udpate_err_cnt++;

		}
		else
		{
			//no need to free p_compile,it was saved in scanner->compile_hash
			table->cfg_num++;
		}
	}
	
	return;	
}

void update_digest_rule(struct _Maat_table_info_t* table,const char* table_line,struct _Maat_scanner_t *scanner,void* logger,int group_mode_on)
{
	struct db_digest_rule_t* digest_rule=(struct db_digest_rule_t*)calloc(sizeof(struct db_digest_rule_t),1);
	int ret=0;
	char digest_buff[MAX_TABLE_LINE_SIZE]={'\0'};
	if(table->table_type==TABLE_TYPE_DIGEST)
	{
		ret=sscanf(table_line,"%d\t%d\t%llu\t%s\t%hd\t%d",&(digest_rule->region_id)
											,&(digest_rule->group_id)
											,&(digest_rule->orgin_len)
											,digest_buff
											,&(digest_rule->confidence_degree)
											,&(digest_rule->is_valid));
	}
	else if(table->table_type==TABLE_TYPE_SIMILARITY)
	{
		digest_rule->orgin_len=0;
		ret=sscanf(table_line,"%d\t%d\t%s\t%hd\t%d",&(digest_rule->region_id)
											,&(digest_rule->group_id)
											,digest_buff
											,&(digest_rule->confidence_degree)
											,&(digest_rule->is_valid));
	}
	else
	{
		assert(0);
	}
	digest_rule->digest_string=digest_buff;
	if(!(ret==6||ret==5)||digest_rule->confidence_degree>100||digest_rule->confidence_degree<0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,invalid format  of digest table %s:%s"
							,table->table_name[table->updating_name],table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}
	ret=sync_region(scanner->region_hash
					,digest_rule->region_id
					,table->table_name[table->updating_name]
					,digest_rule->is_valid,logger);
	if(ret<0)
	{
		table->udpate_err_cnt++;
		goto error_out;
	}
	if(group_mode_on==FALSE)//for compatible old version
	{
		compatible_group_udpate(table
								,digest_rule->region_id
								,digest_rule->group_id
								,digest_rule->is_valid
								,scanner
								,logger);
		digest_rule->group_id=digest_rule->region_id;
	}

	if(digest_rule->is_valid==FALSE)
	{
		//digest rule is not build with rulescan, this rule type is useless in count_rs_region funciton.
		ret=del_region_rule(table,digest_rule->region_id,digest_rule->group_id,0 ,scanner, logger);
		if(ret>0)
		{
			table->cfg_num--;
		}
		else
		{
			table->udpate_err_cnt++;
		}
	}
	else
	{
		ret=add_digest_rule(table, digest_rule,scanner,logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of intval table %s config_id=%d"
							,table->table_name[table->updating_name],digest_rule->region_id);
			table->udpate_err_cnt++;
		}
		else
		{
			table->cfg_num++;
		}
	}
error_out:

	digest_rule->digest_string=NULL;
	free(digest_rule);
	digest_rule=NULL;		
}
void garbage_bagging(enum maat_garbage_type type,void *p,MESA_lqueue_head garbage_q)
{
	if(p==NULL)
	{
		return;
	}
	struct _maat_garbage_t* bag=(struct _maat_garbage_t*)malloc(sizeof(struct _maat_garbage_t));
	bag->raw=p;
	bag->type=type;
	bag->create_time=time(NULL);
	bag->ok_times=0;
	MESA_lqueue_join_tail(garbage_q,&bag,sizeof(void*));
	return;
}
void garbage_bury(MESA_lqueue_head garbage_q,int timeout,void *logger)
{
	MESA_queue_errno_t q_ret=MESA_QUEUE_RET_OK;
	_maat_garbage_t* bag=NULL;
	long data_size=0;
	const long q_cnt=MESA_lqueue_get_count(garbage_q);
	int i=0,bury_cnt=0;
	long long ref_cnt=0;
	int have_timeout=0;
	time_t now=time(NULL);
	for(i=0;i<q_cnt;i++)
	{
		data_size=sizeof(void*);
		q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(garbage_q,&bag,&data_size);
		assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
		if(now-bag->create_time<timeout)
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
				ref_cnt=aligment_int64_array_sum(bag->scanner->ref_cnt,bag->scanner->max_thread_num);
				if(ref_cnt==0)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module,
							"scanner %p version %d has no reference peacefully destroyed.",bag->scanner,bag->scanner->version);
				}
				else
				{
					MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module,
							"scanner %p version %d force destroyed,ref_cnt %lld.",
							bag->scanner,bag->scanner->version,ref_cnt);
					
				}
				destroy_maat_scanner(bag->scanner);
				break;
			case GARBAGE_BOOL_MATCHER:
				destroy_bool_matcher(bag->bool_matcher);
				break;
			case GARBAGE_MAP_STR2INT:
				map_destroy(bag->str2int_map);
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
	char *p=NULL;
	p_table_cb->acc_line_num++;
	if(p_table_cb->cb_plug_cnt>0)
	{
		for(i=0;i<p_table_cb->cb_plug_cnt;i++)
		{
			p_table_cb->cb_plug[i].update(table->table_id,table_line,p_table_cb->cb_plug[i].u_para);
		}
	}
	else
	{
		p=(char*)calloc(len,1);
		memcpy(p,table_line,len);
		p_table_cb->cache_size+=len;
		dynamic_array_write(p_table_cb->cache_lines,p_table_cb->cache_line_num,p);
		p_table_cb->cache_line_num++;
	}
}
void do_scanner_update(struct _Maat_scanner_t* scanner,MESA_lqueue_head garbage_q,int scan_thread_num,void* logger)
{
	void *tmp1=NULL,*tmp2=NULL;
	MESA_htable_handle tmp_map=NULL;
	int i=0;
	long q_cnt;
	GIE_create_para_t para;
	para.gram_value=7;
	para.position_accuracy=10;
	tmp1=create_bool_matcher(scanner->compile_hash,
											scan_thread_num,
											logger);
	tmp2=scanner->expr_compiler;
	
	//assume pinter = operation is thread safe 
	scanner->expr_compiler=tmp1;
	if(tmp2!=NULL)
	{
		garbage_bagging(GARBAGE_BOOL_MATCHER, tmp2, garbage_q);
	}
	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"Version %d dedup string rule %lu",scanner->version,scanner->dedup_expr_num);	
	scanner->dedup_expr_num=0;
	rulescan_batch_update(scanner->region,
							scanner->region_update_q,
							logger
							,scanner);
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		if(scanner->gie_aux[i].update_q==NULL)
		{
			continue;
		}
		q_cnt=MESA_lqueue_get_count(scanner->gie_aux[i].update_q);
		if(q_cnt==0)
		{
			continue;
		}
		if(scanner->gie_aux[i].gie_handle==NULL)
		{
			if(scanner->gie_aux[i].table_type==TABLE_TYPE_SIMILARITY)
			{
				para.ED_reexamine=1;
				para.format=GIE_INPUT_FORMAT_PLAIN;
			}
			else
			{
				para.ED_reexamine=0;
				para.format=GIE_INPUT_FORMAT_SFH;
			}
			scanner->gie_aux[i].gie_handle=GIE_create(&para);
		}
		digest_batch_update(scanner->gie_aux[i].gie_handle
							,scanner->gie_aux[i].update_q
							,logger
							,scanner
							,i);
	}
	scanner->gie_total_q_size=0;
	if(scanner->tmp_district_map!=NULL)
	{
		tmp_map=scanner->district_map;
		scanner->district_map=scanner->tmp_district_map;
		scanner->tmp_district_map=NULL;
		garbage_bagging(GARBAGE_MAP_STR2INT, tmp_map, garbage_q);
	}
	scanner->last_update_time=time(NULL);

	return;

}
void clear_plugin_table_info(struct _plugin_table_info *cb_info)
{
	int i=0;
	void *line=NULL;
	for(i=0;i<cb_info->cache_line_num;i++)
	{
		line=dynamic_array_read(cb_info->cache_lines,i);
		free(line);
		dynamic_array_write(cb_info->cache_lines,i,NULL);
	}
	cb_info->cache_line_num=0;
	cb_info->cache_size=0;
	cb_info->acc_line_num=0;
	return;
}
void maat_start_cb(unsigned int new_version,int update_type,void*u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para; 
	struct _Maat_table_info_t* p_table=NULL;
	struct _plugin_table_info* p_table_cb=NULL;
	int i=0,j=0;
	if(update_type==CM_UPDATE_TYPE_FULL)
	{
		feather->update_tmp_scanner=create_maat_scanner(new_version,feather);
		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Full config version %u -> %u update start",
								feather->maat_version,new_version);
		for(i=0;i<MAX_TABLE_NUM;i++)
		{
			p_table=feather->p_table_info[i];
			if(p_table==NULL)
			{
				continue;
			}
			p_table->cfg_num=0;
			p_table->expr_rule_cnt=0;
			p_table->regex_rule_cnt=0;
			if(p_table->table_type==TABLE_TYPE_PLUGIN)
			{
				clear_plugin_table_info(p_table->cb_info);
			}
		}
	}
	else
	{

		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Inc config version %u -> %u update start",
								feather->maat_version,new_version);
		feather->maat_version=new_version;
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
			if(p_table_cb->cb_plug[j].start!=NULL)
			{
				p_table_cb->cb_plug[j].start(update_type,p_table_cb->cb_plug[j].u_para);
			}
		}
	}
	return;
}
void maat_finish_cb(void* u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para; 
	struct _Maat_table_info_t* p_table=NULL;
	struct _plugin_table_info* p_table_cb=NULL;
	long expr_wait_q_cnt=0;
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
			if(p_table_cb->cb_plug[j].finish!=NULL)
			{
				p_table_cb->cb_plug[j].finish(p_table_cb->cb_plug[j].u_para);
			}
		}
	}
	if(feather->update_tmp_scanner!=NULL)
	{
		feather->update_tmp_scanner->cfg_num=total;
		do_scanner_update(feather->update_tmp_scanner
						,feather->garbage_q
						,feather->scan_thread_num
						,feather->logger);
		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Full config version %u load %d entries complete.",
								feather->update_tmp_scanner->version,feather->update_tmp_scanner->cfg_num);	
	}
	else if(feather->scanner!=NULL)
	{
		feather->scanner->cfg_num=total;
		feather->scanner->version=feather->maat_version;
		expr_wait_q_cnt=MESA_lqueue_get_count(feather->scanner->region_update_q);
		feather->postpone_q_size=expr_wait_q_cnt+feather->scanner->gie_total_q_size;
		if(time(NULL)-feather->scanner->last_update_time>feather->effect_interval_ms/1000)
		{
			do_scanner_update(feather->scanner
							,feather->garbage_q
							,feather->scan_thread_num
							,feather->logger);
			MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
									"Inc config version %u build complete, %d entries in total.",
									feather->scanner->version,feather->scanner->cfg_num);
			feather->postpone_q_size=0;
		}
		else
		{
			MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
									"Postpone %d entries of version %u load to rulescan.",
									feather->scanner->cfg_num,feather->scanner->version);
		}
	}
	else
	{
		 MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
                                                                        "Version %d have no valid scan rules, plugin callback complete.",
                                                                        feather->maat_version);
	}
	return;
}
int maat_update_cb(const char* table_name,const char* line,void *u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para; 
	int ret=-1,i=0;
	int table_id=-1;
	_Maat_scanner_t* scanner=NULL;
	struct _Maat_table_info_t* p_table=NULL;
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
		return -1;	
	}
	p_table=feather->p_table_info[table_id];
	for(i=0;i<p_table->conj_cnt;i++)
	{
		if(0==memcmp(p_table->table_name[i],table_name,strlen(table_name)))
		{
			p_table->updating_name=i;
		}
	}
	assert(i<=p_table->conj_cnt);

	switch(feather->p_table_info[table_id]->table_type)
	{
		case	TABLE_TYPE_EXPR:
		case	TABLE_TYPE_EXPR_PLUS:
			update_expr_rule(feather->p_table_info[table_id], line, scanner,feather->logger,feather->GROUP_MODE_ON);
			break;
		case	TABLE_TYPE_IP:
			update_ip_rule(feather->p_table_info[table_id], line, scanner,feather->logger,feather->GROUP_MODE_ON);
			break;
		case	TABLE_TYPE_INTERVAL:
			update_intval_rule(feather->p_table_info[table_id], line, scanner,feather->logger,feather->GROUP_MODE_ON);
			break;
		case	TABLE_TYPE_DIGEST:
		case	TABLE_TYPE_SIMILARITY:
			update_digest_rule(feather->p_table_info[table_id], line, scanner,feather->logger,feather->GROUP_MODE_ON);
			break;
		case	TABLE_TYPE_COMPILE:
			update_compile_rule(feather->p_table_info[table_id], line, scanner,feather->logger);
			break;
		case	TABLE_TYPE_GROUP:
			update_group_rule(feather->p_table_info[table_id], line, scanner,feather->logger);
			break;
		case	TABLE_TYPE_PLUGIN:
			plugin_table_callback(feather->p_table_info[table_id], line,feather->logger);
		default:
			break;
	
	}
	return 0;
}
void *thread_rule_monitor(void *arg)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)arg;
	const char* inc_cfg_dir=(const char*)feather->inc_dir;
	struct _Maat_scanner_t* old_scanner=NULL;
	long expr_wait_q_cnt=0;
	int scan_dir_cnt=0,ret=0;
	char maat_name[16];//Defined by prctl: The name can be up to 16 bytes long,and should 
						// be null  terminated if it contains fewer bytes.
	if(strlen(feather->instance_name)>0)
	{
		snprintf(maat_name,sizeof(maat_name),"MAAT_%s",feather->instance_name);
	}
	else
	{
		snprintf(maat_name,sizeof(maat_name),"MAAT");
	}
	ret=prctl(PR_SET_NAME,(unsigned long long)maat_name,NULL,NULL,NULL);
	//pthread_setname_np are introduced in glibc2.12
	//ret=pthread_setname_np(pthread_self(),maat_name); 
	assert(ret>=0);
	if(feather->DEFERRED_LOAD_ON!=0)
	{
		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Deferred Loading ON, updating in %s.",__func__);
		maat_read_full_config(feather);
	}
	while(feather->still_working)
	{
		usleep(feather->scan_interval_ms*1000);
		scan_dir_cnt++;
		//plugin table register is not allowed during update;
		pthread_mutex_lock(&(feather->plugin_table_reg_mutex));
		if(feather->REDIS_MODE_ON==1)
		{
			redis_monitor_traverse(feather->maat_version
									,feather->redis_read_ctx
									,maat_start_cb
									,maat_update_cb
									,maat_finish_cb
									,feather
									,feather->decrypt_key	//Not used.
									,feather);
		}
		else
		{
			config_monitor_traverse(feather->maat_version,
									inc_cfg_dir, 
									maat_start_cb,
									maat_update_cb,
									maat_finish_cb,
									feather,
									feather->decrypt_key,
									feather->logger);
		}
		pthread_mutex_unlock(&(feather->plugin_table_reg_mutex));
		if(feather->update_tmp_scanner!=NULL)
		{
			old_scanner=feather->scanner;
			//Some OS doesn't have __sync_lock_test_and_set.
			//feather->scanner=__sync_lock_test_and_set(&(feather->scanner),feather->update_tmp_scanner);
			feather->scanner=feather->update_tmp_scanner;
			if(old_scanner!=NULL)
			{
				if(feather->scanner->version>old_scanner->version)
				{
					MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
											"Maat version updated %d -> %d.",
											old_scanner->version, feather->scanner->version);
				}
				else
				{
					MESA_handle_runtime_log(feather->logger,RLOG_LV_FATAL,maat_module,
											"Maat version roll back %d -> %d.",
											old_scanner->version, feather->scanner->version);
				}
				assert(old_scanner->tomb_ref==feather->garbage_q);
				feather->zombie_rs_stream+=aligment_int64_array_sum(old_scanner->ref_cnt,old_scanner->max_thread_num);
				garbage_bagging(GARBAGE_SCANNER, old_scanner, feather->garbage_q);
			}
			feather->update_tmp_scanner=NULL;
			feather->maat_version=feather->scanner->version;
			feather->last_full_version=feather->scanner->version;
		}
		if(feather->scanner!=NULL)
		{
			expr_wait_q_cnt=MESA_lqueue_get_count(feather->scanner->region_update_q);
			feather->postpone_q_size=expr_wait_q_cnt+feather->scanner->gie_total_q_size;
			if(feather->postpone_q_size>0&&time(NULL)-feather->scanner->last_update_time>feather->effect_interval_ms/1000)
			{
				do_scanner_update(feather->scanner
								,feather->garbage_q
								,feather->scan_thread_num
								,feather->logger);
				feather->postpone_q_size=0;
				MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
										"Actual udpate config version %u, %d entries load to rulescan after postpone.",
										feather->scanner->version,feather->scanner->cfg_num);
			}
		}
		garbage_bury(feather->garbage_q,feather->effect_interval_ms/1000+10,feather->logger);
		if(feather->stat_on==1&&scan_dir_cnt%2==0)//output every 2 seconds
		{
			maat_stat_output(feather);
		}
	}
	
	MESA_htable_destroy(feather->map_tablename2id,free);
	destroy_maat_scanner(feather->scanner);
	garbage_bury(feather->garbage_q,feather->effect_interval_ms/1000+10,feather->logger);
	MESA_lqueue_destroy(feather->garbage_q,lqueue_destroy_cb,NULL);
	FS_stop(&(feather->stat_handle));

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
			for(j=0;j<feather->p_table_info[i]->cb_info->cache_line_num;j++)
			{
				lines=(char*)dynamic_array_read(d_array, j);
				free(lines);
			}
		}
		destroy_table_info(feather->p_table_info[i]);
		feather->p_table_info[i]=NULL;
	}
	aligment_int64_array_free(feather->thread_call_cnt);
	aligment_int64_array_free(feather->inner_mid_cnt);
	aligment_int64_array_free(feather->outer_mid_cnt);
	aligment_int64_array_free(feather->hit_cnt);
	aligment_int64_array_free(feather->orphan_group_saving);
	aligment_int64_array_free(feather->last_region_saving);
	if(feather->REDIS_MODE_ON==1&&feather->redis_read_ctx!=NULL)
	{
		pthread_mutex_lock(&(feather->redis_write_lock));
		redisFree(feather->redis_read_ctx);
		feather->redis_read_ctx=NULL;
		redisFree(feather->redis_write_ctx);
		feather->redis_write_ctx=NULL;
		pthread_mutex_unlock(&(feather->redis_write_lock));
	}
	free(feather);
	return NULL;
}


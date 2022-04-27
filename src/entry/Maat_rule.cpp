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
#include <strings.h>

#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/field_stat2.h>

#include "Maat_rule.h"
#include "Maat_rule_internal.h"
#include "Maat_utils.h"
#include "Maat_hierarchy.h"
#include "Maat_garbage_collection.h"

#include "json2iris.h"
#include "cJSON.h"
#include "dynamic_array.h"
#include "alignment_int64.h"
#include "config_monitor.h"

#include "map_str2int.h"
#include "stream_fuzzy_hash.h"
#include "gram_index_engine.h"

#include "bool_matcher.h"

#define GIT_VERSION_CATTER(v) __attribute__((__used__)) const char * GIT_VERSION_##v = NULL
#define GIT_VERSION_EXPEND(v) GIT_VERSION_CATTER(v)

#ifdef __cplusplus
extern "C"
{
#endif

    /* VERSION TAG */
#ifdef GIT_VERSION
    GIT_VERSION_EXPEND(GIT_VERSION);
#else
    static __attribute__((__used__)) const char * GIT_VERSION_UNKNOWN = NULL;
#endif
#undef GIT_VERSION_CATTER
#undef GIT_VERSION_EXPEND

#ifdef __cplusplus
}
#endif

int MAAT_FRAME_VERSION_3_6_6_20220427=1;

int is_valid_table_name(const char* str)
{
	size_t i=0, integer_cnt=0;
	for(i=0; i<strlen(str); i++)
	{
		if(str[i]>='0'&&str[i]<='9')
		{
			integer_cnt++;
		}
	}
	if(strlen(str)==0 ||
		integer_cnt==strlen(str) ||
		0==strcasecmp(str, "null"))
	{
		return 0;
	}
	return 1;
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


iconv_t maat_iconv_open(struct Maat_scanner* scanner,enum MAAT_CHARSET to,enum MAAT_CHARSET from)
{
	const char *from_s=charset_get_name(from);
	const char *to_s=charset_get_name(to);
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

int iconv_convert(struct Maat_scanner* scanner,enum MAAT_CHARSET from,enum MAAT_CHARSET to,char *src,int srclen,char *dst,int *dstlen)
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
int universal_charset_convert(struct Maat_scanner* scanner,enum MAAT_CHARSET from,enum MAAT_CHARSET to,char *src,int srclen,char *dst,int *dstlen)
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
		case CHARSET_WINDOWS1251:
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
//@param value is a JSON, like {"tags":[{"tag":"location","value":"北京/朝阳/华严北里/甲22号},{"tag":"isp","value":"电信"}]}
int parse_accept_tag(const char* value, struct rule_tag** result, void* logger)
{
	cJSON* json=NULL, *array=NULL,*tag=NULL, *tmp=NULL;
	struct rule_tag* p=NULL;
	int n_tags=0;
	json=cJSON_Parse(value);
	if(!json)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module,
			"MAAT_OPT_ACCEPT_TAGS Error before: %-200.200s",cJSON_GetErrorPtr());
		return 0;
	}
	array=cJSON_GetObjectItem(json, "tags");
	n_tags=cJSON_GetArraySize(array);
	p=ALLOC(struct rule_tag, n_tags);
	for(int i=0;i<n_tags;i++)
	{
		tag=cJSON_GetArrayItem(array, i);
		tmp=cJSON_GetObjectItem(tag, "tag");
		p[i].tag_name=_maat_strdup(tmp->valuestring);
		tmp=cJSON_GetObjectItem(tag, "value");
		p[i].tag_val=_maat_strdup(tmp->valuestring);
	}
	cJSON_Delete(json);
	*result=p;
	return n_tags;
}
static int compare_each_tag(cJSON* tag_obj, const struct rule_tag* accept_tags, int n_accept)
{
	const char* tag_name;
	const char* tag_val;
	int n_val;
	cJSON *tab_name_obj=NULL, *tag_vals_array=NULL, *tag_val_obj=NULL;

	int i=0, j=0, name_matched=0;
	tab_name_obj=cJSON_GetObjectItem(tag_obj,"tag");
	if(!tab_name_obj||tab_name_obj->type!=cJSON_String)
	{
		goto error_out;
	}
	tag_name=tab_name_obj->valuestring;
	tag_vals_array=cJSON_GetObjectItem(tag_obj,"value");
	if(!tag_vals_array||tag_vals_array->type!=cJSON_Array)
	{
		goto error_out;
	}
	n_val=cJSON_GetArraySize(tag_vals_array);
	for(i=0;i<n_accept;i++)
	{
		if(0!=strcmp(accept_tags[i].tag_name, tag_name))
		{
			continue;
		}
		name_matched++;

		for(j=0; j<n_val; j++)
		{
			tag_val_obj=cJSON_GetArrayItem(tag_vals_array, j);
			if(!tag_val_obj||tag_val_obj->type!=cJSON_String)
			{
				goto error_out;
			}
			tag_val=tag_val_obj->valuestring;
			// compare a/b/c with a/b/c/d is a miss.
			if(strlen(accept_tags[i].tag_val)<strlen(tag_val))
			{
				continue;
			}
			// compare a1a2/b1/c1 with a1a2/b/ is a miss.
			//make sure the overlap is ended with a '/' 
			if(0==strncmp(accept_tags[i].tag_val, tag_val, strlen(tag_val))&&
				(strlen(accept_tags[i].tag_val)==strlen(tag_val)||accept_tags[i].tag_val[strlen(tag_val)]=='/'))
			{
				return 1;
			}
		}
	}
	//no matched name is considered as a 
	if(name_matched>0)
	{
		return 0;
	}
	else
	{
		return 1;
	}
error_out:
		return -1;

}
//@param tag_set likes [{"tag":"location","value":["北京/朝阳/华严北里","上海/浦东/陆家嘴"]},{"tag":"isp","value":["电信","移动"]}]
static int compare_each_tag_set(cJSON* tag_set, const struct rule_tag* accept_tags, int n_accept)
{
	cJSON *tag_obj=NULL;
	int  n_tag=0, ret=0, matched=0;	
	n_tag=cJSON_GetArraySize(tag_set);
	for(int i=0; i<n_tag; i++)
	{
		tag_obj=cJSON_GetArrayItem(tag_set, i);
		if(!tag_obj||tag_obj->type!=cJSON_Object)
		{
			goto error_out;
		}
		ret=compare_each_tag(tag_obj,  accept_tags, n_accept);
		if(ret<0)
		{
			return -1;
		}
		if(ret==1)
		{
			matched++;
		}
	}
	if(matched==n_tag)
	{
		return 1;
	}
	else
	{
		return 0;
	}
error_out:
	return -1;
}
//@param value {"tag_sets":[[{"tag":"location","value":["北京/朝阳/华严北里","上海/浦东/陆家嘴"]},{"tag":"isp","value":["电信","移动"]}],[{"tag":"location","value":["北京"]},{"tag":"isp","value":["联通"]}]]}
//@return 1 on match, 0 on not match, -1 on error.
static int compare_accept_tag(const char* value,const struct rule_tag* accept_tags, int n_tags)
{
	cJSON *json=NULL;
	cJSON *tag_set_array=NULL, *tag_set=NULL;
	int ret=-1, n_set=0;
	json=cJSON_Parse(value);
	if(!json)
	{
		goto error_out;
	}
	tag_set_array=cJSON_GetObjectItem(json, "tag_sets");
	if(!tag_set_array||tag_set_array->type!=cJSON_Array)
	{
		goto error_out;
	}
	n_set=cJSON_GetArraySize(tag_set_array);
	for(int i=0; i<n_set; i++)
	{
		tag_set=cJSON_GetArrayItem(tag_set_array,i);
		if(!tag_set||tag_set->type!=cJSON_Array)
		{
			goto error_out;
		}
		ret=compare_each_tag_set(tag_set, accept_tags, n_tags);
		if(ret!=0)//match or error occurs.
		{
			break;
		}
	}
error_out:
	cJSON_Delete(json);
	return ret;
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
MAAT_RULE_EX_DATA rule_ex_data_new(const struct Maat_rule_head * rule_head, const char* srv_def, const struct compile_ex_data_idx* ex_desc)
{
	MAAT_RULE_EX_DATA ad=NULL;
	struct Maat_rule_t rule;
	fill_maat_rule(&rule, rule_head, srv_def, strlen(srv_def)+1);
	ex_desc->new_func(ex_desc->idx, &rule, srv_def, &ad, ex_desc->argl,ex_desc->argp);
	return ad;
}
void rule_ex_data_free(const struct Maat_rule_head * rule_head, const char* srv_def, MAAT_RULE_EX_DATA *ad, const struct compile_ex_data_idx* ex_desc)
{
	struct Maat_rule_t rule;
	fill_maat_rule(&rule, rule_head, srv_def, strlen(srv_def)+1);
	ex_desc->free_func(ex_desc->idx, &rule, srv_def, ad, ex_desc->argl,ex_desc->argp);
	return;
}

void EMPTY_FREE(void*p)
{
	return;
}

struct Maat_compile_rule* create_compile_rule(struct Maat_rule_head* p_head, const char* service_define, int declared_grp_num, double exec_seq, const struct Maat_table_schema* table)
{
	int i=0;
	struct Maat_compile_rule*p=ALLOC(struct Maat_compile_rule, 1);
	p->magic_num=COMPILE_RULE_MAGIC;
	p->head=*p_head;
	p->declared_clause_num=declared_grp_num;
	p->ads=ALLOC(MAAT_RULE_EX_DATA, MAX_COMPILE_EX_DATA_NUM);

	//protect by feather->background_update_mutex
	p->ref_table=table;
	p->head.serv_def_len=strlen(service_define)+1;
	p->service_defined=ALLOC(char, p->head.serv_def_len);
	memcpy(p->service_defined, service_define, p->head.serv_def_len);
	p->evaluation_order=exec_seq;

	for(i=0; i<table->compile.ex_data_num; i++)
	{
		p->ads[i]=rule_ex_data_new(&p->head, p->service_defined, table->compile.ex_desc+i);
	}
	p->is_valid=1;
	p->compile_id=p_head->config_id;
	pthread_rwlock_init(&p->rwlock, NULL);
	return p;
}

void destroy_compile_rule(struct Maat_compile_rule* compile_rule)
{
	int i=0;
	const struct compile_table_schema* compile_desc= &(compile_rule->ref_table->compile);
	assert(compile_rule->magic_num==COMPILE_RULE_MAGIC);
	for(i=0; i<compile_desc->ex_data_num; i++)
	{
		rule_ex_data_free(&(compile_rule->head), compile_rule->service_defined, compile_rule->ads+i, compile_desc->ex_desc+i);
		compile_rule->ads[i]=NULL;
	}
	free(compile_rule->ads);

	compile_rule->is_valid=0;
	compile_rule->declared_clause_num=-1;
	free(compile_rule->service_defined);
	compile_rule->service_defined=NULL;
	free(compile_rule);
	return;
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
scan_rule_t* create_rs_intval_rule(unsigned int sub_type,struct db_interval_rule *intval_rule)
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
void Maat_region_inner_free(struct Maat_region_inner* region)
{
	assert(region->magic_num==REGION_RULE_MAGIC);
	assert(region->expr_id_cnt==0||region->expr_id_cnt==region->expr_id_ub-region->expr_id_lb+1);
	region->magic_num=0;
	free(region);
}

void Maat_region_inner_cancel_last_expr_id(struct Maat_region_inner* region)
{
	assert(region->expr_id_cnt==region->expr_id_ub-region->expr_id_lb+1);
	region->expr_id_ub--;
	region->expr_id_cnt--;
	return;
}

struct Maat_scanner* create_maat_scanner(unsigned int version, _Maat_feather_t *feather)
{
	int scan_thread_num=feather->scan_thread_num;
	UNUSED int ret=0;
	
	struct Maat_scanner* scanner=NULL;
	scanner=ALLOC(struct Maat_scanner, 1);
	scanner->hier=Maat_hierarchy_new(scan_thread_num, feather->logger, feather->garbage_bin);
	Maat_hierarchy_set_compile_user_data_free_func(scanner->hier, (void (*)(void*))destroy_compile_rule);
	Maat_hierarchy_set_region_user_data_free_func(scanner->hier, (void (*)(void*))Maat_region_inner_free);

	scanner->district_map=maat_kv_store_new();
	
	scanner->version=version;
	scanner->cfg_num=0;
	scanner->dedup_expr_num=0;
	scanner->max_thread_num=scan_thread_num;
	//optimized for CPU cache_alignment 64
	scanner->ref_cnt=alignment_int64_array_alloc(scan_thread_num);
	scanner->region_update_q=MESA_lqueue_create(0, 0);
	scanner->region=rulescan_initialize(scan_thread_num);
	
	//For best scan performance:
	//1.Do NOT set this option, rulescan return no hit detail as default;
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
	scanner->ref_garbage_bin=feather->garbage_bin;
	scanner->logger_ref=feather->logger;
	scanner->region_rslt_buff=ALLOC(scan_result_t, MAX_SCANNER_HIT_NUM*scan_thread_num);
	scanner->gie_rslt_buff=ALLOC(GIE_result_t, MAX_SCANNER_HIT_NUM*scan_thread_num);
	scanner->table_rt_mgr=Maat_table_runtime_manager_create(feather->table_mgr, feather->scan_thread_num, feather->garbage_bin);
	scanner->max_table_num=Maat_table_manager_get_size(feather->table_mgr);
	return scanner;
}



void destroy_maat_scanner(struct Maat_scanner*scanner)
{
	long q_cnt=0,data_size=0;
	int i=0,j=0;
	UNUSED int q_ret=0;
	struct op_expr_t* op_expr=NULL;
	if(scanner==NULL)
	{
		return;
	}
	rulescan_destroy(scanner->region);

	maat_kv_store_free(scanner->district_map);
	scanner->district_map=NULL;
	assert(scanner->tmp_district_map==NULL);

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
	free(scanner->gie_rslt_buff);
	scanner->gie_rslt_buff=NULL;
	alignment_int64_array_free(scanner->ref_cnt);
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
	Maat_table_rt_manager_destroy(scanner->table_rt_mgr);
	scanner->table_rt_mgr=NULL;
	Maat_hierarchy_free(scanner->hier);
	scanner->hier=NULL;
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
struct _region_stat_t
{
	int cfg_num;
	union
	{
		int expr_rule_cnt;	//expr_type=0,1,3
		int ipv4_rule_cnt;
	};
	union
	{
		int regex_rule_cnt;	//expr_type=2
		int ipv6_rule_cnt;
	};
};
void count_rs_region(struct op_expr_t* op_expr,struct _region_stat_t* region_stat, size_t size)
{
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

void rulescan_batch_update(rule_scanner_t rs_handle,MESA_lqueue_head expr_queue,void*logger,struct Maat_scanner* maat_scanner)
{
	long data_size=0, i=0;
	unsigned int j=0;
	int ret=0;
	unsigned int failed_ids[MAX_FAILED_NUM];
	char failed_info[512], *p=NULL;
	UNUSED	MESA_queue_errno_t q_ret=MESA_QUEUE_RET_OK; 
	memset(failed_ids,0,sizeof(failed_ids));
	memset(failed_info,0,sizeof(failed_info));
	const long q_cnt=MESA_lqueue_get_count(expr_queue);
	struct timespec start,end;
	unsigned long long update_interval=0;
	size_t max_table_num=maat_scanner->max_table_num;
	struct _region_stat_t region_counter[max_table_num];
	memset(region_counter, 0, sizeof(region_counter));
	struct Maat_table_runtime* table_rt=NULL;
	if(q_cnt==0)
	{
		return;
	}
	boolean_expr_t* to_update_expr= ALLOC(boolean_expr_t, q_cnt);
	struct op_expr_t* op_expr=NULL;
	for(i=0;i<q_cnt;i++)
	{
		data_size=sizeof(void*);
		q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(expr_queue,&op_expr,&data_size);
		assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
		memcpy(&(to_update_expr[i]),op_expr->p_expr,sizeof(boolean_expr_t));
		//make a whole memory chunk
		to_update_expr[i].rules= ALLOC(scan_rule_t, op_expr->p_expr->rnum);
		for(j=0;j<op_expr->p_expr->rnum;j++)
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
		
		count_rs_region(op_expr, region_counter, max_table_num);
		destroy_op_expr(op_expr);
		op_expr=NULL;
	}
	MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_module ,
							"rs_handle %p rulescan_update %ld rules.", rs_handle, q_cnt);
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret=rulescan_update(rs_handle, to_update_expr,q_cnt, failed_ids, MAX_FAILED_NUM);
	clock_gettime(CLOCK_MONOTONIC, &end);
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
	for(i=0; (size_t)i<max_table_num; i++)
	{
		table_rt=Maat_table_runtime_get(maat_scanner->table_rt_mgr, i);
		if(table_rt==NULL)
		{
			continue;
		}
		switch(table_rt->table_type)
		{
			case TABLE_TYPE_EXPR:
			case TABLE_TYPE_EXPR_PLUS:
				table_rt->expr.expr_rule_cnt+=region_counter[i].expr_rule_cnt;
				table_rt->expr.regex_rule_cnt+=region_counter[i].regex_rule_cnt;
				assert(table_rt->expr.expr_rule_cnt>=0);
				assert(table_rt->expr.regex_rule_cnt>=0);
				break;
			case TABLE_TYPE_IP:
			case TABLE_TYPE_IP_PLUS:
				table_rt->ip.ipv4_rule_cnt+=region_counter[i].ipv4_rule_cnt;
				table_rt->ip.ipv6_rule_cnt+=region_counter[i].ipv6_rule_cnt;
				break;
			default:
				break;
		}
		assert(table_rt->origin_rule_num>=0);
	}
	for(i=0;i<q_cnt;i++)
	{
		for(j=0;j<to_update_expr[i].rnum;j++)
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



int get_district_id(Maat_scanner *scanner,const char* district_str)
{
	int map_ret=0, district_id=-1;
	map_ret=maat_kv_read(scanner->district_map, district_str, &district_id);
	if(map_ret<0)
	{
		if(scanner->tmp_district_map==NULL)
		{
			scanner->tmp_district_map=maat_kv_store_duplicate(scanner->district_map);
		}
		map_ret=maat_kv_read(scanner->tmp_district_map, district_str, &district_id);
		if(map_ret<0)
		{
			district_id=scanner->district_num;
			maat_kv_register(scanner->tmp_district_map, district_str, district_id);
			scanner->district_num++;
		}
	}
	return district_id;
}
struct Maat_region_inner* Maat_region_inner_new(int group_id, int region_id, int table_id, int district_id)
{
	struct Maat_region_inner* region=ALLOC(struct Maat_region_inner, 1);
	region->magic_num=REGION_RULE_MAGIC;
	region->region_id=region_id;
	region->group_id=group_id;
	region->table_id=table_id;
	region->district_id=district_id;
	return region;
}
void Maat_region_inner_add_expr_id(struct Maat_region_inner* region, int expr_id)
{
	if(region->expr_id_cnt==0)
	{
		region->expr_id_lb=region->expr_id_ub=expr_id;
	}
	else
	{
		assert(region->expr_id_ub+1==expr_id);
		region->expr_id_ub=expr_id;
	}
	region->expr_id_cnt++;
	return;
}


int add_expr_rule(struct Maat_table_schema* table,struct db_str_rule_t* db_rule,struct Maat_scanner *scanner,void* logger)
{
	unsigned int i=0,j=0;
	char* p=NULL,*saveptr=NULL,*region_string=NULL;
	int region_str_len=0,ret=0,k=0;
	int expr_id=0,district_id=-1;
	struct expr_table_schema* expr_desc=&(table->expr);
	scan_rule_t*p_rule=NULL;

	enum MAAT_CHARSET dst_charset=CHARSET_NONE;
	char *sub_key_array[MAAT_MAX_EXPR_ITEM_NUM], *tmp=NULL;
	int key_left_offset[MAAT_MAX_EXPR_ITEM_NUM]={-1},key_right_offset[MAAT_MAX_EXPR_ITEM_NUM]={-1};
	for(i=0;i<MAAT_MAX_EXPR_ITEM_NUM;i++)
	{
		key_left_offset[i]=-1;
		key_right_offset[i]=-1;
	}
	int sub_expr_cnt=0;
	struct op_expr_t *op_expr=NULL;

	struct Maat_region_inner* u_para=NULL;

	if(table->table_type==TABLE_TYPE_EXPR_PLUS)
	{
		assert(strlen(db_rule->district)>0);
		str_unescape(db_rule->district);
		district_id=get_district_id(scanner, db_rule->district);
	}


	switch(db_rule->expr_type)
	{
		case EXPR_TYPE_AND:
		case EXPR_TYPE_REGEX:
			for(i=0,p=db_rule->keywords;;i++,p=NULL)
			{
				tmp=strtok_r_esc(p, '&', &saveptr);
				if(tmp==NULL)
				{
					break;
				}
				if(i>=MAAT_MAX_EXPR_ITEM_NUM)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d too many expr.", table->table_name[table->updating_name], db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=tmp;
				if(db_rule->expr_type==EXPR_TYPE_REGEX)
				{
					sub_key_array[i]=str_unescape_and(sub_key_array[i]);//regex should use str_unescape_and
				}
				else
				{
					sub_key_array[i]=str_unescape(sub_key_array[i]);
				}
			}
			sub_expr_cnt=i;
			break;
		case EXPR_TYPE_OFFSET:
			for(i=0,p=db_rule->keywords;;i++,p=NULL)
			{
				tmp=strtok_r_esc(p, '&', &saveptr);				
				if(tmp==NULL)
				{
					break;
				}
				if(i>=MAAT_MAX_EXPR_ITEM_NUM)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d too many expr.", table->table_name[table->updating_name], db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=tmp;
				sscanf(sub_key_array[i], "%d-%d:", &(key_left_offset[i]),&(key_right_offset[i]));
				if(!(key_left_offset[i]>=0&&key_right_offset[i]>0&&key_left_offset[i]<=key_right_offset[i]))
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d invalid offset.", table->table_name[table->updating_name], db_rule->region_id);
					return -1;
				}
				sub_key_array[i]=(char*)memchr(sub_key_array[i], ':', strlen(sub_key_array[i]));
				if(sub_key_array[i]==NULL)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"Table %s region cfg %d invalid offset keyword format.", table->table_name[table->updating_name], db_rule->region_id);
					return -1;
				}
				sub_key_array[i]++;//jump over ':'
				sub_key_array[i]=str_unescape(sub_key_array[i]);
			}
			sub_expr_cnt=i;
			break;
		case EXPR_TYPE_STRING:
			sub_expr_cnt=1;
			sub_key_array[0]=db_rule->keywords;
			sub_key_array[0]=str_unescape(sub_key_array[0]);
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
			//this sub string will be skipped before iconv_convert
		}
	}
	
	u_para=Maat_region_inner_new(db_rule->group_id, db_rule->region_id, table->table_id, district_id);
	ret=Maat_hierarchy_add_region_to_group(scanner->hier, db_rule->group_id, db_rule->region_id, table->table_id, u_para);
	if(ret!=0)
	{
		Maat_region_inner_free(u_para);
		u_para=NULL;
		return -1;
	}
	
	if(db_rule->is_hexbin==FALSE && db_rule->expr_type!=EXPR_TYPE_REGEX)
	{
		for(j=0;j<MAX_CHARSET_NUM;j++)
		{
			dst_charset=expr_desc->dst_charset[j];
			if(dst_charset==CHARSET_NONE)
			{
				break;
			}
			expr_id=scanner->exprid_generator++;
			Maat_region_inner_add_expr_id(u_para, expr_id);
			op_expr=create_op_expr(expr_id,
									RULESCAN_OP_ADD,
									u_para,
									table->table_id);
			
			for(k=0;k<sub_expr_cnt;k++)
			{
				if(strlen(sub_key_array[k])==0)
				{
						continue;
				}
				region_str_len=strlen(sub_key_array[k])*8+1; // 1 byte map to 8 bytes maximum, e.g. "&#x0627;" or "\u63221;"
				region_string=(char*)calloc(sizeof(char),region_str_len);
				if(expr_desc->src_charset!=dst_charset)//need convert
				{

					ret=universal_charset_convert(scanner,expr_desc->src_charset, dst_charset, 
										sub_key_array[k],strlen(sub_key_array[k]),
										region_string, &region_str_len);
					if(ret<0)
					{
						MESA_handle_runtime_log(logger, RLOG_LV_DEBUG, maat_module ,
								"Table %s region cfg %d charset convert from %s to %s failed.",
																					table->table_name,
																					db_rule->region_id,
																					charset_get_name(expr_desc->src_charset),
																					charset_get_name(dst_charset));
						free(region_string);
						op_expr->convert_failed++;
						expr_desc->iconv_err_cnt++;
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
				p_rule=create_rs_str_rule(make_sub_type(table->table_id,dst_charset,expr_desc->do_charset_merge)
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
			if((TRUE==expr_desc->src_charset_in_dst&&op_expr->no_effect_convert_cnt==sub_expr_cnt)||
				op_expr->convert_failed>0)
			{
				scanner->dedup_expr_num++;
				Maat_region_inner_cancel_last_expr_id(u_para);
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
	else //For hexbin and regex, no need to do charset conversion.
	{
		expr_id=scanner->exprid_generator++;
		Maat_region_inner_add_expr_id(u_para, expr_id);
		op_expr=create_op_expr(expr_id,
								0,	//add
								u_para,
								table->table_id
								);
		for(k=0;k<sub_expr_cnt;k++)
		{
			if(db_rule->expr_type==EXPR_TYPE_REGEX)
			{
				p_rule=create_rs_str_rule(make_sub_type(table->table_id,dst_charset,expr_desc->do_charset_merge),
										db_rule->match_method,
										db_rule->is_case_sensitive,
										sub_key_array[k],
										strlen(sub_key_array[k]),
										key_left_offset[k],
										key_right_offset[k]);
				p_rule->rule_type=RULETYPE_REG;
			}
			else
			{
				region_str_len=strlen(sub_key_array[k])+1;
				region_string=ALLOC(char, region_str_len);
				region_str_len=hex2bin(sub_key_array[k], strlen(sub_key_array[k]), region_string, region_str_len);
				
				p_rule=create_rs_str_rule(make_sub_type(table->table_id,dst_charset,expr_desc->do_charset_merge),
										db_rule->match_method,
										db_rule->is_case_sensitive,
										region_string,
										region_str_len,
										key_left_offset[k],
										key_right_offset[k]);
				
				free(region_string);
				region_string=NULL;
			}
			op_expr_add_rule(op_expr, p_rule);
		}
		MESA_lqueue_join_tail(scanner->region_update_q,&op_expr, sizeof(void*));
	}
	return 0;
}
int add_ip_rule(struct Maat_table_schema* table, struct db_ip_rule_t* db_ip_rule, struct Maat_scanner *scanner, void* logger)
{
	scan_rule_t* p_rule=NULL;
	struct op_expr_t* op_expr=NULL;
	struct Maat_region_inner* u_para=NULL;
	int expr_id=0, ret=0;

	u_para=Maat_region_inner_new(db_ip_rule->group_id, db_ip_rule->region_id, table->table_id, -1);
	ret=Maat_hierarchy_add_region_to_group(scanner->hier, db_ip_rule->group_id, db_ip_rule->region_id, table->table_id, u_para);
	if(ret!=0)
	{
		Maat_region_inner_free(u_para);
		u_para=NULL;
		return -1;
	}
	
	expr_id=scanner->exprid_generator++;
	Maat_region_inner_add_expr_id(u_para, expr_id);
	op_expr=create_op_expr(expr_id,
						RULESCAN_OP_ADD,
						u_para,
						table->table_id);
	p_rule=create_rs_ip_rule(make_sub_type(table->table_id,CHARSET_NONE,0)
						,db_ip_rule);
	op_expr_add_rule(op_expr, p_rule);
	MESA_lqueue_join_tail(scanner->region_update_q, &op_expr, sizeof(void*));
	return 0;
}
int add_interval_rule(struct Maat_table_schema* table,struct db_interval_rule* intval_rule,struct Maat_scanner *scanner,void* logger)
{
	scan_rule_t* p_rule=NULL;
	struct op_expr_t* op_expr=NULL;
	struct Maat_region_inner* u_para=NULL;
	int expr_id=0, ret=0,district_id=-1;

	if(table->table_type==TABLE_TYPE_INTERVAL_PLUS)
	{
		assert(strlen(intval_rule->district)>0);
		str_unescape(intval_rule->district);
		district_id=get_district_id(scanner, intval_rule->district);
	}

	u_para=Maat_region_inner_new(intval_rule->group_id, intval_rule->region_id, table->table_id, district_id);
	ret=Maat_hierarchy_add_region_to_group(scanner->hier, intval_rule->group_id, intval_rule->region_id, table->table_id, u_para);
	if(ret!=0)
	{
		Maat_region_inner_free(u_para);
		u_para=NULL;
		return -1;
	}
	
	expr_id=scanner->exprid_generator++;
	Maat_region_inner_add_expr_id(u_para, expr_id);

	op_expr=create_op_expr(expr_id,
						RULESCAN_OP_ADD,
						u_para,
						table->table_id);
	
	p_rule=create_rs_intval_rule(make_sub_type(table->table_id,CHARSET_NONE,0)
						,intval_rule);
	op_expr_add_rule(op_expr,p_rule);
	MESA_lqueue_join_tail(scanner->region_update_q, &op_expr, sizeof(void*));
	return 0;
}
int add_digest_rule(struct Maat_table_schema* table, struct db_digest_rule* db_rule, struct Maat_scanner *scanner,void* logger)
{
	struct Maat_region_inner* u_para=NULL;
	struct Maat_table_runtime * table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table->table_id);
	int expr_id=0, ret=0;

	u_para=Maat_region_inner_new(db_rule->group_id, db_rule->region_id, table->table_id, -1);
	ret=Maat_hierarchy_add_region_to_group(scanner->hier, db_rule->group_id, db_rule->region_id, table->table_id, u_para);
	if(ret!=0)
	{
		Maat_region_inner_free(u_para);
		u_para=NULL;
		return -1;
	}
	
	expr_id=scanner->exprid_generator++;
	Maat_region_inner_add_expr_id(u_para, expr_id);

	Maat_table_runtime_digest_add(table_rt, expr_id, db_rule->digest_string, db_rule->confidence_degree, u_para);
	return 0;
}


int del_region_rule(struct Maat_table_schema* table, int region_id, int group_id, int rule_type, struct Maat_scanner *maat_scanner, void* logger)
{
	int i=0;
	struct Maat_table_runtime* table_rt=NULL;
	struct op_expr_t* op_expr=NULL;

	UNUSED int ret=0;
	struct Maat_region_inner* region=NULL;
	region=(struct Maat_region_inner*)Maat_hierarchy_region_dettach_user_data(maat_scanner->hier, region_id);
	if(region==NULL)
	{
		return -1;
	}
	ret=Maat_hierarchy_remove_region_from_group(maat_scanner->hier, group_id, region_id);
	assert(ret==0);
	assert(group_id==region->group_id);
	
	switch(table->table_type)
	{
		case	TABLE_TYPE_IP:
		case	TABLE_TYPE_IP_PLUS:
		case	TABLE_TYPE_EXPR:
		case	TABLE_TYPE_EXPR_PLUS:
		case	TABLE_TYPE_INTERVAL:
		case	TABLE_TYPE_INTERVAL_PLUS:
			for(i=0;i<region->expr_id_cnt;i++)
			{
				op_expr=create_op_expr(region->expr_id_lb+i, RULESCAN_OP_DEL, NULL, table->table_id);//del expr
				op_expr->rule_type=rule_type;
				MESA_lqueue_join_tail(maat_scanner->region_update_q, &op_expr, sizeof(void*));
			}
			break;
		case	TABLE_TYPE_SIMILARITY:
		case	TABLE_TYPE_DIGEST:
			assert(region->expr_id_cnt==1);
			table_rt=Maat_table_runtime_get(maat_scanner->table_rt_mgr, table->table_id);
			Maat_table_runtime_digest_del(table_rt, region->expr_id_lb);
			break;
		default:
			assert(0);
			break;
	}
	Maat_garbage_bagging(maat_scanner->ref_garbage_bin, region, (void (*)(void*))Maat_region_inner_free);

	return 0;
}
void update_group2compile_rule(struct Maat_table_schema* table, const char* table_line, struct Maat_scanner *scanner, struct Maat_table_manager* table_mgr, void* logger)
{
	struct db_group2compile_rule db_g2c_rule;
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table->table_id);
	int ret=0;
	char virtual_table_name[MAX_TABLE_NAME_LEN]={0};
	memset(&db_g2c_rule, 0, sizeof(db_g2c_rule));
	ret=sscanf(table_line,"%d\t%d\t%d\t%d\t%s\t%d", &(db_g2c_rule.group_id),
											&(db_g2c_rule.compile_id),
											&(db_g2c_rule.is_valid),
											&(db_g2c_rule.not_flag),
											virtual_table_name,
											&(db_g2c_rule.clause_index));
	if(ret!=6)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"update error, invalid format of group2compile table %s:%s",
							table->table_name[table->updating_name], table_line);	
		table->udpate_err_cnt++;
		return;
	}
	if(db_g2c_rule.clause_index>=MAX_ITEMS_PER_BOOL_EXPR)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"update error, invalid clause index of group2compile table %s:%s",
							table->table_name[table->updating_name], table_line);	
		table->udpate_err_cnt++;
		return;
	}
	if(is_valid_table_name(virtual_table_name))
	{
		db_g2c_rule.virtual_table_id=Maat_table_get_id_by_name(table_mgr, virtual_table_name);
		if(db_g2c_rule.virtual_table_id<0)
		{
			//This happens when one data source (e.g. redis) is consumed by multiple Maat instance.
			//Maat ignores unrealated groups.
			MESA_handle_runtime_log(logger, RLOG_LV_DEBUG, maat_module,
								"group2compile table load abandon, unknown virtual table name: %s of group table %s:%s.",
								virtual_table_name,
								table->table_name[table->updating_name], table_line);	
			table->udpate_err_cnt++;
			return;
		}
	}
	if(db_g2c_rule.is_valid==FALSE)
	{
		ret=Maat_hierarchy_remove_group_from_compile(scanner->hier, db_g2c_rule.group_id,db_g2c_rule.virtual_table_id, db_g2c_rule.not_flag, db_g2c_rule.clause_index, db_g2c_rule.compile_id);
		if(ret==0)
		{
			table_rt->origin_rule_num--;
			assert(table_rt->origin_rule_num>=0);
			if(db_g2c_rule.not_flag)
			{
				table_rt->group2compile.not_flag_group--;
			}
		}
	}
	else
	{
		ret=Maat_hierarchy_add_group_to_compile(scanner->hier, db_g2c_rule.group_id,db_g2c_rule.virtual_table_id, db_g2c_rule.not_flag, db_g2c_rule.clause_index, db_g2c_rule.compile_id);
		if(ret==0)
		{
			table_rt->origin_rule_num++;
			if(db_g2c_rule.not_flag)
			{
				table_rt->group2compile.not_flag_group++;
			}
		}
	}
	return;
}
void update_group2group_rule(struct Maat_table_schema* table, const char* table_line, struct Maat_scanner *scanner, struct Maat_table_manager* table_mgr, void* logger)
{
	struct db_group2group_rule db_g2g_rule;
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table->table_id);
	int ret=0;
	memset(&db_g2g_rule, 0, sizeof(db_g2g_rule));
	ret=sscanf(table_line,"%d\t%d\t%d", &(db_g2g_rule.group_id),
											&(db_g2g_rule.superior_group_id),
											&(db_g2g_rule.is_valid));
	if(ret!=3)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"update error, invalid format of group2group table %s:%s",
							table->table_name[table->updating_name], table_line);	
		table->udpate_err_cnt++;
		return;
	}
	if(db_g2g_rule.is_valid==FALSE)
	{
		ret=Maat_hierarchy_remove_group_from_group(scanner->hier, db_g2g_rule.group_id, db_g2g_rule.superior_group_id);
		if(ret==0)
		{
			table_rt->origin_rule_num--;
			assert(table_rt->origin_rule_num>=0);
		}
	}
	else
	{
		ret=Maat_hierarchy_add_group_to_group(scanner->hier, db_g2g_rule.group_id, db_g2g_rule.superior_group_id);
		if(ret==0)
		{
			table_rt->origin_rule_num++;
		}
	}

}
void update_expr_rule(struct Maat_table_schema* table,const char* table_line,struct Maat_scanner *scanner,void* logger)
{
	struct db_str_rule_t* maat_str_rule=ALLOC(struct db_str_rule_t, 1);
	int ret=0,db_hexbin=0,rule_type=0;
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table->table_id);
	switch(table->table_type)
	{
		case	TABLE_TYPE_EXPR:
			ret=sscanf(table_line,"%d\t%d\t%1024s\t%d\t%d\t%d\t%d",&(maat_str_rule->region_id)
															,&(maat_str_rule->group_id)
															,maat_str_rule->keywords
															,(int*)&(maat_str_rule->expr_type)
															,(int*)&(maat_str_rule->match_method)
															,&db_hexbin
															,&(maat_str_rule->is_valid));
			if(ret!=7)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"abandon config: invalid format of expr table %s:%s", table->table_name[table->updating_name], table_line);
				free(maat_str_rule);
				maat_str_rule=NULL;	
				table->udpate_err_cnt++;
				return;
			}
			break;
		case	TABLE_TYPE_EXPR_PLUS:
			ret=sscanf(table_line,"%d\t%d\t%64s\t%1024s\t%d\t%d\t%d\t%d",&(maat_str_rule->region_id)
															,&(maat_str_rule->group_id)
															,maat_str_rule->district
															,maat_str_rule->keywords
															,(int*)&(maat_str_rule->expr_type)
															,(int*)&(maat_str_rule->match_method)
															,&db_hexbin
															,&(maat_str_rule->is_valid));
			if(ret!=8)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"abandon config: invalid format of expr_plus table %s:%s", table->table_name[table->updating_name], table_line);
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
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"abandon config %d:update error,invalid hexbin value of expr table %s:%s",
								maat_str_rule->region_id,
								table->table_name[table->updating_name], table_line);
			table->udpate_err_cnt++;
			goto error_out;
	}
	if(!is_valid_match_method(maat_str_rule->match_method))
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
							"abandon config %d:update error,invalid match method=%d in expr table %s:%s",
							maat_str_rule->region_id,
							maat_str_rule->match_method,
							table->table_name[table->updating_name],table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}
	if(!is_valid_expr_type(maat_str_rule->expr_type))
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
							"abandon config %d:update error,invalid expr type=%d in expr table %s:%s",
							maat_str_rule->region_id,
							maat_str_rule->expr_type,
							table->table_name[table->updating_name], table_line);
		table->udpate_err_cnt++;
		goto error_out;
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
		ret=del_region_rule(table, maat_str_rule->region_id, maat_str_rule->group_id, rule_type,
							scanner, logger);
		if(ret<0)
		{
			table->udpate_err_cnt++;
		}
		else
		{
			table_rt->origin_rule_num--;
		}
	}
	else
	{
		if(maat_str_rule->expr_type==EXPR_TYPE_AND
			&&maat_str_rule->match_method!=MATCH_METHOD_SUB)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
			"table %s region cfg %d is EXPR_TYPE_AND,but match method is not MATCH_METHOD_SUB,force fixed.",
			table->table_name[table->updating_name], maat_str_rule->region_id);
			maat_str_rule->match_method=MATCH_METHOD_SUB;
				
		}
		if(strlen(maat_str_rule->keywords)<4)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_module ,
										"Table %s region cfg %d has a expr less than 4 bytes.",
										table->table_name,
										maat_str_rule->region_id);
		}
		ret=add_expr_rule(table, maat_str_rule, scanner, logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_module,
							"duplicate config of expr table %s region_id=%d",
							table->table_name[table->updating_name], maat_str_rule->region_id);
			table->udpate_err_cnt++;
		}
		else
		{
			table_rt->origin_rule_num++;
		}

	}
error_out:
	free(maat_str_rule);
	maat_str_rule=NULL;
}

void update_ip_rule(struct Maat_table_schema* table, const char* table_line, struct Maat_scanner *scanner, void* logger)
{
	struct db_ip_rule_t* ip_rule=(struct db_ip_rule_t*)calloc(sizeof(struct db_ip_rule_t),1);
	char src_ip1[40]={0}, src_ip2[40]={0}, dst_ip1[40]={0}, dst_ip2[40]={0};
	char saddr_format[16]={0}, sport_format[16]={0}, daddr_format[16]={0}, dport_format[16]={0};
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table->table_id);
	unsigned short src_port1=0, src_port2=0, dst_port1=0, dst_port2=0;
	int protocol=0,direction=0;
	int ret=0;
	int ret_array[8]={1},i=0;

	switch(table->table_type)
	{
		case TABLE_TYPE_IP:
			strncpy(saddr_format, "mask", sizeof(saddr_format));
			strncpy(sport_format, "mask", sizeof(sport_format));
			strncpy(daddr_format, "mask", sizeof(daddr_format));
			strncpy(dport_format, "mask", sizeof(dport_format));

			ret=sscanf(table_line,"%d\t%d\t%d\t%s\t%s\t%hu\t%hu\t%s\t%s\t%hu\t%hu\t%d\t%d\t%d",
															&(ip_rule->region_id),
															&(ip_rule->group_id),
															&(ip_rule->addr_type),
															src_ip1,
															src_ip2,
															&src_port1,
															&src_port2,
															dst_ip1,
															dst_ip2,
															&dst_port1,
															&dst_port2,
															&protocol,
															&direction,
															&(ip_rule->is_valid));
			if(ret!=14)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
									"update error, invalid column number of ip table %s:%s"
									,table->table_name[table->updating_name],table_line);
				table->udpate_err_cnt++;
				goto error_out;
			}
			break;
		case TABLE_TYPE_IP_PLUS:
			ret=sscanf(table_line,"%d\t%d\t%d\t%s\t%s\t%s\t%s\t%hu\t%hu\t%s\t%s\t%s\t%s\t%hu\t%hu\t%d\t%d\t%d",
															&(ip_rule->region_id),
															&(ip_rule->group_id),
															&(ip_rule->addr_type),
															saddr_format,
															src_ip1,
															src_ip2,
															sport_format,
															&src_port1,
															&src_port2,
															daddr_format,
															dst_ip1,
															dst_ip2,
															dport_format,
															&dst_port1,
															&dst_port2,
															&protocol,
															&direction,
															&(ip_rule->is_valid));
			if(ret!=18)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
									"update error, invalid column number of ip_plus table %s:%s"
									,table->table_name[table->updating_name],table_line);
				table->udpate_err_cnt++;
				goto error_out;
			}
			break;
		default:
			table->udpate_err_cnt++;
			goto error_out;
			break;
	}
	if(ip_rule->addr_type!=4&&ip_rule->addr_type!=6)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module,
							"update error, invalid addr type %d of ip/ip_plus table %s:%s",
							ip_rule->addr_type,
							table->table_name[table->updating_name], table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}
	if(protocol>65535 || protocol<0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module,
							"update error, invalid protocol value %d of ip/ip_plus table %s:%s",
							protocol,
							table->table_name[table->updating_name],table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}
	if(direction!=0 && direction!=1)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module,
							"update error, invalid direction value %d of ip/ip_plus table %s:%s",
							direction,
							table->table_name[table->updating_name],table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}
	if(FORMAT_UNKNOWN==ip_format_str2int(saddr_format)||
		FORMAT_UNKNOWN==ip_format_str2int(sport_format)||
		FORMAT_UNKNOWN==ip_format_str2int(daddr_format)||	
		FORMAT_UNKNOWN==ip_format_str2int(dport_format))
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module,
							"update error, invalid addr format of ip/ip_plus table %s:%s, should be range, mask or CIDR",
							table->table_name[table->updating_name], table_line);
		table->udpate_err_cnt++;
		goto error_out;
	}

	if(ip_rule->addr_type==4)
	{
		ret_array[0]=ip_format2range(ip_rule->addr_type, ip_format_str2int(saddr_format), src_ip1, src_ip2, &ip_rule->ipv4_rule.min_saddr, &ip_rule->ipv4_rule.max_saddr);
		ret_array[1]=ip_format2range(ip_rule->addr_type, ip_format_str2int(daddr_format), dst_ip1, dst_ip2, &ip_rule->ipv4_rule.min_daddr, &ip_rule->ipv4_rule.max_daddr);
		
		if(FORMAT_MASK==ip_format_str2int(sport_format))
		{
			ip_rule->ipv4_rule.min_sport=src_port1&src_port2;
			ip_rule->ipv4_rule.max_sport=src_port1|~src_port2;		
		}
		else
		{
			ip_rule->ipv4_rule.min_sport=src_port1;
			ip_rule->ipv4_rule.max_sport=src_port2;
		}

		if(FORMAT_MASK==ip_format_str2int(dport_format))
		{
			ip_rule->ipv4_rule.min_dport=dst_port1&dst_port2;
			ip_rule->ipv4_rule.max_dport=dst_port1|~dst_port2;		
		}
		else
		{
			ip_rule->ipv4_rule.min_dport=dst_port1;
			ip_rule->ipv4_rule.max_dport=dst_port2;
		}

		ip_rule->ipv4_rule.proto=protocol;
		ip_rule->ipv4_rule.direction=direction;
	}
	else
	{
		ret_array[0]=ip_format2range(ip_rule->addr_type, ip_format_str2int(saddr_format), src_ip1, src_ip2, ip_rule->ipv6_rule.min_saddr, ip_rule->ipv6_rule.max_saddr);
		ret_array[1]=ip_format2range(ip_rule->addr_type, ip_format_str2int(daddr_format), dst_ip1, dst_ip2, ip_rule->ipv6_rule.min_daddr, ip_rule->ipv6_rule.max_daddr);
	
		if(FORMAT_MASK==ip_format_str2int(sport_format))
		{
			ip_rule->ipv6_rule.min_sport=src_port1&src_port2;
			ip_rule->ipv6_rule.max_sport=src_port1|~src_port2;		
		}
		else
		{
			ip_rule->ipv6_rule.min_sport=src_port1;
			ip_rule->ipv6_rule.max_sport=src_port2;
		}

		if(FORMAT_MASK==ip_format_str2int(dport_format))
		{
			ip_rule->ipv6_rule.min_dport=dst_port1&dst_port2;
			ip_rule->ipv6_rule.max_dport=dst_port1|~dst_port2;			
		}
		else
		{
			ip_rule->ipv6_rule.min_dport=dst_port1;
			ip_rule->ipv6_rule.max_dport=dst_port2;
		}

		ip_rule->ipv6_rule.proto=protocol;
		ip_rule->ipv6_rule.direction=direction;
	}
	for(i=0;i<4;i++)
	{
		if(ret_array[i]<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
								"update error, invalid IP address format of ip table %s:%s"
								,table->table_name[table->updating_name],table_line);
			table->udpate_err_cnt++;
			goto error_out;
		}
	}
	if(ip_rule->is_valid==FALSE)
	{
		ret=del_region_rule(table,
							ip_rule->region_id, ip_rule->group_id, ip_rule->addr_type==6?RULETYPE_IPv6:RULETYPE_IPv4,
							scanner, logger);
		if(ret<0)
		{
			table->udpate_err_cnt++;
		}
		else
		{
			table_rt->origin_rule_num--;
		}
	}
	else
	{

		ret=add_ip_rule(table, ip_rule, scanner, logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of ip table %s config_id=%d"
							,table->table_name[table->updating_name],ip_rule->region_id);
			table->udpate_err_cnt++;
		}
		else
		{
			table_rt->origin_rule_num++;
		}

	}
error_out:
	free(ip_rule);
	ip_rule=NULL;	
}

void update_intval_rule(struct Maat_table_schema* table, const char* table_line, struct Maat_scanner *scanner, void* logger)
{
	struct db_interval_rule* intval_rule=ALLOC(struct db_interval_rule, 1);
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table->table_id);
	int ret=0;
	switch(table->table_type)
	{
		case	TABLE_TYPE_INTERVAL:
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
			break;
		case	TABLE_TYPE_INTERVAL_PLUS:
			ret=sscanf(table_line,"%d\t%d\t%s\t%u\t%u\t%d",&(intval_rule->region_id)
														,&(intval_rule->group_id)
														,intval_rule->district
														,&(intval_rule->intval.lb)
														,&(intval_rule->intval.ub)
														,&(intval_rule->is_valid));

			if(ret!=6||intval_rule->intval.ub<intval_rule->intval.lb)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
									"update error,invalid format  of interval table %s:%s"
									,table->table_name[table->updating_name],table_line);
				table->udpate_err_cnt++;
				goto error_out;
			}
			break;
		default:
			assert(0);
			break;
	}


	if(intval_rule->is_valid==FALSE)
	{
		ret=del_region_rule(table
							,intval_rule->region_id,intval_rule->group_id,RULETYPE_INT
							,scanner, logger);
		if(ret<0)
		{
			table->udpate_err_cnt++;
		}
		else
		{
			table_rt->origin_rule_num--;
		}

	}
	else
	{
		ret=add_interval_rule(table, intval_rule,scanner,logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"duplicate config of intval table %s config_id=%d"
							,table->table_name[table->updating_name],intval_rule->region_id);
			table->udpate_err_cnt++;
		}
		else
		{
			table_rt->origin_rule_num++;
		}

	}
error_out:
	free(intval_rule);
	intval_rule=NULL;		
}

void update_compile_rule(struct Maat_table_schema* table,const char* table_line ,struct Maat_scanner *scanner, const struct rule_tag* tags, int n_tags,void* logger)
{
	struct compile_table_schema* compile_desc=&(table->compile);
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table->table_id);

	struct Maat_compile_rule *p_compile=NULL;
	struct Maat_rule_head m_rule_tmp;
	memset(&m_rule_tmp, 0, sizeof(m_rule_tmp));

	char service_define[MAX_TABLE_LINE_SIZE]={0};
	char tag_str[MAX_TABLE_LINE_SIZE]={0};
	int ret=0;
	int is_valid=0, declared_grp_num=0;
	double exec_seq=0.0;
	ret=sscanf(table_line,"%d\t%d\t%hhd\t%hhd\t%hhd\t%s\t%s\t%d\t%d\t%lf",&(m_rule_tmp.config_id),
													&(m_rule_tmp.service_id),
													&(m_rule_tmp.action),
													&(m_rule_tmp.do_blacklist),
													&(m_rule_tmp.do_log),
													tag_str,
													service_define,
													&is_valid,
													&declared_grp_num,
													&exec_seq);
	if((ret!=8&&ret!=9&&ret!=10)||declared_grp_num>MAAT_MAX_EXPR_ITEM_NUM)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module ,
							"update error, invalid format of compile table %s:%s"
							,table->table_name[table->updating_name],table_line);	
		table->udpate_err_cnt++;
		return;

	}
	if(n_tags>0&&strlen(tag_str)>2)
	{
		str_unescape(tag_str);
		ret=compare_accept_tag(tag_str, tags, n_tags);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
						"update error, invalid tag format of compile table %s:%s",
						table->table_name[table->updating_name],table_line);
			table->udpate_err_cnt++;
			return;

		}
		if(ret==0)
		{
			table->unmatch_tag_cnt++;
			return;
		}
	}
	switch(compile_desc->user_region_encoding)
	{
		case USER_REGION_ENCODE_ESCAPE:
			str_unescape(service_define);
			break;
		default:
			break;
	}

	if(is_valid==FALSE)
	{
		p_compile=(struct Maat_compile_rule*)Maat_hierarchy_compile_dettach_user_data(scanner->hier, m_rule_tmp.config_id);
		if(p_compile)
		{
			ret=Maat_hierarchy_compile_remove(scanner->hier, m_rule_tmp.config_id);
			assert(ret==0);
			table_rt->origin_rule_num--;
			Maat_garbage_bagging(scanner->ref_garbage_bin, p_compile, (void (*)(void*))destroy_compile_rule);
		}
		else
		{
			table->udpate_err_cnt++;
		}
	}
	else
	{
		p_compile=create_compile_rule(&m_rule_tmp, service_define, declared_grp_num, exec_seq, table);
		ret=Maat_hierarchy_compile_add(scanner->hier, m_rule_tmp.config_id, declared_grp_num, p_compile);
		if(ret==0)
		{
			table_rt->origin_rule_num++;
		}
		else
		{
			MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_module,
							"duplicate config of compile table %s compile_id %d",
							table->table_name[table->updating_name], m_rule_tmp.config_id);			
			table->udpate_err_cnt++;			
			destroy_compile_rule(p_compile);			
			p_compile=NULL;
			table->udpate_err_cnt++;
		}
	}
	
	return;
}

void update_digest_rule(struct Maat_table_schema* table, const char* table_line, struct Maat_scanner *scanner, void* logger)
{
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table->table_id);
	struct db_digest_rule* digest_rule=ALLOC(struct db_digest_rule, 1);
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

	if(digest_rule->is_valid==FALSE)
	{
		//digest rule is not build with rulescan, this rule type is useless in count_rs_region funciton.
		ret=del_region_rule(table,digest_rule->region_id,digest_rule->group_id,0 ,scanner, logger);
		if(ret<0)
		{
			table->udpate_err_cnt++;
		}
		else
		{
			table_rt->origin_rule_num--;
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
			table_rt->origin_rule_num++;
		}

	}
error_out:
	digest_rule->digest_string=NULL;
	free(digest_rule);
	digest_rule=NULL;
	return;
}
void update_plugin_table(struct Maat_table_schema* table_schema, const char* row, Maat_scanner* scanner, const struct rule_tag* tags, int n_tags, void* logger)
{
	int ret=1, matched_tag=1;
	struct plugin_table_schema* plugin_desc=&(table_schema->plugin);
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table_schema->table_id);
	char* copy=NULL;
	size_t accept_tag_offset=0, accept_tag_len=0;
	if(plugin_desc->rule_tag_column>0&&n_tags>0)
	{
		ret=Maat_helper_read_column(row, plugin_desc->rule_tag_column, &accept_tag_offset, &accept_tag_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
						"update error, could not locate tag in column %d of plugin table_schema %s:%s",
						plugin_desc->rule_tag_column,
						table_schema->table_name[table_schema->updating_name],
						row);
			table_schema->udpate_err_cnt++;
			return;
		}
		if(accept_tag_len>2)
		{
			copy=ALLOC(char, accept_tag_len+1);
			memcpy(copy, row+accept_tag_offset, accept_tag_len);
			matched_tag=compare_accept_tag(copy, tags, n_tags);
			if(matched_tag<0)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
							"update error,invalid tag format of plugin table_schema %s:%s"
							,table_schema->table_name[table_schema->updating_name],row);
				table_schema->udpate_err_cnt++;
			}
			if(matched_tag==0)
			{
				table_schema->unmatch_tag_cnt++;
			}
			free(copy);
			copy=NULL;
		}
		if(!matched_tag)
		{
			return;
		}
	}
	Maat_table_runtime_plugin_new_row(table_rt, table_schema, row, logger);
}
void update_xx_plugin_table(struct Maat_table_schema* table_schema, const char* table_row, Maat_scanner* scanner, const struct rule_tag* tags, int n_tags, void* logger)
{
	int ret=1, matched_tag=1;
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table_schema->table_id);
	char* copy=NULL;
	size_t accept_tag_offset=0, accept_tag_len=0;
	int rule_tag_column=-1;
	if(table_schema->table_type==TABLE_TYPE_IP_PLUGIN)
	{
		rule_tag_column=table_schema->ip_plugin.rule_tag_column;
	}
	else if(table_schema->table_type==TABLE_TYPE_FQDN_PLUGIN)
	{
		rule_tag_column=table_schema->fqdn_plugin.rule_tag_column;
	}
	else
	{
		assert(0);
		return;
	}
	if(rule_tag_column>0&&n_tags>0)
	{
		ret=Maat_helper_read_column(table_row, rule_tag_column, &accept_tag_offset, &accept_tag_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
						"update error, could not locate tag in column %d of table %s:%s",
						rule_tag_column,
						table_schema->table_name[table_schema->updating_name],
						table_row);
			table_schema->udpate_err_cnt++;
			return;
		}
		if(accept_tag_len>2)
		{
			copy=ALLOC(char, accept_tag_len+1);
			memcpy(copy, table_row+accept_tag_offset, accept_tag_len);
			matched_tag=compare_accept_tag(copy, tags, n_tags);
			if(matched_tag<0)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
							"update error, invalid tag format of ip_plugin table_schema %s:%s",
							table_schema->table_name[table_schema->updating_name], table_row);
				table_schema->udpate_err_cnt++;
			}
			if(matched_tag==0)
			{
				table_schema->unmatch_tag_cnt++;
			}
			free(copy);
			copy=NULL;
		}
		if(!matched_tag)
		{
			return;
		}
	}
	if(table_schema->table_type==TABLE_TYPE_IP_PLUGIN)
	{
		Maat_table_runtime_ip_plugin_new_row(table_rt, table_schema, table_row, logger);
	}
	else //TABLE_TYPE_FQDN_PLUGIN
	{
		Maat_table_runtime_fqdn_plugin_new_row(table_rt, table_schema, table_row, logger);
	}
	scanner->xx_plugin_rule_to_update_cnt++;
	return;
}

void do_scanner_update(struct Maat_scanner* scanner, int scan_thread_num, void* logger)
{
	MESA_htable_handle tmp_map=NULL;
	struct Maat_table_runtime* table_rt=NULL;
	int i=0, ret=0;
	enum MAAT_TABLE_TYPE table_type=TABLE_TYPE_INVALID;

	ret=Maat_hierarchy_rebuild(scanner->hier);
	if(ret!=0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module ,
								"Version %d hierarchy rebuild failed.",
								scanner->version);
	}
	else
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_module ,
							"Version %d hierarchy rebuild success, dedup string rule %lu.",
							scanner->version,
							scanner->dedup_expr_num);	
	}
	
	scanner->dedup_expr_num=0;
	rulescan_batch_update(scanner->region,
							scanner->region_update_q,
							logger,
							scanner);

	for(i=0; (size_t)i<scanner->max_table_num; i++)
	{
		table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, i);
		if(table_rt==NULL)
		{
			continue;
		}
		table_type=Maat_table_runtime_get_type(table_rt);	
		switch(table_type)
		{
			case TABLE_TYPE_DIGEST:
			case TABLE_TYPE_SIMILARITY:				
				ret=Maat_table_runtime_digest_batch_udpate(table_rt);
				if(ret<0)
				{
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
										"GIE_update error.");
				}
				break;
			case TABLE_TYPE_PLUGIN:
				Maat_table_runtime_plugin_update_commit(table_rt);
				break;
			case TABLE_TYPE_IP_PLUGIN:				
				ret=Maat_table_runtime_ip_plugin_rebuild_ip_matcher(table_rt);
				if(ret<0)
				{
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
										"IP plugin table_id %d build failed.", i);

				}

				break;
			case TABLE_TYPE_FQDN_PLUGIN:
				ret=Maat_table_runtime_fqdn_plugin_rebuild_fqdn_engine(table_rt);
				if(ret<0)
				{
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
										"FQDN plugin table_id %d build failed.", i);

				}
				break;
			default:
				break;
		}

	}
	if(scanner->tmp_district_map!=NULL)
	{
		tmp_map=scanner->district_map;
		scanner->district_map=scanner->tmp_district_map;
		scanner->tmp_district_map=NULL;
		Maat_garbage_bagging(scanner->ref_garbage_bin, tmp_map, (void (*)(void*))maat_kv_store_free);
	}
	scanner->last_update_time=time(NULL);
	scanner->xx_plugin_rule_to_update_cnt=0;
	return;

}

void maat_start_cb(long long new_version, int update_type, void*u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para;
	feather->new_version=new_version;
	
	if(update_type==CM_UPDATE_TYPE_FULL)
	{
		feather->update_tmp_scanner=create_maat_scanner(new_version,feather);
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
	Maat_table_manager_all_plugin_cb_start(feather->table_mgr, update_type);
	return;
}
long long scanner_rule_num(struct Maat_scanner *scanner)
{
	long long total=0;
	struct Maat_table_runtime* table_rt=NULL;
	int i=0;
	for(i=0; (size_t)i<scanner->max_table_num; i++)
	{
		table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, i);
		if(table_rt!=NULL)
		{
			total+=table_rt->origin_rule_num;
		}
	}
	return total;
}
void maat_finish_cb(void* u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para; 
	long rulescan_wait_q_cnt=0;

	Maat_table_manager_all_plugin_cb_finish(feather->table_mgr);

	if(feather->update_tmp_scanner!=NULL)
	{
		feather->update_tmp_scanner->cfg_num=scanner_rule_num(feather->update_tmp_scanner);
		do_scanner_update(feather->update_tmp_scanner,
						feather->scan_thread_num,
						feather->logger);
		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Full config version %u load %d entries complete.",
								feather->update_tmp_scanner->version,feather->update_tmp_scanner->cfg_num);	
	}
	else if(feather->scanner!=NULL)
	{
		feather->scanner->cfg_num=scanner_rule_num(feather->scanner);
		feather->scanner->version=feather->maat_version;
		rulescan_wait_q_cnt=MESA_lqueue_get_count(feather->scanner->region_update_q);
		feather->postpone_q_size=rulescan_wait_q_cnt;
		if(time(NULL)-feather->scanner->last_update_time>=feather->rule_effect_interval_ms/1000)
		{
			do_scanner_update(feather->scanner,
							feather->scan_thread_num,
							feather->logger);
			MESA_handle_runtime_log(feather->logger, RLOG_LV_INFO, maat_module
									,"Inc config version %u build complete, %d entries in total."
									,feather->scanner->version,feather->scanner->cfg_num);
			feather->postpone_q_size=0;
		}
		else
		{
			MESA_handle_runtime_log(feather->logger, RLOG_LV_INFO, maat_module,
									"Postpone %d entries of version %u load to rulescan.",
									feather->scanner->cfg_num, feather->scanner->version);
		}
	}
	else
	{
		 MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
									"Version %d have no valid scan rules, plugin callback complete.",
									feather->maat_version);
	}
	feather->new_version=-1;
	return;
}
int maat_update_cb(const char* table_name,const char* line,void *u_para)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)u_para; 
	Maat_scanner* scanner=NULL;
	struct Maat_table_schema* p_table=NULL;
	if(feather->update_tmp_scanner!=NULL)
	{
		scanner=feather->update_tmp_scanner;
	}
	else
	{
		scanner=feather->scanner;
	}
//	MESA_handle_runtime_log(feather->logger, RLOG_LV_DEBUG, maat_module, "Maat table %s input: %s", table_name, line);
	p_table=Maat_table_get_desc_by_name(feather->table_mgr, table_name);
	if(!p_table)
	{
		MESA_handle_runtime_log(feather->logger, RLOG_LV_INFO, maat_module ,"update warning, unknown table name %s", table_name);
		return -1;	
	}
	Maat_table_set_updating_name(p_table, table_name);

	switch(p_table->table_type)
	{
		case	TABLE_TYPE_EXPR:
		case	TABLE_TYPE_EXPR_PLUS:
			update_expr_rule(p_table, line, scanner, feather->logger);
			break;
		case	TABLE_TYPE_IP:
		case	TABLE_TYPE_IP_PLUS:
			update_ip_rule(p_table, line, scanner, feather->logger);
			break;
		case	TABLE_TYPE_INTERVAL:
		case	TABLE_TYPE_INTERVAL_PLUS:
			update_intval_rule(p_table, line, scanner,feather->logger);
			break;
		case	TABLE_TYPE_DIGEST:
		case	TABLE_TYPE_SIMILARITY:
			update_digest_rule(p_table, line, scanner,feather->logger);
			break;
		case	TABLE_TYPE_COMPILE:
			update_compile_rule(p_table, line, scanner, feather->accept_tags, feather->n_tags, feather->logger);
			break;
		case	TABLE_TYPE_GROUP2COMPILE:
			update_group2compile_rule(p_table, line, scanner, feather->table_mgr, feather->logger);
			break;
		case	TABLE_TYPE_GROUP2GROUP:
			update_group2group_rule(p_table, line, scanner, feather->table_mgr, feather->logger);
			break;
		case	TABLE_TYPE_PLUGIN:
			update_plugin_table(p_table, line, scanner, feather->accept_tags, feather->n_tags, feather->logger);
			break;
		case	TABLE_TYPE_IP_PLUGIN:
		case	TABLE_TYPE_FQDN_PLUGIN:
			update_xx_plugin_table(p_table, line, scanner, feather->accept_tags, feather->n_tags, feather->logger);
			break;
		default:
			break;
	
	}
	return 0;
}
void *thread_rule_monitor(void *arg)
{
	struct _Maat_feather_t *feather=(struct _Maat_feather_t *)arg;
	struct Maat_scanner* old_scanner=NULL;
	long rulescan_update_wait_q_cnt=0;
	int scan_dir_cnt=0;
	int ret=0;
	char md5_tmp[MD5_DIGEST_LENGTH*2+1]={0};
	char err_str[MAX_TABLE_NAME_LEN]={0};

	struct stat attrib;
	size_t total_wait_rule_cnt=0;

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
	
	pthread_mutex_lock(&(feather->background_update_mutex));
	if(feather->DEFERRED_LOAD_ON!=0)
	{
		MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
								"Deferred Loading ON, updating in %s.",__func__);
		maat_read_full_config(feather);
	}
	pthread_mutex_unlock(&(feather->background_update_mutex));
	while(feather->is_running)
	{
		usleep(feather->rule_update_checking_interval_ms*1000);
		scan_dir_cnt++;
		if(0==pthread_mutex_trylock(&(feather->background_update_mutex)))
		{
			switch(feather->input_mode)
			{
				case SOURCE_REDIS:
					redis_monitor_traverse(feather->maat_version,
											&(feather->mr_ctx),
											maat_start_cb,
											maat_update_cb,
											maat_finish_cb,
											feather,
											feather->decrypt_key,	//Not used.
											feather);
					break;
				case SOURCE_IRIS_FILE:
					config_monitor_traverse(feather->maat_version,
											feather->iris_ctx.inc_dir, 
											maat_start_cb,
											maat_update_cb,
											maat_finish_cb,
											feather,
											feather->decrypt_key,
											feather->logger);
					break;
				case SOURCE_JSON_FILE:
					memset(md5_tmp, 0, sizeof(md5_tmp));
				    stat(feather->json_ctx.json_file, &attrib);
					if(memcmp(&attrib.st_ctim, &(feather->json_ctx.last_md5_time), sizeof(attrib.st_ctim)))
					{
						feather->json_ctx.last_md5_time=attrib.st_ctim;
						md5_file(feather->json_ctx.json_file, md5_tmp);
						if(0!=strcmp(md5_tmp,feather->json_ctx.effective_json_md5))
						{
							ret=load_maat_json_file(feather, feather->json_ctx.json_file, err_str, sizeof(err_str));
							if(ret<0)
							{
								MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module ,
												"Maat re-initiate with JSON file %s (md5=%s)failed: %s",
												feather->json_ctx.json_file,
												md5_tmp,
												err_str);
							}
							else
							{
								config_monitor_traverse(0,
														feather->json_ctx.iris_file,
														maat_start_cb,
														maat_update_cb,
														maat_finish_cb,
														feather,
														feather->decrypt_key,
														feather->logger);
								MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module ,
												"Maat re-initiate with JSON file %s success, md5: %s",
												feather->json_ctx.json_file,
												md5_tmp);

							}

						}
					}
					break;
				default:
					assert(0);
					break;
			}

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
					feather->zombie_rs_stream+=alignment_int64_array_sum(old_scanner->ref_cnt,old_scanner->max_thread_num);
					Maat_garbage_bagging(feather->garbage_bin, old_scanner, (void (*)(void*))destroy_maat_scanner);
				}
				feather->update_tmp_scanner=NULL;
				feather->maat_version=feather->scanner->version;
				feather->last_full_version=feather->scanner->version;
			}
			if(feather->scanner!=NULL)
			{
				rulescan_update_wait_q_cnt=MESA_lqueue_get_count(feather->scanner->region_update_q);
				feather->postpone_q_size=rulescan_update_wait_q_cnt;
				total_wait_rule_cnt=feather->postpone_q_size+feather->scanner->xx_plugin_rule_to_update_cnt;
				if(total_wait_rule_cnt>0&&time(NULL)-feather->scanner->last_update_time>=feather->rule_effect_interval_ms/1000)
				{
					do_scanner_update(feather->scanner,
									feather->scan_thread_num,
									feather->logger);
					feather->postpone_q_size=0;
					MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO,maat_module,
											"Actual udpate config version %u, %d entries load to rulescan after postpone.",
											feather->scanner->version,feather->scanner->cfg_num);
				}
			}
			pthread_mutex_unlock(&(feather->background_update_mutex));
		}
		Maat_garbage_collect_routine(feather->garbage_bin);
		if(feather->stat_on==1&&time(NULL)%2==0)//output every 2 seconds
		{
			maat_stat_output(feather);
		}
	}
	
	destroy_maat_scanner(feather->scanner);
	Maat_garbage_bin_free(feather->garbage_bin);
	Maat_table_manager_destroy(feather->table_mgr);//Table manager MUST be freed at last.
	
	alignment_int64_array_free(feather->thread_call_cnt);
	alignment_int64_array_free(feather->compile_mid_cnt);
	alignment_int64_array_free(feather->outer_mid_cnt);
	alignment_int64_array_free(feather->hit_cnt);
	alignment_int64_array_free(feather->not_grp_hit_cnt);
	if(feather->input_mode==SOURCE_REDIS)
	{
		if(feather->mr_ctx.read_ctx)
		{
			redisFree(feather->mr_ctx.read_ctx);
			feather->mr_ctx.read_ctx=NULL;
		}
		if(feather->mr_ctx.write_ctx)
		{
			redisFree(feather->mr_ctx.write_ctx);
			feather->mr_ctx.write_ctx=NULL;
		}
	}
	int i=0;
	for(i=0; i<feather->n_tags; i++)
	{
		free(feather->accept_tags[i].tag_name);
		free(feather->accept_tags[i].tag_val);
	}
	free(feather->accept_tags);
	free(feather->accept_tags_raw);
	if(feather->stat_on&& feather->stat_handle)
	{
		FS_stop(&(feather->stat_handle));
	}
	free(feather);
	return NULL;
}


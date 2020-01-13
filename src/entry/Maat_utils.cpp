#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "Maat_utils.h"
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
char* str_tolower(char* string)
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
char *strtok_r_esc(char *s, const char delim, char **save_ptr)
{  
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
int get_column_pos(const char* line, int column_seq, size_t *offset, size_t *len)
{
	const char* seps=" \t";
	char* saveptr=NULL, *subtoken=NULL, *str=NULL;
	char* dup_line=_maat_strdup(line);
	int i=0, ret=-1;
	for (str = dup_line; ; str = NULL)
	{
		subtoken = strtok_r(str, seps, &saveptr);
		if (subtoken == NULL)
			break;
		if(i==column_seq-1)
		{
			*offset=subtoken-dup_line;
			*len=strlen(subtoken);
			ret=0;
			break;
		}
		i++;
	}
	free(dup_line);
	return ret;
}

#define MAX_SYSTEM_CMD_LEN	512

int system_cmd_mkdir(const char* path)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd, sizeof(cmd),"mkdir -p %s", path);
	return  system(cmd) ;
}
int system_cmd_mv(const char* src_file,const char*dst_file)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd,sizeof(cmd), "mv %s %s", src_file, dst_file);
	return  system(cmd);
}
int system_cmd_cp(const char* src_file,const char*dst_file)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd,sizeof(cmd), "cp -f %s %s", src_file, dst_file);
	return  system(cmd);
}

int system_cmd_rm(const char* src_file)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd,sizeof(cmd), "rm %s -f", src_file);
	return  system(cmd);
}
char* md5_file(const char* filename, char* md5string)
{
	FILE* fp=NULL;
	int i=0;
	unsigned char md5[MD5_DIGEST_LENGTH];
	struct stat file_info;	
	stat(filename, &file_info);
	size_t file_size=file_info.st_size;

	fp=fopen(filename,"r");
	if(fp==NULL)
	{
		return NULL;
	}
	char* file_buff=(char*)malloc(file_size);
	fread(file_buff,1,file_size,fp);
	fclose(fp);
	
	MD5((const unsigned char *)(file_buff), (unsigned long)(file_size), md5);
	for(i = 0; i < MD5_DIGEST_LENGTH; ++i)
	{
		sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
	}
	free(file_buff);
	return md5string;
}
const char* CHARSET_STRING[]={"NONE","gbk","big5","unicode","utf8","bin",
							"unicode_ascii_esc","unicode_ascii_aligned","unicode_ncr_dec","unicode_ncr_hex","url_encode_gb2312","url_encode_utf8", "windows-1251", ""};

const char** charset_get_all_name(void)
{
	return CHARSET_STRING;
}
const char* charset_get_name(enum MAAT_CHARSET charset)
{
	return CHARSET_STRING[charset];
}
int lqueue_destroy_cb(void *data, long data_len, void *arg)
{
	assert(0);
	return 0;
}
#define DECRYPT_BLOCK_SIZE	(16*1024)
int decrypt_open(const char* filename, const char* key, const char* algorithm, unsigned char**pp_out, char* err_str, size_t err_str_sz)
{

	unsigned char inbuf[DECRYPT_BLOCK_SIZE];
	int inlen, out_blk_len=0;
	int out_buff_len=0,buff_offset=0;
	EVP_CIPHER_CTX *ctx;

	unsigned char cipher_key[EVP_MAX_KEY_LENGTH];
	unsigned char cipher_iv[EVP_MAX_IV_LENGTH];
	memset(cipher_key,0,sizeof(cipher_key));
	memset(cipher_iv,0,sizeof(cipher_iv));

	const EVP_CIPHER *cipher;
	const EVP_MD *dgst=NULL;
	const unsigned char *salt=NULL;
	int ret=0;
	
	FILE*in=fopen(filename, "r");
	if(in==NULL)
	{
		return -1;
	}

	OpenSSL_add_all_algorithms();
	cipher=EVP_get_cipherbyname(algorithm);
	if(cipher==NULL)
	{
		snprintf(err_str, err_str_sz, "Cipher %s is not supported.",algorithm);
		return 0;
	}
	dgst=EVP_get_digestbyname("md5");
	if(dgst==NULL)
	{
		snprintf(err_str, err_str_sz, "Get MD5 object failed.");
		return 0;
	}
	ret=EVP_BytesToKey(cipher, dgst, salt, (unsigned char*)key, strlen((const char*)key), 1, cipher_key,  cipher_iv);
	if(ret==0)
	{
		snprintf(err_str, err_str_sz, "Key and IV generatioin failed.");
		return 0;
	}
     /* Don't set key or IV right away; we want to check lengths */
	ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL,0);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) % 16==0);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
	 
	/* Now we can set key and IV */
	EVP_CipherInit_ex(ctx, NULL, NULL, cipher_key, cipher_iv, 0);
	out_buff_len=DECRYPT_BLOCK_SIZE;
	*pp_out=(unsigned char*)malloc(out_buff_len*sizeof(unsigned char));
	for (;;) 
	{
		inlen = fread(inbuf, 1, sizeof(inbuf), in);
		if (inlen <= 0)
			break;
		
		if(out_buff_len-buff_offset<inlen+EVP_CIPHER_block_size(cipher)-1)
		{
			out_buff_len*=2;
			*pp_out=(unsigned char*)realloc(*pp_out, out_buff_len);
		}
		out_blk_len=out_buff_len-buff_offset;
		if (!EVP_CipherUpdate(ctx, *pp_out+buff_offset, &out_blk_len, inbuf, inlen))
		{
			snprintf(err_str, err_str_sz, "EVP_CipherUpdate failed.");
			EVP_CIPHER_CTX_free(ctx);
			goto error_out;
		}
		buff_offset+=out_blk_len;

	}
	if (!EVP_CipherFinal_ex(ctx, *pp_out+buff_offset, &out_blk_len))
	{
		snprintf(err_str, err_str_sz, "EVP_CipherFinal_ex failed. Maybe password is wrong?");
		EVP_CIPHER_CTX_free(ctx);
		goto error_out;
	}
	buff_offset+=out_blk_len;
	EVP_CIPHER_CTX_free(ctx);
	fclose(in);
	return buff_offset;
error_out:
	free(*pp_out);
	*pp_out=NULL;	
	fclose(in);
	return 0;
}
int load_file_to_memory(const char* file_name, char**pp_out)
{
	int ret=0;
	FILE* fp=NULL;		
	struct stat fstat_buf;
	size_t read_size=0;
	
	ret=stat(file_name, &fstat_buf);
	if(ret!=0)
	{
		return -1;
	}
	fp=fopen(file_name, "r");
	if(fp==NULL)
	{
		return -1;
	}
	
	*pp_out=(char*)calloc(1, fstat_buf.st_size+1);
	read_size=fread(*pp_out,1, fstat_buf.st_size, fp);
	if(read_size!= (size_t)fstat_buf.st_size)
	{
		free(*pp_out);
		pp_out=NULL;
		return -1;
	}	
	
	fclose(fp);
	fp=NULL;	
	return fstat_buf.st_size;
}

#pragma once
#include "Maat_rule.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>//fstat
#include <sys/types.h>//fstat
#include <sys/stat.h>//fstat

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#define	FREE(p)	{free(*p);*p=NULL;}

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 411)
#define atomic_inc(x) __sync_add_and_fetch((x),1)
#define atomic_dec(x) __sync_sub_and_fetch((x),1)
#define atomic_add(x,y) __sync_add_and_fetch((x),(y))
#define atomic_sub(x,y) __sync_sub_and_fetch((x),(y))
	typedef int atomic_t;
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) __sync_add_and_fetch((x),0)
#define atomic_set(x,y) __sync_lock_test_and_set((x),y)
#else 
#include <alsa/iatomic.h>
#endif 
#define	TRUE	1
#define	FALSE	0

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			 \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define UNUSED	__attribute__((unused))
const char*	module_name_str(const char*name);
#define maat_module	(module_name_str("MAAT_Frame"))
#define	TO_RELATION_ID(vid, gid)	((unsigned long long)vid<<32|gid)
char* _maat_strdup(const char* s);
char* str_unescape(char* s);
inline void ipv6_ntoh(unsigned int *v6_addr)
{
	unsigned int i=0;
	for(i=0;i<4;i++)
	{
		v6_addr[i]=ntohl(v6_addr[i]);
	}
	return;
}
int  hex2bin(char *hex,int hex_len,char *binary,int size);
char* str_tolower(char* string);
char *strtok_r_esc(char *s, const char delim, char **save_ptr);
char *str_unescape_and(char*s);
char* str_unescape(char* s);
size_t memcat(void**dest, size_t offset, size_t *n_dest, const void* src, size_t n_src);

pid_t gettid(void);
int system_cmd_mkdir(const char* path);
int system_cmd_rm(const char* src_file);
int system_cmd_mv(const char* src_file, const char*dst_file);
int system_cmd_cp(const char* src_file, const char*dst_file);
int system_cmd_encrypt(const char* src_file, const char* dst_file, const char* password);

char* md5_file(const char* filename, char* md5string);
int get_column_pos(const char* line, int column_seq, size_t *offset, size_t *len);
const char** charset_get_all_name(void);
const char* charset_get_name(enum MAAT_CHARSET charset);
int lqueue_destroy_cb(void *data, long data_len, void *arg);
int decrypt_open(const char* file_name, const char* key, const char* algorithm, unsigned char**pp_out, size_t *out_sz, char* err_str, size_t err_str_sz);
int load_file_to_memory(const char* file_name, unsigned char**pp_out, size_t *out_sz);
//do_encrypt: 1 for encryption, 0 for decryption.
int crypt_memory(const unsigned char* inbuf, size_t inlen, unsigned char** pp_out, size_t *out_sz, const char* key, const char* algorithm, int do_encrypt, char* err_str, size_t err_str_sz);
enum MAAT_IP_FORMAT
{
	FORMAT_RANGE,
	FORMAT_MASK,
	FORMAT_CIDR,
	FORMAT_UNKNOWN
};
enum MAAT_IP_FORMAT ip_format_str2int(const char* format);
int ip_format2range(int ip_type, enum MAAT_IP_FORMAT format, const char* ip1, const char* ip2, unsigned int range_begin[], unsigned int range_end[]);



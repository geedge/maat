#pragma once
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/syscall.h>

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#define	FREE(p)	{free(*p);*p=NULL;}

#define	ATOMIC_INC(x) 	__atomic_fetch_add(x,1,__ATOMIC_RELAXED)
#define	ATOMIC_READ(x)	__atomic_fetch_add(x,0,__ATOMIC_RELAXED)


#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

const char*	module_name_str(const char*name);
#define maat_module	(module_name_str("MAAT_Frame"))

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
pid_t gettid(void);
int system_cmd_mkdir(const char* path);
int system_cmd_rm(const char* src_file);


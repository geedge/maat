/*
**********************************************************************************************
*	File: maat_utils.h
*   Description: maat utils entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_UTILS_H_
#define _MAAT_UTILS_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>

#define	TRUE	1
#define	FALSE	0

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))

#define FREE(ptr)  \
    {                   \
        if (ptr)        \
        {               \
            free(ptr);  \
            ptr = NULL; \
        }               \
    }

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			 \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define	MAX_SCANNER_HIT_COMPILE_NUM  4096
#define MAX_SCANNER_HIT_GROUP_NUM    4096
#define MAX_SCANNER_HIT_ITEM_NUM    4096

enum maat_ip_format {
	IP_FORMAT_RANGE,
	IP_FORMAT_MASK,
	IP_FORMAT_CIDR,
	IP_FORMAT_UNKNOWN
};

enum maat_ip_format ip_format_str2int(const char *format);
int ip_format2range(int ip_type, enum maat_ip_format format, const char *ip1, const char *ip2, 
                    uint32_t range_begin[], uint32_t range_end[]);

inline void ipv6_ntoh(unsigned int *v6_addr)
{
	for (unsigned int i = 0; i < 4; i++) {
		v6_addr[i] = ntohl(v6_addr[i]);
	}
}

#define UNUSED	__attribute__((unused))

const char *module_name_str(const char *name);

char *maat_strdup(const char *s);

int get_column_pos(const char *line, int column_seq, size_t *offset, size_t *len);

/* the column value must be integer */
int get_column_value(const char *line, int column_seq);

int load_file_to_memory(const char *file_name, unsigned char **pp_out, size_t *out_sz);

char *strtok_r_esc(char *s, const char delim, char **save_ptr);

char *str_unescape_and(char *s);

char *str_unescape(char *s);

char *md5_file(const char *filename, char *md5string);

int decrypt_open(const char* file_name, const char* key, const char* algorithm, 
                 unsigned char**pp_out, size_t *out_sz, char* err_str, size_t err_str_sz);

int crypt_memory(const unsigned char *inbuf, size_t inlen, unsigned char **pp_out, size_t *out_sz, 
                 const char *key, const char *algorithm, int do_encrypt, char *err_str, size_t err_str_sz);

int gzip_uncompress(const unsigned char *in_compressed_data, size_t in_compressed_sz, 
                    unsigned char **out_uncompressed_data, size_t *out_uncompressed_sz);

size_t memcat(void **dest, size_t offset, size_t *n_dest, const void *src, size_t n_src);

/* system cmd wrapper */
int system_cmd_mkdir(const char* path);

int system_cmd_rmdir(const char *dir);

#ifdef __cpluscplus
}
#endif

#endif
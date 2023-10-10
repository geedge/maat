/*
**********************************************************************************************
*	File: maat_utils.c
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/syscall.h> 
#include <zlib.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

#include "maat_utils.h"

pid_t gettid() 
{
	return syscall(SYS_gettid);
}

const char *module_name_str(const char *name)
{
	static __thread char module[64];
	snprintf(module,sizeof(module),"%s(%d)", name, gettid());
    
	return module;
}

inline void ipv6_ntoh(unsigned int *v6_addr)
{
	for (unsigned int i = 0; i < 4; i++) {
		v6_addr[i] = ntohl(v6_addr[i]);
	}
}

char *maat_strdup(const char *s)
{
	if (NULL == s) {
		return NULL;
	}

    char *d = (char *)malloc(strlen(s) + 1);
	memcpy(d, s, strlen(s) + 1);

	return d;
}

long long get_column_value(const char *line, int column_seq)
{
    size_t column_offset = 0;
    size_t column_len = 0;

    int ret = get_column_pos(line, column_seq, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }

    return atoll(line + column_offset);
}

int get_column_pos(const char *line, int column_seq, size_t *offset, size_t *len)
{
	int i = 0;
    int ret = -1;
    char *str = NULL;
	char *saveptr = NULL;
    char *subtoken = NULL;
    const char *seps = "\t";
	char *dup_line = maat_strdup(line);
	
	for (str = dup_line; ; str = NULL) {
		subtoken = strtok_r(str, seps, &saveptr);
		if (subtoken == NULL)
			break;
		if (i == column_seq - 1) {
			*offset = subtoken - dup_line;
			*len = strlen(subtoken);
			ret = 0;
			break;
		}
		i++;
	}
	FREE(dup_line);
    
	return ret;
}

int load_file_to_memory(const char *file_name, unsigned char **pp_out, size_t *out_sz)
{
	int ret = 0;
	FILE *fp = NULL;		
	struct stat fstat_buf;
	size_t read_size = 0;
	
	ret = stat(file_name, &fstat_buf);
	if (ret != 0) {
		return -1;
	}

	fp = fopen(file_name, "r");
	if (fp == NULL) {
		return -1;
	}

	*out_sz = fstat_buf.st_size;
	*pp_out = (unsigned char *)calloc(1, *out_sz+1);
	read_size = fread(*pp_out, 1, *out_sz, fp);
	if (read_size != *out_sz) {
		FREE(*pp_out);
	}	
	
	fclose(fp);
	fp = NULL;
	return 0;
}

static char *strchr_esc(char *s, const char delim)
{
	char *token = NULL;

	if (NULL == s) {
        return NULL;
    }
	
	for (token = s; *token != '\0'; token++) {
		if (*token == '\\') {
			token++;
			continue;
		}

		if(*token == delim) {
            break;
        }
	}

	if (*token == '\0') { 
		return NULL;
	} else {
		return token;
	}
}

char *strtok_r_esc(char *s, const char delim, char **save_ptr)
{  
    char *token = NULL;  
  
    if (NULL == s) {
        s = *save_ptr; 
    } 
  
    /* Scan leading delimiters.  */
	token = strchr_esc(s,delim);
	if (NULL == token) {
		*save_ptr = token;
		return s;
	}

    /* Find the end of the token.  */  
	*token = '\0';
	token++;
	*save_ptr = token;

    return s;  
}

char *str_escape(char *dst, int size, const char *src)
{
    int i = 0, j = 0;
	int len = strlen(src);

	for (i = 0, j = 0; i < len && j < size; i++) {
		switch (src[i]) {
			case '&':
				dst[j] = '\\';
				dst[j+1] = '&';
				j += 2;
				break;
			case ' ':
				dst[j] = '\\';
				dst[j+1] = 'b';//space,0x20;
				j += 2;
				break;
			case '\\':
				dst[j] = '\\';
				dst[j+1] = '\\';
				j += 2;
				break;
			default:
				dst[j] = src[i];
				j++;	//undo the followed i++
				break;
		}
	}
	dst[j] = '\0';

	return dst;
}

char *str_unescape(char *s)
{
	size_t i=0;
    size_t j=0;
	
	for (i = 0, j = 0; i < strlen(s); i++) {
		if (s[i] == '\\') {
			switch (s[i+1]) {
				case '&':
					s[j] = '&';
					break;
				case 'b':
					s[j] = ' ';//space,0x20;
					break;
				case '\\':
					s[j] = '\\';
					break;
				default:
					s[j] = s[i];
					i--;	//undo the followed i++
					break;
			}
			i++;
			j++;
		} else {
			s[j] = s[i];
			j++;
		}
	}
	s[j] = '\0';
	return s;
}

#define MAX_SYSTEM_CMD_LEN	512
int system_cmd_mkdir(const char *path)
{
    char cmd[MAX_SYSTEM_CMD_LEN] = {0};
	snprintf(cmd, sizeof(cmd), "mkdir -p %s", path);
	return system(cmd);
}

int system_cmd_rmdir(const char *dir)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd,sizeof(cmd), "rm %s -rf", dir);
	return system(cmd);
}

int system_cmd_gzip(const char *src_file, const char *dst_file)
{
    char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd, sizeof(cmd), "gzip -9 < %s > %s", src_file, dst_file);
    return system(cmd);
}

int system_cmd_encrypt(const char *src_file, const char *dst_file, const char *password)
{
    char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd, sizeof(cmd), "openssl enc -e -aes-256-cbc -k %s -p -nosalt -in %s -out %s -md md5",
             password, src_file, dst_file);
	return system(cmd);
}

char *md5_file(const char *filename, char *md5string)
{
	unsigned char md5[MD5_DIGEST_LENGTH] = {0};
	struct stat file_info;	
	stat(filename, &file_info);
	size_t file_size = file_info.st_size;

	FILE *fp = fopen(filename,"r");
	if (NULL == fp) {
		return NULL;
	}

	char *file_buff = (char *)malloc(file_size);
	fread(file_buff, 1, file_size, fp);
	fclose(fp);
	
	MD5((const unsigned char *)(file_buff), (unsigned long)(file_size), md5);
	for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
		sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
	}

	FREE(file_buff);

	return md5string;
}

int crypt_memory(const unsigned char *inbuf, size_t inlen, unsigned char **pp_out, 
                 size_t *out_sz, const char *key, const char *algorithm, int do_encrypt, 
                 char *err_str, size_t err_str_sz)
{
	OpenSSL_add_all_algorithms();
	const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
	if (NULL == cipher) {
		snprintf(err_str, err_str_sz, "Cipher %s is not supported.", algorithm);
		return 0;
	}

	const EVP_MD *dgst = EVP_get_digestbyname("md5");
	if (NULL == dgst) {
		snprintf(err_str, err_str_sz, "Get MD5 object failed.");
		return 0;
	}

    const unsigned char *salt = NULL;
    unsigned char cipher_key[EVP_MAX_KEY_LENGTH];
	unsigned char cipher_iv[EVP_MAX_IV_LENGTH];

	memset(cipher_key,0,sizeof(cipher_key));
	memset(cipher_iv,0,sizeof(cipher_iv));

	int ret = EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)key, 
                             strlen((const char *)key), 1, cipher_key, cipher_iv);
	if(0 == ret) {
		snprintf(err_str, err_str_sz, "Key and IV generation failed.");
		return 0;
	}

    /* Don't set key or IV right away; we want to check lengths */
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, do_encrypt);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) % 16 == 0);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

	/* Now we can set key and IV */
	//It should be set to 1 for encryption, 0 for decryption and -1 
    //to leave the value unchanged (the actual value of 'enc' being supplied in a previous call).
	EVP_CipherInit_ex(ctx, NULL, NULL, cipher_key, cipher_iv, -1);
    int out_blk_len = 0;
    int out_buff_offset = 0;
	int out_buff_len = inlen + EVP_CIPHER_block_size(cipher) - 1;
	*pp_out = (unsigned char *)malloc(out_buff_len * sizeof(unsigned char));
	if (!EVP_CipherUpdate(ctx, *pp_out + out_buff_offset, &out_blk_len, inbuf, inlen)) {
		snprintf(err_str, err_str_sz, "EVP_CipherUpdate failed.");
		EVP_CIPHER_CTX_free(ctx);
		goto error_out;
	}

	out_buff_offset += out_blk_len;
	if (!EVP_CipherFinal_ex(ctx, *pp_out+out_buff_offset, &out_blk_len)) {
		snprintf(err_str, err_str_sz, "EVP_CipherFinal_ex failed. Maybe password is wrong?");
		EVP_CIPHER_CTX_free(ctx);
		goto error_out;
	}

	out_buff_offset += out_blk_len;
	EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
	*out_sz = out_buff_offset;
	return 0;	
	
error_out:	
	FREE(*pp_out);
	return -1;
}

int decrypt_open(const char* file_name, const char* key, const char* algorithm, 
                 unsigned char**pp_out, size_t *out_sz, 
                 char* err_str, size_t err_str_sz)
{
	size_t file_sz = 0;
	unsigned char *file_buff = NULL;
	int ret = load_file_to_memory(file_name, &file_buff, &file_sz);
	if (ret < 0) {
		return -1;
	}

	ret = crypt_memory(file_buff, file_sz, pp_out, out_sz, key, algorithm, 
                        0, err_str, err_str_sz);
	FREE(file_buff);

	return ret;
}

int gzip_uncompress_one_try(const unsigned char *in_compressed_data, size_t in_compressed_sz, 
                            unsigned char **out_uncompressed_data, size_t *out_uncompressed_sz)
{
	z_stream strm;
	strm.zalloc = NULL;
	strm.zfree = NULL;
	strm.opaque = NULL;

	strm.avail_in = in_compressed_sz;
	strm.avail_out = *out_uncompressed_sz;
	strm.next_in = (Bytef *) in_compressed_data;
	strm.next_out = *out_uncompressed_data;

	int ret = -1;
	ret = inflateInit2(&strm, MAX_WBITS+16);
	if (ret == Z_OK) {
		ret = inflate(&strm, Z_FINISH);
		if (ret == Z_STREAM_END) {
			*out_uncompressed_sz = strm.total_out;
			ret = inflateEnd(&strm);
			return ret;
		}
	}
	inflateEnd(&strm);
	return ret;
}

int gzip_uncompress(const unsigned char *in_compressed_data, size_t in_compressed_sz, 
                    unsigned char **out_uncompressed_data, size_t *out_uncompressed_sz)
{
	int z_result;
	int ret = -1;
	size_t buffer_sz = in_compressed_sz * 2;	
    *out_uncompressed_data = ALLOC(unsigned char, buffer_sz);

	do {
		*out_uncompressed_sz = buffer_sz;
		z_result = gzip_uncompress_one_try(in_compressed_data, in_compressed_sz,
			                                out_uncompressed_data, out_uncompressed_sz);
		switch (z_result) {
			case Z_OK:
				ret = 0;
				break;			
			case Z_BUF_ERROR:
				buffer_sz *= 2;
				*out_uncompressed_data = (unsigned char *)realloc(*out_uncompressed_data,
                                                                  buffer_sz);
                memset(*out_uncompressed_data, 0, buffer_sz);
				break;
			default:
				ret = -1;
				break;
		}
	} while (z_result == Z_BUF_ERROR);

	return ret;
}

size_t memcat(void **dest, size_t offset, size_t *n_dest, const void *src, size_t n_src)
{
	if (*n_dest < offset + n_src) {
		*n_dest = (offset + n_src) * 2;
		*dest = realloc(*dest, sizeof(char) * (*n_dest));
	}
	memcpy((char *) * dest + offset, src, n_src);
    
	return n_src;
}

enum ip_format ip_format_str2int(const char *format)
{
    if (0 == strcasecmp(format, "single")) {
        return IP_FORMAT_SINGLE;
    }else if (0 == strcasecmp(format, "range")) {
		return IP_FORMAT_RANGE;
	} else if (0 == strcasecmp(format, "CIDR")) {
		return IP_FORMAT_CIDR;
	} else if (0 == strcasecmp(format, "mask")) {
        return IP_FORMAT_MASK;
    } else {
		assert(0);
	}
	return IP_FORMAT_UNKNOWN;
}

enum port_format port_format_str2int(const char *format)
{
    if (0 == strcasecmp(format, "single")) {
        return PORT_FORMAT_SINGLE;
    } else if (0 == strcasecmp(format, "range")) {
        return PORT_FORMAT_RANGE;
    } else {
        assert(0);
    }
    return PORT_FORMAT_UNKNOWN;
}

int ip_format2range(int ip_type, enum ip_format format, const char *ip1, const char *ip2,
                    uint32_t range_begin[], uint32_t range_end[])
{
	int cidr = 0;
	int ret = 0;

	if (ip_type != IPV4 && ip_type != IPV6) {
		assert(0);
		return -1;
	}

	if (ip_type == IPV4) {
        uint32_t ipv4_addr = 0;
		ret = inet_pton(AF_INET, ip1, &ipv4_addr);
		if (ret <= 0) {
			return -1;
		}

		ipv4_addr = ntohl(ipv4_addr);
        uint32_t ipv4_range_end = 0;
        uint32_t ipv4_mask = 0;
		switch (format) {
            case IP_FORMAT_SINGLE:
			case IP_FORMAT_RANGE:
				range_begin[0] = ipv4_addr;
				ret = inet_pton(AF_INET, ip2, &ipv4_range_end);
				if (ret <= 0) {
					return -1;
				}				
				ipv4_range_end = ntohl(ipv4_range_end);
				range_end[0] = ipv4_range_end;
				break;
            case IP_FORMAT_MASK:
                ret = inet_pton(AF_INET, ip2, &ipv4_mask);
				if (ret <= 0) {
					return -1;
				}
				ipv4_mask = ntohl(ipv4_mask);
				range_begin[0] = ipv4_addr & ipv4_mask;
				range_end[0] = ipv4_addr | ~ipv4_mask;
				break;
			case IP_FORMAT_CIDR:
				cidr = atoi(ip2);
				if (cidr > 32 || cidr < 0) {
					return -1;
				}
				ipv4_mask = (0xFFFFFFFFUL << (32 - cidr)) & 0xFFFFFFFFUL;
				range_begin[0] = ipv4_addr & ipv4_mask;
				range_end[0] = ipv4_addr | ~ipv4_mask;
				break;
			default:
				assert(0);
		}
	} else {
        //ipv6
        int i = 0;
        uint32_t ipv6_addr[4] = {0};
        uint32_t ipv6_mask[4] = {0};
        uint32_t ipv6_range_end[4] = {0};

		ret = inet_pton(AF_INET6, ip1, ipv6_addr);
		if (ret <= 0) {
			return -1;
		}
		ipv6_ntoh(ipv6_addr);

		switch (format) {
            case IP_FORMAT_SINGLE:
			case IP_FORMAT_RANGE:
				ret = inet_pton(AF_INET6, ip2, ipv6_range_end);
				if (ret <= 0) {
					return -1;
				}
				ipv6_ntoh(ipv6_range_end);

				memcpy(range_begin, ipv6_addr, sizeof(ipv6_addr));				
				memcpy(range_end, ipv6_range_end, sizeof(ipv6_range_end));
				break;
            case IP_FORMAT_MASK:
				ret = inet_pton(AF_INET6, ip2, ipv6_mask);
				if (ret <= 0) {
					return -1;
				}
				ipv6_ntoh(ipv6_mask);
                
				for (i = 0; i < 4; i++) {
					range_begin[i]=ipv6_addr[i] & ipv6_mask[i];	
					range_end[i] = ipv6_addr[i] | ~ipv6_mask[i];
				}
				break;
			case IP_FORMAT_CIDR:
				cidr = atoi(ip2);
				if (cidr > 128 || cidr < 0) {
					return -1;
				}

				for (i = 0; i < 4; i++) {
					int bit32 = 128 - cidr - 32 * (3 - i);
					if (bit32 < 0) {
                        bit32 = 0;
                    }
                    
					ipv6_mask[i] = (0xFFFFFFFFUL << bit32) & 0xFFFFFFFFUL;
					range_begin[i] = ipv6_addr[i] & ipv6_mask[i];	
					range_end[i] = ipv6_addr[i] | ~ipv6_mask[i];
				}
				break;
			default:
				assert(0);
		}
	}
	return 0;
}
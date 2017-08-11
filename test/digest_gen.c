#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include "stream_fuzzy_hash.h"
#include "gram_index_engine.h"

void* entropy_start(void)
{
	unsigned long long * char_num=(unsigned long long*)calloc(sizeof(unsigned long long),256+1);
	return (void*)char_num;
}
void entropy_feed(void* handle,const unsigned char*buff, int size)
{
	int i=0;
	unsigned long long * char_num=(unsigned long long *)handle;
	for(i=0;i<size;i++)
	{
		char_num[buff[i]+1]++;;
	}
	char_num[0]+=size;
	return;
}
double entropy_stop(void* handle)
{
	unsigned long long * char_num=(unsigned long long *)handle;
	int i;
	double sum = 0,p=0;
	for(i = 0; i < 256; i++)
	{
		p = (double)char_num[i+1]/char_num[0];
		if(p != 0)
		{
			sum += (p*(log(p)/log(2))); 
		}
	}
	free(handle);
	return (-sum);
}
void hash_file(const char* path)
{
	unsigned long long read_size=0,feed_offset=0;
	char read_buff[1024*4];
	void * entropy_handle=NULL;
	double file_entropy=0.0;
	int hash_length;
	char * digest_result_buff=NULL;
	struct stat digest_fstat;
	FILE* fp;
	stat(path,&digest_fstat);
	fp = fopen(path, "r");
	if(NULL == fp)
	{
		printf("Open %s failed\n", path);
		return;
	}
	read_size=0;
	feed_offset=0;
	sfh_instance_t * fhandle = SFH_instance(0);
	entropy_handle=entropy_start();
	while(0==feof(fp))
	{
		read_size=fread(read_buff,1,sizeof(read_buff),fp);
		SFH_feed(fhandle,read_buff,read_size,feed_offset);
		feed_offset+=read_size;
		entropy_feed(entropy_handle,(const unsigned char*) read_buff, read_size);
	}
	file_entropy=entropy_stop(entropy_handle);
	hash_length = SFH_status(fhandle, HASH_LENGTH);
	digest_result_buff= (char *)malloc(sizeof(char) * (hash_length));
	SFH_digest(fhandle, digest_result_buff, hash_length);
	printf("%s %u %lf %s\n",path,digest_fstat.st_size,file_entropy,digest_result_buff);
	SFH_release(fhandle);
	free(digest_result_buff);
	fclose(fp);
}
void digest_gen_print_usage(void)
{
	printf("digest_gen uasge:\n\t-f [FILE], caculate a file's SFH digest.\n");
	printf("\t-s specify first string for comparing.\n");
	printf("\t-d specify second string for comparing.\n");
	printf("\t-c compare two simple string with similairity.\n");
	printf("\t-m compare two SFH signature.\n");
	return;
}
int main(int argc, char * argv[])
{
	char path[256];
	char str1[4096],str2[4096];
	int oc=0;
	int confidence=0;
	int model=0;
	const char* b_opt_arg=NULL;
	if(argc<2)
	{
		digest_gen_print_usage();
		return 0;
	}
	while((oc=getopt(argc,argv,"f:cms:d:"))!=-1)
	{
		switch(oc)
		{
			case 'f':
				strncpy(path,optarg,sizeof(path));
				break;
			case 'c':
			case 'm':
				model=oc;
				break;
			case 's':
				strncpy(str1,optarg,sizeof(str1));
				break;
			case 'd':
				strncpy(str2,optarg,sizeof(str2));
				break;
			case '?':
			default:
				digest_gen_print_usage();
				return 0;
				break;
		}
	}
	switch(model)
	{
		case 'f':
			hash_file(path);
			break;
		case 'c':
			confidence=GIE_string_similiarity(str1, strlen(str1), str2, strlen(str2));
			printf("%d\n",confidence);
			break;
		case 'm':
			sscanf(optarg,"%s,%s",str1,str2);
			confidence=GIE_sfh_similiarity(str1, strlen(str1), str2, strlen(str2));
			printf("%d\n",confidence);
			break;
		default:
			assert(0);
	}
	return 0;
}

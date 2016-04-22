#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<dirent.h>
#include<sys/stat.h>
#include<time.h>
#include<math.h>
#include "mesa_fuzzy.h"

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

void dir_digest(int argc, char * argv[])
{

    if(argc != 2)
    {
        printf("uasge: ./digest_gen [Dir]\n");
        exit(-1);
    }

    DIR * dir;
    struct dirent * file;
    char * dir_path = argv[1];
	char read_buff[1024*4];
	unsigned long long read_size=0,feed_offset=0;
    dir = opendir(dir_path);
    chdir(dir_path);
	int ret =0;
	unsigned int file_id = 1;
	unsigned long hash_length=0,file_effective_length=0;
	FILE * result_fp = NULL,*fp=NULL;
	struct stat digest_fstat;
	char * digest_result_buff=NULL;
	const char* result_file="./digest_result.txt";
	result_fp = fopen(result_file,"a");
	void * entropy_handle=NULL;
	double file_entropy=0.0;
	if(NULL == result_fp)
	{
		printf("open file failed!");
		exit(-1);
	}
    while((file = readdir(dir)) != NULL)
    {
        if(!strcmp(file->d_name, ".") ||!strcmp(file->d_name, "..")||file->d_type!=DT_REG)
        {
            continue;
        }
		ret=stat(file->d_name,&digest_fstat);
		if(ret!=0)
		{
			printf("fstat %s error.\n",file->d_name);
			continue;
		}
		
        off_t file_size = digest_fstat.st_size;
        fp = fopen(file->d_name, "r");
        if(NULL == fp)
        {
            printf("Can't open file %s\n", file->d_name);
            continue;
        }
		read_size=0;
		feed_offset=0;
        fuzzy_handle_t * fhandle = fuzzy_create_handle((unsigned long long)file_size);
		entropy_handle=entropy_start();
		while(0==feof(fp))
		{
			read_size=fread(read_buff,1,sizeof(read_buff),fp);
			fuzzy_feed(fhandle,read_buff,read_size,feed_offset);
			feed_offset+=read_size;
			entropy_feed(entropy_handle,(const unsigned char*) read_buff, read_size);
		}
		file_entropy=entropy_stop(entropy_handle);
        hash_length = fuzzy_status(fhandle, HASH_LENGTH);
		file_effective_length = fuzzy_status(fhandle, EFFECTIVE_LENGTH);
        digest_result_buff= (char *)malloc(sizeof(char) * (hash_length));
        if(fuzzy_digest(fhandle, digest_result_buff, hash_length) != 0)
        {
            printf("error\n");
            continue;
        }
		fprintf(result_fp, "%u\t%s\t%llu\t%lu\t%lf\n", file_id, file->d_name,file_size, hash_length,file_entropy);
		fprintf(result_fp, "%s\n", digest_result_buff);
		printf("%u %s\n", file_id,file->d_name);
		file_id++;
        fuzzy_destroy_handle(fhandle);
        fclose(fp);
		free(digest_result_buff);
    }
	fclose(result_fp);
    closedir(dir);
	printf("write result to %s\n", result_file);

}


int main(int argc, char * argv[])
{
    dir_digest(argc, argv);
    //overlap_test(argc, argv);
    return 0;
}

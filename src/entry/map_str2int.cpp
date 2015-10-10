#include <MESA/MESA_htable.h>
void map_tmp_free(void* ptr)
{
	free(ptr);
}
MESA_htable_handle map_create(void)
{
	MESA_htable_handle string2int_map;
	MESA_htable_create_args_t hargs;
	memset(&hargs,0,sizeof(hargs));
	hargs.thread_safe=1;
	hargs.hash_slot_size = 1024*1024;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_LRU;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;
	hargs.recursive = 0;
	hargs.data_free = map_tmp_free;
	hargs.data_expire_with_condition = NULL;
	string2int_map=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(string2int_map, 0);
	return string2int_map;
}
void map_destroy(MESA_htable_handle p)
{
	MESA_htable_destroy(p,NULL);
	return;
}
int map_register(MESA_htable_handle handle,const char* string,int value)
{
	unsigned int size=strlen(string);
	unsigned char *key=(unsigned char *)string;
	int *data=(int*)malloc(sizeof(int));
	int ret=0;
	*data=value;
	ret=MESA_htable_add(handle,key,size,data);
	return ret;
}
int map_str2int(MESA_htable_handle handle,const char* string,int* value)
{
	int *data=NULL;
	unsigned int size=strlen(string);
	data=(int*)MESA_htable_search(handle,(unsigned char*)string,size);
	if(data!=NULL)
	{
		*value=*data;
		return 1;
	}
	else
	{
		return -1;
	}	
}


#include <assert.h>
#include <MESA/MESA_htable.h>

void map_tmp_free(void* ptr)
{
	free(ptr);
}

long read_map_val(void *data, const uchar *key, uint size, void *user_arg)
{
	if(data!=NULL)
	{
		*(int*)user_arg=*(int*)data;
		return 1;
	}
	else
	{
		return 0;
	}
}
MESA_htable_handle map_create(void)
{
	MESA_htable_handle string2int_map;
	MESA_htable_create_args_t hargs;
	memset(&hargs,0,sizeof(hargs));
	hargs.thread_safe=0;
	hargs.hash_slot_size = 4*1024;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;
	hargs.recursive = 1;
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
	int ret=0;
	int * data= (int*)malloc(sizeof(int));
	*data=value;
	ret=MESA_htable_add(handle,key,size,data);
	if(ret<0)
	{
		free(data);
	}
	return ret;
}
int map_str2int(MESA_htable_handle handle,const char* string,int* value)
{
	long cb_ret=0;
	unsigned int size=strlen(string);
	
	MESA_htable_search_cb(handle,(unsigned char*)string,size,
									read_map_val,value,&cb_ret);
									
//	data=(int*)MESA_htable_search(handle,(unsigned char*)string,size);
	if(cb_ret>0)
	{
		return 1;
	}
	else
	{
		return -1;
	}	
}
int map_unNullstr2int(MESA_htable_handle handle,const char* string,int len,int* value)
{
	long cb_ret=0;
	
	MESA_htable_search_cb(handle,(unsigned char*)string,len,
									read_map_val,value,&cb_ret);
									
//	data=(int*)MESA_htable_search(handle,(unsigned char*)string,len);
	if(cb_ret>0)
	{
		return 1;
	}
	else
	{
		return -1;
	}	
}
void duplicate_func(const uchar * key, uint size, void * data, void * user)
{
	MESA_htable_handle target=(MESA_htable_handle)user;
	int value=*(int*)data;
	int ret=0;
	char* string=(char*)calloc(sizeof(char),(size+1));
	memcpy(string,key,size);
	ret=map_register(target,string,value);
	assert(ret>0);
}
MESA_htable_handle map_duplicate(MESA_htable_handle origin_map)
{
	int ret=0;
	MESA_htable_handle target=NULL;
	target=map_create();
	ret=MESA_htable_iterate(origin_map, duplicate_func, target);
	assert(ret==0);
	return target;
}


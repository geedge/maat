#ifndef	_DYNAMIC_ARRAY_H_INCLUDE_
#define	_DYNAMIC_ARRAY_H_INCLUDE_
struct dynamic_array_t
{
	void ** array;
	long long size;
	long long enlarge_step;
};
struct dynamic_array_t* dynamic_array_create(long long init_size, long long step);
void dynamic_array_destroy(struct dynamic_array_t* d_array,void (* free_data)(void *));
void* dynamic_array_read(struct dynamic_array_t* d_array,long long i);
void dynamic_array_write(struct dynamic_array_t* d_array, long long i,void* data);
#endif //_DYNAMIC_ARRAY_H_INCLUDE_

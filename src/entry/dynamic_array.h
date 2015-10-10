#ifndef	_DYNAMIC_ARRAY_H_INCLUDE_
#define	_DYNAMIC_ARRAY_H_INCLUDE_
struct dynamic_array_t
{
	void ** array;
	int size;
	int enlarge_step;
};
struct dynamic_array_t* dynamic_array_create(int size,int step);
void dynamic_array_destroy(struct dynamic_array_t* d_array,void (* free_data)(void *));
void* dynamic_array_read(struct dynamic_array_t* d_array,int i);
void dynamic_array_write(struct dynamic_array_t* d_array,int i,void* data);
#endif //_DYNAMIC_ARRAY_H_INCLUDE_

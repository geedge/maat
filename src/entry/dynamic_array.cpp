#include"dynamic_array.h"
#include <stdlib.h>
#include <string.h>
int dynamic_array_VERSION_20141202=0;
struct dynamic_array_t* dynamic_array_create(int size,int step)
{
	struct dynamic_array_t* d_array=(struct dynamic_array_t*)calloc(sizeof(struct dynamic_array_t),1);
	d_array->array=(void**)calloc(sizeof(void*),size);
	d_array->size=size;
	d_array->enlarge_step=step;
	return d_array;
}
void dynamic_array_destroy(struct dynamic_array_t* d_array,void (* free_data)(void *))
{
	int i;
	if(free_data!=NULL)
	{
		for(i=0;i<d_array->size;i++)
		{
			free_data(d_array->array[i]);
		}
	}
	free(d_array->array);
	free(d_array);
}
void* dynamic_array_read(struct dynamic_array_t* d_array,int i)
{
	if(i<d_array->size)
	{
		return d_array->array[i];
	}
	else
	{
		return NULL;
	}
}
void dynamic_array_write(struct dynamic_array_t* d_array,int i,void* data)
{
	int new_size=0;
	if(i<d_array->size)
	{
		d_array->array[i]=data;
	}
	else
	{
		new_size=i+d_array->enlarge_step;
		d_array->array=(void**)realloc(d_array->array,new_size*sizeof(void*));
		memset(d_array->array+d_array->size,0,(new_size-d_array->size)*sizeof(void*));
		d_array->size=new_size;
		d_array->array[i]=data;
		return;
	}
}

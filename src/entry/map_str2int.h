#ifndef	__MAP_STR2INT_H_INCLUDE_
#define	__MAP_STR2INT_H_INCLUDE_
MESA_htable_handle map_create(void);
void map_destroy(MESA_htable_handle p);
int map_register(MESA_htable_handle handle,const char* string,int value);
int map_str2int(MESA_htable_handle handle,const char* string,int* value);
int map_unNullstr2int(MESA_htable_handle handle,const char* string,int size,int* value);
MESA_htable_handle map_duplicate(MESA_htable_handle origin_map);
#endif


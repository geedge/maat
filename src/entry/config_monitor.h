#ifndef	__CONFIG_MONITOR_H_INCLUDE_
#define	__CONFIG_MONITOR_H_INCLUDE_

#define	CM_UPDATE_TYPE_FULL	1
#define	CM_UPDATE_TYPE_INC	2

void config_monitor_traverse(unsigned int version,const char*idx_dir,
							void (*start)(unsigned int ,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
							int (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
							void (*finish)(void*),//u_para
							void* u_para,
							const unsigned char* dec_key,
							void* logger);
#endif


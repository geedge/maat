#ifndef H_MAAT_JSON2IRIS_H_INCLUDE
#define H_MAAT_JSON2IRIS_H_INCLUDE
int json2iris(const char* json_file,const char*compile_tn,const char* group_tn,char* iris_dir_buf,int buf_len,void* logger);
int set_file_rulenum(const char* path,int rulenum,void* logger);
#endif


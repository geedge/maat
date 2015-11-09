#ifndef _GREAT_INDEX_ENGINE_
#define _GREAT_INDEX_ENGINE_

#ifdef __cplusplus
extern "C" {
#endif

#define GIE_INSERT_OPT 0
#define GIE_DELETE_OPT 1

typedef struct 
{
	/* data */
}GIE_handle_t;


typedef struct 
{
	unsigned int id;
	unsigned long long orilen;
	char * fh;
	void * tag;
}fuzzy_digest_t;


typedef struct 
{
	unsigned int id;
	int confidence_level;
	unsigned long long orilen;
	void * tag;
}result_t;


typedef struct 
{
	unsigned long long precision;
	int confidence_level_threshold;
	double query_accuracy;
}GIE_create_para_t;


GIE_handle_t * GIE_create(GIE_create_para_t * usrpara);


int GIE_update(GIE_handle_t * handle, fuzzy_digest_t ** digests, int size, int opration);


int GIE_query(GIE_handle_t * handle, unsigned long long orilen, char * fuzzy_string, int strsize, result_t * results, int size);


void GIE_destory(GIE_handle_t * handle);


#ifdef __cplusplus
}
#endif

#endif

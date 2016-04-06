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
	short operation;//GIE_INSERT_OPT or GIE_DELETE_OPT.if operation is GIE_DELETE_OPT, only id is needed;
	short cfds_lvl;
	unsigned long long origin_len;	
	char * fuzzy_hash;
	void * tag;
}GIE_digest_t;


typedef struct 
{
	unsigned int id;
	short cfds_lvl;
	unsigned long long origin_len;
	void * tag;
}GIE_result_t;


typedef struct 
{
	unsigned long long index_interval;
//	int confidence_level_threshold;
	double query_accuracy;
}GIE_create_para_t;


GIE_handle_t * GIE_create(const GIE_create_para_t * para);


int GIE_update(GIE_handle_t * handle, GIE_digest_t ** digests, int size);

//return actual matched result count
//return 0 when matched nothing;
//return -1 when error occurs;
int GIE_query(GIE_handle_t * handle, unsigned long long origin_len, const char * fuzzy_string, GIE_result_t * results, int result_size);


void GIE_destory(GIE_handle_t * handle);


#ifdef __cplusplus
}
#endif

#endif

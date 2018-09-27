#include "zt_hash.h"
#include "interval_index.h"
#include "stream_fuzzy_hash.h"

#ifndef	__SFH_INTERNAL_H_INCLUDE_
#define	__SFH_INTERNAL_H_INCLUDE_

#define ROLLING_WINDOW 7
#define BLOCKSIZE_MIN 3
#define HASH_PRIME 0x01000193
#define HASH_INIT 0x28021967
#define CALCULATE 0
#define MODIFY 1 
#define EXPECT_SIGNATURE_LEN 64
#define MEMORY_OCCUPY 3

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif
#ifndef container_of
#define container_of(ptr, type, member) ({			 \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define DEBUG (0)

//int count = 0;
struct roll_state_t
{
	unsigned char window[ROLLING_WINDOW];
	unsigned char pad[1];
	unsigned int h1, h2, h3;
	unsigned int  n;
};

typedef struct
{
	char mbuf[ROLLING_WINDOW-1];
	char pad[8-ROLLING_WINDOW+1];
	int slice_num;
	unsigned int msize;

	struct zt_state_t p_state;		//partial strong hash value
	struct zt_state_t s_state; //strong hash state
	struct roll_state_t r_state;

	unsigned long long left_offset;
	unsigned long long right_offset;

	unsigned int * r_array;		//array to store  rolling hash value
	unsigned int r_cnt;
	unsigned int r_size;
	struct zt_state_t * s_array;		//array to store strong(Tillichi-Zemor) hash value
	unsigned int s_cnt;		//always point to the next available position
	unsigned int s_size;
}sfh_seg_t;


typedef struct
{
	unsigned long long orilen;
	IVI_t * ivi;  //每一个handle里面保存一个IVI指针，一个IVI里面保存的是一个文件里的片
	unsigned long long effective_length;
	unsigned long long blocksize;
	unsigned long long fuzzy_node_memory;
	unsigned long long IVI_memory;
	unsigned long long length_increase;
	int s_state_cnt;
	unsigned int sim_tuned_rs_cnt;//rolling state count after a tune simulation
	int do_tune;
}fuzzy_handle_inner_t;


typedef struct
{
	char * hash_b1;  //最后输出结果的char数组
	char * hash_b2;
	unsigned int size_b1,size_b2;
	unsigned int offset_b1,offset_b2;  //数组长度
	unsigned long long first_ZTH_offset;
	unsigned long long last_ZTH_offset;
	char last_char_b1, last_char_b2;
	unsigned long long b1,b2;
}sfh_output_t;


typedef struct
{
	unsigned long long first_ZTH_offset;
	unsigned long long last_ZTH_offset;
	unsigned long long hash_length;
}final_length;

int destroy_sfh_seg(sfh_seg_t*p);
unsigned long long get_blocksize(unsigned long long orilen);
int sfh_merge_seg(fuzzy_handle_inner_t * _handle,sfh_seg_t * seg, sfh_seg_t * next_seg, unsigned long long blocksize);	
int sfh_update_seg(fuzzy_handle_inner_t * _handle,sfh_seg_t * p, const char * data, unsigned long data_size, unsigned long long blocksize);
unsigned int segment_overlap(fuzzy_handle_inner_t * handle, unsigned int size, unsigned long long offset, const char * data);
void sfh_tune_callback(IVI_seg_t * seg, void * user_para);
void sfh_output_callback(IVI_seg_t * seg, void * user_para);
void fuzzy_hash_length(IVI_seg_t * seg, void * user_para);
#endif


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <sfh_internal.h>
#include "stream_fuzzy_hash.h"
#include "interval_index.h"
//#define	DEBUG_PRINT
#define INIT_SIZE 128
#define ENTROPY_THRESHOLD 0.5
#define MULTIPLE 4
int count = 0;
const char * map_to64bytes =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



double get_rs_entropy(unsigned int * r_array, unsigned int r_index);
int cmp(const void * a, const void * b);
void sfh_rs_entropy(IVI_seg_t * seg, void * user_para);
void sfh_output_state_t(IVI_seg_t * seg, void * user_para);
int write_uint_array(unsigned int ** array, unsigned int *index,unsigned int *size,unsigned int value);
/**
 * roll_state初始化
 */
static inline void  roll_init(struct roll_state_t * self)
{
	memset(self, 0, sizeof(struct roll_state_t));
}

/**
 * 计算roll_hash值，将外部数据读取到窗口中
 */
static inline  void roll_hash(struct roll_state_t * self, unsigned char c)
{
	self->h2 -= self->h1;
	self->h2 += ROLLING_WINDOW * (unsigned int)c;

	self->h1 += (unsigned int)c;
	self->h1 -= (unsigned int)self->window[self->n];

	self->window[self->n] = c;
	self->n++;
	if (self->n == ROLLING_WINDOW)
	{
			self->n = 0;
	}
	self->h3 <<= 5;
	self->h3 ^= c;
}

/**
 * 计算窗口里面的roll_hash值，每次roll_hash值满足一定条件，分片
 */
static  inline unsigned int roll_sum(const struct roll_state_t * self)
{
	return self->h1 + self->h2 + self->h3;
}

/**
 * 计算分片的FNV值
 */
static inline unsigned int sum_hash(unsigned char c, unsigned int h)
{
	return (h * HASH_PRIME) ^ c;
}

/**
 * 创建handle
 */
sfh_instance_t * SFH_instance(unsigned long long origin_len)
{
		fuzzy_handle_inner_t * handle = NULL;
		unsigned long long tmp_blksize = 0;
		tmp_blksize = get_blocksize(origin_len);
	
		if(tmp_blksize==0)
		{
			return NULL;
		}
		handle = (fuzzy_handle_inner_t *)calloc(1,sizeof(fuzzy_handle_inner_t));
		handle->fuzzy_node_memory = 0;
		handle->IVI_memory = 0;
		handle->fuzzy_node_memory += sizeof(fuzzy_handle_inner_t);
		handle->orilen = origin_len;
		handle->ivi = IVI_create();
		handle->effective_length = 0;
		handle->length_increase = 0;
		handle->sim_tuned_rs_cnt = 0;
		//handle->blocksize=tmp_blksize;
		handle->blocksize = 3;
		handle->do_tune=1;
		return (sfh_instance_t *)handle;
}


/**
 * IVI_destroy的回调函数，销毁IVI中的数据
 */
void fuzzy_node_free(IVI_seg_t * seg, void * usr_para)
{
	fuzzy_handle_inner_t * _handle = (fuzzy_handle_inner_t *)usr_para;
	sfh_seg_t * temp = (sfh_seg_t*)(seg->data);
	_handle->fuzzy_node_memory-=destroy_sfh_seg(temp);
	return;
}


void SFH_release(sfh_instance_t * handle)
{		
		IVI_destroy(((fuzzy_handle_inner_t *)handle)->ivi, fuzzy_node_free, (void *)handle);
		((fuzzy_handle_inner_t *)handle)->fuzzy_node_memory -= sizeof(fuzzy_handle_inner_t);
		free((fuzzy_handle_inner_t *)handle);
		return;
}
void sfh_tune_simulation(IVI_seg_t * seg, void * user_para)
{
	sfh_seg_t * tmp = (sfh_seg_t *)(seg->data);
	int i = 0;
	fuzzy_handle_inner_t * _handle = (fuzzy_handle_inner_t *)user_para;
	unsigned long long blocksize = _handle->blocksize * MULTIPLE;
	for(i = 0; i < tmp->r_cnt; i++)
	{
		if(tmp->r_array[i] % blocksize == blocksize -1)
		{
			_handle->sim_tuned_rs_cnt ++;
		}
	}
}
void sfh_tune_seg(sfh_seg_t * p, unsigned long long blocksize)
{
	int i = 0, j = 0;
	struct zt_state_t tmp_zt;
	int new_zt_cnt=0;
	zt_hash_initial(&tmp_zt);

	for(j = 0; j < p->r_cnt; j++)
	{
		if(j == 0)
		{
			zt_hash_arymul(&tmp_zt, &(p->p_state));
		}
		else
		{
			zt_hash_arymul(&tmp_zt, &(p->s_array[j - 1]));
		}
		if(p->r_array[j] % blocksize == blocksize - 1)
		{
			p->r_array[i]=p->r_array[j];
			i++;
			if(i>1)
			{
				p->s_array[new_zt_cnt].val=tmp_zt.val;
				new_zt_cnt++;
			}
			else
			{
				p->p_state.val=tmp_zt.val;
			}
			zt_hash_initial(&tmp_zt);
		}
	}
	zt_hash_arymul(&tmp_zt, &(p->s_state));
	if(i == 0)
	{
		zt_hash_initial(&(p->p_state));
	}
	p->s_state.val = tmp_zt.val;
	p->s_cnt = new_zt_cnt;
	p->r_cnt = i;
	assert(p->r_cnt>=p->s_cnt);
}
void sfh_tune_callback(IVI_seg_t * seg, void * user_para)
{
	sfh_seg_t * p = (sfh_seg_t *)(seg->data);
	if(p->r_cnt== 0)
	{
		return;
	}
	
	fuzzy_handle_inner_t * _handle = (fuzzy_handle_inner_t *)user_para;
	unsigned long long blocksize = _handle->blocksize;
	_handle->s_state_cnt-=p->s_cnt;
	sfh_tune_seg(p, blocksize);
	_handle->s_state_cnt+=p->s_cnt;
	//printf("after state_cnt:%d,block:%llu\n",_handle->s_state_cnt,_handle->blocksize);
}

void do_sfh_tune(sfh_instance_t * handle)
{
	fuzzy_handle_inner_t * _handle=(fuzzy_handle_inner_t *)handle;
	do{
		_handle->sim_tuned_rs_cnt = 0;
		IVI_traverse(_handle->ivi, sfh_tune_simulation, (void *)_handle);
		if(_handle->sim_tuned_rs_cnt>EXPECT_SIGNATURE_LEN)
		{
			_handle->blocksize*= MULTIPLE;
			IVI_traverse(_handle->ivi, sfh_tune_callback, (void *)_handle);		
		}
		else
		{
			break;
		}
		
	}while(_handle->s_state_cnt>EXPECT_SIGNATURE_LEN);
	return;
}
unsigned int SFH_feed(sfh_instance_t * handle, const char * data, unsigned int size, unsigned long long offset)
{
	fuzzy_handle_inner_t * _handle=(fuzzy_handle_inner_t *)handle;
	if(data == NULL || size == 0)
	{
		return 0;
	}
	unsigned int length = segment_overlap(_handle, size, offset, data);
	_handle->effective_length += length;
	_handle->length_increase += length;
	if(_handle->s_state_cnt>EXPECT_SIGNATURE_LEN&&_handle->do_tune==1)
	{
		unsigned long long check_length = (_handle->effective_length/_handle->s_state_cnt)*EXPECT_SIGNATURE_LEN;

		if(_handle->length_increase > check_length)
		{
			do_sfh_tune(handle);
			_handle->length_increase = 0;
		}
	}
#if 0
	SFH_digest(handle,result, sizeof(result));
	printf("%llu %s\n",offset,result);
#endif
	return length;
}





unsigned long long get_blocksize(unsigned long long orilen)
{
		double tmp = orilen/(64 * BLOCKSIZE_MIN);
		double index = floor(log(tmp)/log(2));
		double tmp_t = pow(2, index);
		unsigned long long blocksize = (unsigned long long)(tmp_t * BLOCKSIZE_MIN);
		if(blocksize == 0)
		{
			blocksize = BLOCKSIZE_MIN;
		}
		return blocksize;
//		return BLOCKSIZE_MIN;
}

sfh_seg_t* create_sfh_seg(fuzzy_handle_inner_t * _handle,unsigned long long offset)
{
	sfh_seg_t*p=(sfh_seg_t*)calloc(sizeof(sfh_seg_t),1);
	roll_init(&(p->r_state));
	p->s_size = INIT_SIZE;
	p->s_cnt=0;
	p->r_size = INIT_SIZE;
	p->r_cnt=0;
	p->left_offset=p->right_offset=offset;
	p->r_array = (unsigned int*)malloc(sizeof(unsigned int)*(p->r_size));
	_handle->fuzzy_node_memory+=sizeof(unsigned int)*(p->r_size);
	p->s_array = (struct zt_state_t*)malloc(sizeof(struct zt_state_t)*(p->s_size));
	_handle->fuzzy_node_memory+=sizeof(struct zt_state_t)*(p->s_size);
	zt_hash_initial(&(p->s_state));
	zt_hash_initial(&(p->p_state));
	_handle->fuzzy_node_memory += sizeof(sfh_seg_t);
	return p;
}
//return freed memory size
int destroy_sfh_seg(sfh_seg_t*p)
{
	int ret_size=0;
	if(p->s_array != NULL)
	{
		free(p->s_array);
		p->s_array=NULL;
		ret_size+=p->s_size*sizeof(struct zt_state_t);
	}
	if(p->r_array != NULL)
	{
		free(p->r_array);
		p->r_array=NULL;
		ret_size+=p->r_size*sizeof(unsigned int);
	}
	ret_size+=sizeof(sfh_seg_t);
	free(p);
	p=NULL;
	return ret_size;
}
/**
 * 判断数据是否与已经计算过的数据有覆盖
 */
unsigned int segment_overlap(fuzzy_handle_inner_t * _handle, unsigned int size, unsigned long long offset, const char * data)
{
	IVI_seg_t ** overlap_segs = NULL;
	IVI_seg_t *new_seg=NULL,*target_seg=NULL;
	sfh_seg_t* sfh_seg=NULL;
	int overlap_segnum = 0,i=0,co_seg_num=0,ret=0;
	unsigned int effective_length = 0;
	unsigned long long calc_begin=offset;
	unsigned long long calc_end=offset+size-1;
	
	//printf("size: %u\n",size);
	//printf("before query\n");
	/*查询是否有覆盖，如果有覆盖，返回覆盖的segment的片数，如果没有覆盖，返回0*/
	if(offset>0)
	{
		overlap_segnum = IVI_query(_handle->ivi, offset-1, offset + size, &overlap_segs);
	}
	else
	{
		overlap_segnum = IVI_query(_handle->ivi, 0, offset + size, &overlap_segs);
	}
	IVI_seg_t * co_overlap_segs[overlap_segnum+1];
	assert(overlap_segnum>=0);

	if(overlap_segnum==0||offset<overlap_segs[0]->left)
	{
		sfh_seg=create_sfh_seg(_handle,offset);
		calc_begin=offset;
		if(overlap_segnum == 0)
		{
			calc_end=offset+size-1;
		}
		else
		{
			calc_end=MIN(overlap_segs[0]->left-1,offset+size-1);
		}
		new_seg = IVI_seg_malloc(calc_begin, calc_end, (void *)sfh_seg);
		_handle->s_state_cnt+=sfh_update_seg(_handle, sfh_seg,data+calc_begin-offset, calc_end-calc_begin+1, _handle->blocksize);
		effective_length+=(calc_end-calc_begin+1);
		co_overlap_segs[co_seg_num]=new_seg;
		co_seg_num++;
	}
	for(i=0;i<overlap_segnum;i++,co_seg_num++)
	{
		co_overlap_segs[co_seg_num]=overlap_segs[i];
		ret=IVI_remove(_handle->ivi,overlap_segs[i]);
		_handle->IVI_memory = IVI_mem_occupy(_handle->ivi);
		assert(ret==0);
	}
	for(i=0;i<co_seg_num;i++)
	{
		calc_begin=MAX(co_overlap_segs[i]->right+1,calc_begin);
		if(i+1<co_seg_num)
		{
			calc_end=MIN(co_overlap_segs[i+1]->left-1,offset+size-1);
		}
		else
		{
			calc_end=offset+size-1;
		}
		if(!after(calc_begin,calc_end))
		{
			sfh_seg=(sfh_seg_t*)(co_overlap_segs[i]->data);
			_handle->s_state_cnt+=sfh_update_seg(_handle,sfh_seg,data+calc_begin-offset, calc_end-calc_begin+1, _handle->blocksize);
			effective_length+=(calc_end-calc_begin+1);
			co_overlap_segs[i]->right+=calc_end-calc_begin+1;
			calc_begin=calc_end+1;
		}
	}
	target_seg=co_overlap_segs[0];
	for(i=0;i<co_seg_num;i++)
	{
		if(i==0)
		{
			continue;
		}
#if 0
		if(((sfh_seg_t*)target_seg->data)->r_index>0&&((sfh_seg_t*)co_overlap_segs[i]->data)->r_index>0)
		{
			memset(&result_p,0,sizeof(result_p));
			result_p.data=rp_buff;
			result_p.size=sizeof(rp_buff);
			sfh_output_callback(target_seg,&result_p);
			memset(&result_n,0,sizeof(result_n));
			result_n.data=rn_buff;
			result_n.size=sizeof(rn_buff);	
			sfh_output_callback(co_overlap_segs[i],&result_n);
			printf("%s[%llu:%llu] %s[%llu:%llu]\n",rp_buff,target_seg->left,
													target_seg->right,
													rn_buff,co_overlap_segs[i]->left,
													co_overlap_segs[i]->right);
		}
#endif
		_handle->s_state_cnt+=sfh_merge_seg(_handle,(sfh_seg_t*)target_seg->data, (sfh_seg_t*)co_overlap_segs[i]->data, _handle->blocksize);
		target_seg->right=co_overlap_segs[i]->right;
		IVI_seg_free(co_overlap_segs[i], fuzzy_node_free, (void *)_handle);
	}
	//IVI_seg_t * insert_seg=NULL;
	//insert_seg = IVI_seg_malloc(target_seg->left, target_seg->right, target_seg->data);
	ret=IVI_insert(_handle->ivi,target_seg);
	_handle->IVI_memory = IVI_mem_occupy(_handle->ivi);
	assert(ret==0);
	free(overlap_segs);
	return effective_length;
}

int cmp(const void * a, const void * b)
{
	unsigned int tmp_a = *(unsigned int *)a;
	unsigned int tmp_b = *(unsigned int *)b;
	if(before(tmp_a, tmp_b))
	{
		return -1;
	}
	else if(after(tmp_a, tmp_b))
	{
		return 1;
	}	
	else
	{
		return 0;
	}
}

double get_rs_entropy(unsigned int * r_array, unsigned int r_index)
{
	qsort(r_array, r_index, sizeof(unsigned int), cmp);
	unsigned int current_r = r_array[0];
	unsigned int * tmp_r = r_array;
	unsigned int count = 0;
	double sum  = 0;
	int i = 0;
	for(i = 0; i <= r_index; i++)
	{
		if(i == r_index || *tmp_r != current_r)
		{
			double p = (double)count/r_index;
			//printf("count : %d\n",count);
			//printf("r_index: %u\n",r_index);
			//printf("p:%f\n",p);
			if(p != 0)
			{
				sum += p * (log(p)/log(2));
			}
			current_r = *tmp_r;
			count = 0;
		}
		else	
		{
			count++;
		}
		if(i < r_index)
		{
			tmp_r ++;
		}
	}
	return (-sum);

}




int write_uint_array(unsigned int ** array,unsigned int *index, unsigned int *size,unsigned int value)
{
	int mem_size=0;
	if(*index==*size)
	{
		(*size)*=2;
		mem_size+=*size;
		*array=(unsigned int*)realloc(*array,sizeof(unsigned int)*(*size));
	}
	(*array)[*index]=value;
	(*index)++;
	return mem_size;
}

int sfh_update_seg(fuzzy_handle_inner_t * _handle, sfh_seg_t * p, const char * data, unsigned long data_size,unsigned long long blocksize)
{
	unsigned long i = 0;
	unsigned int roll_hash_value = 0;
	int state_inc_cnt=0;
	if(p->msize < ROLLING_WINDOW - 1)
	{
		for(i = 0; i < ROLLING_WINDOW - p->msize && i < data_size; i++)
		{
			p->mbuf[p->msize + i] = data[i];
			roll_hash(&(p->r_state), data[i]);
		}
		p->msize += i;
	}
	for(; i < data_size; i++)
	{
		roll_hash(&(p->r_state), data[i]);
		roll_hash_value = roll_sum(&(p->r_state));			    		
		
		zt_hash(&(p->s_state),data[i]);        
		if((roll_hash_value % (blocksize)) == blocksize - 1)
		{
			p->slice_num ++;
			if(p->r_cnt==0)
			{
				p->p_state.val=p->s_state.val;
			}
			else
			{
#ifdef	DEBUG_PRINT
				printf("p->s_cnt:%u\n",p->s_cnt);
				printf("p->s_size:%u\n",p->s_size);
#endif
				_handle->fuzzy_node_memory+=write_uint_array((unsigned int**)(&(p->s_array)), &(p->s_cnt),&(p->s_size),p->s_state.val);
				state_inc_cnt++;
			}
#ifdef DEBUG_PRINT			
			printf("p->r_cnt:%u\n",p->s_cnt);
			printf("p->r_size:%u\n",p->s_size);
#endif	
			_handle->fuzzy_node_memory+=write_uint_array(&(p->r_array),&(p->r_cnt),&(p->r_size),roll_hash_value); 
			zt_hash_initial(&(p->s_state));	
		}
	}
	assert(p->r_cnt>=p->s_cnt);
	p->right_offset+=data_size;
	return state_inc_cnt;		
}

int sfh_merge_seg(fuzzy_handle_inner_t * _handle, sfh_seg_t * p, sfh_seg_t * n,unsigned long long blocksize)	
{

	unsigned int roll_hash_value = 0;
	int i = 0,state_inc_cnt=0;
	struct roll_state_t * rs = &(p->r_state);
	for(i = 0; i < n->msize; i++)
	{
		roll_hash(rs, n->mbuf[i]);
		roll_hash_value = roll_sum(rs);
		zt_hash(&(p->s_state), n->mbuf[i]);
		if(roll_hash_value % blocksize == blocksize - 1)
		{
			p->slice_num ++;
			if(p->r_cnt == 0)
			{
				p->p_state.val = p->s_state.val;
			}
			else
			{
				_handle->fuzzy_node_memory+=write_uint_array((unsigned int **)(&(p->s_array)), &(p->s_cnt), &(p->s_size), p->s_state.val);
				state_inc_cnt++;
			}
			_handle->fuzzy_node_memory+=write_uint_array(&(p->r_array),&(p->r_cnt), &(p->r_size), roll_hash_value);
			zt_hash_initial(&(p->s_state));
		}
	}
	if(n->r_cnt==0)
	{
		zt_hash_arymul(&(p->s_state),&(n->p_state));
		zt_hash_arymul(&(p->s_state), &(n->s_state));
	}
	else
	{
		if(p->r_cnt==0)
		{
			zt_hash_arymul(&(p->s_state),&(n->p_state));
			p->p_state.val=p->s_state.val;
		}
		else
		{
			zt_hash_arymul(&(p->s_state), &(n->p_state));
			_handle->fuzzy_node_memory+=write_uint_array((unsigned int **)(&(p->s_array)), &(p->s_cnt), &(p->s_size), p->s_state.val);
			state_inc_cnt++;
		}
		p->s_state.val=n->s_state.val;
	}
	for(i=0;i<n->r_cnt;i++)
	{
		_handle->fuzzy_node_memory+=write_uint_array(&(p->r_array),&(p->r_cnt), &(p->r_size), n->r_array[i]);
	}
	for(i=0;i<n->s_cnt;i++)
	{
		_handle->fuzzy_node_memory+=write_uint_array((unsigned int **)(&(p->s_array)), &(p->s_cnt), &(p->s_size), n->s_array[i].val);
	}
	memcpy(&(p->r_state),&(n->r_state),sizeof(p->r_state));	
	assert(p->r_cnt>=p->s_cnt);
	p->right_offset=n->right_offset;
	return state_inc_cnt;		
}

/**
 * 取出区间链表里面的hash_result值，并进行拼接，形成最后的result输出，并且满足abc[1:100]def[200:300]这种格式
 */
int SFH_digest(sfh_instance_t * handle, char * hash_buffer, unsigned int size)
{
	fuzzy_handle_inner_t* _handle=(fuzzy_handle_inner_t *)handle;
	unsigned int estimate_len=_handle->s_state_cnt+IVI_seg_cnt(_handle->ivi)*24+1;
	int actual_len=0;
	char* p=NULL;
	sfh_output_t result;
	memset(&result,0,sizeof(result));
	result.size_b1 = estimate_len;
	result.size_b2 = estimate_len;
	result.hash_b1 = (char*)calloc(sizeof(char),estimate_len);
	result.hash_b2 = (char*)calloc(sizeof(char),estimate_len);
	result.offset_b1 = 0;
	result.offset_b2 = 0;
	result.b1=_handle->blocksize;
	result.b2=_handle->blocksize*MULTIPLE;
	
	IVI_traverse(_handle->ivi, sfh_output_callback, (void *) &result);

	if(result.offset_b1==0||result.offset_b2==0)
	{
		hash_buffer[0]='\0';
		goto fast_out;
	}
	if(result.last_char_b1!='\0')
	{
		p =strrchr(result.hash_b1,'[');
		assert(p!=NULL);
		memmove(p+1,p,strlen(p));
		*p=result.last_char_b1;
	}
	if(result.last_char_b2!='\0')
	{
		p =strrchr(result.hash_b2,'[');
		assert(p!=NULL);
		memmove(p+1,p,strlen(p));
		*p=result.last_char_b2;
	}
	actual_len=snprintf(hash_buffer,size,"%llu:%s#%llu:%s",result.b1,result.hash_b1,
															result.b2,result.hash_b2);
fast_out:
	free(result.hash_b1);
	result.hash_b1=NULL;
	free(result.hash_b2);
	result.hash_b2=NULL;
	return actual_len;
}
sfh_seg_t* sfh_clone_seg(sfh_seg_t* origin)
{
	sfh_seg_t* clone=NULL;
	clone=(sfh_seg_t*)calloc(sizeof(sfh_seg_t),1);
	memcpy(clone,origin,sizeof(sfh_seg_t));
	clone->s_array=calloc(sizeof(struct zt_state_t),clone->s_size);
	memcpy(clone->s_array,origin->s_array,sizeof(struct zt_state_t)*clone->s_size);
	clone->r_array=calloc(sizeof(unsigned int),clone->r_size);
	memcpy(clone->r_array,origin->r_array,sizeof(unsigned int)*clone->r_size);
	return clone;
}
int sfh_print_seg(sfh_seg_t* p, char* hash_result, int size,char* last_char)
{
	int idx=0,i=0;
	if(p->left_offset== 0)
	{
		hash_result[idx] = map_to64bytes[zt_hash_code(&(p->p_state)) & 0x3F];
		idx++;
	}
	for(i = 0; i < p->s_cnt&&idx<size; i++,idx++)
	{
		hash_result[idx] = map_to64bytes[(p->s_array[i].val) & 0x3F];
	}
	if(p->s_state.val!=*((unsigned int*)ZT_INIT_VAL))
	{
		*last_char=map_to64bytes[zt_hash_code(&(p->s_state)) & 0x3F];
	}
	else
	{
		*last_char='\0';
	}
	// p->right_offset-1 to get a closed interval
	idx+=snprintf(hash_result+idx,size-idx,"[%llu:%llu]",p->left_offset, p->right_offset-1);
	assert(idx<size);
	return idx;
}
void sfh_output_callback(IVI_seg_t * seg, void * user_para)
{
	sfh_output_t * result = (sfh_output_t *)user_para;
	sfh_seg_t* node = (sfh_seg_t *)(seg->data);
	sfh_seg_t* tmp;
	if(node->s_cnt==0&&!(seg->left==0&&node->s_cnt > 0))
	{
		return;
	}
	result->offset_b1+=sfh_print_seg(node,result->hash_b1+result->offset_b1,result->size_b1-result->offset_b1,&(result->last_char_b1));
	tmp=sfh_clone_seg(node);
	sfh_tune_seg(tmp, result->b2);
	result->offset_b2+=sfh_print_seg(tmp,result->hash_b2+result->offset_b2,result->size_b2-result->offset_b2,&(result->last_char_b2));
	destroy_sfh_seg(tmp);
	tmp=NULL;
	return;
}

/**
 * 计算fuzzy_hash的各种长度
 */
unsigned long long SFH_status(sfh_instance_t * handle, int type)
{
	unsigned long long length;
	fuzzy_handle_inner_t * _handle = (fuzzy_handle_inner_t *)(handle);
	final_length tmp_length;
	char buffer[64];
	switch(type)
	{
		case TOTAL_LENGTH: //已经计算过hash值的全部长度
			 length = IVI_seg_length(_handle->ivi);
			 break;
		case EFFECTIVE_LENGTH:  //包含在计算hash值里面的有效长度
				length = _handle->effective_length;
				break;
		case HASH_LENGTH:   //最后输出哈希结果的长度
				tmp_length.hash_length = 0;
				tmp_length.first_ZTH_offset = 0;
				tmp_length.last_ZTH_offset = 0;
				tmp_length.hash_length+=snprintf(buffer,sizeof(buffer),"%llu:",_handle->blocksize);
				IVI_traverse(_handle->ivi, fuzzy_hash_length, (void *)&tmp_length);
				length = tmp_length.hash_length + 1;
				break;
		case MEMORY_OCCUPY:
				length = _handle->fuzzy_node_memory + _handle->IVI_memory;
				break;
		default:
				return 0;
	}
	return length;
}

void fuzzy_hash_length(IVI_seg_t * seg, void * user_para)
{
	char buffer[100];
	final_length * tmp = (final_length *)user_para;
	sfh_seg_t * node = (sfh_seg_t *)(seg->data);
	if(node->s_cnt==0&&!(seg->left==0&&node->r_cnt > 0))
	{
		return;
	}
	snprintf(buffer, sizeof(buffer), "[%llu:%llu]", seg->left, seg->right);
	tmp->hash_length += 2*node->r_cnt*sizeof(char) + 2*strlen(buffer);
	return;
}



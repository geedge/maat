#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "mesa_fuzzy.h"
#include "interval_index.h"


#define ROLLING_WINDOW 7
#define BLOCKSIZE_MIN 3
#define MAXSIZE 10000
#define HASH_PRIME 0x01000193
#define HASH_INIT 0x28021967

#define DEBUG (0)

struct roll_state
{
    unsigned char window[ROLLING_WINDOW];
    unsigned int h1, h2, h3;
    unsigned int  n;
};


typedef struct
{
    char * left_data; //指向数据的头指针
    unsigned int left_len; //左边保留数据的长度

    char * hash_result; //这个segment的FNV值
    unsigned long long left_offset;
    unsigned long long right_offset;

    struct roll_state * right_status_r; //右边界的rollhash状态
    unsigned int right_status_shash; //右边界的FNV值
    unsigned int right_len;//右边界的长度
    int slice_num;

}fuzzy_node;


typedef struct
{
	unsigned long long orilen;
	IVI_t * ivi;  //每一个handle里面保存一个IVI指针，一个IVI里面保存的是一个文件里的片
	unsigned long long effective_length;
	unsigned long long blocksize;
}fuzzy_handle_inner_t;


typedef struct
{
    char * head;  //最后输出结果的char数组
    unsigned int size;
    unsigned int offset;  //数组长度
    unsigned long long first_FNV_offset;
    unsigned long long last_FNV_offset;
}final_result;


typedef struct
{
   unsigned long long first_FNV_offset;
   unsigned long long last_FNV_offset;
   unsigned long long hash_length;
}final_length;


unsigned int fuzzy_hash_calculate(IVI_seg_t * seg, const char * data, unsigned long long offset, unsigned long long blocksize);
void fuzzy_calculate_self(IVI_seg_t * seg, const char * data, unsigned long long offset, unsigned long long blocksize);
void fuzzy_calculate_self_with_prev(IVI_seg_t * prev_seg, IVI_seg_t * seg, const char * data, unsigned long long blocksize);
void fuzzy_modify_next(IVI_seg_t * seg, IVI_seg_t * next_seg, unsigned long long blocksize);
unsigned long long get_prev_continous_length(IVI_seg_t * seg);
unsigned int segment_overlap(fuzzy_handle_t * handle, fuzzy_node * fnode, unsigned int size, unsigned long long offset, const char * data);
void fuzzy_hash_merge(IVI_seg_t * seg, void * user_para);
void fuzzy_hash_merge_new(IVI_seg_t * seg, void * user_para);
void fuzzy_hash_length(IVI_seg_t * seg, void * user_para);
unsigned long long fuzzy_status(fuzzy_handle_t * handle, int type);
unsigned long long get_blocksize(unsigned long long orilen);

char * b64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/**
 * roll_state初始化
 */
static void roll_init(struct roll_state * self)
{
    memset(self, 0, sizeof(struct roll_state));
}


/**
 * 计算roll_hash值，将外部数据读取到窗口中
 */
static void roll_hash(struct roll_state * self, unsigned char c)
{
    self->h2 -= self->h1;
    self->h2 += ROLLING_WINDOW * (unsigned int)c;

    self->h1 += (unsigned int)c;
    self->h1 -= (unsigned int)self->window[self->n];

    self->window[self->n] = c;
    self->n++;
    if (self->n == ROLLING_WINDOW)
        self->n = 0;
    self->h3 <<= 5;
    self->h3 ^= c;
}


/**
 * 计算窗口里面的roll_hash值，每次roll_hash值满足一定条件，分片
 */
static unsigned int roll_sum(const struct roll_state * self)
{
    return self->h1 + self->h2 + self->h3;
    /* return self->h1 + self->h2; */
}


/**
 * 计算分片的FNV值
 */
static unsigned int sum_hash(unsigned char c, unsigned int h)
{
    return (h * HASH_PRIME) ^ c;
}


/**
 * 创建handle
 */
fuzzy_handle_t * fuzzy_create_handle(unsigned long long origin_len)
{
	fuzzy_handle_inner_t * handle = NULL;
	unsigned long long tmp_blksize=get_blocksize(origin_len);
	if(tmp_blksize==0)
	{
		return NULL;
	}
	handle = (fuzzy_handle_inner_t *)malloc(sizeof(fuzzy_handle_inner_t));
	handle->orilen = origin_len;
	handle->ivi = IVI_create();
	handle->effective_length = 0;
	handle->blocksize=tmp_blksize;
	return (fuzzy_handle_t *)handle;
}


/**
 * IVI_destroy的回调函数，销毁IVI中的数据
 */
void fuzzy_node_free(IVI_seg_t * seg, void * usr_para)
{
	//printf("free seg[%lu, %lu]\n", seg->left, seg->right);
    fuzzy_node * temp = (fuzzy_node*)(seg->data);
    if(temp->left_data != NULL)
    {
        free(temp->left_data);
        temp->left_data = NULL;
    }
    if(temp->hash_result != NULL)
    {
        free(temp->hash_result);
        temp->hash_result = NULL;
    }
    free(temp->right_status_r);
    temp->right_status_r = NULL;
    free(temp);
    temp = NULL;
    return;
}



/**
 * 销毁handle
 */
void fuzzy_destroy_handle(fuzzy_handle_t * handle)
{
    IVI_destroy(((fuzzy_handle_inner_t *)handle)->ivi, fuzzy_node_free, NULL);
    free((fuzzy_handle_inner_t *)handle);
    return;
}


/**
 * 输入数据，并且计算数据的fuzzy_hash值
 */
unsigned int fuzzy_feed(fuzzy_handle_t * handle, const char * data, unsigned int size, unsigned long long offset)
{
	if(data == NULL || size == 0)
	{
		return 0;
	}
    fuzzy_node * node = (fuzzy_node *)calloc(sizeof(fuzzy_node), 1);
    node->right_status_r = (struct roll_state *)calloc(sizeof (struct roll_state), 1);
    roll_init(node->right_status_r);
    node->slice_num = 0;
    unsigned int length = segment_overlap(handle, node, size, offset, data);
	if(offset == 0)
	{
    	((fuzzy_handle_inner_t *)handle)->effective_length += size - node->right_len;
		return (size - node->right_len);
	}
	else
	{
    	((fuzzy_handle_inner_t *)handle)->effective_length += length;
	}
    return length; //返回已经计算的有效长度
}



unsigned long long get_blocksize(unsigned long long orilen)
{
	double tmp = orilen/(64 * BLOCKSIZE_MIN);
	double index = floor(log(tmp)/log(2));
	double tmp_t = pow(2, index);
	unsigned long long blocksize = (unsigned long long)(tmp_t * BLOCKSIZE_MIN);
	return blocksize;
}

/**
 * 判断数据是否与已经计算过的数据有覆盖
 */
unsigned int segment_overlap(fuzzy_handle_t * handle, fuzzy_node * fnode, unsigned int size, unsigned long long offset, const char * data)
{
	IVI_seg_t ** overlap_segs = NULL;
	IVI_seg_t * seg = IVI_seg_malloc(offset, offset + size -1, (void *)fnode);
	int overlap_segnum = 0;
	unsigned int effective_length = 0;
	unsigned int total_length = 0;
	unsigned long long blocksize = ((fuzzy_handle_inner_t *)handle)->blocksize;

    /*查询是否有覆盖，如果有覆盖，返回覆盖的segment的片数，如果没有覆盖，返回0*/
    overlap_segnum = IVI_query(((fuzzy_handle_inner_t *)handle)->ivi, offset, offset + size - 1, &overlap_segs);

    /*如果返回值为负数，说明输入的参数有问题，打印错误信息*/
    if(overlap_segnum < 0)
    {
        printf("fragment info error!\n");
        IVI_seg_free(seg, fuzzy_node_free, NULL);
        return 0;
    }

    /*如果返回值为0，说明没有覆盖的情况，直接插入就行*/
    if(overlap_segnum == 0)
    {
        IVI_insert(((fuzzy_handle_inner_t *)handle)->ivi,seg);
        effective_length = fuzzy_hash_calculate(seg, data, offset, blocksize);

        total_length = seg->right - seg->left + 1;
        return effective_length;
    }

    /*如果返回值为覆盖的片数，则需要根据覆盖类型一一进行处理*/
    int flag = 0;
    int i;
    for(i = 0; i < overlap_segnum; i++)
    {
        switch(IVI_relative_position(seg, overlap_segs[i]))
        {
            case LEFT_OVERLAP:  //左覆盖，把seg的右值改为overlap_seg的左值
            {
                seg->right = overlap_segs[i]->left - 1;
                break;
            }
            case CONTAIN:  //包含关系，将左边那部分直接插入，然后改变seg的左值，并将data移动到指定的位置
            {
                if(overlap_segs[i]->left >= 1 && overlap_segs[i]->left - 1 >= seg->left)
                {
                    fuzzy_node * node = (fuzzy_node *)calloc(sizeof(fuzzy_node), 1);
                    memcpy(node, fnode, sizeof(fuzzy_node));
    				node->right_status_r = (struct roll_state *)calloc(sizeof (struct roll_state), 1);
    				roll_init(node->right_status_r);
                    IVI_seg_t * thseg = IVI_seg_malloc(seg->left, overlap_segs[i]->left - 1, (void *)node);
                    IVI_insert(((fuzzy_handle_inner_t *)handle)->ivi,thseg);
                    effective_length += fuzzy_hash_calculate(thseg, data, offset, blocksize);
                    total_length += thseg->right - thseg->left + 1;
                }
                seg->left = overlap_segs[i]->right + 1;
                data = data + ((seg->left) - offset);
                offset = seg->left;
                break;
            }
            case RIGHT_OVERLAP:  //右覆盖，把seg的左值改为overlap_seg的右值
            {
                seg->left = overlap_segs[i]->right + 1;
                data = data + ((seg->left) - offset);
                offset = seg->left;
                break;
            }
            case CONTAINED: //如果被包含，就直接舍弃掉这片
            {
                flag = 1;
                //printf("contained! free seg\n");
                IVI_seg_free(seg, fuzzy_node_free, NULL);
                free(overlap_segs);
                break;
            }
            default:
                break;
        }
        if(flag == 1)
        {
            return 0;
        }

    }

    /*将余下的数据插入到区间链表里面，并且进行计算*/
    if(seg->left <= seg->right)
    {
        IVI_insert(((fuzzy_handle_inner_t *)handle)->ivi, seg);
        effective_length += fuzzy_hash_calculate(seg, data, offset, blocksize);
        total_length += seg->right - seg->left + 1;
        //((fuzzy_handle_inner_t *)handle)->effective_length += effective_length;
    }
    else
    {
        IVI_seg_free(seg, fuzzy_node_free, NULL);
    }

    free(overlap_segs);
    return effective_length;
}


/**
 * 处理前后分片，计算fuzzy_hash值
 */
unsigned int fuzzy_hash_calculate(IVI_seg_t * seg, const char * data, unsigned long long offset, unsigned long long blocksize)
{
    IVI_seg_t * prev_seg;
    IVI_seg_t * next_seg;
    unsigned int effective_length = 0;

    prev_seg = IVI_prev_continuous_seg(seg);
    next_seg = IVI_next_continuous_seg(seg);
    //printf("seg->right = %lu, seg->left = %lu\n", seg->right, seg->left);
    unsigned int size = seg->right - seg->left + 1;
    fuzzy_node * node = (fuzzy_node *)(seg->data);
    if(NULL == prev_seg)
    {
        //如果不存在前分片，直接初始化roll_state进行计算
        roll_init(node->right_status_r);
        fuzzy_calculate_self(seg, data, offset, blocksize);
		effective_length = size - node->left_len;
        node->left_offset = offset + node->left_len;
    }
    else
    {
        //如果存在前分片，取出前分片的右边界的中间状态值进行计算

        fuzzy_calculate_self_with_prev(prev_seg, seg, data, blocksize);
        effective_length = size + ((fuzzy_node *)(prev_seg->data))->right_len;
        node->left_offset = offset - ((fuzzy_node *)(prev_seg->data))->right_len;
    }

    /* 如果有后分片,并且自己计算的结果里需要分片,则修改后面的分片 */
    if(next_seg != NULL)
    {
        //如果存在后分片，将本分片的右边界的中间状态值取出来和后分片的左边界的中间状态进行计算
        fuzzy_modify_next(seg, next_seg, blocksize);

        effective_length += ((fuzzy_node *)(next_seg->data))->left_len;
        node->right_offset = offset + size + ((fuzzy_node *)(next_seg->data))->left_len;

    }
    else
    {
        effective_length -= node->right_len;
        node->right_offset = offset + (size - (node->right_len));
    }
    return effective_length;
}



void fuzzy_calculate_self(IVI_seg_t * seg, const char * data, unsigned long long offset, unsigned long long blocksize)
{
    fuzzy_node * node = (fuzzy_node *)(seg->data);
    struct roll_state * rs = node->right_status_r;
    unsigned long long size = seg->right - seg->left + 1;
    unsigned int FNV_hash_value = HASH_INIT;

    char * FNV_hash = (char *)malloc(sizeof(char)*size);
    unsigned long long fnv_index = 0, i=0, last_slice_index=0;
    unsigned int roll_hash_value;
    for(i = 0; i < size; i++)
    {
        roll_hash(rs, data[i]);
        roll_hash_value = roll_sum(rs);
        FNV_hash_value = sum_hash(data[i], FNV_hash_value);
        if(i >= ROLLING_WINDOW - 1 && roll_hash_value % blocksize == blocksize - 1)
        {
            node->slice_num ++;

            if(node->slice_num == 1)
            {
                node->left_len = i + 1;
            }
            last_slice_index = i;
            /* 保存FNV的值 */
            FNV_hash[fnv_index ++] = b64[FNV_hash_value % 64];
            //printf("data[%lu]=%c, FNV_hash = %c\n", i, data[i], b64[FNV_hash_value % 64]);
            FNV_hash_value = HASH_INIT;
        }
    }

    /* 一片都没有找到 */
    if(node->slice_num == 0)
    {
        node->left_len = size;
        node->right_len = 0;
    }
    else
    {
        node->right_len = size - last_slice_index - 1;
    }
    node->right_status_shash = FNV_hash_value;

    /* 复制结果到hash_result里 */
    node->hash_result = (char *)malloc(sizeof(char) * (fnv_index + 1));
    memcpy(node->hash_result, FNV_hash, fnv_index);
    (node->hash_result)[fnv_index] = '\0';

    node->left_data = (char *)malloc(sizeof(char) * (node->left_len));
    memcpy(node->left_data, data, node->left_len);

	free(FNV_hash);
    return;
}


unsigned long long get_prev_continous_length(IVI_seg_t * seg)
{
    unsigned long long length = 0;
    IVI_seg_t * temp = seg;
    while(temp != NULL)
    {
        length += temp->right - temp->left + 1;
        if(length >= ROLLING_WINDOW)
            return length;
        temp = IVI_prev_continuous_seg(temp);
    }
    return length;
}

/**
 * 处理前段的保留数据
 */
void fuzzy_calculate_self_with_prev(IVI_seg_t * prev_seg, IVI_seg_t * seg, const char * data, unsigned long long blocksize)
{
    fuzzy_node * prev_node = (fuzzy_node *)(prev_seg->data);
    fuzzy_node * node = (fuzzy_node *)(seg->data);

    /* 使用前段的roll state */
    memcpy(node->right_status_r, prev_node->right_status_r, sizeof(struct roll_state));
    struct roll_state * rs = node->right_status_r;
    unsigned long long size = seg->right - seg->left + 1;
    unsigned int FNV_hash_value = prev_node->right_status_shash;


    char * FNV_hash = (char *)malloc(sizeof(char)*size);
    unsigned long long fnv_index = 0, i=0, last_slice_index=0;
    unsigned int roll_hash_value;
    unsigned long long prev_len = get_prev_continous_length(prev_seg);

    for(i = 0; i < size; i++)
    {
        roll_hash(rs, data[i]);
        roll_hash_value = roll_sum(rs);
        FNV_hash_value = sum_hash(data[i], FNV_hash_value);
        if(i + prev_len >= ROLLING_WINDOW \
                && roll_hash_value % blocksize == blocksize - 1)
        {
            node->slice_num ++;
            if(node->slice_num == 1)
            {
                node->left_len = i + 1;
            }

            last_slice_index = i;
            /* 保存FNV的值 */
            FNV_hash[fnv_index ++] = b64[FNV_hash_value % 64];
            //printf("data[%lu]=%c, FNV_hash = %c\n", i, data[i], b64[FNV_hash_value % 64]);
            FNV_hash_value = HASH_INIT;
        }
    }

    /* 一片都没有找到 */
    if(node->slice_num == 0)
    {
        node->left_len = size;
        node->right_len = 0;
    }
    else
    {
        node->right_len = size - last_slice_index - 1;
    }
    node->right_status_shash = FNV_hash_value;

    /* 复制结果到hash_result里 */
    node->hash_result = (char *)malloc(sizeof(char) * (fnv_index + 1));
    memcpy(node->hash_result, FNV_hash, fnv_index);
    (node->hash_result)[fnv_index] = '\0';

    node->left_data = (char *)malloc(sizeof(char) * (node->left_len));
    memcpy(node->left_data, data, node->left_len);

	free(FNV_hash);
}



void fuzzy_modify_self_with_prev(IVI_seg_t * prev_seg, IVI_seg_t * seg, char * data, unsigned long long blocksize)
{
    fuzzy_node * prev_node = (fuzzy_node *)(prev_seg->data);
    fuzzy_node * node = (fuzzy_node *)(seg->data);

    /* 使用前段的roll state */
    memcpy(node->right_status_r, prev_node->right_status_r, sizeof(struct roll_state));
    struct roll_state * rs = node->right_status_r;
    unsigned long long size = seg->right - seg->left + 1;
    unsigned int FNV_hash_value = prev_node->right_status_shash;


    char * FNV_hash = (char *)malloc(sizeof(char)*size);
    unsigned long long fnv_index = 0, i=0, last_slice_index=0;
    unsigned int roll_hash_value;
    unsigned long long prev_len = get_prev_continous_length(prev_seg);
    for(i = 0; i < size; i++)
    {
        roll_hash(rs, data[i]);
        roll_hash_value = roll_sum(rs);
        FNV_hash_value = sum_hash(data[i], FNV_hash_value);
        if(i + prev_len >= ROLLING_WINDOW \
                && roll_hash_value % blocksize == blocksize- 1)
        {
            node->slice_num ++;
            if(node->slice_num == 1)
            {
                node->left_len = i + 1;
            }

            last_slice_index = i;
            /* 保存FNV的值 */
            FNV_hash[fnv_index ++] = b64[FNV_hash_value % 64];
            //printf("data[%lu]=%c, FNV_hash = %c\n", i, data[i], b64[FNV_hash_value % 64]);
            FNV_hash_value = HASH_INIT;
        }
    }

    /* 一片都没有找到 */
    if(node->slice_num == 0)
    {
        node->left_len = size;
        node->right_len = 0;
    }
    else
    {
        node->right_len = size - last_slice_index - 1;
    }
    node->right_status_shash = FNV_hash_value;

    /* 复制结果到hash_result里 */
    free(node->hash_result);
    node->hash_result = (char *)malloc(sizeof(char) * (fnv_index + 1));
    memcpy(node->hash_result, FNV_hash, fnv_index);
    (node->hash_result)[fnv_index] = '\0';

    //printf("old node->left_data = %s\n", node->left_data);
    free(node->left_data);
    node->left_data = (char *)malloc(sizeof(char) * (node->left_len));
    memcpy(node->left_data, data, node->left_len);
    //printf("new node->left_data = %s\n", node->left_data);
    free(FNV_hash);
}



/**
 * 处理后段的保留数据
 */
void fuzzy_modify_next(IVI_seg_t * seg, IVI_seg_t * next_seg, unsigned long long blocksize)
{
    IVI_seg_t * tmp_curr_seg = seg;
    IVI_seg_t * tmp_next_seg = next_seg;
    while(tmp_next_seg != NULL)
    {
        fuzzy_node * tmp_next_node = (fuzzy_node *)(tmp_next_seg->data);
        if(tmp_next_node->slice_num != 0)
        {
            break;
        }

        /* 下一段没有分片, 则重新计算 */
		
		char * data = (char *)malloc(sizeof(char) * (tmp_next_node->left_len));
		memcpy(data, tmp_next_node->left_data, tmp_next_node->left_len);
        fuzzy_modify_self_with_prev(tmp_curr_seg, tmp_next_seg, data, blocksize);
		free(data);
        
        tmp_curr_seg = tmp_next_seg;
        tmp_next_seg = IVI_next_continuous_seg(tmp_next_seg);
    }

    unsigned long long prev_len = get_prev_continous_length(tmp_curr_seg);
    /* tmp_next_seg中是有分片的 */
    if(tmp_next_seg != NULL)
    {
        fuzzy_node * tmp_curr_node = (fuzzy_node *)(tmp_curr_seg->data);
        fuzzy_node * tmp_next_node = (fuzzy_node *)(tmp_next_seg->data);

        unsigned long long size = tmp_next_node->left_len;
		
    	char * FNV_hash = (char *)malloc(sizeof(char)*size);
        unsigned long long fnv_index = 0, i;
        unsigned int roll_hash_value;

        struct roll_state rs;
        memcpy(&rs, tmp_curr_node->right_status_r, sizeof(struct roll_state));
        char * data = tmp_next_node->left_data;
        unsigned int FNV_hash_value = tmp_curr_node->right_status_shash;
        for(i = 0; i < size; i++)
        {
            roll_hash(&rs, data[i]);
            roll_hash_value = roll_sum(&rs);
            FNV_hash_value = sum_hash(data[i], FNV_hash_value);

            if((i + prev_len >= ROLLING_WINDOW) \
                    && roll_hash_value % blocksize == blocksize - 1)
            {
                tmp_next_node->slice_num ++;
                FNV_hash[fnv_index ++] = b64[FNV_hash_value % 64];
                //printf("data[%lu]=%c, FNV_hash = %c\n", i, data[i], b64[FNV_hash_value % 64]);
                FNV_hash_value = HASH_INIT;

                if(fnv_index == 1)
                {
                    tmp_next_node->left_len = i + 1;
                }
            }
        }

        tmp_next_node->slice_num --;


        /* 复制结果到hash_result里 */
        unsigned long long old_len = strlen(tmp_next_node->hash_result);
        if(old_len == 1)
        {
            free(tmp_next_node->hash_result);
            tmp_next_node->hash_result = (char *)malloc(sizeof(char) * (fnv_index + 1));
            memcpy(tmp_next_node->hash_result, FNV_hash, fnv_index);
            (tmp_next_node->hash_result)[fnv_index] = '\0';
        }
        else
        {
            unsigned long long new_len = old_len - 1 + fnv_index;
            char tmp[old_len - 1];
            char * old_hash = (tmp_next_node->hash_result) + 1;
            memcpy(tmp, old_hash, old_len - 1);
            free(tmp_next_node->hash_result);
            tmp_next_node->hash_result = (char *)malloc(sizeof(char) * (new_len + 1));
            memset(tmp_next_node->hash_result, '\0', (new_len + 1));
            memcpy(tmp_next_node->hash_result, FNV_hash, fnv_index);
            strncat(tmp_next_node->hash_result, tmp, old_len - 1);
            (tmp_next_node->hash_result)[new_len] = '\0';
        }
		free(FNV_hash);
    }
    return;
}



/**
 * 取出区间链表里面的hash_result值，并进行拼接，形成最后的result输出，并且满足abc[1:100]def[200:300]这种格式
 */
int fuzzy_digest(fuzzy_handle_t * handle, char * result, unsigned int size)
{
    final_result * temp = (final_result *)malloc(sizeof(final_result));
    temp->head = result;
    temp->size = size;
    temp->offset = 0;
    temp->first_FNV_offset = 0;
    temp->last_FNV_offset = 0;
    //final_result * temp = (final_result *)malloc(sizeof(final_result));
    //temp->offset = 0;
    IVI_traverse(((fuzzy_handle_inner_t *)handle)->ivi, fuzzy_hash_merge_new, (void *) temp);
	result[size - 1] = '\0';
    //memcpy(result, temp->result, size);
    free(temp);
    return 0;
}


void fuzzy_hash_merge_new(IVI_seg_t * seg, void * user_para)
{
    IVI_seg_t * prev_seg;
    IVI_seg_t * next_seg;
    prev_seg = IVI_prev_continuous_seg(seg);
    next_seg = IVI_next_continuous_seg(seg);
    char buffer[MAXSIZE];
    final_result * tmp = (final_result *)user_para;
    fuzzy_node * node = (fuzzy_node *)(seg->data);
    if(node->slice_num != 0)
    {
    	tmp->last_FNV_offset = seg->right - node->right_len;
    }

    if(prev_seg == NULL && next_seg == NULL) //如果前分片和后分片都为空，则不用拼接
    {
        tmp->first_FNV_offset = seg->left;
        tmp->last_FNV_offset = seg->right - node->right_len;
        sprintf(buffer, "%s[%llu:%llu]", node->hash_result, tmp->first_FNV_offset, seg->right);
    }
    if(prev_seg == NULL && next_seg != NULL) //如果前分片为空，后分片不为空，更新左值，将FNV值链接上去
    {
        tmp->first_FNV_offset = seg->left;

        sprintf(buffer, "%s", node->hash_result);
    }
    if(prev_seg != NULL && next_seg == NULL) //如果前分片不为空，后分片为空，更新右值输出偏移
    {

        sprintf(buffer, "%s[%llu:%llu]", node->hash_result, tmp->first_FNV_offset, seg->right);
    }
    if(prev_seg != NULL && next_seg != NULL) //如果前分片不为空，后分片不为空，将链接FNV值上去
    {
        sprintf(buffer, "%s", node->hash_result);
    }

    unsigned int inner_size = strlen(buffer);
    tmp->offset += inner_size;
    if(tmp->offset <= tmp->size)
    {
        memcpy(tmp->head, buffer, inner_size);
        tmp->head += inner_size;
    }
    else
    {
        unsigned int length = (tmp->size - (tmp->offset - inner_size)); 
       if(length != 0)
        { 
            memcpy(tmp->head, buffer, length);
        }
        tmp->offset = tmp->size;
        tmp->head += length;
    }
    return;
}


/**
 * 计算fuzzy_hash的各种长度
 */
unsigned long long fuzzy_status(fuzzy_handle_t * handle, int type)
{
	unsigned long long length;
	final_length tmp_length;
	fuzzy_handle_inner_t * _handle = (fuzzy_handle_inner_t *)(handle);
	switch(type)
	{
		case TOTAL_LENGTH:  //已经计算过hash值的全部长度
			length = IVI_seg_length(_handle->ivi);
			break;
		case EFFECTIVE_LENGTH:  //包含在计算hash值里面的有效长度
			length = _handle->effective_length;
			break;
		case HASH_LENGTH:   //最后输出哈希结果的长度
			tmp_length.hash_length = 0;
			tmp_length.first_FNV_offset = 0;
			tmp_length.last_FNV_offset = 0;
			IVI_traverse(_handle->ivi, fuzzy_hash_length, (void *)&tmp_length);
			length = tmp_length.hash_length + 1;
			break;
		default:
			return 0;
	}
	return length;
}


void fuzzy_hash_length(IVI_seg_t * seg, void * user_para)
{

    IVI_seg_t * prev_seg;
    IVI_seg_t * next_seg;
    prev_seg = IVI_prev_continuous_seg(seg);
    next_seg = IVI_next_continuous_seg(seg);
    char buffer[MAXSIZE];
    final_length * tmp = (final_length *)user_para;
    fuzzy_node * node = (fuzzy_node *)(seg->data);
    if(node->slice_num != 0)
    {
        //printf("node->slice_num != 0\n");
    	tmp->last_FNV_offset = seg->right - node->right_len;
        //printf("%lu\n", tmp->last_FNV_offset);
    }

    if(prev_seg == NULL && next_seg == NULL) //如果前分片和后分片都为空，则不用拼接
    {
        tmp->first_FNV_offset = seg->left;
        tmp->last_FNV_offset = seg->right - node->right_len;
        sprintf(buffer, "%s[%llu:%llu]", node->hash_result, tmp->first_FNV_offset, seg->right);
    }
    if(prev_seg == NULL && next_seg != NULL) //如果前分片为空，后分片不为空，更新左值，将FNV值链接上去
    {
        tmp->first_FNV_offset = seg->left;

        sprintf(buffer, "%s", node->hash_result);
    }
    if(prev_seg != NULL && next_seg == NULL) //如果前分片不为空，后分片为空，更新右值输出偏移
    {

        sprintf(buffer, "%s[%llu:%llu]", node->hash_result, tmp->first_FNV_offset, seg->right);
    }
    if(prev_seg != NULL && next_seg != NULL) //如果前分片不为空，后分片不为空，将链接FNV值上去
    {
        sprintf(buffer, "%s", node->hash_result);
    }
    tmp->hash_length += strlen(buffer);
    return;
}


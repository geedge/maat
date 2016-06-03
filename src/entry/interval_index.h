/************************************************************************
 *   InterVal Index interface
 *   NOTE that:
 *       (1) There are no overlapping intervals in InterVal Index;
 *       (2) Each interval is closed;
 *       (3) The interval supports rollback.
 *
 *   author: zhengchao@iie.ac.cn  tangqi@iie.ac.cn
 *   last modify time: 2015-12-04
 *************************************************************************/

#ifndef _INTERVAL_INDEX_H_
#define _INTERVAL_INDEX_H_

#ifdef __cplusplus
extern "C"{
#endif


#define SIZE_8

#ifdef  SIZE_8
typedef unsigned long long OFFSET_TYPE;
typedef signed long long S_OFFSET_TYPE;
#else
typedef unsigned int OFFSET_TYPE;
typedef signed int S_OFFSET_TYPE;
#endif


typedef struct{
}IVI_t;


/**
 * structure of segment
 **/
typedef struct __IVI_seg_t{
    OFFSET_TYPE left;
    OFFSET_TYPE right;
    void * data;
}IVI_seg_t;


typedef void IVI_callback_t(IVI_seg_t * seg, void * usr_para);

/**
 * Deal with rollback
 * Refering to the approach of Linux's kernel to solute tcp seq rollback
 **/
static inline int before(OFFSET_TYPE off1, OFFSET_TYPE off2)
{
    return (S_OFFSET_TYPE)(off1 - off2) < 0;
}
#define after(off2, off1) before(off1, off2)

static inline int continuous(OFFSET_TYPE prev, OFFSET_TYPE next)
{
    return ((next - prev) == 1);
}


IVI_seg_t * IVI_first_seg(IVI_t * handler);
IVI_seg_t * IVI_last_seg(IVI_t * handler);
IVI_seg_t * IVI_prev_seg(IVI_seg_t * seg);
IVI_seg_t * IVI_next_seg(IVI_seg_t * seg);
IVI_seg_t * IVI_prev_continuous_seg(IVI_seg_t * seg);
IVI_seg_t * IVI_next_continuous_seg(IVI_seg_t * seg);


/**
 * Relation of two segments
 **/
typedef enum __Relation_t{
    LEFT_NO_OVERLAP = 1,                //  |___A___|
                                        //             |___B___|

    LEFT_OVERLAP,                       //  |___A___|
                                        //        |___B___|

    CONTAINED,                          //   |___A___|
                                        // |_____B_____|

    CONTAIN,                            // |_____A_____|
                                        //   |___B___|

    RIGHT_OVERLAP,                      //        |___A___|
                                        //  |___B___|

    RIGHT_NO_OVERLAP,                   //             |___A___|
                                        //  |___B___|

    ERROR
}Relation_t;


/**
 * Name:
 *     IVI_relative_position
 * Description:
 *     Get relative position of given two interval segments
 * Params:
 *     seg1: Subject of relation
 *     seg2: Object of relation
 * Relation:
 *     On success, return the relation of two segments with enum;
 *     Else, return ERROR in enum;
 **/
Relation_t IVI_relative_position(IVI_seg_t * seg1, IVI_seg_t * seg2);



/**
 * Name:
 *     IVI_create
 * Description:
 *     Create an InterVal Index
 * Params:
 *    void
 * Return:
 *    Return a handler of this InterVal Index
 **/
IVI_t * IVI_create(void);



/**
 * Name:
 *     IVI_destroy
 * Description:
 *     Destroy a given InterVal Index's handler
 * Params:
 *    handler: The InterVal Index you want to destroy
 *    cb: Callback function for user to free data in segement
 *    usr_para: User parameter
 * Return:
 *    void
 **/
void IVI_destroy(IVI_t * handler, IVI_callback_t cb, void * usr_para);



/**
 * Name:
 *     IVI_seg_malloc
 * Description:
 *     Malloc a segment with given parameters
 * Params:
 *     left: Left point of segment
 *     right: Right point of segment
 *     data: User data
 * Return:
 *    Return a pointer of segment structure.
 **/
IVI_seg_t * IVI_seg_malloc(OFFSET_TYPE left, OFFSET_TYPE right, void * data);



/**
 * Name:
 *     IVI_seg_free
 * Description:
 *     Free the memory of given segment
 * Params:
 *    seg: The segment that you want to free
 *    cb: Callback function for user to free *data in seg
 *    usr_para: User parameter for cb
 * Return:
 *    void
 **/
void IVI_seg_free(IVI_seg_t * seg, IVI_callback_t cb, void * usr_para);



/**
 * Name:
 *     IVI_insert
 * Description:
 *    Insert a segment to an InterVal Index handler,and  the segment
 *    MUST not be overlapped with others in handler.
 * Params:
 *    handler: The handler of InterVal Index created by IVI_create
 *    seg: A segment that user wants to add. It MUST be created
 *             by IVI_seg_malloc.
 * Return:
 *    On success, 0 is returned;
 *    Else when overlapp occures or error occures, -1 is returned.
 **/
int IVI_insert(IVI_t * handler, IVI_seg_t * seg);



/**
 * Name:
 *     IVI_remove
 * Description:
 *    Remove a given segment from given InterVal Index handler.
 * Params:
 *    handler: The handler of InterVal Index created by IVI_create
 *    seg: A segment that user wants to delete. It MUST be created
 *           by IVI_seg_malloc.
 * Return:
 *    On success, 0 is returned;
 *    Else when overlapp occures, -1 is returned.
 **/
int IVI_remove(IVI_t * handler, IVI_seg_t * seg);



/**
 * Name:
 *     IVI_query
 * Description:
 *     Query from given InterVal Index and get the number of segments
 *     which are overlapped with given interval, and store those segments
 *     in the last parameter.
 * Params:
 *    handler: The handler of interval index created by IVI_create
 *    left: Left point of given interval
 *    right: Right point of given interval
 *    segs: An address of a segment pointer array to store those segments which
 *          are overlapped with given interval. NOTE that user should not malloc
 *          the array, and segs need to be freed by user. The element of *segs
 *          MUST not be freed by user.
 * Return:
 *    Return the number of segments which are overlapped with given interval
 **/
int IVI_query(IVI_t * handler, OFFSET_TYPE left, OFFSET_TYPE right, IVI_seg_t *** segs);



/**
 * Name:
 *     IVI_query_continuous
 * Description:
 *     Query from interval index handler and get the number of continous segments
 *     which are overlapped with given interval.
 * Params:
 *     handler: The handler of InterVal Index created by IVI_create.
 *     left: Left point of given interval
 *     right: Right point of given interval
 *     segs: An address of a segment pointer array to store those segments which
 *           are overlapped with given interval. NOTE that user should not malloc
 *           the array, and segs need to be freed by user. The element of *segs
 *           MUST not be freed by user.
 *  Return:
 *     Return the number of continous segments which are overlapped with given interval
 **/
int IVI_query_continuous(IVI_t * handler, OFFSET_TYPE left, OFFSET_TYPE right, IVI_seg_t *** segs);



/**
 * Name:
 *     IVI_seg_cnt
 * Description:
 *     Get the count of segments in given interval index handler
 * Params:
 *     handler: The handler of InterVal Index created by IVI_create.
 * Return:
 *     Return the count of segments in given interval index handler
 **/
int IVI_seg_cnt(IVI_t * handler);


/**
 * Name:
 *     IVI_seg_len
 * Description:
 *     Get the length of whole segments in given interval index handler
 * Params:
 *     handler: The handler of InterVal Index created by IVI_create.
 * Return:
 *     Return the length of whole segments in given interval index handler
 **/
OFFSET_TYPE IVI_seg_length(IVI_t * handler);


/**
 * Name:
 *     IVI_mem_occupy
 * Description:
 *     Get the memory occupy of given interval index handler
 * Params:
 *     handler: The handler of InterVal Index created by IVI_create.
 * Return:
 *     Return the memory occupy of given interval index handler
 **/
unsigned long long IVI_mem_occupy(IVI_t * handler);


/**
 * Name:
 *     IVI_traverse
 * Description:
 *     Traverse given InterVal Index and execute given callback function
 *     one time for each seg in InterVal Index.
 * Params:
 *     handler: The handler of InterVal Index created by IVI_create.
 *     IVI_callback_t: Callback function for user to define.
 *     usr_para: Parameter user want to pass to callback function.
 * Return:
 *    void
 **/
void IVI_traverse(IVI_t * handler, IVI_callback_t cb, void * usr_para);



#ifdef __cplusplus
}
#endif

#endif /* _INTERVAL_INDEX_H_ */

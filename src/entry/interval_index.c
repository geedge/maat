#include<stdio.h>
#include<stdlib.h>
#include"interval_index.h"


/**
 * There is a trick here. In order to hide specific
 * realization of some structures, we use some approaches.
 * Then the inner structure is named with "shadow", and
 * the outer structure is named with "light". These words
 * come from movie <<The Grand Master>>. Enjoy it :)
 **/


/**
 * Structure of inner segment
 **/
typedef struct __IVI_shadow_seg_t{
    IVI_seg_t lightseg;
    TAILQ_ENTRY(__IVI_shadow_seg_t) ENTRY;
}IVI_shadow_seg_t;


TAILQ_HEAD(TQ, __IVI_shadow_seg_t);

/* Structure of inner InterVal Index */
typedef struct __IVI_shadow_t{
    struct TQ ivi_queue;
    int segs_cnt;
    OFFSET_TYPE segs_length;
}IVI_shadow_t;



/**
 *  new is closer to head or tail ?
 *  Return 1 if closer to head than tail
 *  Else return 0
 */
int closer_to_head(IVI_shadow_seg_t * head, IVI_shadow_seg_t * tail, OFFSET_TYPE target)
{
    if(head == NULL || tail == NULL)
        return 1;
    S_OFFSET_TYPE tmp1 = (S_OFFSET_TYPE)(target - head->lightseg.left);
    S_OFFSET_TYPE tmp2 = (S_OFFSET_TYPE)(target - tail->lightseg.left);
    S_OFFSET_TYPE distance_to_head = tmp1 > 0 ? tmp1 : -tmp1;
    S_OFFSET_TYPE distance_to_tail = tmp2 > 0 ? tmp2 : -tmp2;
    return (distance_to_tail - distance_to_head > 0);
}


IVI_seg_t * IVI_prev_continuous_seg(IVI_seg_t * seg)
{
    if(NULL == seg)
    {
        return NULL;
    }

    IVI_shadow_seg_t * _seg = (IVI_shadow_seg_t *)seg;
    IVI_shadow_seg_t * prev = TAILQ_PREV(_seg, TQ, ENTRY);
    if(NULL == prev)
    {
        return NULL;
    }
    if(continuous((prev->lightseg).right, seg->left))
        return (IVI_seg_t *)prev;
    return NULL;
}


IVI_seg_t * IVI_next_continuous_seg(IVI_seg_t * seg)
{
    if(NULL == seg)
    {
        return NULL;
    }
    IVI_shadow_seg_t * _seg = (IVI_shadow_seg_t *)seg;
    IVI_shadow_seg_t * next = TAILQ_NEXT(_seg, ENTRY);
    if(NULL == next)
    {
        return NULL;
    }
    if(continuous(seg->right, (next->lightseg).left))
        return (IVI_seg_t *)next;
    return NULL;
}


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
Relation_t IVI_relative_position(IVI_seg_t * seg1, IVI_seg_t * seg2)
{
    if(NULL == seg1 || NULL == seg2)
    {
        return ERROR;
    }

    if(before(seg1->right, seg2->left))
    {
        return LEFT_NO_OVERLAP;
    }

    if(!before(seg1->right, seg2->left) && before(seg1->right, seg2->right) && before(seg1->left, seg2->left))
    {
        return LEFT_OVERLAP;
    }

    if(!before(seg1->left, seg2->left) && !after(seg1->right, seg2->right))
    {
        return CONTAINED;
    }

    if(!after(seg1->left, seg2->left) && !before(seg1->right, seg2->right))
    {
        return CONTAIN;
    }

    if(!after(seg1->left, seg2->right) && after(seg1->right, seg2->right) && after(seg1->left, seg2->left))
    {
        return RIGHT_OVERLAP;
    }

    if(after(seg1->left, seg2->right))
    {
        return RIGHT_NO_OVERLAP;
    }
    return ERROR;
}



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
IVI_t * IVI_create(void)
{
    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)malloc(sizeof(IVI_shadow_t));
    TAILQ_INIT(&(shadow_ivi->ivi_queue));
    shadow_ivi->segs_cnt = 0;
    shadow_ivi->segs_length = 0;
    return (IVI_t *)shadow_ivi;
}


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
void IVI_destroy(IVI_t * handler, IVI_callback_t cb, void * usr_para)
{
    if(handler == NULL)
    {
        return;
    }

    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    IVI_shadow_seg_t * tmpseg = TAILQ_FIRST(&(shadow_ivi->ivi_queue));
    IVI_shadow_seg_t * tmp;
    /* Free each seg in IVI */
    while(tmpseg != NULL)
    {
        tmp = TAILQ_NEXT(tmpseg, ENTRY);
        /* Free *data in seg */
        if(NULL != cb)
        {
            cb(&(tmpseg->lightseg), usr_para);
        }
        free(tmpseg);
        tmpseg = tmp;
    }

    /* Free IVI */
    free(shadow_ivi);
    handler = NULL;
}



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
IVI_seg_t * IVI_seg_malloc(OFFSET_TYPE left, OFFSET_TYPE right, void * data)
{
    /* Left must <= Right */
    if(after(left, right))
    {
        return NULL;
    }
    IVI_shadow_seg_t * shadow_seg = (IVI_shadow_seg_t *)malloc(sizeof(IVI_shadow_seg_t));
    shadow_seg->lightseg.left = left;
    shadow_seg->lightseg.right= right;
    shadow_seg->lightseg.data = data;

    return (IVI_seg_t *)shadow_seg;
}



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
void IVI_seg_free(IVI_seg_t * seg, IVI_callback_t cb, void * usr_para)
{
    /* Free user data first */
    if(cb != NULL)
    {
        cb(seg, usr_para);
    }
    IVI_shadow_seg_t * shadow_seg = (IVI_shadow_seg_t *)seg;

    /* Free seg */
    free(shadow_seg);
    seg = NULL;
}


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
int IVI_insert(IVI_t * handler, IVI_seg_t * seg)
{
    IVI_shadow_t * shadow_ivi;
    IVI_shadow_seg_t *head, *tail, *new_seg, *tmp_seg;

    if(NULL == handler || NULL == seg)
    {
        return -1;
    }

    shadow_ivi = (IVI_shadow_t *)handler;
    new_seg = (IVI_shadow_seg_t *)seg;
    head = TAILQ_FIRST(&(shadow_ivi->ivi_queue));
    tail = TAILQ_LAST(&(shadow_ivi->ivi_queue), TQ);

    if(closer_to_head(head, tail, seg->left))
    {
        TAILQ_FOREACH(tmp_seg, &(shadow_ivi->ivi_queue), ENTRY)
        {
            /* Find the first seg whose left is bigger than given seg's right, we will insert new seg before it */
            if(after(tmp_seg->lightseg.left, new_seg->lightseg.right))
            {
                TAILQ_INSERT_BEFORE(tmp_seg, new_seg, ENTRY);
                shadow_ivi->segs_cnt ++;
                shadow_ivi->segs_length += (seg->right - seg->left + 1);
                return 0;
            }
            else if(before(tmp_seg->lightseg.right, new_seg->lightseg.left))
            {
                continue;
            }
            else  /* Overlap */
            {
                return -1;
            }
        }

        /* If have searched to the end of list, we will inset it to the tail */
        TAILQ_INSERT_TAIL(&(shadow_ivi->ivi_queue), new_seg, ENTRY);
        shadow_ivi->segs_cnt ++;
        shadow_ivi->segs_length += (seg->right - seg->left + 1);
    }
    else
    {
        TAILQ_FOREACH_REVERSE(tmp_seg, &(shadow_ivi->ivi_queue), TQ, ENTRY)
        {
            /* Find the first seg whose right is smaller than given seg's left, we will insert new seg after it */
            if(before(tmp_seg->lightseg.right, new_seg->lightseg.left))
            {
                TAILQ_INSERT_AFTER(&(shadow_ivi->ivi_queue), tmp_seg, new_seg, ENTRY);
                shadow_ivi->segs_cnt ++;
                shadow_ivi->segs_length += (seg->right - seg->left + 1);
                return 0;
            }
            else if(after(tmp_seg->lightseg.left, new_seg->lightseg.right))
            {
                continue;
            }
            else  /* Overlap */
            {
                return -1;
            }
        }

        /* If have searched to the head of list, we will inset it to the head */
        TAILQ_INSERT_HEAD(&(shadow_ivi->ivi_queue), new_seg, ENTRY);
        shadow_ivi->segs_cnt ++;
        shadow_ivi->segs_length += (seg->right - seg->left + 1);
    }

    return 0;
}



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
int IVI_remove(IVI_t * handler, IVI_seg_t * seg)
{
    if(NULL == handler || NULL == seg)
    {
        return -1;
    }

    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    IVI_shadow_seg_t * shadow_seg = (IVI_shadow_seg_t *)seg;

    TAILQ_REMOVE(&(shadow_ivi->ivi_queue), shadow_seg, ENTRY);
    shadow_ivi->segs_cnt --;
    shadow_ivi->segs_length -= (seg->right - seg->left + 1);
    return 0;
}



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
int IVI_query(IVI_t * handler, OFFSET_TYPE left, OFFSET_TYPE right, IVI_seg_t *** segs)
{
    IVI_shadow_t * shadow_ivi;
    IVI_shadow_seg_t *head, *tail, *tmp, *left_tmp, *right_tmp;
    int interval_cnt = 0, i;

    if(NULL == handler || after(left, right))
    {
        return -1;
    }

    shadow_ivi = (IVI_shadow_t *)handler;
    head = TAILQ_FIRST(&(shadow_ivi->ivi_queue));
    tail = TAILQ_LAST(&(shadow_ivi->ivi_queue), TQ);

    /* Traverse from head or tail? We need to decide */
    if(closer_to_head(head, tail, left))
    {
        tmp = head;
        while(tmp != NULL)
        {
            if(after(left, tmp->lightseg.right))
            {
                tmp = TAILQ_NEXT(tmp, ENTRY);
            }
            else
            {
                /* Get the seg which left is in or before*/
                left_tmp = tmp;
                break;
            }
        }
        if(tmp == NULL)
        {
            *segs = NULL;
            return 0;
        }

        /* Get the num of overlapped segs */
        while(tmp != NULL)
        {
            if(!before(right, tmp->lightseg.left))
            {
                tmp = TAILQ_NEXT(tmp, ENTRY);
                interval_cnt ++;
            }
            else
            {
                break;
            }
        }

        tmp = left_tmp;
        if(interval_cnt == 0)
        {
            *segs = NULL;
            return 0;
        }
        *segs = (IVI_seg_t **)malloc(interval_cnt * sizeof(IVI_seg_t *));
        for(i = 0; i < interval_cnt; i++)
        {
            (*segs)[i] = (IVI_seg_t *)tmp;
            tmp = TAILQ_NEXT(tmp, ENTRY);
        }
    }
    else
    {
        tmp = tail;
        while(tmp != NULL)
        {
            if(before(right, tmp->lightseg.left))
            {
                tmp = TAILQ_PREV(tmp, TQ, ENTRY);
            }
            else
            {
                right_tmp = tmp;
                break;
            }
        }
        if(tmp == NULL)
        {
            *segs = NULL;
            return 0;
        }

        /* Get the num of overlapped segs */
        while(tmp != NULL)
        {
            if(!after(left, tmp->lightseg.right))
            {
                tmp = TAILQ_PREV(tmp, TQ, ENTRY);
                interval_cnt ++;
            }
            else
            {
                break;
            }
        }
        tmp = right_tmp;
        if(interval_cnt == 0)
        {
            *segs = NULL;
            return 0;
        }
        *segs = (IVI_seg_t **)malloc(interval_cnt * sizeof(IVI_seg_t *));
        for(i = interval_cnt - 1; i >= 0; i--)
        {
            (*segs)[i] = (IVI_seg_t *)tmp;
            tmp = TAILQ_PREV(tmp, TQ, ENTRY);
        }
    }
    return interval_cnt;
}



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
int IVI_query_continuous(IVI_t * handler, OFFSET_TYPE left, OFFSET_TYPE right, IVI_seg_t *** segs)
{
    IVI_shadow_t * shadow_ivi;
    IVI_shadow_seg_t *head, *tail, *tmp, *left_tmp, *right_tmp;
    int interval_cnt = 0, i;

    if(NULL == handler || after(left, right))
    {
        return -1;
    }
    shadow_ivi = (IVI_shadow_t *)handler;
    head = TAILQ_FIRST(&(shadow_ivi->ivi_queue));
    tail = TAILQ_LAST(&(shadow_ivi->ivi_queue), TQ);



    /* Traverse from head or tail? We need to decide */
    if(closer_to_head(head, tail, left))
    {
        tmp = head;
        while(tmp != NULL)
        {
            if(after(left, tmp->lightseg.right))
            {
                tmp = TAILQ_NEXT(tmp, ENTRY);
            }
            else
            {
                /* Get the seg which left is in or before*/
                left_tmp = tmp;
                break;
            }
        }
        if(tmp == NULL)
        {
            *segs = NULL;
            return 0;
        }

        /* Get the num of overlapped segs */
        while(tmp != NULL)
        {
            if(!before(right, tmp->lightseg.left))
            {
                tmp = TAILQ_NEXT(tmp, ENTRY);
                interval_cnt ++;
            }
            else
            {
                break;
            }

            IVI_shadow_seg_t * prev = TAILQ_PREV(tmp, TQ, ENTRY);
            if(tmp != NULL && !continuous(prev->lightseg.right, tmp->lightseg.left))
            {
                break;
            }
        }

        tmp = left_tmp;
        if(interval_cnt == 0)
        {
            *segs = NULL;
            return 0;
        }
        *segs = (IVI_seg_t **)malloc(interval_cnt * sizeof(IVI_seg_t *));
        for(i = 0; i < interval_cnt; i++)
        {
            (*segs)[i] = (IVI_seg_t *)tmp;
            tmp = TAILQ_NEXT(tmp, ENTRY);
        }
    }
    else
    {
        tmp = tail;
        while(tmp != NULL)
        {
            if(before(right, tmp->lightseg.left))
            {
                tmp = TAILQ_PREV(tmp, TQ, ENTRY);
            }
            else
            {
                right_tmp = tmp;
                break;
            }
        }
        if(tmp == NULL)
        {
            *segs = NULL;
            return 0;
        }

        /* Get the num of overlapped segs */
        while(tmp != NULL)
        {
            if(!after(left, tmp->lightseg.right))
            {
                tmp = TAILQ_PREV(tmp, TQ, ENTRY);
                interval_cnt ++;
            }
            else
            {
                break;
            }
            IVI_shadow_seg_t * next = TAILQ_NEXT(tmp, ENTRY);
            if(tmp != NULL && !continuous(tmp->lightseg.right, next->lightseg.left))
            {
                break;
            }
        }
        tmp = right_tmp;
        if(interval_cnt == 0)
        {
            *segs = NULL;
            return 0;
        }
        *segs = (IVI_seg_t **)malloc(interval_cnt * sizeof(IVI_seg_t *));
        for(i = interval_cnt - 1; i >= 0; i--)
        {
            (*segs)[i] = (IVI_seg_t *)tmp;
            tmp = TAILQ_PREV(tmp, TQ, ENTRY);
        }
    }

    return interval_cnt;
}



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
int IVI_seg_cnt(IVI_t * handler)
{
    if(handler == NULL)
        return -1;
    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    return shadow_ivi->segs_cnt;
}



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
OFFSET_TYPE IVI_seg_length(IVI_t * handler)
{
    if(handler == NULL)
        return -1;
    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    return shadow_ivi->segs_length;
}



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
void IVI_traverse(IVI_t * handler, IVI_callback_t cb, void * usr_para)
{
    if(NULL == handler || NULL == cb)
    {
        return;
    }

    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    IVI_shadow_seg_t * tmp_seg = TAILQ_FIRST(&(shadow_ivi->ivi_queue));
    IVI_shadow_seg_t * tmp;
    /* Traverse the IVI */
    while(tmp_seg != NULL)
    {
        /*
         * The place we can't use TAILQ_FOREACH because we
         * do not no what will callback funciton does.
         * */
        tmp = TAILQ_NEXT(tmp_seg, ENTRY);
        cb((IVI_seg_t *)tmp_seg, usr_para);
        tmp_seg = tmp;
    }
}

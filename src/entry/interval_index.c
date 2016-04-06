/*********************************************************************
 *  File:
 *		interval_index.c
 *  Author:
 *		TangQi
 *	E-mail:
 *		tangqi@iie.ac.cn 
 *********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "interval_index.h"
#include "rbtree.h"
#include "rbtree_augmented.h"

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
    IVI_seg_t lightseg;     /* interval for user, including left edge, right edge, and user's data */
    struct rb_node rb;      /* node of rb-tree */
    OFFSET_TYPE max;        /* max edge of subtree */
}IVI_shadow_seg_t;


/* Structure of inner InterVal Index */
typedef struct __IVI_shadow_t{
    struct rb_root root;

    /* statistics */
    int segs_cnt;
    OFFSET_TYPE segs_length;
    unsigned long long mem_occupy;  //do not include user data
}IVI_shadow_t;





IVI_seg_t * IVI_first_seg(IVI_t * handler)
{
    assert(handler != NULL);
    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    struct rb_node *first_node = rb_first(&(shadow_ivi->root));
    if(first_node == NULL)
        return NULL;
    return (IVI_seg_t *)(rb_entry(first_node, IVI_shadow_seg_t, rb));
}


IVI_seg_t * IVI_last_seg(IVI_t * handler)
{
    assert(handler != NULL);
    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    struct rb_node *last_node = rb_last(&(shadow_ivi->root));
    if(last_node == NULL)
        return NULL;
    return (IVI_seg_t *)(rb_entry(last_node, IVI_shadow_seg_t, rb));
}



IVI_seg_t * IVI_prev_seg(IVI_seg_t * seg)
{
    assert(seg != NULL);
    IVI_shadow_seg_t * shadow_seg = (IVI_shadow_seg_t *)seg;
    struct rb_node * prev_node = rb_prev(&(shadow_seg->rb));
    if(prev_node == NULL)
        return NULL;
    return (IVI_seg_t *)(rb_entry(prev_node, IVI_shadow_seg_t, rb));
}



IVI_seg_t * IVI_next_seg(IVI_seg_t * seg)
{
    assert(seg != NULL);
    IVI_shadow_seg_t * shadow_seg = (IVI_shadow_seg_t *)seg;
    struct rb_node * next_node = rb_next(&(shadow_seg->rb));
    if(next_node == NULL)
        return NULL;
    return (IVI_seg_t *)(rb_entry(next_node, IVI_shadow_seg_t, rb));
}


IVI_seg_t * IVI_prev_continuous_seg(IVI_seg_t * seg)
{
    assert(seg != NULL);
    IVI_shadow_seg_t * shadow_seg = (IVI_shadow_seg_t *)seg;
    struct rb_node * prev_node = rb_prev(&(shadow_seg->rb));
    if(prev_node == NULL)
    {
        return NULL;
    }
    IVI_seg_t * prev_seg = (IVI_seg_t *)(rb_entry(prev_node, IVI_shadow_seg_t, rb));
    if(!continuous(prev_seg->right, seg->left))
    {
        return NULL;
    }
    return prev_seg;
}


IVI_seg_t * IVI_next_continuous_seg(IVI_seg_t * seg)
{
    assert(seg != NULL);
    IVI_shadow_seg_t * shadow_seg = (IVI_shadow_seg_t *)seg;
    struct rb_node * next_node = rb_next(&(shadow_seg->rb));
    if(next_node == NULL)
    {
        return NULL;
    }
    IVI_seg_t * next_seg = (IVI_seg_t *)(rb_entry(next_node, IVI_shadow_seg_t, rb));
    if(!continuous(seg->right, next_seg->left))
    {
        return NULL;
    }
    return next_seg;
}


static inline int __is_overlapped(OFFSET_TYPE left1, OFFSET_TYPE right1, OFFSET_TYPE left2, OFFSET_TYPE right2)
{
    if(!after(left1, right2) && !after(left2, right1))
        return 1;
    return 0;
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
    shadow_ivi->root = RB_ROOT;      //init rb tree's root
    shadow_ivi->segs_cnt = 0;
    shadow_ivi->segs_length = 0;
    shadow_ivi->mem_occupy = sizeof(IVI_shadow_t);
    return (IVI_t *)shadow_ivi;
}



static void __free_rb_tree(struct rb_node * root, IVI_callback_t cb, void * usr_para)
{
	if(root == NULL)
	{
		return;	
	}
	if(root->rb_left != NULL)
	{
		__free_rb_tree(root->rb_left, cb, usr_para);
	}
	if(root->rb_right != NULL)
	{
		__free_rb_tree(root->rb_right, cb, usr_para);
	}
    /* free user data */
    IVI_shadow_seg_t * shadow_seg = rb_entry(root, IVI_shadow_seg_t, rb);
	if(cb != NULL)
	{
		cb((IVI_seg_t *)shadow_seg, usr_para);
	}

    /* free seg */
    free(shadow_seg);
    shadow_seg = NULL;
    return;
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
    __free_rb_tree(shadow_ivi->root.rb_node, cb, usr_para);
    free(shadow_ivi);
    handler = NULL;
    return;
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
    shadow_seg->max = 0;

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
    assert(seg != NULL);

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




static inline OFFSET_TYPE __interval_tree_get_subtree_max(IVI_shadow_seg_t * node)
{
    OFFSET_TYPE max = node->lightseg.right, subtree_max;
    if(node->rb.rb_left)
    {
        subtree_max = (rb_entry(node->rb.rb_left, IVI_shadow_seg_t, rb))->max;
        if(before(max, subtree_max))
            max = subtree_max;
    }
    if(node->rb.rb_right)
    {
        subtree_max = (rb_entry(node->rb.rb_right, IVI_shadow_seg_t, rb))->max;
        if(before(max, subtree_max))
            max = subtree_max;
    }
    return max;
}


static void __interval_tree_augment_propagate(struct rb_node * rb, struct rb_node * stop)
{
    while(rb != stop)
    {
        IVI_shadow_seg_t * node = rb_entry(rb, IVI_shadow_seg_t, rb);
        OFFSET_TYPE subtree_max = __interval_tree_get_subtree_max(node);
        if(node->max == subtree_max)
        {
            break;
        }
        node->max = subtree_max;
        rb = rb_parent(&node->rb);
    }
    return;
}


static void __interval_tree_augment_copy(struct rb_node * rb_old, struct rb_node * rb_new)
{
    IVI_shadow_seg_t * old = rb_entry(rb_old, IVI_shadow_seg_t, rb);
    IVI_shadow_seg_t * new = rb_entry(rb_new, IVI_shadow_seg_t, rb);
    new->max = old->max;
    return;
}


static void __interval_tree_augment_rotate(struct rb_node * rb_old, struct rb_node * rb_new)
{
    IVI_shadow_seg_t * old = rb_entry(rb_old, IVI_shadow_seg_t, rb);
    IVI_shadow_seg_t * new = rb_entry(rb_new, IVI_shadow_seg_t, rb);
    new->max = old->max;
    old->max = __interval_tree_get_subtree_max(old);
    return;
}


static const struct rb_augment_callbacks __interval_tree_augment_callbacks = {
    __interval_tree_augment_propagate,
    __interval_tree_augment_copy,
    __interval_tree_augment_rotate
};


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
    if(NULL == handler || NULL == seg)
    {
        return -1;
    }

    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    struct rb_root * root = &(shadow_ivi->root);
    OFFSET_TYPE left = seg->left, right = seg->right;
    struct rb_node **link = &root->rb_node, *rb_parent = NULL;
    IVI_shadow_seg_t * parent = NULL;
	IVI_shadow_seg_t * new_seg = (IVI_shadow_seg_t *)seg;
    while(*link)
    {
        rb_parent = *link;
        parent = rb_entry(rb_parent, IVI_shadow_seg_t, rb);
		/* is overlapped */
		if(__is_overlapped(left, right, parent->lightseg.left, parent->lightseg.right))	
		{
			//overlapped, return
			return -1;	
		}

        if(before(parent->max, right))
        {
            parent->max = right;
        }
        if(before(left, parent->lightseg.left))
        {
            link = &parent->rb.rb_left;
        }
        else
        {
            link = &parent->rb.rb_right;
        }
    }
    new_seg->max = right;
    rb_link_node(&new_seg->rb, rb_parent, link);
    rb_insert_augmented(&new_seg->rb, root, &__interval_tree_augment_callbacks);

    /*  updata statistics */
    shadow_ivi->segs_cnt ++;
    shadow_ivi->segs_length += seg->right - seg->left + 1;
    shadow_ivi->mem_occupy += sizeof(IVI_shadow_seg_t);
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
    struct rb_root * root = &(shadow_ivi->root);
    IVI_shadow_seg_t * new_seg = (IVI_shadow_seg_t *)seg;
    rb_erase_augmented(&new_seg->rb, root, &__interval_tree_augment_callbacks);

    /*  updata statistics */
    shadow_ivi->segs_cnt --;
    shadow_ivi->segs_length -= seg->right - seg->left + 1;
    shadow_ivi->mem_occupy -= sizeof(IVI_shadow_seg_t);

    return 0;
}



static struct rb_node * __min_interval_search_from(struct rb_node * node, OFFSET_TYPE left, OFFSET_TYPE right)
{
	if(node == NULL)
	{
		return NULL;
	}
    IVI_shadow_seg_t * seg = rb_entry(node, IVI_shadow_seg_t, rb);
    IVI_shadow_seg_t * left_seg = rb_entry(node->rb_left, IVI_shadow_seg_t, rb);
    if(node->rb_left != NULL && !before(left_seg->max, left))
    {
        struct rb_node * ret = __min_interval_search_from(node->rb_left, left, right);
        if(ret != NULL)
        {
            return ret;
        }
        else if(__is_overlapped(left, right, seg->lightseg.left, seg->lightseg.right))
        {
            return node;
        }
        else
        {
            return NULL;
        }
    }
    else if(__is_overlapped(left, right, seg->lightseg.left, seg->lightseg.right))
    {
        return node;
    }
    else
    {
        return __min_interval_search_from(node->rb_right, left, right);
    }
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
    if(NULL == handler || after(left, right))
    {
        //augments error
        return -1;
    }

    int interval_cnt = 0, max_cnt = 8;
    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    struct rb_node * root = shadow_ivi->root.rb_node;
    struct rb_node * min_overlap = __min_interval_search_from(root, left, right);
    struct rb_node * tmp_node = min_overlap;

    *segs = (IVI_seg_t **)malloc(max_cnt * sizeof(IVI_seg_t *));
    while (tmp_node != NULL)
    {
        IVI_seg_t * tmp_seg = (IVI_seg_t *)(rb_entry(tmp_node, IVI_shadow_seg_t, rb));
        if(!__is_overlapped(tmp_seg->left, tmp_seg->right, left, right))
        {
            break;
        }
        if(interval_cnt > max_cnt)
        {
            max_cnt *= 2;
            *segs = (IVI_seg_t **)realloc(*segs, max_cnt * sizeof(IVI_seg_t *));
        }
        (*segs)[interval_cnt] = tmp_seg;
        interval_cnt ++;
        tmp_node = rb_next(tmp_node);
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
    if(NULL == handler || after(left, right))
    {
        //augments error
        return -1;
    }

    int interval_cnt = 0, max_cnt = 8;
    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    struct rb_node * root = shadow_ivi->root.rb_node;
    struct rb_node * min_overlap = __min_interval_search_from(root, left, right);
    struct rb_node * tmp_node = min_overlap;

    *segs = (IVI_seg_t **)malloc(max_cnt * sizeof(IVI_seg_t *));
    while (tmp_node != NULL)
    {
        IVI_seg_t * tmp_seg = (IVI_seg_t *)(rb_entry(tmp_node, IVI_shadow_seg_t, rb));
        if(!__is_overlapped(tmp_seg->left, tmp_seg->right, left, right))
        {
            break;
        }
        if(interval_cnt > max_cnt)
        {
            max_cnt += 8;
            *segs = (IVI_seg_t **)realloc(*segs, max_cnt * sizeof(IVI_seg_t *));
        }
        (*segs)[interval_cnt] = tmp_seg;
        interval_cnt ++;
        tmp_node = rb_next(tmp_node);
        IVI_seg_t * prev_tmp_seg = tmp_seg;
        tmp_seg = (IVI_seg_t *)(rb_entry(tmp_node, IVI_shadow_seg_t, rb));
        if(!continuous(prev_tmp_seg->right, tmp_seg->left))
        {
            break;
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
 *     IVI_mem_occupy
 * Description:
 *     Get the memory occupy of given interval index handler
 * Params:
 *     handler: The handler of InterVal Index created by IVI_create.
 * Return:
 *     Return the memory occupy of given interval index handler
 **/
unsigned long long IVI_mem_occupy(IVI_t * handler)
{
    if(handler == NULL)
        return 0;
    IVI_shadow_t * shadow_ivi = (IVI_shadow_t *)handler;
    return shadow_ivi->mem_occupy;
}


static void __inorder_traverse(struct rb_node * root, IVI_callback_t cb, void * usr_para)
{
    if(root == NULL)
    {
        return;
    }

    /* save first in case of root is freed in callback */
    struct rb_node * left_node = root->rb_left;
    struct rb_node * right_node = root->rb_right;
    __inorder_traverse(left_node, cb, usr_para);
    IVI_seg_t * seg = (IVI_seg_t *)(rb_entry(root, IVI_shadow_seg_t, rb));
    cb(seg, usr_para);
    __inorder_traverse(right_node, cb, usr_para);
    return;
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
    __inorder_traverse(shadow_ivi->root.rb_node, cb, usr_para);
    return;
}

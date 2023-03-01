#include <stdio.h>
#include <assert.h>
#include <malloc.h>
#include "cgranges.h"

/**************
 * Radix sort *
 **************/

#define RS_MIN_SIZE 64
#define RS_MAX_BITS 8

#define KRADIX_SORT_INIT(name, rstype_t, rskey, sizeof_key) \
	typedef struct { \
		rstype_t *b, *e; \
	} rsbucket_##name##_t; \
	void rs_insertsort_##name(rstype_t *beg, rstype_t *end) \
	{ \
		rstype_t *i; \
		for (i = beg + 1; i < end; ++i) \
			if (rskey(*i) < rskey(*(i - 1))) { \
				rstype_t *j, tmp = *i; \
				for (j = i; j > beg && rskey(tmp) < rskey(*(j-1)); --j) \
					*j = *(j - 1); \
				*j = tmp; \
			} \
	} \
	void rs_sort_##name(rstype_t *beg, rstype_t *end, int n_bits, int s) \
	{ \
		rstype_t *i; \
		int size = 1<<n_bits, m = size - 1; \
		rsbucket_##name##_t *k, b[1<<RS_MAX_BITS], *be = b + size; \
		assert(n_bits <= RS_MAX_BITS); \
		for (k = b; k != be; ++k) k->b = k->e = beg; \
		for (i = beg; i != end; ++i) ++b[rskey(*i)>>s&m].e; \
		for (k = b + 1; k != be; ++k) \
			k->e += (k-1)->e - beg, k->b = (k-1)->e; \
		for (k = b; k != be;) { \
			if (k->b != k->e) { \
				rsbucket_##name##_t *l; \
				if ((l = b + (rskey(*k->b)>>s&m)) != k) { \
					rstype_t tmp = *k->b, swap; \
					do { \
						swap = tmp; tmp = *l->b; *l->b++ = swap; \
						l = b + (rskey(tmp)>>s&m); \
					} while (l != k); \
					*k->b++ = tmp; \
				} else ++k->b; \
			} else ++k; \
		} \
		for (b->b = beg, k = b + 1; k != be; ++k) k->b = (k-1)->e; \
		if (s) { \
			s = s > n_bits? s - n_bits : 0; \
			for (k = b; k != be; ++k) \
				if (k->e - k->b > RS_MIN_SIZE) rs_sort_##name(k->b, k->e, n_bits, s); \
				else if (k->e - k->b > 1) rs_insertsort_##name(k->b, k->e); \
		} \
	} \
	void radix_sort_##name(rstype_t *beg, rstype_t *end) \
	{ \
		if (end - beg <= RS_MIN_SIZE) rs_insertsort_##name(beg, end); \
		else rs_sort_##name(beg, end, RS_MAX_BITS, (sizeof_key - 1) * RS_MAX_BITS); \
	}

/*********************
 * Convenient macros *
 *********************/

#ifndef kroundup32
#define kroundup32(x) (--(x), (x)|=(x)>>1, (x)|=(x)>>2, (x)|=(x)>>4, (x)|=(x)>>8, (x)|=(x)>>16, ++(x))
#endif

#define CALLOC(type, len) ((type*)calloc((len), sizeof(type)))
#define REALLOC(ptr, len) ((ptr) = (__typeof__(ptr))realloc((ptr), (len) * sizeof(*(ptr))))

#define EXPAND(a, m) do { \
		(m) = (m)? (m) + ((m)>>1) : 16; \
		REALLOC((a), (m)); \
	} while (0)

/********************
 * Basic operations *
 ********************/

#define cr_intv_key(r) ((r).x)
KRADIX_SORT_INIT(cr_intv, cr_intv_t, cr_intv_key, 8)

cgranges_t *cr_init(void)
{
	cgranges_t *cr;
	cr = CALLOC(cgranges_t, 1);

	return cr;
}

void cr_destroy(cgranges_t *cr)
{
	if (cr == 0) return;
	if (cr->n_r && cr->r)
	{
		free(cr->r);
		cr->r = NULL;
	}

	free(cr);
	cr = NULL;
}

// int32_t cr_add_ctg(cgranges_t *cr, const char *ctg, int32_t len)
// {
// 	int absent;
// 	khint_t k;
// 	strhash_t *h = (strhash_t*)cr->hc;
// 	k = kh_put(str, h, ctg, &absent);
// 	if (absent) {
// 		cr_ctg_t *p;
// 		if (cr->n_ctg == cr->m_ctg)
// 			EXPAND(cr->ctg, cr->m_ctg);
// 		kh_val(h, k) = cr->n_ctg;
// 		p = &cr->ctg[cr->n_ctg++];
// 		p->name = strdup(ctg);
// 		kh_key(h, k) = p->name;
// 		p->len = len;
// 		p->n = 0, p->off = -1;
// 	}
// 	if (len > cr->ctg[kh_val(h, k)].len)
// 		cr->ctg[kh_val(h, k)].len = len;
// 	return kh_val(h, k);
// }

// int32_t cr_get_ctg(const cgranges_t *cr, const char *ctg)
// {
// 	khint_t k;
// 	strhash_t *h = (strhash_t*)cr->hc;
// 	k = kh_get(str, h, ctg);
// 	return k == kh_end(h)? -1 : kh_val(h, k);
// }

cr_intv_t *cr_add(cgranges_t *cr, uint64_t st, uint64_t en, user_label_t label)
{
	cr_intv_t *p;
	if (st > en) return 0;
	if (cr->n_r == cr->m_r)
		EXPAND(cr->r, cr->m_r);
	p = &cr->r[cr->n_r++];
	p->x = st;
	p->real_y = en;
	p->label = label;
	if (cr->len < en)
		cr->len = en;
	return p;
}

void cr_sort(cgranges_t *cr)
{
	// if (cr->n_ctg == 0 || cr->n_r == 0) return;
	if (cr->n_r == 0) return;
	radix_sort_cr_intv(cr->r, cr->r + cr->n_r);
}

int32_t cr_is_sorted(const cgranges_t *cr)
{
	uint64_t i;
	for (i = 1; i < cr->n_r; ++i)
		if (cr->r[i-1].x > cr->r[i].x)
			break;
	return (i == cr->n_r);
}

/************
 * Indexing *
 ************/

int64_t cr_index1(cr_intv_t *a, int64_t n)
{
	int64_t i, last_i;
	uint64_t last;
	int64_t k;
	if (n <= 0) return -1;
	for (i = 0; i < n; i += 2) last_i = i, last = a[i].y = (a[i].real_y);
	for (k = 1; 1LL<<k <= n; ++k) {
		int64_t x = 1LL<<(k-1), i0 = (x<<1) - 1, step = x<<2;
		for (i = i0; i < n; i += step) {
			uint64_t el = a[i - x].y;
			uint64_t er = i + x < n? a[i + x].y : last;
			uint64_t e = a[i].real_y;
			e = e > el? e : el;
			e = e > er? e : er;
			a[i].y = e;
		}
		last_i = last_i>>k&1? last_i - x : last_i + x;
		if (last_i < n && a[last_i].y > last)
			last = a[last_i].y;
	}
	return k - 1;
}

void cr_index(cgranges_t *cr)
{
	if (!cr_is_sorted(cr)) cr_sort(cr);
	cr->root_k = cr_index1(cr->r, cr->n_r);
}

/*********
 * Query *
 *********/

// int64_t cr_min_start_int(const cgranges_t *cr, int32_t ctg_id, int32_t st) // find the smallest i such that cr_st(&r[i]) >= st
// {
// 	int64_t left, right;
// 	const cr_ctg_t *c;
// 	const cr_intv_t *r;

// 	if (ctg_id < 0 || ctg_id >= cr->n_ctg) return -1;
// 	c = &cr->ctg[ctg_id];
// 	r = &cr->r[c->off];
// 	if (c->n == 0) return -1;
// 	left = 0, right = c->n;
// 	while (right > left) {
// 		int64_t mid = left + ((right - left) >> 1);
// 		if (cr_st(&r[mid]) >= st) right = mid;
// 		else left = mid + 1;
// 	}
// 	assert(left == right);
// 	return left == c->n? -1 : c->off + left;
// }

typedef struct {
	int64_t x;
	int64_t k, w;
} istack_t;

int64_t cr_overlap_int(const cgranges_t *cr, uint64_t st, uint64_t en, int64_t **b_, int64_t *m_b_)
{
	int32_t t = 0;
	const cr_intv_t *r;
	int64_t *b = *b_, m_b = *m_b_, n = 0;
	istack_t stack[64], *p;

	r = cr->r;
	p = &stack[t++];
	p->k = cr->root_k, p->x = (1LL<<p->k) - 1, p->w = 0; // push the root into the stack
	while (t) { // stack is not empyt
		istack_t z = stack[--t];
		if (z.k <= 3) { // the subtree is no larger than (1<<(z.k+1))-1; do a linear scan
			int64_t i, i0 = z.x >> z.k << z.k, i1 = i0 + (1LL<<(z.k+1)) - 1;
			if (i1 >= cr->n_r) i1 = cr->n_r;
			for (i = i0; i < i1 && cr_st(&r[i]) < en; ++i)
				if (st < cr_en(&r[i])) {
					if (n == m_b) EXPAND(b, m_b);
					b[n++] = i;
				}
		} else if (z.w == 0) { // if left child not processed
			int64_t y = z.x - (1LL<<(z.k-1));
			p = &stack[t++];
			p->k = z.k, p->x = z.x, p->w = 1;
			if (y >= cr->n_r || r[y].y > st) {
				p = &stack[t++];
				p->k = z.k - 1, p->x = y, p->w = 0; // push the left child to the stack
			}
		} else if (z.x < cr->n_r && cr_st(&r[z.x]) < en) {
			if (st < cr_en(&r[z.x])) { // then z.x overlaps the query; write to the output array
				if (n == m_b) EXPAND(b, m_b);
				b[n++] = z.x;
			}
			p = &stack[t++];
			p->k = z.k - 1, p->x = z.x + (1LL<<(z.k-1)), p->w = 0; // push the right child
		}
	}
	*b_ = b, *m_b_ = m_b;
	return n;
}

// int64_t cr_contain_int(const cgranges_t *cr, int32_t ctg_id, int32_t st, int32_t en, int64_t **b_, int64_t *m_b_)
// {
// 	int64_t n = 0, i, s, e, *b = *b_, m_b = *m_b_;
// 	s = cr_min_start_int(cr, ctg_id, st);
// 	if (s < 0) return 0;
// 	e = cr->ctg[ctg_id].off + cr->ctg[ctg_id].n;
// 	for (i = s; i < e; ++i) {
// 		const cr_intv_t *r = &cr->r[i];
// 		if (cr_st(r) >= en) break;
// 		if (cr_st(r) >= st && cr_en(r) <= en) {
// 			if (n == m_b) EXPAND(b, m_b);
// 			b[n++] = i;
// 		}
// 	}
// 	*b_ = b, *m_b_ = m_b;
// 	return n;
// }

// int64_t cr_min_start(const cgranges_t *cr, const char *ctg, int32_t st)
// {
// 	return cr_min_start_int(cr, cr_get_ctg(cr, ctg), st);
// }

int64_t cr_overlap(const cgranges_t *cr, uint64_t st, uint64_t en, int64_t **b_, int64_t *m_b_)
{
	return cr_overlap_int(cr, st, en, b_, m_b_);
}

// int64_t cr_contain(const cgranges_t *cr, const char *ctg, int32_t st, int32_t en, int64_t **b_, int64_t *m_b_)
// {
// 	return cr_contain_int(cr, cr_get_ctg(cr, ctg), st, en, b_, m_b_);
// }

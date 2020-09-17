/*
 *
 * Copyright (c) 2020
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2020-09-01
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#include "FQDN_engine.h"
#include <math.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*************************************************************************************/
#include <nmmintrin.h>
#define popcnt_u64 _mm_popcnt_u64

#define FOR(i, n) for(int i=0, _n=(int)(n); i<_n; i++)

struct packedRT_t
{
	unsigned long long bitmap[4];
	unsigned int A;
	unsigned char B[4];
};

void * aligned_malloc(size_t size, size_t align)
{
	void * malloc_ptr;
	void * aligned_ptr;

	/* Error if align is not a power of two.  */
	if (align & (align - 1))
	{
		return ((void*) 0);
	}

	if (align==0 || size == 0)
	{
		return ((void *) 0);
	}

	malloc_ptr = malloc (sizeof(void *) + align - 1 + size);
	if (!malloc_ptr)
	{
		return ((void *) 0);
	}

	aligned_ptr = (void *) (((size_t)malloc_ptr + sizeof(void *) + align-1) & ~(align-1));
  
	((void **) aligned_ptr) [-1] = malloc_ptr;

	return aligned_ptr;
}

void aligned_free(void * aligned_ptr)
{
	if (aligned_ptr)
	{
		free (((void **) aligned_ptr) [-1]);
	}
}

/*************************************************************************************/
struct domain_impl_t
{
	unsigned int       id;
	int                suf_match;
	unsigned int       len;
	unsigned long long hash; /*用64位哈希值唯一表示一个域名*/
	domain_impl_t *    next;
	void *             utag;	
};

class CHashTrieFQDN
{
public:
	CHashTrieFQDN();
	~CHashTrieFQDN();

	int initialize(const struct FQDN_rule * rules, size_t n_rule);
	int search(const char * FQDN, size_t FQDN_len, struct FQDN_match * results, size_t n_result);

protected:
	unsigned int rank(unsigned int h);

protected:
	unsigned int         m_num;
	domain_impl_t *      m_domains;
	unsigned int         m_H;
	unsigned int         m_max_pat_len;
	unsigned long long * m_B;
	packedRT_t *         m_RT;
	domain_impl_t **     m_matched;
	unsigned char        m_case_tab[256];
};


const unsigned long long ONE=1;

#define is_bit_set(tbl, off)    ( tbl[off>>6] & ( ONE<<(off&63) ) )
#define set_bit(tbl, off)       ( tbl[off>>6] |= ( ONE<<(off&63) ) )

const unsigned long long A=6364136223846793005LL;

CHashTrieFQDN::CHashTrieFQDN()
{
	m_num=0;
	m_domains=NULL;
	m_B=NULL;
	m_RT=NULL;
	m_matched=NULL;
	FOR(c, 256) m_case_tab[c]=tolower(c);
}

CHashTrieFQDN::~CHashTrieFQDN()
{
	if(m_domains!=NULL)
	{
		delete [] m_domains;
	}

	if(m_B!=NULL)
	{
		delete [] m_B;
	}

	if(m_RT!=NULL)
	{
		aligned_free(m_RT);
	}

	if(m_matched!=NULL)
	{
		delete [] m_matched;
	}
}

int CHashTrieFQDN::initialize(const struct FQDN_rule * rules, size_t n_rule)
{
	long long mem_bytes=0;

	if(n_rule==0) return -1;
	m_num=n_rule;
	m_domains=new domain_impl_t[m_num];
	mem_bytes+=m_num*sizeof(domain_impl_t);

	unsigned int N=m_num;
	m_max_pat_len=0;

	FOR(k, m_num)
	{
		m_domains[k].id =rules[k].id;
		m_domains[k].suf_match=rules[k].is_suffix_match;
		m_domains[k].len=rules[k].len;
		m_domains[k].next=NULL;
		m_domains[k].utag=rules[k].user_tag;		

		FOR(j, rules[k].len)
		{			
			if(rules[k].FQDN[j]=='.') ++N;
		}

		if(m_max_pat_len<rules[k].len)
		{
			m_max_pat_len=rules[k].len;
		}
	}

	unsigned int w=(int)(log10((double)N)/log10(2.0)+0.5)+4;
	if(w<8) w=8;
	m_H=(1U<<w);

	m_B=new unsigned long long[m_H>>6];
	mem_bytes+=(m_H>>6)*sizeof(unsigned long long);
	FOR(i, (m_H>>6)) m_B[i]=0;

	m_RT=(packedRT_t *)aligned_malloc(sizeof(packedRT_t)*((m_H>>8)+1), 64);
	mem_bytes+=((m_H>>8)+1)*sizeof(packedRT_t);
	FOR(i, (m_H>>8))
	{
		FOR(j, 4) m_RT[i].bitmap[j]=0;
	}

	FOR(k, m_num)
	{
		const unsigned char * pb=(const unsigned char *)rules[k].FQDN;
		m_domains[k].hash=0;

		for(int j=rules[k].len-1; j>=-1; --j)
		{
			if(j==-1 || pb[j]=='.')
			{
				unsigned int h=m_domains[k].hash&(m_H-1);
				set_bit(m_B, h);
				if(j==-1)
				{
					int q=h&255;
					m_RT[h>>8].bitmap[q>>6]|=(ONE<<(q&63));
				}
			}
			else
			{
				m_domains[k].hash=A*m_domains[k].hash+m_case_tab[pb[j]];
			}
		}
	}

	m_RT[0].A=0;
	FOR(i, (m_H>>8))
	{
		m_RT[i].B[0]=0;
		m_RT[i].B[1]=                      popcnt_u64(m_RT[i].bitmap[0]);
		m_RT[i].B[2]=         m_RT[i].B[1]+popcnt_u64(m_RT[i].bitmap[1]);
		m_RT[i].B[3]=         m_RT[i].B[2]+popcnt_u64(m_RT[i].bitmap[2]);
		m_RT[i+1].A=m_RT[i].A+m_RT[i].B[3]+popcnt_u64(m_RT[i].bitmap[3]);
	}

	int tn=m_RT[m_H>>8].A;

	m_matched=new domain_impl_t *[tn];
	mem_bytes+=tn*sizeof(domain_impl_t *);
	FOR(i, tn) m_matched[i]=NULL;

	FOR(k, m_num)
	{
		unsigned int h=m_domains[k].hash&(m_H-1);
		unsigned idx=rank(h);
		m_domains[k].next=m_matched[idx];
		m_matched[idx]=&(m_domains[k]);
	}

	printf("mem_bytes=%u(MB)\n", mem_bytes/(1U<<20));

	return 1;
}

unsigned int CHashTrieFQDN::rank(unsigned int h)
{
	int p=(h>>8);
	int r=((h&255)>>6);
	int s=(h&63);
	unsigned long long e=m_RT[p].bitmap[r]&((ONE<<s)-1);

	return m_RT[p].A+m_RT[p].B[r]+popcnt_u64(e);
}

int CHashTrieFQDN::search(const char * FQDN, size_t FQDN_len, struct FQDN_match * results, size_t n_result)
{
	if(m_num==0 || FQDN_len==0 || FQDN==NULL || n_result==0) return -1;

	int match_num=0;
	const unsigned char * pb=(unsigned char *)FQDN;
	unsigned long long HASH[16]; /*假设域名级数不超过16*/
	unsigned int P[16];
	int t=0;
	unsigned long long hash=0;
	for(int j=FQDN_len-1; j>=-1; --j)
	{
		if(j==-1 || pb[j]=='.')
		{
			unsigned int h=hash&(m_H-1);
			if(is_bit_set(m_B, h)==0) break;
			HASH[t]=hash;
			P[t]=j+1;
			++t;
		}
		else if(j+m_max_pat_len<FQDN_len) break;
		else
		{
			hash=A*hash+m_case_tab[pb[j]];
		}
	}

	for(--t; t>=0; t--)
	{
		unsigned int h=HASH[t]&(m_H-1);
		int q=h&255;

		if(m_RT[h>>8].bitmap[q>>6]&(ONE<<(q&63)))
		{
			unsigned idx=rank(h);

			for(domain_impl_t * pt=m_matched[idx]; pt!=NULL; pt=pt->next)
			{
				if(P[t]!=0 && pt->suf_match==0) continue;
				if(pt->len+P[t]==FQDN_len && pt->hash==HASH[t])
				{
					if(match_num>0 && P[t]!=results[match_num-1].offset) return match_num;
					results[match_num].id=pt->id;
					results[match_num].offset=P[t];
					results[match_num].user_tag=pt->utag;
					++match_num;
					if(match_num==n_result) return match_num;
				}
			}
		}
	}

	return match_num;
}

/*************************************************************************************/
struct FQDN_engine
{
	CHashTrieFQDN ht;
};

struct FQDN_engine * FQDN_engine_new(const struct FQDN_rule * rules, size_t n_rule)
{
	struct FQDN_engine * instance=new struct FQDN_engine;
	if(instance->ht.initialize(rules, n_rule)<0)
	{
		delete instance;
		return NULL;
	}
	else
	{
		return instance;
	}
}

int FQDN_engine_search(struct FQDN_engine * instance, const char * FQDN, size_t FQDN_len, struct FQDN_match * results, size_t n_result)
{
	if(instance==NULL) return -1;
	return instance->ht.search(FQDN, FQDN_len, results, n_result);
}

void FQDN_engine_free(struct FQDN_engine * instance)
{
	if(instance!=NULL) delete instance;
}

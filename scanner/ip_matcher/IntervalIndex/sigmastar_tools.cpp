#include "sigmastar_tools.h"
#include <stdlib.h>
#include <stdio.h>

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

unsigned char popcnt_u16[65536];
unsigned char popcnt_u32(unsigned int x)
{
	char c=0;
	while(x)
	{
		if(x&1) c++;
		x>>=1;
	}
	return c;
}

#ifndef USE_SSE_INSTR
int popcnt_u64(unsigned long long x)
{
	return  popcnt_u16[x&0xFFFF]
	       +popcnt_u16[(x>>16)&0xFFFF]
		   +popcnt_u16[(x>>32)&0xFFFF]
		   +popcnt_u16[(x>>48)&0xFFFF];
}
#endif

int initialize_sigmastar_tools()
{
	for(unsigned int i=0; i<65536; i++)
	{
		popcnt_u16[i]=popcnt_u32(i);
	}
	return 1;
}


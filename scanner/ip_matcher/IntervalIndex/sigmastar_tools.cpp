#include "sigmastar_tools.h"
#include <stdlib.h>
#include <stdio.h>

static unsigned char popcnt_u16[65536];

#ifndef USE_SSE_INSTR
int popcnt_u64(unsigned long long x)
{
	return  popcnt_u16[x&0xFFFF]
	       +popcnt_u16[(x>>16)&0xFFFF]
		   +popcnt_u16[(x>>32)&0xFFFF]
		   +popcnt_u16[(x>>48)&0xFFFF];
}
#endif
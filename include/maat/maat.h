#pragma once

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdint.h>
#include <netinet/in.h>

struct maat_feather;

/* network-order */
struct ipv4_tuple4{
        uint32_t saddr;   /* network order */
        uint32_t daddr;   /* network order */
        uint16_t source;  /* network order */
        uint16_t dest;    /* network order */
};

#define IPV6_ADDR_LEN   (sizeof(struct in6_addr))

struct ipv6_tuple4
{
        uint8_t saddr[IPV6_ADDR_LEN] ;
        uint8_t daddr[IPV6_ADDR_LEN] ;
        uint16_t source;  /* network order */
        uint16_t dest;    /* network order */
};

struct maat_scan_state;
int maat_scan_ipv4(struct maat_feather *feather, int table_id, struct maat_scan_state *state, 
                   const struct ipv4_tuple4 *tuple4, unsigned int *matched_ids, size_t n_match_id);

int maat_scan_string(struct maat_feather *feather, int table_id, struct maat_scan_state *state, 
                     const char *data, size_t length);

#ifdef __cpluscplus
}
#endif
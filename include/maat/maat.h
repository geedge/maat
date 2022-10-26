#pragma once
struct maat_feather;
/* network-order */
struct ipv4_tuple4{
        UINT32 saddr;   /* network order */
        UINT32 daddr;   /* network order */
        UINT16 source;  /* network order */
        UINT16 dest;    /* network order */
};

#define IPV6_ADDR_LEN   (sizeof(struct in6_addr))

struct ipv6_tuple4
{
        UCHAR saddr[IPV6_ADDR_LEN] ;
        UCHAR daddr[IPV6_ADDR_LEN] ;
        UINT16 source;  /* network order */
        UINT16 dest;    /* network order */
};
struct maat_scan_state;
int maat_scan_ipv4(struct maat_feather *feather, struct maat_scan_state *state, const struct ipv4_tuple4 *tuple4, unsigned int *matched_ids, size_t n_match_id);
int maat_scan_string(struct maat_feather *feather, struct maat_scan_state *state, const char *data, size_t length, )


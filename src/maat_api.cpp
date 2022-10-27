#include <stdio.h>
#include <hs/hs.h>

#include "../include/maat/maat.h"

int maat_scan_ipv4(struct maat_feather *feather, struct maat_scan_state *state, 
                   const struct ipv4_tuple4 *tuple4, unsigned int *matched_ids, size_t n_match_id)
{
    return 0;
}

int maat_scan_string(struct maat_feather *feather, int table_id, struct maat_scan_state *state, 
                     const char *data, size_t length)
{
    return 0;
}

int maat_hyperscan_compile(char *pattern)
{
    hs_database_t *database;
    hs_compile_error_t *compile_err;
    if (hs_compile(pattern, HS_FLAG_DOTALL, HS_MODE_BLOCK, NULL, &database,
                   &compile_err) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to compile pattern \"%s\": %s\n",
                pattern, compile_err->message);
        hs_free_compile_error(compile_err);
        return -1;
    }

    return 0;
}
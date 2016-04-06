#ifndef _MESA_FUZZY_
#define _MESA_FUZZY_

/*
 * Copyright (C) MESA 2015
 *
 * These functions allow a programmer to compute the fuzzy hashes
 * (also called the context-triggered piecewise hashes) of
 * buffer[s] of text.
 *
 * See also:
 * ssdeep, and
 * Identifying almost identical files using context triggered piecewise hashing
 *
 */

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOTAL_LENGTH     0
#define EFFECTIVE_LENGTH 1
#define HASH_LENGTH      2

// typedef fuzzy_handle_t void*;
typedef struct
{
}fuzzy_handle_t;

/**
 * create a fuzzy hash handle and return it.
 * @return        [handle]
 */
fuzzy_handle_t * fuzzy_create_handle(unsigned long long origin_len);

/**
 * destroy context by a fuzzy hash handle.
 * @param handle  [handle]
 */
void fuzzy_destroy_handle(fuzzy_handle_t * handle);

/**
 * Feed the function your data.
 * Call this function several times, if you have several parts of data to feed.
 * @param  handle [handle]
 * @param  data   [data that you want to fuzzy_hash]
 * @param  size   [data size]
 * @param  offset [offset]
 * @return        [return effective data length in current feed]
 */
unsigned int fuzzy_feed(fuzzy_handle_t * handle, const char* data, unsigned int size, unsigned long long offset);

/**
 * Obtain the fuzzy hash values.
 * @param  handle  [handle]
 * @param  result  [fuzzy hash result]
 *     Fuzzy hash result with offsets(in the square brackets, with colon splitted).
 *     eg. abc[1:100]def[200:300]
 * @param  size    [@result size]
 * @return         [return zero on success, non-zero on error]
 */
int fuzzy_digest(fuzzy_handle_t * handle, char* result, unsigned int size);

/**
 * Obtain certain length of fuzzy hash status.
 * @param  handle [handle]
 * @param  type   [length type]
     * TOTAL_LENGTH:Total length of data you have fed.
     *     Overlapped data will NOT count for 2 times.
     * EFFECTIVE_LENGTH:Length of data that involved in the calculation of hash.
     * HASH_LENGTH:Hash result length.
 * @return        [length value]
 */
unsigned long long fuzzy_status(fuzzy_handle_t * handle, int type);


#ifdef __cplusplus
}
#endif

#endif


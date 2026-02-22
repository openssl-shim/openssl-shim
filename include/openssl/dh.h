#pragma once

/*
 * Minimal DH compatibility header.
 *
 * OpenSSL 3.x code paths in our target libraries do not require low-level
 * DH APIs. We only expose the opaque type for compatibility with includes.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dh_st DH;

#ifdef __cplusplus
}
#endif

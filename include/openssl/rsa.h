#pragma once

/*
 * Minimal RSA compatibility header.
 *
 * OpenSSL 3.x code paths in our target libraries do not require low-level
 * RSA APIs. We only expose the opaque type for compatibility with includes.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rsa_st RSA;

#ifdef __cplusplus
}
#endif

#pragma once

/*
 * Minimal DH compatibility header.
 *
 * OpenSSL 3.x code paths in our target libraries do not require low-level
 * DH APIs. We only expose the opaque type for compatibility with includes.
 */

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int pem_password_cb(char* buf, int size, int rwflag, void* userdata);

typedef struct dh_st {
  int placeholder;
} DH;

DH* PEM_read_DHparams(FILE* fp, DH** x, pem_password_cb* cb, void* u);
void DH_free(DH* dh);

#ifdef __cplusplus
}
#endif

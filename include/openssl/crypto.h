#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void* OPENSSL_malloc(size_t size);
void  OPENSSL_free(void* ptr);
void  OPENSSL_cleanse(void* ptr, size_t len);
void  OPENSSL_thread_stop(void);

/* Kept for source compatibility with legacy callback code paths. */
#define CRYPTO_LOCK 1

#ifdef __cplusplus
}
#endif

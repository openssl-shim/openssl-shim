#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_LIB_SSL   20
#define ERR_LIB_PEM    9
#define ERR_LIB_EVP    6
#define ERR_LIB_X509  11

#define ERR_R_PEM_LIB 108

#define ERR_GET_LIB(l)    ((int)(((l) >> 24) & 0xFF))
#define ERR_GET_REASON(l) ((int)((l) & 0xFFFFFF))
#define ERR_PACK(lib, func, reason) \
  ((((unsigned long)((lib) & 0xFF)) << 24) | ((unsigned long)((reason) & 0xFFFFFF)))

/* OpenSSL 3 stores system errors as packed values in the same code-path. */
#define ERR_SYSTEM_FLAG 0x80000000UL
#define ERR_SYSTEM_ERROR(errcode) (((unsigned long)(errcode) & ERR_SYSTEM_FLAG) != 0)

unsigned long ERR_get_error(void);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_last_error(void);
void          ERR_error_string_n(unsigned long e, char* buf, size_t len);
char*         ERR_error_string(unsigned long e, char* buf);
const char*   ERR_lib_error_string(unsigned long e);
const char*   ERR_reason_error_string(unsigned long e);
void          ERR_clear_error(void);

#ifdef __cplusplus
}
#endif

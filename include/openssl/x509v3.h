#pragma once

#include "x509.h"

#ifdef __cplusplus
extern "C" {
#endif

void* X509_get_ext_d2i(X509* x, int nid, int* crit, int* idx);

#ifdef __cplusplus
}
#endif

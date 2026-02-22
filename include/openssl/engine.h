#pragma once

/*
 * Minimal ENGINE compatibility header.
 *
 * native-tls-shim targets OpenSSL 3.x style code paths and does not expose
 * legacy ENGINE APIs.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct engine_st ENGINE;

#ifdef __cplusplus
}
#endif

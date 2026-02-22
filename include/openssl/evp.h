#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;

#define EVP_MAX_MD_SIZE 64
#define EVP_R_EXPECTING_AN_RSA_KEY 147

EVP_MD_CTX* EVP_MD_CTX_new(void);
void        EVP_MD_CTX_free(EVP_MD_CTX* ctx);

int         EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void* engine);
int         EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt);
int         EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s);

const EVP_MD* EVP_md5(void);
const EVP_MD* EVP_sha256(void);
const EVP_MD* EVP_sha512(void);

EVP_PKEY* d2i_PrivateKey_bio(BIO* bp, EVP_PKEY** a);
int       EVP_PKEY_is_a(const EVP_PKEY* pkey, const char* name);
void      EVP_PKEY_free(EVP_PKEY* pkey);

#ifdef __cplusplus
}
#endif

#pragma once

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ssl_ctx_st;

typedef struct x509_st X509;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_name_st X509_NAME;
typedef struct x509_name_entry_st X509_NAME_ENTRY;
typedef struct x509_object_st X509_OBJECT;
typedef struct x509_verify_param_st X509_VERIFY_PARAM;
typedef struct x509_crl_st X509_CRL;

typedef struct asn1_string_st ASN1_STRING;
typedef ASN1_STRING ASN1_INTEGER;
typedef struct asn1_time_st ASN1_TIME;

typedef struct general_name_st GENERAL_NAME;
typedef struct stack_st_GENERAL_NAME STACK_OF_GENERAL_NAME;
typedef struct stack_st_GENERAL_NAME GENERAL_NAMES;
typedef struct stack_st_X509_OBJECT STACK_OF_X509_OBJECT;
typedef struct stack_st_X509_NAME STACK_OF_X509_NAME;
typedef struct x509_info_st X509_INFO;
typedef struct stack_x509_info_st STACK_OF_X509_INFO;

struct x509_info_st {
    X509* x509;
    X509_CRL* crl;
};

#define STACK_OF(type) struct stack_st_##type

/* NIDs and constants used by cpp-httplib / IXWebSocket */
#define NID_commonName        13
#define NID_subject_alt_name  85

#define GEN_OTHERNAME  0
#define GEN_EMAIL      1
#define GEN_DNS        2
#define GEN_X400       3
#define GEN_DIRNAME    4
#define GEN_EDIPARTY   5
#define GEN_URI        6
#define GEN_IPADD      7
#define GEN_RID        8

#define X509_V_OK                          0
#define X509_V_ERR_UNSPECIFIED             1
#define X509_V_ERR_CERT_HAS_EXPIRED       10
#define X509_V_ERR_CERT_NOT_YET_VALID      9
#define X509_V_ERR_CERT_REVOKED           23
#define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT 18
#define X509_V_ERR_HOSTNAME_MISMATCH      62

#define X509_R_CERT_ALREADY_IN_HASH_TABLE 101

#define X509_V_FLAG_TRUSTED_FIRST 0x8000
#define X509_V_FLAG_PARTIAL_CHAIN 0x80000

#define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4

#define X509_LU_X509 1

/* ASN1 string/time */
const unsigned char* ASN1_STRING_get0_data(const ASN1_STRING* x);
unsigned char*       ASN1_STRING_data(ASN1_STRING* x);
int                  ASN1_STRING_length(const ASN1_STRING* x);

ASN1_TIME* ASN1_TIME_new(void);
void       ASN1_TIME_free(ASN1_TIME* t);
ASN1_TIME* ASN1_TIME_set(ASN1_TIME* s, time_t t);
int        ASN1_TIME_diff(int* pday, int* psec, const ASN1_TIME* from,
                          const ASN1_TIME* to);

/* BN helpers for serial conversion */
typedef struct bignum_st BIGNUM;
BIGNUM* ASN1_INTEGER_to_BN(const ASN1_INTEGER* ai, BIGNUM* bn);
char*   BN_bn2hex(const BIGNUM* a);
void    BN_free(BIGNUM* a);

/* Certificate lifecycle and inspection */
X509* d2i_X509(X509** px, const unsigned char** in, int len);
int   i2d_X509(const X509* x, unsigned char** out);

void X509_free(X509* cert);
int  X509_up_ref(X509* cert);

X509_NAME* X509_get_subject_name(const X509* x);
X509_NAME* X509_get_issuer_name(const X509* x);
ASN1_INTEGER* X509_get_serialNumber(X509* x);
const ASN1_TIME* X509_get0_notBefore(const X509* x);
const ASN1_TIME* X509_get0_notAfter(const X509* x);

char* X509_NAME_oneline(const X509_NAME* a, char* buf, int size);
int   X509_NAME_get_text_by_NID(X509_NAME* name, int nid, char* buf, int len);
X509_NAME* X509_NAME_dup(const X509_NAME* name);
void  X509_NAME_free(X509_NAME* name);

int X509_check_host(X509* x, const char* chk, size_t chklen,
                    unsigned int flags, char** peername);
int X509_check_ip_asc(X509* x, const char* ipasc, unsigned int flags);

const char* X509_verify_cert_error_string(long n);

/********** X509 store **********/
X509_STORE* SSL_CTX_get_cert_store(const struct ssl_ctx_st* ctx);
void        SSL_CTX_set_cert_store(struct ssl_ctx_st* ctx, X509_STORE* store);

X509_STORE* X509_STORE_new(void);
void        X509_STORE_free(X509_STORE* store);
int         X509_STORE_add_cert(X509_STORE* store, X509* cert);
int         X509_STORE_add_crl(X509_STORE* store, X509_CRL* crl);
void        X509_STORE_set_flags(X509_STORE* store, unsigned long flags);

STACK_OF_X509_OBJECT* X509_STORE_get0_objects(const X509_STORE* store);
int                   X509_OBJECT_get_type(const X509_OBJECT* obj);
X509*                 X509_OBJECT_get0_X509(const X509_OBJECT* obj);

int         sk_X509_OBJECT_num(const STACK_OF_X509_OBJECT* st);
X509_OBJECT* sk_X509_OBJECT_value(const STACK_OF_X509_OBJECT* st, int i);

/********** X509 verify param **********/
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const char* name, size_t namelen);
void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM* param, unsigned int flags);

/********** X509 store ctx (verify callback compatibility) **********/
X509* X509_STORE_CTX_get_current_cert(X509_STORE_CTX* ctx);
int   X509_STORE_CTX_get_error(X509_STORE_CTX* ctx);
int   X509_STORE_CTX_get_error_depth(X509_STORE_CTX* ctx);
void* X509_STORE_CTX_get_ex_data(X509_STORE_CTX* ctx, int idx);

/********** GENERAL_NAME stack **********/
struct general_name_st {
    int type;
    union {
        ASN1_STRING* ptr;
        ASN1_STRING* ia5;
        ASN1_STRING* dNSName;
        ASN1_STRING* iPAddress;
        ASN1_STRING* rfc822Name;
        ASN1_STRING* uniformResourceIdentifier;
    } d;
};

int           native_sk_GENERAL_NAME_num(const STACK_OF_GENERAL_NAME* st);
GENERAL_NAME* native_sk_GENERAL_NAME_value(const STACK_OF_GENERAL_NAME* st, int i);
#define sk_GENERAL_NAME_num(st)      native_sk_GENERAL_NAME_num(st)
#define sk_GENERAL_NAME_value(st, i) native_sk_GENERAL_NAME_value(st, i)
void          sk_GENERAL_NAME_pop_free(STACK_OF_GENERAL_NAME* st,
                                       void (*freefn)(GENERAL_NAME*));
void          GENERAL_NAME_free(GENERAL_NAME* a);
void          GENERAL_NAMES_free(STACK_OF_GENERAL_NAME* st);

/********** X509_NAME stack **********/
STACK_OF_X509_NAME* sk_X509_NAME_new_null(void);
int                 sk_X509_NAME_push(STACK_OF_X509_NAME* sk, X509_NAME* name);
int                 sk_X509_NAME_num(const STACK_OF_X509_NAME* sk);
void                sk_X509_NAME_free(STACK_OF_X509_NAME* sk);
void                sk_X509_NAME_pop_free(STACK_OF_X509_NAME* sk,
                                          void (*free_fn)(X509_NAME*));

/********** X509_INFO stack **********/
int         sk_X509_INFO_num(const STACK_OF_X509_INFO* st);
X509_INFO*  sk_X509_INFO_value(const STACK_OF_X509_INFO* st, int i);
void        X509_INFO_free(X509_INFO* info);
void        sk_X509_INFO_pop_free(STACK_OF_X509_INFO* st,
                                  void (*freefn)(X509_INFO*));

/* legacy helper */
STACK_OF_X509_NAME* SSL_load_client_CA_file(const char* file);

#ifdef __cplusplus
}
#endif

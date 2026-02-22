#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bio.h"
#include "crypto.h"
#include "evp.h"
#include "pem.h"
#include "x509.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_session_st SSL_SESSION;
typedef struct evp_pkey_st EVP_PKEY;

typedef int pem_password_cb(char* buf, int size, int rwflag, void* userdata);

/* OpenSSL compatibility constants */
#define SSL_ERROR_NONE           0
#define SSL_ERROR_SSL            1
#define SSL_ERROR_WANT_READ      2
#define SSL_ERROR_WANT_WRITE     3
#define SSL_ERROR_WANT_X509_LOOKUP 4
#define SSL_ERROR_SYSCALL        5
#define SSL_ERROR_ZERO_RETURN    6
#define SSL_ERROR_WANT_CONNECT   7
#define SSL_ERROR_WANT_ACCEPT    8

#define SSL_VERIFY_NONE          0x00
#define SSL_VERIFY_PEER          0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE   0x04

#define SSL_MODE_ENABLE_PARTIAL_WRITE        0x00000001L
#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER  0x00000002L
#define SSL_MODE_AUTO_RETRY                  0x00000004L
#define SSL_MODE_RELEASE_BUFFERS             0x00000010L

#define SSL_OP_ALL                               0x80000U
#define SSL_OP_NO_SSLv2                          0x01000000U
#define SSL_OP_NO_SSLv3                          0x02000000U
#define SSL_OP_NO_TLSv1                          0x04000000U
#define SSL_OP_NO_TLSv1_1                        0x10000000U
#define SSL_OP_NO_TLSv1_2                        0x08000000U
#define SSL_OP_NO_TLSv1_3                        0x20000000U
#define SSL_OP_NO_COMPRESSION                    0x00020000U
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION 0x00010000U
#define SSL_OP_CIPHER_SERVER_PREFERENCE          0x00400000U
#define SSL_OP_SINGLE_DH_USE                     0x00100000U

#define SSL_FILETYPE_PEM  1
#define SSL_FILETYPE_ASN1 2

#define SSL_SESS_CACHE_OFF 0x0000

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name 0

#define SSL_SENT_SHUTDOWN     0x01
#define SSL_RECEIVED_SHUTDOWN 0x02

#define SSL3_VERSION   0x0300
#define TLS1_VERSION   0x0301
#define TLS1_1_VERSION 0x0302
#define TLS1_2_VERSION 0x0303
#define TLS1_3_VERSION 0x0304

#define SSL_TXT_TLSV1   "TLSv1"
#define SSL_TXT_TLSV1_1 "TLSv1.1"
#define SSL_TXT_TLSV1_2 "TLSv1.2"

#define OPENSSL_INIT_LOAD_CONFIG 0x00000040L

/* Keep Asio from pulling <openssl/engine.h>. */
#ifndef OPENSSL_NO_ENGINE
#define OPENSSL_NO_ENGINE 1
#endif

#ifndef OPENSSL_NO_SSL2
#define OPENSSL_NO_SSL2 1
#endif

/* Methods */
const SSL_METHOD* TLS_method(void);
const SSL_METHOD* TLS_client_method(void);
const SSL_METHOD* TLS_server_method(void);
const SSL_METHOD* SSLv23_method(void);
const SSL_METHOD* SSLv23_client_method(void);
const SSL_METHOD* SSLv23_server_method(void);

/* Global init */
int OPENSSL_init_ssl(uint64_t opts, const void* settings);
int OpenSSL_add_ssl_algorithms(void);
int SSL_load_error_strings(void);
void OPENSSL_thread_stop(void);

/* SSL_CTX lifecycle */
SSL_CTX* SSL_CTX_new(const SSL_METHOD* method);
void     SSL_CTX_free(SSL_CTX* ctx);

/* SSL_CTX config */
void SSL_CTX_set_verify(SSL_CTX* ctx, int mode,
                        int (*verify_callback)(int, X509_STORE_CTX*));
int  SSL_CTX_get_verify_mode(const SSL_CTX* ctx);
int  (*SSL_CTX_get_verify_callback(const SSL_CTX* ctx))(int, X509_STORE_CTX*);
void SSL_CTX_set_verify_depth(SSL_CTX* ctx, int depth);
long SSL_CTX_set_mode(SSL_CTX* ctx, long mode);
long SSL_CTX_clear_mode(SSL_CTX* ctx, long mode);
long SSL_CTX_set_options(SSL_CTX* ctx, long options);
long SSL_CTX_clear_options(SSL_CTX* ctx, long options);
int  SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, int mode);
int  SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* str);
int  SSL_CTX_set_ciphersuites(SSL_CTX* ctx, const char* str);
int  SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* ca_file, const char* ca_path);
int  SSL_CTX_set_default_verify_paths(SSL_CTX* ctx);
int  SSL_CTX_default_verify_paths(SSL_CTX* ctx);
int  SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int type);
int  SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file);
int  SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type);
int  SSL_CTX_use_certificate(SSL_CTX* ctx, X509* x);
int  SSL_CTX_use_certificate_ASN1(SSL_CTX* ctx, int len, const unsigned char* d);
int  SSL_CTX_use_PrivateKey(SSL_CTX* ctx, EVP_PKEY* pkey);
int  SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX* ctx, const unsigned char* d, long len);
int  SSL_CTX_check_private_key(const SSL_CTX* ctx);
void SSL_CTX_set_default_passwd_cb(SSL_CTX* ctx, pem_password_cb* cb);
pem_password_cb* SSL_CTX_get_default_passwd_cb(SSL_CTX* ctx);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX* ctx, void* u);
void* SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX* ctx);
void SSL_CTX_set_client_CA_list(SSL_CTX* ctx, struct stack_st_X509_NAME* list);
int  SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version);
int  SSL_CTX_set_max_proto_version(SSL_CTX* ctx, int version);
int  SSL_CTX_set_alpn_protos(SSL_CTX* ctx, const unsigned char* protos, unsigned int len);
int  SSL_CTX_add_extra_chain_cert(SSL_CTX* ctx, X509* x509);
void SSL_CTX_clear_chain_certs(SSL_CTX* ctx);
int  SSL_CTX_set0_tmp_dh_pkey(SSL_CTX* ctx, EVP_PKEY* pkey);

void  SSL_CTX_set_app_data(SSL_CTX* ctx, void* arg);
void* SSL_CTX_get_app_data(const SSL_CTX* ctx);

/* SSL lifecycle */
SSL* SSL_new(SSL_CTX* ctx);
void SSL_free(SSL* ssl);
int  SSL_set_fd(SSL* ssl, int fd);
void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio);
BIO* SSL_get_rbio(const SSL* ssl);
int  SSL_set_tlsext_host_name(SSL* ssl, const char* name);
long SSL_ctrl(SSL* ssl, int cmd, long larg, void* parg);
void SSL_set_verify(SSL* ssl, int mode,
                    int (*verify_callback)(int, X509_STORE_CTX*));
int  SSL_get_verify_mode(const SSL* ssl);
int  (*SSL_get_verify_callback(const SSL* ssl))(int, X509_STORE_CTX*);
void SSL_set_verify_depth(SSL* ssl, int depth);
long SSL_set_mode(SSL* ssl, long mode);
void SSL_clear_mode(SSL* ssl, long mode);
int  SSL_set_ecdh_auto(SSL* ssl, int onoff);
void SSL_set_app_data(SSL* ssl, void* arg);
void* SSL_get_app_data(const SSL* ssl);
SSL_CTX* SSL_get_SSL_CTX(const SSL* ssl);

/* Handshake / I/O */
int SSL_connect(SSL* ssl);
int SSL_accept(SSL* ssl);
int SSL_read(SSL* ssl, void* buf, int num);
int SSL_write(SSL* ssl, const void* buf, int num);
int SSL_peek(SSL* ssl, void* buf, int num);
int SSL_pending(const SSL* ssl);
int SSL_shutdown(SSL* ssl);
int SSL_get_shutdown(const SSL* ssl);
int SSL_get_error(const SSL* ssl, int ret);

/* Cert/verify */
X509* SSL_get_peer_certificate(const SSL* ssl);
X509* SSL_get1_peer_certificate(const SSL* ssl);
long  SSL_get_verify_result(const SSL* ssl);
X509_VERIFY_PARAM* SSL_get0_param(SSL* ssl);
int   SSL_get_ex_data_X509_STORE_CTX_idx(void);
const char* SSL_get_servername(const SSL* ssl, const int type);

void SSL_get0_alpn_selected(const SSL* ssl, const unsigned char** data, unsigned int* len);

#ifdef __cplusplus
}
#endif

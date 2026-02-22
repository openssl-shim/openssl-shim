#include "tls_internal.hpp"

#include "openssl/bio.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#if MBEDTLS_VERSION_MAJOR >= 3
#include <psa/crypto.h>
#endif

#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <cstddef>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

using native_tls::clear_error_message;
using native_tls::close_socket_fd;
using native_tls::extract_dn_component;
using native_tls::is_ip_literal;
using native_tls::set_error_message;
using native_tls::set_fd_nonblocking;
using native_tls::trim;
using native_tls::wildcard_match;

#ifdef _WIN32
using socket_len_t = int;
#else
using socket_len_t = socklen_t;
#endif

time_t timegm_utc(std::tm* tmv) {
#ifdef _WIN32
  return _mkgmtime(tmv);
#else
  return timegm(tmv);
#endif
}

int map_mbedtls_to_ssl_error(int ret) {
  if (ret > 0) return SSL_ERROR_NONE;
  if (ret == 0) return SSL_ERROR_ZERO_RETURN;
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) return SSL_ERROR_WANT_READ;
  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) return SSL_ERROR_WANT_WRITE;
  if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return SSL_ERROR_ZERO_RETURN;
  return SSL_ERROR_SSL;
}

struct x509_st {
  mbedtls_x509_crt crt;
  int refs = 1;
  x509_name_st subject_name;
  x509_name_st issuer_name;
  asn1_string_st serial;
  asn1_time_st not_before;
  asn1_time_st not_after;

  x509_st() { mbedtls_x509_crt_init(&crt); }
  ~x509_st() { mbedtls_x509_crt_free(&crt); }
};

struct x509_store_st {
  mbedtls_x509_crt ca_chain;
  std::vector<X509*> certs;
  unsigned long flags = 0;
  stack_st_X509_OBJECT object_cache;

  x509_store_st() { mbedtls_x509_crt_init(&ca_chain); }
  ~x509_store_st() {
    for (auto* cert : certs) {
      if (cert) X509_free(cert);
    }
    mbedtls_x509_crt_free(&ca_chain);
  }
};

struct bio_method_st {
  int kind;
};

enum class BioKind { Socket, Memory, Pair };

struct bio_st {
  BioKind kind = BioKind::Memory;
  int fd = -1;
  bool close_on_free = false;
  std::vector<unsigned char> data;
  size_t offset = 0;
  BIO* pair = nullptr;
};

struct evp_pkey_st {
  mbedtls_pk_context pk;
  bool has_key = false;
  std::string pem;

  evp_pkey_st() { mbedtls_pk_init(&pk); }
  ~evp_pkey_st() { mbedtls_pk_free(&pk); }
};

struct evp_md_st {
  mbedtls_md_type_t type;
};

struct evp_md_ctx_st {
  mbedtls_md_context_t md;
  const EVP_MD* current = nullptr;
  bool setup = false;

  evp_md_ctx_st() { mbedtls_md_init(&md); }
  ~evp_md_ctx_st() { mbedtls_md_free(&md); }
};

struct ssl_ctx_st {
  bool is_client = true;
  int verify_mode = SSL_VERIFY_NONE;
  int verify_depth = 0;
  int (*verify_callback)(int, X509_STORE_CTX*) = nullptr;

  long mode = 0;
  long options = 0;
  int session_cache_mode = SSL_SESS_CACHE_OFF;
  int min_proto_version = TLS1_2_VERSION;
  int max_proto_version = TLS1_3_VERSION;

  pem_password_cb* passwd_cb = nullptr;
  void* passwd_userdata = nullptr;

  X509_STORE* cert_store = nullptr;
  stack_st_X509_NAME* client_ca_list = nullptr;

  mbedtls_ssl_config conf;
  mbedtls_x509_crt own_cert_chain;
  mbedtls_pk_context own_key;
  bool own_cert_loaded = false;
  bool own_key_loaded = false;

  std::vector<std::string> alpn_protocols;
  std::vector<const char*> alpn_protocol_ptrs;

  std::vector<int> ciphersuites;
  bool ciphersuites_set = false;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  ssl_ctx_st() {
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&own_cert_chain);
    mbedtls_pk_init(&own_key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
  }

  ~ssl_ctx_st() {
    if (client_ca_list) sk_X509_NAME_pop_free(client_ca_list, X509_NAME_free);
    if (cert_store) X509_STORE_free(cert_store);
    mbedtls_pk_free(&own_key);
    mbedtls_x509_crt_free(&own_cert_chain);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
  }
};

struct ssl_st {
  SSL_CTX* ctx = nullptr;
  mbedtls_ssl_context ssl;
  bool ssl_setup = false;

  int fd = -1;
  BIO* rbio = nullptr;
  BIO* wbio = nullptr;

  int verify_mode = SSL_VERIFY_NONE;
  int verify_depth = 0;
  int (*verify_callback)(int, X509_STORE_CTX*) = nullptr;

  long mode = 0;
  int shutdown_state = 0;

  int last_error = SSL_ERROR_NONE;
  int last_ret = 1;

  std::string hostname;
  std::string selected_alpn;
  x509_verify_param_st param;
  bool ignore_verify_result = false;

  std::vector<unsigned char> peeked_plaintext;

  ssl_st() { mbedtls_ssl_init(&ssl); }
  ~ssl_st() {
    if (rbio) {
      if (wbio == rbio) {
        BIO_free(rbio);
      } else {
        BIO_free(rbio);
        if (wbio) BIO_free(wbio);
      }
      rbio = nullptr;
      wbio = nullptr;
    }
    mbedtls_ssl_free(&ssl);
  }
};

const ssl_method_st g_any_method{0};
const bio_method_st g_mem_method{1};

const EVP_MD g_md5{MBEDTLS_MD_MD5};
const EVP_MD g_sha256{MBEDTLS_MD_SHA256};
const EVP_MD g_sha512{MBEDTLS_MD_SHA512};

#if MBEDTLS_VERSION_MAJOR >= 3
std::once_flag g_psa_init_once;
#endif

int ssl_send_cb(void* ctx, const unsigned char* buf, size_t len) {
  int fd = *static_cast<int*>(ctx);
#ifdef _WIN32
  int rc = send(fd, reinterpret_cast<const char*>(buf), static_cast<int>(len), 0);
#else
#ifdef MSG_NOSIGNAL
  int flags = MSG_NOSIGNAL;
#else
  int flags = 0;
#endif
  int rc = static_cast<int>(::send(fd, buf, len, flags));
#endif
  if (rc < 0) {
#ifdef _WIN32
    int wsa = WSAGetLastError();
    if (wsa == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
#endif
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }
  return rc;
}

int ssl_recv_cb(void* ctx, unsigned char* buf, size_t len) {
  int fd = *static_cast<int*>(ctx);
#ifdef _WIN32
  int rc = recv(fd, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
#else
  int rc = static_cast<int>(::recv(fd, buf, len, 0));
#endif
  if (rc == 0) return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  if (rc < 0) {
#ifdef _WIN32
    int wsa = WSAGetLastError();
    if (wsa == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
#endif
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }
  return rc;
}

int ssl_send_bio_cb(void* ctx, const unsigned char* buf, size_t len);
int ssl_recv_bio_cb(void* ctx, unsigned char* buf, size_t len);

void refresh_x509_fields(X509* x) {
  if (!x) return;

  char buf[1024];
  buf[0] = '\0';
  if (mbedtls_x509_dn_gets(buf, sizeof(buf), &x->crt.subject) > 0) {
    x->subject_name.text = buf;
    x->subject_name.common_name = extract_dn_component(x->subject_name.text, "CN");
  } else {
    x->subject_name.text.clear();
    x->subject_name.common_name.clear();
  }

  buf[0] = '\0';
  if (mbedtls_x509_dn_gets(buf, sizeof(buf), &x->crt.issuer) > 0) {
    x->issuer_name.text = buf;
    x->issuer_name.common_name = extract_dn_component(x->issuer_name.text, "CN");
  } else {
    x->issuer_name.text.clear();
    x->issuer_name.common_name.clear();
  }

  x->serial.bytes.assign(x->crt.serial.p, x->crt.serial.p + x->crt.serial.len);

  std::tm tmnb{};
  tmnb.tm_year = x->crt.valid_from.year - 1900;
  tmnb.tm_mon = x->crt.valid_from.mon - 1;
  tmnb.tm_mday = x->crt.valid_from.day;
  tmnb.tm_hour = x->crt.valid_from.hour;
  tmnb.tm_min = x->crt.valid_from.min;
  tmnb.tm_sec = x->crt.valid_from.sec;
  x->not_before.epoch = timegm_utc(&tmnb);

  std::tm tmna{};
  tmna.tm_year = x->crt.valid_to.year - 1900;
  tmna.tm_mon = x->crt.valid_to.mon - 1;
  tmna.tm_mday = x->crt.valid_to.day;
  tmna.tm_hour = x->crt.valid_to.hour;
  tmna.tm_min = x->crt.valid_to.min;
  tmna.tm_sec = x->crt.valid_to.sec;
  x->not_after.epoch = timegm_utc(&tmna);
}

X509* x509_from_der(const unsigned char* der, size_t len) {
  auto* x = new X509();
  int rc = mbedtls_x509_crt_parse_der(&x->crt, der, len);
  if (rc != 0) {
    delete x;
    return nullptr;
  }
  refresh_x509_fields(x);
  return x;
}

X509* x509_clone(const X509* in) {
  if (!in || !in->crt.raw.p || in->crt.raw.len == 0) return nullptr;
  return x509_from_der(in->crt.raw.p, in->crt.raw.len);
}

int verify_mode_to_authmode(int mode, bool is_server) {
  if (!(mode & SSL_VERIFY_PEER)) return MBEDTLS_SSL_VERIFY_NONE;
  if (is_server && !(mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
    return MBEDTLS_SSL_VERIFY_OPTIONAL;
  }
  return MBEDTLS_SSL_VERIFY_REQUIRED;
}

bool ctx_has_ca_store(const SSL_CTX* ctx) {
  return ctx && ctx->cert_store && !ctx->cert_store->certs.empty();
}

bool ctx_should_verify_peer(const SSL_CTX* ctx) {
  if (!ctx) return false;
  if (ctx->verify_mode & SSL_VERIFY_PEER) return true;
  return ctx->is_client && ctx_has_ca_store(ctx);
}

bool ssl_should_verify_peer(const SSL* ssl) {
  if (!ssl || !ssl->ctx) return false;
  if (ssl->verify_mode & SSL_VERIFY_PEER) return true;
  return ctx_should_verify_peer(ssl->ctx);
}

void apply_ctx_verify_mode(SSL_CTX* ctx) {
  if (!ctx) return;
  int auth = MBEDTLS_SSL_VERIFY_NONE;
  if (ctx->verify_mode & SSL_VERIFY_PEER) {
    auth = verify_mode_to_authmode(ctx->verify_mode, !ctx->is_client);
  } else if (ctx->is_client && ctx_has_ca_store(ctx)) {
    auth = MBEDTLS_SSL_VERIFY_REQUIRED;
  }
  mbedtls_ssl_conf_authmode(&ctx->conf, auth);
}

void apply_ctx_ca_store(SSL_CTX* ctx) {
  if (!ctx) return;

  bool should_set = ctx_should_verify_peer(ctx);
  if (!should_set) {
    mbedtls_ssl_conf_ca_chain(&ctx->conf, nullptr, nullptr);
    return;
  }

  if (ctx->cert_store && ctx->cert_store->ca_chain.raw.p) {
    mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cert_store->ca_chain, nullptr);
  } else {
    mbedtls_ssl_conf_ca_chain(&ctx->conf, nullptr, nullptr);
  }
}

bool apply_ctx_own_cert(SSL_CTX* ctx) {
  if (!ctx) return false;
  if (!ctx->own_cert_loaded || !ctx->own_key_loaded) return true;
  int rc = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->own_cert_chain, &ctx->own_key);
  if (rc != 0) {
    char err[256] = {0};
    mbedtls_strerror(rc, err, sizeof(err));
    set_error_message(std::string("mbedtls_ssl_conf_own_cert failed: ") + err);
    return false;
  }
  return true;
}

void parse_alpn_blob(SSL_CTX* ctx, const unsigned char* protos, unsigned int len) {
  ctx->alpn_protocols.clear();
  ctx->alpn_protocol_ptrs.clear();

  size_t i = 0;
  while (i < len) {
    unsigned int l = protos[i++];
    if (l == 0 || i + l > len) break;
    ctx->alpn_protocols.emplace_back(reinterpret_cast<const char*>(protos + i), l);
    i += l;
  }

  for (auto& s : ctx->alpn_protocols) {
    ctx->alpn_protocol_ptrs.push_back(s.c_str());
  }
  ctx->alpn_protocol_ptrs.push_back(nullptr);

  if (!ctx->alpn_protocols.empty()) {
    mbedtls_ssl_conf_alpn_protocols(&ctx->conf, ctx->alpn_protocol_ptrs.data());
  }
}

bool setup_ssl_context(SSL_CTX* ctx) {
  if (!ctx) return false;

#if MBEDTLS_VERSION_MAJOR >= 3
  std::call_once(g_psa_init_once, []() { psa_crypto_init(); });
#endif

  const char* pers = "native_tls_shim";
  int rc = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                                 reinterpret_cast<const unsigned char*>(pers),
                                 std::strlen(pers));
  if (rc != 0) {
    set_error_message("mbedtls_ctr_drbg_seed failed");
    return false;
  }

  rc = mbedtls_ssl_config_defaults(&ctx->conf,
                                   ctx->is_client ? MBEDTLS_SSL_IS_CLIENT
                                                  : MBEDTLS_SSL_IS_SERVER,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc != 0) {
    set_error_message("mbedtls_ssl_config_defaults failed");
    return false;
  }

  mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
  mbedtls_ssl_conf_max_tls_version(&ctx->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#else
  mbedtls_ssl_conf_max_tls_version(&ctx->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif
  apply_ctx_verify_mode(ctx);
  apply_ctx_ca_store(ctx);

  return true;
}

bool setup_ssl_instance(SSL* ssl) {
  if (!ssl || !ssl->ctx) return false;
  apply_ctx_ca_store(ssl->ctx);
  int rc = mbedtls_ssl_setup(&ssl->ssl, &ssl->ctx->conf);
  if (rc != 0) {
    char err[256] = {0};
    mbedtls_strerror(rc, err, sizeof(err));
    set_error_message(std::string("mbedtls_ssl_setup failed: ") + err);
    return false;
  }
  int auth = MBEDTLS_SSL_VERIFY_NONE;
  if (ssl->verify_mode & SSL_VERIFY_PEER) {
    auth = verify_mode_to_authmode(ssl->verify_mode, !ssl->ctx->is_client);
  } else if (ssl->ctx && ssl->ctx->is_client && ctx_has_ca_store(ssl->ctx)) {
    auth = MBEDTLS_SSL_VERIFY_REQUIRED;
  } else if (!(ssl->verify_mode & SSL_VERIFY_PEER) && ssl->ctx &&
             (ssl->ctx->verify_mode & SSL_VERIFY_PEER)) {
    auth = verify_mode_to_authmode(ssl->ctx->verify_mode, !ssl->ctx->is_client);
  }
  mbedtls_ssl_set_hs_authmode(&ssl->ssl, auth);

  ssl->ssl_setup = true;

  if (ssl->fd >= 0) {
    mbedtls_ssl_set_bio(&ssl->ssl, &ssl->fd, ssl_send_cb, ssl_recv_cb, nullptr);
  } else if (ssl->rbio || ssl->wbio) {
    mbedtls_ssl_set_bio(&ssl->ssl, ssl, ssl_send_bio_cb, ssl_recv_bio_cb, nullptr);
  }
  return true;
}

bool add_cert_to_store(X509_STORE* store, X509* cert, bool allow_duplicate_error) {
  if (!store || !cert) return false;

  for (auto* existing : store->certs) {
    if (!existing) continue;
    if (existing->crt.raw.len == cert->crt.raw.len &&
        existing->crt.raw.p && cert->crt.raw.p &&
        std::memcmp(existing->crt.raw.p, cert->crt.raw.p, cert->crt.raw.len) == 0) {
      if (!allow_duplicate_error) return true;
      set_error_message("certificate already in store", X509_R_CERT_ALREADY_IN_HASH_TABLE);
      return false;
    }
  }

  int rc = mbedtls_x509_crt_parse_der(&store->ca_chain, cert->crt.raw.p, cert->crt.raw.len);
  if (rc != 0) {
    set_error_message("mbedtls_x509_crt_parse_der failed while adding cert");
    return false;
  }

  X509_up_ref(cert);
  store->certs.push_back(cert);
  return true;
}

bool load_ca_file_into_store(X509_STORE* store, const char* file) {
  if (!store || !file || !*file) return false;

  mbedtls_x509_crt chain;
  mbedtls_x509_crt_init(&chain);
  int rc = mbedtls_x509_crt_parse_file(&chain, file);
  if (rc < 0) {
    mbedtls_x509_crt_free(&chain);
    return false;
  }

  bool any = false;
  for (mbedtls_x509_crt* p = &chain; p && p->raw.p; p = p->next) {
    auto* x = x509_from_der(p->raw.p, p->raw.len);
    if (!x) continue;
    if (add_cert_to_store(store, x, false)) any = true;
    X509_free(x);
  }

  mbedtls_x509_crt_free(&chain);
  return any;
}

bool load_default_ca_paths(X509_STORE* store) {
  static const char* paths[] = {
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/etc/ssl/ca-bundle.pem",
      "/etc/ssl/cert.pem",
  };
  bool loaded = false;
  for (auto* p : paths) {
    if (load_ca_file_into_store(store, p)) loaded = true;
  }
  return loaded;
}

bool cert_matches_hostname(const X509* cert, const std::string& host, bool check_ip) {
  if (!cert) return false;

  auto names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(const_cast<X509*>(cert), NID_subject_alt_name, nullptr, nullptr));
  if (names) {
    int n = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < n; ++i) {
      auto* gn = sk_GENERAL_NAME_value(names, i);
      if (!gn) continue;
      if (check_ip && gn->type == GEN_IPADD && gn->d.iPAddress) {
        auto* data = ASN1_STRING_get0_data(gn->d.iPAddress);
        int len = ASN1_STRING_length(gn->d.iPAddress);
        char buf[INET6_ADDRSTRLEN] = {0};
        if (len == 4) inet_ntop(AF_INET, data, buf, sizeof(buf));
        else if (len == 16) inet_ntop(AF_INET6, data, buf, sizeof(buf));
        if (host == buf) {
          GENERAL_NAMES_free(names);
          return true;
        }
      } else if (!check_ip && gn->type == GEN_DNS && gn->d.dNSName) {
        auto* data = reinterpret_cast<const char*>(ASN1_STRING_get0_data(gn->d.dNSName));
        int len = ASN1_STRING_length(gn->d.dNSName);
        std::string pattern(data, static_cast<size_t>(len));
        if (wildcard_match(pattern, host) || pattern == host) {
          GENERAL_NAMES_free(names);
          return true;
        }
      }
    }
    GENERAL_NAMES_free(names);
  }

  if (!check_ip) {
    auto cn = cert->subject_name.common_name;
    if (!cn.empty() && (cn == host || wildcard_match(cn, host))) return true;
  }

  return false;
}

int run_verify_callback_if_any(SSL* ssl) {
  if (!ssl) return 1;
  auto* cb = ssl->verify_callback ? ssl->verify_callback : ssl->ctx->verify_callback;
  if (!cb) return 1;

  auto* cert = SSL_get_peer_certificate(ssl);
  x509_store_ctx_st verify_ctx;
  verify_ctx.ssl = ssl;
  verify_ctx.current_cert = cert;
  verify_ctx.depth = 0;

  long verify_result = ssl->ignore_verify_result ? X509_V_OK : SSL_get_verify_result(ssl);
  verify_ctx.error = (verify_result == X509_V_OK) ? X509_V_OK : X509_V_ERR_UNSPECIFIED;

  int preverify = (verify_result == X509_V_OK) ? 1 : 0;
  int rc = cb(preverify, &verify_ctx);

  if (cert) X509_free(cert);
  return rc;
}

bool next_pem_block(BIO* bio, const char* begin_tag, const char* end_tag,
                    std::string& out_block) {
  if (!bio || bio->kind != BioKind::Memory) return false;
  if (bio->offset >= bio->data.size()) return false;

  std::string text(reinterpret_cast<const char*>(bio->data.data()), bio->data.size());
  auto begin = text.find(begin_tag, bio->offset);
  if (begin == std::string::npos) return false;
  auto end = text.find(end_tag, begin);
  if (end == std::string::npos) return false;
  end += std::strlen(end_tag);
  // include trailing newline if present
  if (end < text.size() && text[end] == '\r') ++end;
  if (end < text.size() && text[end] == '\n') ++end;

  out_block = text.substr(begin, end - begin);
  bio->offset = end;
  return true;
}

size_t bio_pending_bytes(const BIO* bio) {
  if (!bio || bio->offset >= bio->data.size()) return 0;
  return bio->data.size() - bio->offset;
}

void bio_compact(BIO* bio) {
  if (!bio || bio->offset == 0) return;
  if (bio->offset >= bio->data.size()) {
    bio->data.clear();
    bio->offset = 0;
    return;
  }

  if (bio->offset > 4096) {
    bio->data.erase(bio->data.begin(), bio->data.begin() + static_cast<std::ptrdiff_t>(bio->offset));
    bio->offset = 0;
  }
}

int ssl_send_bio_cb(void* ctx, const unsigned char* buf, size_t len) {
  auto* ssl = static_cast<SSL*>(ctx);
  if (!ssl || !ssl->wbio) return MBEDTLS_ERR_NET_SEND_FAILED;
  int rc = BIO_write(ssl->wbio, buf, static_cast<int>(len));
  if (rc <= 0) return MBEDTLS_ERR_SSL_WANT_WRITE;
  return rc;
}

int ssl_recv_bio_cb(void* ctx, unsigned char* buf, size_t len) {
  auto* ssl = static_cast<SSL*>(ctx);
  if (!ssl || !ssl->rbio) return MBEDTLS_ERR_NET_RECV_FAILED;
  int rc = BIO_read(ssl->rbio, buf, static_cast<int>(len));
  if (rc <= 0) return MBEDTLS_ERR_SSL_WANT_READ;
  return rc;
}

extern "C" {

#include "tls_shared_exports.inl"

/* ===== BIO ===== */
BIO* BIO_new_file(const char* filename, const char* mode) {
  if (!filename || !mode || std::strchr(mode, 'r') == nullptr) return nullptr;
  std::ifstream ifs(filename, std::ios::binary);
  if (!ifs) return nullptr;

  std::string bytes((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
  return BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size()));
}

int BIO_new_bio_pair(BIO** bio1, size_t /*writebuf1*/, BIO** bio2, size_t /*writebuf2*/) {
  if (!bio1 || !bio2) return 0;
  auto* a = new BIO();
  auto* b = new BIO();
  a->kind = BioKind::Pair;
  b->kind = BioKind::Pair;
  a->pair = b;
  b->pair = a;
  *bio1 = a;
  *bio2 = b;
  return 1;
}

int BIO_read(BIO* bio, void* data, int len) {
  if (!bio || !data || len <= 0) return -1;

  if ((bio->kind == BioKind::Memory || bio->kind == BioKind::Pair) && bio_pending_bytes(bio) > 0) {
    int n = static_cast<int>(std::min<size_t>(static_cast<size_t>(len), bio_pending_bytes(bio)));
    std::memcpy(data, bio->data.data() + bio->offset, static_cast<size_t>(n));
    bio->offset += static_cast<size_t>(n);
    bio_compact(bio);
    return n;
  }

  if (bio->kind == BioKind::Socket && bio->fd >= 0) {
#ifdef _WIN32
    int rc = recv(bio->fd, static_cast<char*>(data), len, 0);
#else
    int rc = static_cast<int>(recv(bio->fd, data, static_cast<size_t>(len), 0));
#endif
    return rc;
  }

  return -1;
}

int BIO_write(BIO* bio, const void* data, int len) {
  if (!bio || !data || len <= 0) return -1;

  if (bio->kind == BioKind::Pair) {
    if (!bio->pair) return -1;
    auto* dst = bio->pair;
    dst->data.insert(dst->data.end(), static_cast<const unsigned char*>(data),
                     static_cast<const unsigned char*>(data) + len);
    return len;
  }

  if (bio->kind == BioKind::Memory) {
    bio->data.insert(bio->data.end(), static_cast<const unsigned char*>(data),
                     static_cast<const unsigned char*>(data) + len);
    return len;
  }

  if (bio->kind == BioKind::Socket && bio->fd >= 0) {
#ifdef _WIN32
    return send(bio->fd, static_cast<const char*>(data), len, 0);
#else
    return static_cast<int>(send(bio->fd, data, static_cast<size_t>(len), 0));
#endif
  }

  return -1;
}

size_t BIO_ctrl_pending(BIO* bio) { return bio_pending_bytes(bio); }

size_t BIO_wpending(BIO* bio) { return bio_pending_bytes(bio); }

long BIO_get_mem_data(BIO* bio, char** pp) {
  if (!bio || bio->kind != BioKind::Memory) {
    if (pp) *pp = nullptr;
    return 0;
  }
  if (pp) {
    *pp = reinterpret_cast<char*>(bio->data.data() + bio->offset);
  }
  return static_cast<long>(bio_pending_bytes(bio));
}

int BIO_free(BIO* a) {
  if (!a) return 0;
  if (a->kind == BioKind::Socket && a->close_on_free && a->fd >= 0) {
    close_socket_fd(a->fd);
  }
  if (a->kind == BioKind::Pair && a->pair) {
    a->pair->pair = nullptr;
  }
  delete a;
  return 1;
}

/* ===== EVP (digest + pkey lifecycle) ===== */
int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void* /*engine*/) {
  if (!ctx || !type) return 0;
  mbedtls_md_free(&ctx->md);
  mbedtls_md_init(&ctx->md);

  auto* info = mbedtls_md_info_from_type(type->type);
  if (!info) return 0;
  if (mbedtls_md_setup(&ctx->md, info, 0) != 0) return 0;
  if (mbedtls_md_starts(&ctx->md) != 0) return 0;
  ctx->current = type;
  ctx->setup = true;
  return 1;
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) {
  if (!ctx || !ctx->setup) return 0;
  return mbedtls_md_update(&ctx->md, static_cast<const unsigned char*>(d), cnt) == 0 ? 1 : 0;
}

int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s) {
  if (!ctx || !ctx->setup || !md) return 0;
  if (mbedtls_md_finish(&ctx->md, md) != 0) return 0;
  if (s) {
    auto* info = mbedtls_md_info_from_type(ctx->current->type);
    *s = info ? static_cast<unsigned int>(mbedtls_md_get_size(info)) : 0;
  }
  return 1;
}

EVP_PKEY* d2i_PrivateKey_bio(BIO* bp, EVP_PKEY** a) {
  if (!bp) return nullptr;
  char* p = nullptr;
  long n = BIO_get_mem_data(bp, &p);
  if (!p || n <= 0) return nullptr;

  auto* pkey = new EVP_PKEY();
#if MBEDTLS_VERSION_MAJOR >= 3
  int rc = mbedtls_pk_parse_key(&pkey->pk,
                                reinterpret_cast<const unsigned char*>(p),
                                static_cast<size_t>(n),
                                nullptr,
                                0,
                                mbedtls_ctr_drbg_random,
                                nullptr);
#else
  int rc = mbedtls_pk_parse_key(&pkey->pk,
                                reinterpret_cast<const unsigned char*>(p),
                                static_cast<size_t>(n),
                                nullptr,
                                0);
#endif
  if (rc != 0) {
    delete pkey;
    return nullptr;
  }

  pkey->has_key = true;
  if (a) *a = pkey;
  return pkey;
}

int EVP_PKEY_is_a(const EVP_PKEY* pkey, const char* name) {
  if (!pkey || !name) return 0;
  if (std::strcmp(name, "RSA") == 0) {
    return mbedtls_pk_get_type(&pkey->pk) == MBEDTLS_PK_RSA ? 1 : 0;
  }
  return 0;
}

void EVP_PKEY_free(EVP_PKEY* pkey) { delete pkey; }

/* ===== X509 ===== */
int i2d_X509(const X509* x, unsigned char** out) {
  if (!x || !x->crt.raw.p) return -1;
  int len = static_cast<int>(x->crt.raw.len);
  if (!out) return len;
  std::memcpy(*out, x->crt.raw.p, x->crt.raw.len);
  *out += x->crt.raw.len;
  return len;
}

/* ===== X509 store ===== */
void* X509_get_ext_d2i(X509* x, int nid, int* /*crit*/, int* /*idx*/) {
  if (!x || nid != NID_subject_alt_name) return nullptr;

  auto* out = new STACK_OF_GENERAL_NAME();

  for (const mbedtls_x509_sequence* cur = &x->crt.subject_alt_names; cur && cur->buf.p; cur = cur->next) {
    mbedtls_x509_subject_alternative_name san;
    int rc = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
    if (rc != 0) continue;

    auto* gn = new GENERAL_NAME();
    gn->type = GEN_OTHERNAME;
    gn->d.ptr = new ASN1_STRING();

    if (san.type == MBEDTLS_X509_SAN_DNS_NAME) {
      gn->type = GEN_DNS;
      gn->d.ptr->bytes.assign(san.san.unstructured_name.p,
                              san.san.unstructured_name.p + san.san.unstructured_name.len);
      gn->d.dNSName = gn->d.ptr;
      out->names.push_back(gn);
    } else if (san.type == MBEDTLS_X509_SAN_IP_ADDRESS) {
      gn->type = GEN_IPADD;
      gn->d.ptr->bytes.assign(san.san.unstructured_name.p,
                              san.san.unstructured_name.p + san.san.unstructured_name.len);
      gn->d.iPAddress = gn->d.ptr;
      out->names.push_back(gn);
    } else if (san.type == MBEDTLS_X509_SAN_RFC822_NAME) {
      gn->type = GEN_EMAIL;
      gn->d.ptr->bytes.assign(san.san.unstructured_name.p,
                              san.san.unstructured_name.p + san.san.unstructured_name.len);
      gn->d.rfc822Name = gn->d.ptr;
      out->names.push_back(gn);
    } else if (san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) {
      gn->type = GEN_URI;
      gn->d.ptr->bytes.assign(san.san.unstructured_name.p,
                              san.san.unstructured_name.p + san.san.unstructured_name.len);
      gn->d.uniformResourceIdentifier = gn->d.ptr;
      out->names.push_back(gn);
    } else {
      GENERAL_NAME_free(gn);
    }

    mbedtls_x509_free_subject_alt_name(&san);
  }

  if (out->names.empty()) {
    delete out;
    return nullptr;
  }

  return out;
}

/* ===== PEM ===== */
X509* PEM_read_bio_X509(BIO* bp, X509** x, void* /*cb*/, void* /*u*/) {
  if (!bp) return nullptr;

  std::string pem;
  if (!next_pem_block(bp, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", pem)) {
    return nullptr;
  }

  auto* cert = new X509();
  int rc = mbedtls_x509_crt_parse(&cert->crt,
                                  reinterpret_cast<const unsigned char*>(pem.c_str()),
                                  pem.size() + 1);
  if (rc != 0) {
    delete cert;
    return nullptr;
  }
  refresh_x509_fields(cert);
  if (x) *x = cert;
  return cert;
}

EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, EVP_PKEY** x, void* /*cb*/, void* u) {
  if (!bp) return nullptr;

  std::string pem;
  if (!next_pem_block(bp, "-----BEGIN", "-----END", pem)) return nullptr;

  auto* pkey = new EVP_PKEY();
  const unsigned char* pwd = u ? reinterpret_cast<const unsigned char*>(u) : nullptr;
  size_t pwd_len = u ? std::strlen(reinterpret_cast<const char*>(u)) : 0;

#if MBEDTLS_VERSION_MAJOR >= 3
  int rc = mbedtls_pk_parse_key(&pkey->pk,
                                reinterpret_cast<const unsigned char*>(pem.c_str()),
                                pem.size() + 1,
                                pwd,
                                pwd_len,
                                mbedtls_ctr_drbg_random,
                                nullptr);
#else
  int rc = mbedtls_pk_parse_key(&pkey->pk,
                                reinterpret_cast<const unsigned char*>(pem.c_str()),
                                pem.size() + 1,
                                pwd,
                                pwd_len);
#endif
  if (rc != 0) {
    delete pkey;
    return nullptr;
  }
  pkey->has_key = true;
  pkey->pem = pem;
  if (x) *x = pkey;
  return pkey;
}

EVP_PKEY* PEM_read_bio_Parameters(BIO* bp, EVP_PKEY** x) {
  return PEM_read_bio_PrivateKey(bp, x, nullptr, nullptr);
}

int PEM_write_bio_X509(BIO* bp, X509* x) {
  if (!bp || !x || bp->kind != BioKind::Memory || !x->crt.raw.p) return 0;
  std::array<unsigned char, 8192> out{};
  size_t olen = 0;
  int rc = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                    "-----END CERTIFICATE-----\n",
                                    x->crt.raw.p,
                                    x->crt.raw.len,
                                    out.data(),
                                    out.size(),
                                    &olen);
  if (rc != 0) return 0;
  bp->data.insert(bp->data.end(), out.data(), out.data() + olen);
  return 1;
}

int PEM_write_bio_PrivateKey(BIO* bp, EVP_PKEY* x, const void* /*enc*/, unsigned char* /*kstr*/,
                             int /*klen*/, void* /*cb*/, void* /*u*/) {
  if (!bp || !x || bp->kind != BioKind::Memory || !x->has_key) return 0;
  if (!x->pem.empty()) {
    bp->data.insert(bp->data.end(), x->pem.begin(), x->pem.end());
    if (!x->pem.empty() && x->pem.back() != '\n') bp->data.push_back('\n');
    return 1;
  }

  std::array<unsigned char, 8192> out{};
  int rc = mbedtls_pk_write_key_pem(&x->pk, out.data(), out.size());
  if (rc != 0) return 0;
  auto len = std::strlen(reinterpret_cast<const char*>(out.data()));
  bp->data.insert(bp->data.end(), out.data(), out.data() + len);
  return 1;
}

/* ===== SSL methods/context ===== */
const SSL_METHOD* TLS_method(void) { return &g_any_method; }
const SSL_METHOD* SSLv23_method(void) { return &g_any_method; }

SSL_CTX* SSL_CTX_new(const SSL_METHOD* method) {
  auto* ctx = new SSL_CTX();
  ctx->is_client = !(method && method->endpoint == MBEDTLS_SSL_IS_SERVER);
  ctx->verify_mode = SSL_VERIFY_NONE;
  ctx->cert_store = X509_STORE_new();

  if (!setup_ssl_context(ctx)) {
    delete ctx;
    return nullptr;
  }

  return ctx;
}

void SSL_CTX_set_verify(SSL_CTX* ctx, int mode,
                        int (*verify_callback)(int, X509_STORE_CTX*)) {
  if (!ctx) return;
  ctx->verify_mode = mode;
  ctx->verify_callback = verify_callback;
  apply_ctx_verify_mode(ctx);
  apply_ctx_ca_store(ctx);
}

int SSL_CTX_get_verify_mode(const SSL_CTX* ctx) {
  return ctx ? ctx->verify_mode : SSL_VERIFY_NONE;
}

int (*SSL_CTX_get_verify_callback(const SSL_CTX* ctx))(int, X509_STORE_CTX*) {
  return ctx ? ctx->verify_callback : nullptr;
}
long SSL_CTX_clear_options(SSL_CTX* ctx, long options) {
  if (!ctx) return 0;
  ctx->options &= ~options;
  return ctx->options;
}

static void append_default_ciphers(std::vector<int>& out) {
  const int* defaults = mbedtls_ssl_list_ciphersuites();
  if (!defaults) return;
  for (const int* p = defaults; *p != 0; ++p) {
    out.push_back(*p);
  }
}

static void append_default_tls13_ciphers(std::vector<int>& out) {
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
  const int* defaults = mbedtls_ssl_list_ciphersuites();
  if (!defaults) return;
  for (const int* p = defaults; *p != 0; ++p) {
    const auto* info = mbedtls_ssl_ciphersuite_from_id(*p);
    if (!info) continue;
    const char* name = mbedtls_ssl_ciphersuite_get_name(info);
    if (!name || std::strncmp(name, "TLS1-3-", 7) != 0) continue;
    if (std::find(out.begin(), out.end(), *p) == out.end()) {
      out.push_back(*p);
    }
  }
#else
  (void) out;
#endif
}

static bool add_cipher_from_token(const std::string& token, std::vector<int>& out) {
  const char* mbedtls_name = nullptr;
  if (token == "ECDHE-ECDSA-AES128-GCM-SHA256") {
    mbedtls_name = "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256";
  } else if (token == "ECDHE-ECDSA-AES256-GCM-SHA384") {
    mbedtls_name = "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384";
  } else if (token == "ECDHE-RSA-AES128-GCM-SHA256") {
    mbedtls_name = "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256";
  } else if (token == "ECDHE-RSA-AES256-GCM-SHA384") {
    mbedtls_name = "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384";
  } else if (token == "DHE-RSA-AES128-GCM-SHA256") {
    mbedtls_name = "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256";
  } else if (token == "DHE-RSA-AES256-GCM-SHA384") {
    mbedtls_name = "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384";
  } else if (token == "AES128-GCM-SHA256") {
    mbedtls_name = "TLS-RSA-WITH-AES-128-GCM-SHA256";
  } else if (token == "AES256-GCM-SHA384") {
    mbedtls_name = "TLS-RSA-WITH-AES-256-GCM-SHA384";
  } else if (token == "ECDHE-ECDSA-CHACHA20-POLY1305" ||
             token == "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256") {
    mbedtls_name = "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256";
  } else if (token == "ECDHE-RSA-CHACHA20-POLY1305" ||
             token == "ECDHE-RSA-CHACHA20-POLY1305-SHA256") {
    mbedtls_name = "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256";
  }

  if (!mbedtls_name) return false;
  int id = mbedtls_ssl_get_ciphersuite_id(mbedtls_name);
  if (id == 0) return false;
  out.push_back(id);
  return true;
}

static bool parse_cipher_list_string(const char* str, std::vector<int>& out) {
  if (!str) return false;
  std::string input(str);
  if (input.empty()) return false;

  std::vector<int> ciphers;
  std::string token;
  auto flush = [&]() {
    if (token.empty()) return;
    std::string normalized = native_tls::normalize(token);
    token.clear();
    if (normalized.empty()) return;
    if (normalized[0] == '!') return;
    if (normalized == "DEFAULT" || normalized == "HIGH" || normalized == "SECURE") {
      append_default_ciphers(ciphers);
      return;
    }
    add_cipher_from_token(normalized, ciphers);
  };

  for (char ch : input) {
    if (ch == ':' || ch == ',' || ch == ';' || std::isspace(static_cast<unsigned char>(ch))) {
      flush();
    } else {
      token.push_back(ch);
    }
  }
  flush();

  if (ciphers.empty()) return false;
  out = std::move(ciphers);
  return true;
}

int SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* str) {
  if (!ctx || !str) return 0;
  std::vector<int> parsed;
  if (!parse_cipher_list_string(str, parsed)) {
    set_error_message("SSL_CTX_set_cipher_list: no matching cipher suites");
    return 0;
  }

  append_default_tls13_ciphers(parsed);

  parsed.push_back(0);
  ctx->ciphersuites = std::move(parsed);
  ctx->ciphersuites_set = true;
  mbedtls_ssl_conf_ciphersuites(&ctx->conf, ctx->ciphersuites.data());
  return 1;
}

int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* ca_file, const char* ca_path) {
  if (!ctx || !ctx->cert_store) return 0;
  bool loaded = false;

  if (ca_file && *ca_file) {
    loaded = load_ca_file_into_store(ctx->cert_store, ca_file) || loaded;
  }

  if (ca_path && *ca_path) {
    std::error_code ec;
    for (auto const& entry : std::filesystem::directory_iterator(ca_path, ec)) {
      if (ec) break;
      if (!entry.is_regular_file()) continue;
      auto p = entry.path().string();
      loaded = load_ca_file_into_store(ctx->cert_store, p.c_str()) || loaded;
    }
  }

  if (loaded) apply_ctx_ca_store(ctx);
  return loaded ? 1 : 0;
}

int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx) {
  if (!ctx || !ctx->cert_store) return 0;
  bool loaded = load_default_ca_paths(ctx->cert_store);
  if (loaded) apply_ctx_ca_store(ctx);
  return loaded ? 1 : 0;
}

int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int /*type*/) {
  if (!ctx || !file) return 0;
  mbedtls_x509_crt_free(&ctx->own_cert_chain);
  mbedtls_x509_crt_init(&ctx->own_cert_chain);
  int rc = mbedtls_x509_crt_parse_file(&ctx->own_cert_chain, file);
  if (rc != 0) return 0;
  ctx->own_cert_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file) {
  return SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int /*type*/) {
  if (!ctx || !file) return 0;
  mbedtls_pk_free(&ctx->own_key);
  mbedtls_pk_init(&ctx->own_key);

#if MBEDTLS_VERSION_MAJOR >= 3
  int rc = mbedtls_pk_parse_keyfile(&ctx->own_key, file,
      ctx->passwd_userdata ? static_cast<const char*>(ctx->passwd_userdata) : nullptr,
      mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
#else
  int rc = mbedtls_pk_parse_keyfile(&ctx->own_key, file,
      ctx->passwd_userdata ? static_cast<const char*>(ctx->passwd_userdata) : nullptr);
#endif
  if (rc != 0) return 0;
  ctx->own_key_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_use_certificate(SSL_CTX* ctx, X509* x) {
  if (!ctx || !x || !x->crt.raw.p) return 0;
  mbedtls_x509_crt_free(&ctx->own_cert_chain);
  mbedtls_x509_crt_init(&ctx->own_cert_chain);
  int rc = mbedtls_x509_crt_parse_der(&ctx->own_cert_chain, x->crt.raw.p, x->crt.raw.len);
  if (rc != 0) return 0;
  ctx->own_cert_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_use_PrivateKey(SSL_CTX* ctx, EVP_PKEY* pkey) {
  if (!ctx || !pkey || !pkey->has_key) return 0;
  mbedtls_pk_free(&ctx->own_key);
  mbedtls_pk_init(&ctx->own_key);

  int rc = 0;
  if (!pkey->pem.empty()) {
#if MBEDTLS_VERSION_MAJOR >= 3
    rc = mbedtls_pk_parse_key(&ctx->own_key,
                              reinterpret_cast<const unsigned char*>(pkey->pem.c_str()),
                              pkey->pem.size() + 1,
                              nullptr,
                              0,
                              mbedtls_ctr_drbg_random,
                              &ctx->ctr_drbg);
#else
    rc = mbedtls_pk_parse_key(&ctx->own_key,
                              reinterpret_cast<const unsigned char*>(pkey->pem.c_str()),
                              pkey->pem.size() + 1,
                              nullptr,
                              0);
#endif
  } else {
    return 0;
  }

  if (rc != 0) return 0;
  ctx->own_key_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_use_certificate_ASN1(SSL_CTX* ctx, int len, const unsigned char* d) {
  if (!ctx || !d || len <= 0) return 0;
  mbedtls_x509_crt_free(&ctx->own_cert_chain);
  mbedtls_x509_crt_init(&ctx->own_cert_chain);
  int rc = mbedtls_x509_crt_parse_der(&ctx->own_cert_chain, d, static_cast<size_t>(len));
  if (rc != 0) return 0;
  ctx->own_cert_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_use_PrivateKey_ASN1(int /*pk*/, SSL_CTX* ctx, const unsigned char* d, long len) {
  if (!ctx || !d || len <= 0) return 0;
  mbedtls_pk_free(&ctx->own_key);
  mbedtls_pk_init(&ctx->own_key);
#if MBEDTLS_VERSION_MAJOR >= 3
  int rc = mbedtls_pk_parse_key(&ctx->own_key, d, static_cast<size_t>(len), nullptr, 0,
                                mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
#else
  int rc = mbedtls_pk_parse_key(&ctx->own_key, d, static_cast<size_t>(len), nullptr, 0);
#endif
  if (rc != 0) return 0;
  ctx->own_key_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_check_private_key(const SSL_CTX* ctx) {
  if (!ctx || !ctx->own_cert_loaded || !ctx->own_key_loaded) return 0;
#if MBEDTLS_VERSION_MAJOR >= 3
  return mbedtls_pk_check_pair(&ctx->own_cert_chain.pk, &ctx->own_key,
                               mbedtls_ctr_drbg_random,
                               const_cast<mbedtls_ctr_drbg_context*>(&ctx->ctr_drbg)) == 0
             ? 1
             : 0;
#else
  return mbedtls_pk_check_pair(&ctx->own_cert_chain.pk, &ctx->own_key) == 0 ? 1 : 0;
#endif
}

void SSL_CTX_set_default_passwd_cb(SSL_CTX* ctx, pem_password_cb* cb) {
  if (ctx) ctx->passwd_cb = cb;
}

pem_password_cb* SSL_CTX_get_default_passwd_cb(SSL_CTX* ctx) {
  return ctx ? ctx->passwd_cb : nullptr;
}

void* SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX* ctx) {
  return ctx ? ctx->passwd_userdata : nullptr;
}

void SSL_CTX_set_cert_store(SSL_CTX* ctx, X509_STORE* store) {
  if (!ctx || !store) return;
  if (ctx->cert_store == store) return;
  if (ctx->cert_store) X509_STORE_free(ctx->cert_store);
  ctx->cert_store = store;
  apply_ctx_ca_store(ctx);
}

int SSL_CTX_add_extra_chain_cert(SSL_CTX* /*ctx*/, X509* x509) {
  if (x509) X509_free(x509);
  return 1;
}

void SSL_CTX_clear_chain_certs(SSL_CTX* /*ctx*/) {}

int SSL_CTX_set0_tmp_dh_pkey(SSL_CTX* /*ctx*/, EVP_PKEY* pkey) {
  if (pkey) EVP_PKEY_free(pkey);
  set_error_message("SSL_CTX_set0_tmp_dh_pkey is not implemented by native-tls-shim",
                    1, ERR_LIB_SSL);
  return 0;
}

int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version) {
  if (!ctx) return 0;
  ctx->min_proto_version = version;

  mbedtls_ssl_protocol_version v = MBEDTLS_SSL_VERSION_TLS1_2;
  switch (version) {
    case SSL3_VERSION:
    case TLS1_VERSION:
    case TLS1_1_VERSION:
    case TLS1_2_VERSION:
      v = MBEDTLS_SSL_VERSION_TLS1_2;
      break;
#ifdef MBEDTLS_SSL_VERSION_TLS1_3
    case TLS1_3_VERSION:
      v = MBEDTLS_SSL_VERSION_TLS1_3;
      break;
#endif
    default:
      v = MBEDTLS_SSL_VERSION_TLS1_2;
      break;
  }

  mbedtls_ssl_conf_min_tls_version(&ctx->conf, v);
  return 1;
}

int SSL_CTX_set_max_proto_version(SSL_CTX* ctx, int version) {
  if (!ctx) return 0;
  ctx->max_proto_version = version;

  mbedtls_ssl_protocol_version v = MBEDTLS_SSL_VERSION_TLS1_2;
  switch (version) {
    case SSL3_VERSION:
    case TLS1_VERSION:
    case TLS1_1_VERSION:
    case TLS1_2_VERSION:
      v = MBEDTLS_SSL_VERSION_TLS1_2;
      break;
#ifdef MBEDTLS_SSL_VERSION_TLS1_3
    case TLS1_3_VERSION:
      v = MBEDTLS_SSL_VERSION_TLS1_3;
      break;
#endif
    default:
      v = MBEDTLS_SSL_VERSION_TLS1_2;
      break;
  }

  mbedtls_ssl_conf_max_tls_version(&ctx->conf, v);
  return 1;
}

int SSL_CTX_set_alpn_protos(SSL_CTX* ctx, const unsigned char* protos, unsigned int len) {
  if (!ctx || !protos || len == 0) return 1;
  parse_alpn_blob(ctx, protos, len);
  return 0; // OpenSSL returns 0 on success
}

/* ===== SSL object ===== */
SSL* SSL_new(SSL_CTX* ctx) {
  if (!ctx) return nullptr;
  auto* ssl = new SSL();
  ssl->ctx = ctx;
  ssl->verify_mode = ctx->verify_mode;
  ssl->verify_depth = ctx->verify_depth;
  ssl->verify_callback = ctx->verify_callback;
  ssl->mode = ctx->mode;
  if (!setup_ssl_instance(ssl)) {
    delete ssl;
    return nullptr;
  }
  return ssl;
}

int SSL_set_fd(SSL* ssl, int fd) {
  if (!ssl) return 0;
  ssl->fd = fd;
  if (ssl->ssl_setup) {
    mbedtls_ssl_set_bio(&ssl->ssl, &ssl->fd, ssl_send_cb, ssl_recv_cb, nullptr);
  }
  return 1;
}

void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio) {
  if (!ssl) return;
  if (ssl->rbio) {
    if (ssl->wbio == ssl->rbio) BIO_free(ssl->rbio);
    else {
      BIO_free(ssl->rbio);
      if (ssl->wbio) BIO_free(ssl->wbio);
    }
  }
  ssl->rbio = rbio;
  ssl->wbio = wbio ? wbio : rbio;

  if (ssl->rbio && ssl->rbio->kind == BioKind::Socket) {
    ssl->fd = ssl->rbio->fd;
    if (ssl->ssl_setup) {
      mbedtls_ssl_set_bio(&ssl->ssl, &ssl->fd, ssl_send_cb, ssl_recv_cb, nullptr);
    }
    return;
  }

  ssl->fd = -1;
  if (ssl->ssl_setup && (ssl->rbio || ssl->wbio)) {
    mbedtls_ssl_set_bio(&ssl->ssl, ssl, ssl_send_bio_cb, ssl_recv_bio_cb, nullptr);
  }
}

int SSL_set_tlsext_host_name(SSL* ssl, const char* name) {
  if (!ssl || !name) return 0;
  ssl->hostname = name;

  if (ssl->ssl_setup) {
    if (!ssl->hostname.empty() && !is_ip_literal(ssl->hostname)) {
      return mbedtls_ssl_set_hostname(&ssl->ssl, ssl->hostname.c_str()) == 0 ? 1 : 0;
    }
    return 1;
  }
  return 1;
}

void SSL_set_verify(SSL* ssl, int mode,
                    int (*verify_callback)(int, X509_STORE_CTX*)) {
  if (!ssl) return;
  ssl->verify_mode = mode;
  ssl->verify_callback = verify_callback;
  if (ssl->ssl_setup && ssl->ctx) {
    int auth = MBEDTLS_SSL_VERIFY_NONE;
    if (mode & SSL_VERIFY_PEER) {
      auth = verify_mode_to_authmode(mode, !ssl->ctx->is_client);
    } else if (ssl->ctx->is_client && ctx_has_ca_store(ssl->ctx)) {
      auth = MBEDTLS_SSL_VERIFY_REQUIRED;
    } else if (!(mode & SSL_VERIFY_PEER) && (ssl->ctx->verify_mode & SSL_VERIFY_PEER)) {
      auth = verify_mode_to_authmode(ssl->ctx->verify_mode, !ssl->ctx->is_client);
    }
    mbedtls_ssl_set_hs_authmode(&ssl->ssl, auth);
  }
}

int SSL_get_verify_mode(const SSL* ssl) {
  return ssl ? ssl->verify_mode : SSL_VERIFY_NONE;
}

int (*SSL_get_verify_callback(const SSL* ssl))(int, X509_STORE_CTX*) {
  return ssl ? ssl->verify_callback : nullptr;
}

void SSL_set_verify_depth(SSL* ssl, int depth) {
  if (ssl) ssl->verify_depth = depth;
}

long SSL_set_mode(SSL* ssl, long mode) {
  if (!ssl) return 0;
  ssl->mode |= mode;
  return ssl->mode;
}

int SSL_connect(SSL* ssl) {
  if (!ssl || !ssl->ssl_setup) return -1;

  int effective_verify_mode = ssl->verify_mode ? ssl->verify_mode : ssl->ctx->verify_mode;

  if (ssl->hostname.empty() && !ssl->param.host.empty()) {
    ssl->hostname = ssl->param.host;
  }

  if (!ssl->hostname.empty()) {
    bool is_ip = is_ip_literal(ssl->hostname);
    bool should_verify = (effective_verify_mode & SSL_VERIFY_PEER) != 0 ||
                         (ssl->ctx && ssl->ctx->is_client && ctx_has_ca_store(ssl->ctx));
    if (!is_ip || should_verify) {
      mbedtls_ssl_set_hostname(&ssl->ssl, ssl->hostname.c_str());
    }
  }

  ssl->ignore_verify_result = false;

  int ret = mbedtls_ssl_handshake(&ssl->ssl);

  if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl->ssl);

    bool verify_disabled = !(effective_verify_mode & SSL_VERIFY_PEER);
    bool hostname_mismatch_only =
        (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) &&
        ((flags & ~MBEDTLS_X509_BADCERT_CN_MISMATCH) == 0);

    bool hostname_disabled_but_chain_ok =
        (ssl->param.host.empty() && !ssl->hostname.empty() && hostname_mismatch_only);

    if (verify_disabled || hostname_disabled_but_chain_ok) {
      ssl->ignore_verify_result = true;
      ret = 0;
    }
  }

  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);

  if (ret == 0) {
    ssl->last_ret = 1;
    ssl->last_error = SSL_ERROR_NONE;
    if (!run_verify_callback_if_any(ssl)) {
      ssl->last_error = SSL_ERROR_SSL;
      set_error_message("verify callback rejected certificate");
      return -1;
    }
    if ((effective_verify_mode & SSL_VERIFY_PEER) && !ssl->param.host.empty()) {
      auto* cert = SSL_get_peer_certificate(ssl);
      bool ok = cert && cert_matches_hostname(cert, ssl->param.host, is_ip_literal(ssl->param.host));
      if (cert) X509_free(cert);
      if (!ok) {
        ssl->last_error = SSL_ERROR_SSL;
        set_error_message("hostname verification failed", X509_V_ERR_HOSTNAME_MISMATCH);
        return -1;
      }
    }
    auto* alpn = mbedtls_ssl_get_alpn_protocol(&ssl->ssl);
    ssl->selected_alpn = alpn ? alpn : "";
    return 1;
  }

  char err[256] = {0};
  mbedtls_strerror(ret, err, sizeof(err));
  set_error_message(std::string("SSL_connect failed: ") + err);
  return -1;
}

int SSL_accept(SSL* ssl) {
  if (!ssl || !ssl->ssl_setup) return -1;

  ssl->ignore_verify_result = false;

  int ret = mbedtls_ssl_handshake(&ssl->ssl);

  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);

  if (ret == 0) {
    ssl->last_ret = 1;
    ssl->last_error = SSL_ERROR_NONE;
    if (!run_verify_callback_if_any(ssl)) {
      ssl->last_error = SSL_ERROR_SSL;
      set_error_message("verify callback rejected peer certificate");
      return -1;
    }
    auto* alpn = mbedtls_ssl_get_alpn_protocol(&ssl->ssl);
    ssl->selected_alpn = alpn ? alpn : "";
    return 1;
  }

  char err[256] = {0};
  mbedtls_strerror(ret, err, sizeof(err));
  set_error_message(std::string("SSL_accept failed: ") + err);
  return -1;
}

int SSL_read(SSL* ssl, void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;

  if (!ssl->peeked_plaintext.empty()) {
    int n = std::min<int>(num, static_cast<int>(ssl->peeked_plaintext.size()));
    std::memcpy(buf, ssl->peeked_plaintext.data(), static_cast<size_t>(n));
    ssl->peeked_plaintext.erase(ssl->peeked_plaintext.begin(), ssl->peeked_plaintext.begin() + n);
    ssl->last_ret = n;
    ssl->last_error = SSL_ERROR_NONE;
    return n;
  }

  int ret = mbedtls_ssl_read(&ssl->ssl, static_cast<unsigned char*>(buf), static_cast<size_t>(num));
  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);
  if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
    ssl->shutdown_state |= SSL_RECEIVED_SHUTDOWN;
    ssl->last_error = SSL_ERROR_ZERO_RETURN;
  }
  if (ret < 0 && ssl->last_error == SSL_ERROR_SSL) {
    char err[256] = {0};
    mbedtls_strerror(ret, err, sizeof(err));
    set_error_message(std::string("SSL_read failed: ") + err);
  }
  return ret;
}

int SSL_write(SSL* ssl, const void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;
  int ret = mbedtls_ssl_write(&ssl->ssl, static_cast<const unsigned char*>(buf), static_cast<size_t>(num));
  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);
  if (ret < 0 && ssl->last_error == SSL_ERROR_SSL) {
    char err[256] = {0};
    mbedtls_strerror(ret, err, sizeof(err));
    set_error_message(std::string("SSL_write failed: ") + err);
  }
  return ret;
}

int SSL_peek(SSL* ssl, void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;

  if (ssl->peeked_plaintext.empty()) {
    std::vector<unsigned char> tmp(static_cast<size_t>(num));
    int ret = mbedtls_ssl_read(&ssl->ssl, tmp.data(), tmp.size());
    ssl->last_ret = ret;
    ssl->last_error = map_mbedtls_to_ssl_error(ret);
    if (ret <= 0) return ret;
    ssl->peeked_plaintext.assign(tmp.begin(), tmp.begin() + ret);
  }

  int n = std::min<int>(num, static_cast<int>(ssl->peeked_plaintext.size()));
  std::memcpy(buf, ssl->peeked_plaintext.data(), static_cast<size_t>(n));
  ssl->last_ret = n;
  ssl->last_error = SSL_ERROR_NONE;
  return n;
}

int SSL_pending(const SSL* ssl) {
  if (!ssl) return 0;
  return static_cast<int>(ssl->peeked_plaintext.size()) +
         static_cast<int>(mbedtls_ssl_get_bytes_avail(&ssl->ssl));
}

int SSL_shutdown(SSL* ssl) {
  if (!ssl) return 0;
  int ret = mbedtls_ssl_close_notify(&ssl->ssl);
  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);
  if (ret == 0) {
    ssl->shutdown_state |= SSL_SENT_SHUTDOWN;
    ssl->last_ret = 1;
    ssl->last_error = SSL_ERROR_NONE;
    return 1;
  }
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return 0;
  }
  return -1;
}

int SSL_get_shutdown(const SSL* ssl) {
  return ssl ? ssl->shutdown_state : 0;
}

SSL_CTX* SSL_get_SSL_CTX(const SSL* ssl) {
  return ssl ? ssl->ctx : nullptr;
}

X509* SSL_get_peer_certificate(const SSL* ssl) {
  if (!ssl) return nullptr;
  auto* cert = mbedtls_ssl_get_peer_cert(&ssl->ssl);
  if (!cert || !cert->raw.p) return nullptr;
  return x509_from_der(cert->raw.p, cert->raw.len);
}

long SSL_get_verify_result(const SSL* ssl) {
  if (!ssl) return X509_V_ERR_UNSPECIFIED;
  if (ssl->ignore_verify_result) return X509_V_OK;
  uint32_t flags = mbedtls_ssl_get_verify_result(&ssl->ssl);
  if (flags == 0) return X509_V_OK;
  if (flags & MBEDTLS_X509_BADCERT_EXPIRED) return X509_V_ERR_CERT_HAS_EXPIRED;
  if (flags & MBEDTLS_X509_BADCERT_FUTURE) return X509_V_ERR_CERT_NOT_YET_VALID;
  if (flags & MBEDTLS_X509_BADCERT_REVOKED) return X509_V_ERR_CERT_REVOKED;
  if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) return X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
  return X509_V_ERR_UNSPECIFIED;
}

const char* SSL_get_servername(const SSL* ssl, const int type) {
  if (!ssl || type != TLSEXT_NAMETYPE_host_name) return nullptr;
  return ssl->hostname.empty() ? nullptr : ssl->hostname.c_str();
}

void SSL_clear_mode(SSL* ssl, long mode) {
  if (!ssl) return;
  ssl->mode &= ~mode;
}

STACK_OF_X509_NAME* SSL_load_client_CA_file(const char* file) {
  if (!file) return nullptr;
  mbedtls_x509_crt chain;
  mbedtls_x509_crt_init(&chain);
  if (mbedtls_x509_crt_parse_file(&chain, file) < 0) {
    mbedtls_x509_crt_free(&chain);
    return nullptr;
  }

  auto* list = sk_X509_NAME_new_null();
  for (mbedtls_x509_crt* p = &chain; p && p->raw.p; p = p->next) {
    auto* tmp = x509_from_der(p->raw.p, p->raw.len);
    if (!tmp) continue;
    auto* dup = X509_NAME_dup(X509_get_subject_name(tmp));
    if (dup) sk_X509_NAME_push(list, dup);
    X509_free(tmp);
  }
  mbedtls_x509_crt_free(&chain);

  if (sk_X509_NAME_num(list) == 0) {
    sk_X509_NAME_free(list);
    return nullptr;
  }
  return list;
}

} // extern "C"

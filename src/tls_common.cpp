#include "tls_common.hpp"

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/dh.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {
thread_local unsigned long g_last_error_code = 0;
thread_local std::string g_last_error_message;
thread_local unsigned long g_last_popped_error_code = 0;
thread_local std::string g_last_popped_error_message;

struct BioState {
  const BIO_METHOD* method = nullptr;
  void* data = nullptr;
  int init = 0;
  int flags = 0;
  int refs = 1;
};

std::mutex g_app_data_mutex;
std::unordered_map<const SSL*, void*> g_ssl_app_data;
std::unordered_map<const SSL_CTX*, void*> g_ssl_ctx_app_data;
std::unordered_map<const SSL*, std::unordered_map<int, void*>> g_ssl_ex_data;
std::unordered_map<const SSL_CTX*, std::unordered_map<int, void*>> g_ssl_ctx_ex_data;
std::unordered_map<const SSL_CTX*, SSL_tlsext_servername_callback> g_ctx_sni_callbacks;
std::unordered_map<const SSL_CTX*, void*> g_ctx_sni_args;
std::unordered_map<const SSL_CTX*, SSL_CTX_alpn_select_cb_func> g_ctx_alpn_select_callbacks;
std::unordered_map<const SSL_CTX*, void*> g_ctx_alpn_select_args;

std::mutex g_bio_mutex;
std::unordered_map<const BIO*, BioState> g_bio_state;
} // namespace

namespace openssl_shim {

void set_last_error(unsigned long code, const std::string& message) {
  g_last_error_code = code;
  g_last_error_message = message;
  if (code == 0) {
    g_last_popped_error_code = 0;
    g_last_popped_error_message.clear();
  }
}

unsigned long peek_last_error_code() { return g_last_error_code; }

unsigned long pop_last_error_code() {
  auto e = g_last_error_code;
  g_last_popped_error_code = g_last_error_code;
  g_last_popped_error_message = g_last_error_message;
  g_last_error_code = 0;
  g_last_error_message.clear();
  return e;
}

std::string get_last_error_string(unsigned long code) {
  if (code == 0) return std::string();
  if (!g_last_error_message.empty() && code == g_last_error_code) {
    return g_last_error_message;
  }
  if (!g_last_popped_error_message.empty() && code == g_last_popped_error_code) {
    return g_last_popped_error_message;
  }
  return "openssl-shim error: " + std::to_string(code);
}

unsigned long make_error_code(int lib, int reason) {
  return (static_cast<unsigned long>(lib & 0xFF) << 24) |
         static_cast<unsigned long>(reason & 0xFFFFFF);
}

void set_error_message(const std::string& msg, int reason, int lib) {
  set_last_error(make_error_code(lib, reason), msg);
}

void clear_error_message() { set_last_error(0, {}); }

std::string read_file_text(const char* path) {
  if (!path) return {};
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) return {};
  return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

bool ip_bytes_match_host(const unsigned char* data, size_t len, const std::string& host) {
  if (!data || host.empty()) return false;

  std::array<unsigned char, 16> buf{};
  if (inet_pton(AF_INET, host.c_str(), buf.data()) == 1) {
    return len == 4 && std::memcmp(data, buf.data(), 4) == 0;
  }
  if (inet_pton(AF_INET6, host.c_str(), buf.data()) == 1) {
    return len == 16 && std::memcmp(data, buf.data(), 16) == 0;
  }
  return false;
}

void clear_ssl_app_data(const ssl_st* ssl) {
  if (!ssl) return;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  auto* s = reinterpret_cast<const SSL*>(ssl);
  g_ssl_app_data.erase(s);
  g_ssl_ex_data.erase(s);
}

void clear_ssl_ctx_app_data(const ssl_ctx_st* ctx) {
  if (!ctx) return;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  auto* c = reinterpret_cast<const SSL_CTX*>(ctx);
  g_ssl_ctx_app_data.erase(c);
  g_ssl_ctx_ex_data.erase(c);
  g_ctx_sni_callbacks.erase(c);
  g_ctx_sni_args.erase(c);
  g_ctx_alpn_select_callbacks.erase(c);
  g_ctx_alpn_select_args.erase(c);
}

void bio_set_method(BIO* bio, const BIO_METHOD* method) {
  if (!bio) return;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto& st = g_bio_state[bio];
  st.method = method;
}

const BIO_METHOD* bio_get_method(const BIO* bio) {
  if (!bio) return nullptr;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto it = g_bio_state.find(bio);
  return it == g_bio_state.end() ? nullptr : it->second.method;
}

void bio_set_data(BIO* bio, void* data) {
  if (!bio) return;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto& st = g_bio_state[bio];
  st.data = data;
}

void* bio_get_data(BIO* bio) {
  if (!bio) return nullptr;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto it = g_bio_state.find(bio);
  return it == g_bio_state.end() ? nullptr : it->second.data;
}

void bio_set_init(BIO* bio, int init) {
  if (!bio) return;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto& st = g_bio_state[bio];
  st.init = init;
}

int bio_get_init(BIO* bio) {
  if (!bio) return 0;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto it = g_bio_state.find(bio);
  return it == g_bio_state.end() ? 0 : it->second.init;
}

void bio_set_flags(BIO* bio, int flags) {
  if (!bio) return;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto& st = g_bio_state[bio];
  st.flags |= flags;
}

int bio_get_flags(BIO* bio) {
  if (!bio) return 0;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto it = g_bio_state.find(bio);
  return it == g_bio_state.end() ? 0 : it->second.flags;
}

int bio_up_ref(BIO* bio) {
  if (!bio) return 0;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto& st = g_bio_state[bio];
  st.refs++;
  return 1;
}

bool bio_should_delete(BIO* bio) {
  if (!bio) return false;
  std::lock_guard<std::mutex> lock(g_bio_mutex);
  auto it = g_bio_state.find(bio);
  if (it == g_bio_state.end()) return true;
  if (--it->second.refs > 0) return false;
  g_bio_state.erase(it);
  return true;
}

bool bio_dispatch_read(BIO* bio, void* data, int len, int& out) {
  if (!bio || !data || len <= 0) return false;
  const BIO_METHOD* method = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_bio_mutex);
    auto it = g_bio_state.find(bio);
    if (it == g_bio_state.end() || !it->second.method || !it->second.method->read) return false;
    method = it->second.method;
  }
  out = method->read(bio, static_cast<char*>(data), len);
  return true;
}

bool bio_dispatch_write(BIO* bio, const void* data, int len, int& out) {
  if (!bio || !data || len <= 0) return false;
  const BIO_METHOD* method = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_bio_mutex);
    auto it = g_bio_state.find(bio);
    if (it == g_bio_state.end() || !it->second.method || !it->second.method->write) return false;
    method = it->second.method;
  }
  out = method->write(bio, static_cast<const char*>(data), len);
  return true;
}

std::string trim(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
    s.erase(s.begin());
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
    s.pop_back();
  return s;
}

std::string normalize(std::string s) {
  s = trim(s);
  for (auto& c : s) {
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  }
  return s;
}

std::string extract_dn_component(const std::string& dn, const std::string& key) {
  auto pattern = key + "=";
  auto pos = dn.find(pattern);
  if (pos == std::string::npos) return {};
  pos += pattern.size();
  auto end = dn.find(',', pos);
  if (end == std::string::npos) end = dn.size();
  return trim(dn.substr(pos, end - pos));
}

bool wildcard_match(const std::string& pattern, const std::string& host) {
  if (pattern == host) return true;

  if (pattern.size() < 3 || pattern[0] != '*' || pattern[1] != '.') return false;
  if (pattern.find('*', 1) != std::string::npos) return false;

  std::string suffix = pattern.substr(1); // ".example.com"
  if (host.size() <= suffix.size()) return false;
  if (host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0) return false;

  std::string left = host.substr(0, host.size() - suffix.size());
  if (left.empty() || left.find('.') != std::string::npos) return false;

  return true;
}

int close_socket_fd(int fd) {
#ifdef _WIN32
  return closesocket(fd);
#else
  return close(fd);
#endif
}

bool set_fd_nonblocking(int fd, bool on) {
#ifdef _WIN32
  u_long mode = on ? 1 : 0;
  return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  if (on)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags) == 0;
#endif
}

bool is_ip_literal(const std::string& s) {
  std::array<unsigned char, 16> buf{};
  return inet_pton(AF_INET, s.c_str(), buf.data()) == 1 ||
         inet_pton(AF_INET6, s.c_str(), buf.data()) == 1;
}

} // namespace openssl_shim

extern "C" {

void* OPENSSL_malloc(size_t size) { return ::operator new(size, std::nothrow); }

void OPENSSL_free(void* ptr) { ::operator delete(ptr); }

void OPENSSL_cleanse(void* ptr, size_t len) {
  if (!ptr || len == 0) return;
  volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
  while (len--) *p++ = 0;
}

void OPENSSL_thread_stop(void) {}

unsigned long ERR_get_error(void) { return openssl_shim::pop_last_error_code(); }

unsigned long ERR_peek_error(void) { return openssl_shim::peek_last_error_code(); }

unsigned long ERR_peek_last_error(void) {
  return openssl_shim::peek_last_error_code();
}

void ERR_error_string_n(unsigned long e, char* buf, size_t len) {
  if (!buf || len == 0) return;
  auto msg = openssl_shim::get_last_error_string(e);
  if (msg.empty()) msg = "ok";
  auto n = std::min(msg.size(), len - 1);
  std::memcpy(buf, msg.data(), n);
  buf[n] = '\0';
}

char* ERR_error_string(unsigned long e, char* buf) {
  static thread_local std::array<char, 256> local{};
  if (!buf) {
    ERR_error_string_n(e, local.data(), local.size());
    return local.data();
  }
  ERR_error_string_n(e, buf, 256);
  return buf;
}

const char* ERR_lib_error_string(unsigned long e) {
  switch (ERR_GET_LIB(e)) {
    case ERR_LIB_SSL: return "SSL routines";
    case ERR_LIB_PEM: return "PEM routines";
    case ERR_LIB_EVP: return "digital envelope routines";
    case ERR_LIB_X509: return "X509 routines";
    default: return nullptr;
  }
}

const char* ERR_reason_error_string(unsigned long e) {
  static thread_local std::array<char, 256> buf{};
  ERR_error_string_n(e, buf.data(), buf.size());
  return buf.data();
}

void ERR_print_errors_fp(FILE* fp) {
  if (!fp) return;
  unsigned long e = 0;
  while ((e = ERR_get_error()) != 0) {
    char buf[256] = {0};
    ERR_error_string_n(e, buf, sizeof(buf));
    std::fputs(buf, fp);
    std::fputc('\n', fp);
  }
}

void ERR_clear_error(void) { openssl_shim::set_last_error(0, {}); }

int OPENSSL_init_ssl(uint64_t /*opts*/, const void* /*settings*/) { return 1; }

int OpenSSL_add_ssl_algorithms(void) { return 1; }

int SSL_load_error_strings(void) { return 1; }

BIO_METHOD* BIO_meth_new(int type, const char* /*name*/) {
  auto* m = new BIO_METHOD();
  m->type = type;
  return m;
}

void BIO_meth_free(BIO_METHOD* biom) {
  if (!biom || biom == BIO_s_mem()) return;
  delete biom;
}

int BIO_meth_set_create(BIO_METHOD* biom, int (*create)(BIO*)) {
  if (!biom) return 0;
  biom->create = create;
  return 1;
}

int BIO_meth_set_write(BIO_METHOD* biom, int (*write)(BIO*, const char*, int)) {
  if (!biom) return 0;
  biom->write = write;
  return 1;
}

int BIO_meth_set_read(BIO_METHOD* biom, int (*read)(BIO*, char*, int)) {
  if (!biom) return 0;
  biom->read = read;
  return 1;
}

int BIO_meth_set_ctrl(BIO_METHOD* biom, long (*ctrl)(BIO*, int, long, void*)) {
  if (!biom) return 0;
  biom->ctrl = ctrl;
  return 1;
}

void BIO_set_data(BIO* bio, void* data) { openssl_shim::bio_set_data(bio, data); }

void* BIO_get_data(BIO* bio) { return openssl_shim::bio_get_data(bio); }

void BIO_set_init(BIO* bio, int init) { openssl_shim::bio_set_init(bio, init); }

int BIO_get_init(BIO* bio) { return openssl_shim::bio_get_init(bio); }

void BIO_set_flags(BIO* bio, int flags) { openssl_shim::bio_set_flags(bio, flags); }

int BIO_up_ref(BIO* bio) { return openssl_shim::bio_up_ref(bio); }

const unsigned char* ASN1_STRING_get0_data(const ASN1_STRING* x) {
  if (!x || x->bytes.empty()) return nullptr;
  return x->bytes.data();
}

unsigned char* ASN1_STRING_data(ASN1_STRING* x) {
  return const_cast<unsigned char*>(ASN1_STRING_get0_data(x));
}

int ASN1_STRING_length(const ASN1_STRING* x) {
  if (!x) return 0;
  return static_cast<int>(x->bytes.size());
}

ASN1_TIME* ASN1_TIME_new(void) { return new ASN1_TIME(); }

void ASN1_TIME_free(ASN1_TIME* t) { delete t; }

ASN1_TIME* ASN1_TIME_set(ASN1_TIME* s, time_t t) {
  if (!s) s = ASN1_TIME_new();
  if (s) s->epoch = t;
  return s;
}

int ASN1_TIME_diff(int* pday, int* psec, const ASN1_TIME* from, const ASN1_TIME* to) {
  if (!pday || !psec || !from || !to) return 0;
  auto diff = static_cast<long long>(to->epoch) - static_cast<long long>(from->epoch);
  *pday = static_cast<int>(diff / 86400);
  *psec = static_cast<int>(diff % 86400);
  return 1;
}

BIGNUM* ASN1_INTEGER_to_BN(const ASN1_INTEGER* ai, BIGNUM* bn) {
  if (!ai) return nullptr;
  if (!bn) bn = new BIGNUM();
  if (!bn) return nullptr;
  bn->bytes = ai->bytes;
  return bn;
}

char* BN_bn2hex(const BIGNUM* a) {
  if (!a) return nullptr;
  static const char* hex = "0123456789ABCDEF";
  if (a->bytes.empty()) {
    char* z = static_cast<char*>(OPENSSL_malloc(2));
    if (!z) return nullptr;
    z[0] = '0';
    z[1] = '\0';
    return z;
  }
  size_t out_len = a->bytes.size() * 2;
  char* out = static_cast<char*>(OPENSSL_malloc(out_len + 1));
  if (!out) return nullptr;
  for (size_t i = 0; i < a->bytes.size(); ++i) {
    out[2 * i] = hex[(a->bytes[i] >> 4) & 0x0F];
    out[2 * i + 1] = hex[a->bytes[i] & 0x0F];
  }
  out[out_len] = '\0';
  return out;
}

void BN_free(BIGNUM* a) { delete a; }

int X509_OBJECT_get_type(const X509_OBJECT* obj) { return obj ? obj->type : 0; }

X509* X509_OBJECT_get0_X509(const X509_OBJECT* obj) { return obj ? obj->cert : nullptr; }

int sk_X509_OBJECT_num(const STACK_OF_X509_OBJECT* st) {
  return st ? static_cast<int>(st->items.size()) : 0;
}

X509_OBJECT* sk_X509_OBJECT_value(const STACK_OF_X509_OBJECT* st, int i) {
  if (!st || i < 0 || static_cast<size_t>(i) >= st->items.size()) return nullptr;
  return const_cast<X509_OBJECT*>(&st->items[static_cast<size_t>(i)]);
}

int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const char* name, size_t namelen) {
  if (!param || !name) return 0;
  param->host = namelen ? std::string(name, namelen) : std::string(name);
  return 1;
}

void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM* param, unsigned int flags) {
  if (param) param->hostflags = flags;
}

X509* X509_STORE_CTX_get_current_cert(X509_STORE_CTX* ctx) {
  return ctx ? ctx->current_cert : nullptr;
}

int X509_STORE_CTX_get_error(X509_STORE_CTX* ctx) {
  return ctx ? ctx->error : X509_V_ERR_UNSPECIFIED;
}

int X509_STORE_CTX_get_error_depth(X509_STORE_CTX* ctx) { return ctx ? ctx->depth : 0; }

void* X509_STORE_CTX_get_ex_data(X509_STORE_CTX* ctx, int idx) {
  if (!ctx || idx != 0) return nullptr;
  return ctx->ssl;
}

int native_sk_GENERAL_NAME_num(const STACK_OF_GENERAL_NAME* st) {
  return st ? static_cast<int>(st->names.size()) : 0;
}

GENERAL_NAME* native_sk_GENERAL_NAME_value(const STACK_OF_GENERAL_NAME* st, int i) {
  if (!st || i < 0 || static_cast<size_t>(i) >= st->names.size()) return nullptr;
  return st->names[static_cast<size_t>(i)];
}

void GENERAL_NAME_free(GENERAL_NAME* a) {
  if (!a) return;
  delete a->d.ptr;
  delete a;
}

void sk_GENERAL_NAME_pop_free(STACK_OF_GENERAL_NAME* st, void (*freefn)(GENERAL_NAME*)) {
  if (!st) return;
  for (auto* n : st->names) {
    if (freefn) freefn(n);
  }
  delete st;
}

void GENERAL_NAMES_free(STACK_OF_GENERAL_NAME* st) {
  sk_GENERAL_NAME_pop_free(st, GENERAL_NAME_free);
}

STACK_OF_X509_NAME* sk_X509_NAME_new_null(void) { return new STACK_OF_X509_NAME(); }

int sk_X509_NAME_push(STACK_OF_X509_NAME* sk, X509_NAME* name) {
  if (!sk || !name) return 0;
  sk->names.push_back(name);
  return 1;
}

int sk_X509_NAME_num(const STACK_OF_X509_NAME* sk) {
  return sk ? static_cast<int>(sk->names.size()) : 0;
}

void sk_X509_NAME_free(STACK_OF_X509_NAME* sk) { delete sk; }

void sk_X509_NAME_pop_free(STACK_OF_X509_NAME* sk, void (*free_fn)(X509_NAME*)) {
  if (!sk) return;
  for (auto* n : sk->names) {
    if (free_fn) free_fn(n);
  }
  delete sk;
}

int sk_X509_INFO_num(const STACK_OF_X509_INFO* st) {
  return st ? static_cast<int>(st->items.size()) : 0;
}

X509_INFO* sk_X509_INFO_value(const STACK_OF_X509_INFO* st, int i) {
  if (!st || i < 0 || static_cast<size_t>(i) >= st->items.size()) return nullptr;
  return st->items[static_cast<size_t>(i)];
}

void X509_INFO_free(X509_INFO* info) {
  if (!info) return;
  if (info->x509) X509_free(info->x509);
  delete info;
}

void sk_X509_INFO_pop_free(STACK_OF_X509_INFO* st, void (*freefn)(X509_INFO*)) {
  if (!st) return;
  for (auto* i : st->items) {
    if (freefn) freefn(i);
  }
  delete st;
}

char* X509_NAME_oneline(const X509_NAME* a, char* buf, int size) {
  if (!a || !buf || size <= 0) return nullptr;
  auto n = (std::min)(static_cast<int>(a->text.size()), size - 1);
  std::memcpy(buf, a->text.data(), n);
  buf[n] = '\0';
  return buf;
}

int X509_NAME_get_text_by_NID(X509_NAME* name, int nid, char* buf, int len) {
  if (!name || !buf || len <= 0) return -1;
  std::string val;
  if (nid == NID_commonName)
    val = name->common_name;
  else
    return -1;
  auto n = (std::min)(static_cast<int>(val.size()), len - 1);
  std::memcpy(buf, val.data(), n);
  buf[n] = '\0';
  return n;
}

X509_NAME* X509_NAME_dup(const X509_NAME* name) {
  if (!name) return nullptr;
  auto* n = new X509_NAME();
  n->text = name->text;
  n->common_name = name->common_name;
  return n;
}

void X509_NAME_free(X509_NAME* name) { delete name; }

const char* X509_verify_cert_error_string(long n) {
  switch (n) {
    case X509_V_OK: return "ok";
    case X509_V_ERR_CERT_HAS_EXPIRED: return "certificate has expired";
    case X509_V_ERR_CERT_NOT_YET_VALID: return "certificate is not yet valid";
    case X509_V_ERR_CERT_REVOKED: return "certificate revoked";
    case X509_V_ERR_CERT_CHAIN_TOO_LONG: return "certificate chain too long";
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: return "self signed certificate";
    case X509_V_ERR_HOSTNAME_MISMATCH: return "hostname mismatch";
    default: return "certificate verify error";
  }
}

X509* PEM_read_bio_X509_AUX(BIO* bp, X509** x, pem_password_cb* cb, void* u) {
  return PEM_read_bio_X509(bp, x, cb, u);
}

STACK_OF_X509_INFO* PEM_X509_INFO_read_bio(BIO* bp, STACK_OF_X509_INFO* sk,
                                           pem_password_cb* /*cb*/, void* /*u*/) {
  if (!bp) return nullptr;
  if (!sk) sk = new STACK_OF_X509_INFO();

  while (true) {
    auto* cert = PEM_read_bio_X509(bp, nullptr, nullptr, nullptr);
    if (!cert) break;
    auto* info = new X509_INFO();
    info->x509 = cert;
    info->crl = nullptr;
    sk->items.push_back(info);
  }
  return sk;
}

DH* PEM_read_DHparams(FILE* fp, DH** x, pem_password_cb* /*cb*/, void* /*u*/) {
  if (!fp) return nullptr;
  auto* out = new DH();
  if (x) *x = out;
  return out;
}

void DH_free(DH* dh) { delete dh; }

const SSL_METHOD* TLS_client_method(void) {
  static const ssl_method_st method{0};
  return &method;
}

const SSL_METHOD* TLS_server_method(void) {
  static const ssl_method_st method{1};
  return &method;
}

const SSL_METHOD* SSLv23_client_method(void) { return TLS_client_method(); }

const SSL_METHOD* SSLv23_server_method(void) { return TLS_server_method(); }

int SSL_CTX_set_ciphersuites(SSL_CTX* ctx, const char* str) {
  return SSL_CTX_set_cipher_list(ctx, str);
}

int SSL_CTX_default_verify_paths(SSL_CTX* ctx) {
  return SSL_CTX_set_default_verify_paths(ctx);
}

int SSL_set_ecdh_auto(SSL* /*ssl*/, int /*onoff*/) { return 1; }

int SSL_get_ex_data_X509_STORE_CTX_idx(void) { return 0; }

long SSL_CTX_set_read_ahead(SSL_CTX* /*ctx*/, int m) { return m ? 1 : 0; }

int SSL_CTX_set_tmp_dh(SSL_CTX* /*ctx*/, DH* /*dh*/) { return 1; }

int SSL_read_ex(SSL* ssl, void* buf, size_t num, size_t* readbytes) {
  if (readbytes) *readbytes = 0;
  if (!ssl || !buf) return 0;
  int rc = SSL_read(ssl, buf, static_cast<int>(num));
  if (rc <= 0) return 0;
  if (readbytes) *readbytes = static_cast<size_t>(rc);
  return 1;
}

int SSL_write_ex(SSL* ssl, const void* buf, size_t num, size_t* written) {
  if (written) *written = 0;
  if (!ssl || !buf) return 0;
  int rc = SSL_write(ssl, buf, static_cast<int>(num));
  if (rc <= 0) return 0;
  if (written) *written = static_cast<size_t>(rc);
  return 1;
}

void SSL_set_app_data(SSL* ssl, void* arg) {
  if (!ssl) return;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  if (arg) {
    g_ssl_app_data[ssl] = arg;
  } else {
    g_ssl_app_data.erase(ssl);
  }
}

void* SSL_get_app_data(const SSL* ssl) {
  if (!ssl) return nullptr;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  auto it = g_ssl_app_data.find(ssl);
  return it == g_ssl_app_data.end() ? nullptr : it->second;
}

int SSL_set_ex_data(SSL* ssl, int idx, void* data) {
  if (!ssl || idx < 0) return 0;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  g_ssl_ex_data[ssl][idx] = data;
  return 1;
}

void* SSL_get_ex_data(const SSL* ssl, int idx) {
  if (!ssl || idx < 0) return nullptr;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  auto sit = g_ssl_ex_data.find(ssl);
  if (sit == g_ssl_ex_data.end()) return nullptr;
  auto it = sit->second.find(idx);
  return it == sit->second.end() ? nullptr : it->second;
}

void SSL_CTX_set_app_data(SSL_CTX* ctx, void* arg) {
  if (!ctx) return;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  if (arg) {
    g_ssl_ctx_app_data[ctx] = arg;
  } else {
    g_ssl_ctx_app_data.erase(ctx);
  }
}

void* SSL_CTX_get_app_data(const SSL_CTX* ctx) {
  if (!ctx) return nullptr;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  auto it = g_ssl_ctx_app_data.find(ctx);
  return it == g_ssl_ctx_app_data.end() ? nullptr : it->second;
}

int SSL_CTX_set_ex_data(SSL_CTX* ctx, int idx, void* data) {
  if (!ctx || idx < 0) return 0;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  g_ssl_ctx_ex_data[ctx][idx] = data;
  return 1;
}

void* SSL_CTX_get_ex_data(const SSL_CTX* ctx, int idx) {
  if (!ctx || idx < 0) return nullptr;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  auto sit = g_ssl_ctx_ex_data.find(ctx);
  if (sit == g_ssl_ctx_ex_data.end()) return nullptr;
  auto it = sit->second.find(idx);
  return it == sit->second.end() ? nullptr : it->second;
}

long SSL_CTX_set_tlsext_servername_callback(SSL_CTX* ctx, SSL_tlsext_servername_callback cb) {
  if (!ctx) return 0;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  if (cb)
    g_ctx_sni_callbacks[ctx] = cb;
  else
    g_ctx_sni_callbacks.erase(ctx);
  return 1;
}

long SSL_CTX_set_tlsext_servername_arg(SSL_CTX* ctx, void* arg) {
  if (!ctx) return 0;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  g_ctx_sni_args[ctx] = arg;
  return 1;
}

int SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx, SSL_CTX_alpn_select_cb_func cb, void* arg) {
  if (!ctx) return 0;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  if (cb)
    g_ctx_alpn_select_callbacks[ctx] = cb;
  else
    g_ctx_alpn_select_callbacks.erase(ctx);
  g_ctx_alpn_select_args[ctx] = arg;
  return 1;
}

} // extern "C"

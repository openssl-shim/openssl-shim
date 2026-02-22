#include "tls_internal.hpp"

#include "openssl/bio.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
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
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <io.h>

#ifdef X509_NAME
#undef X509_NAME
#endif
#ifdef X509_CERT_PAIR
#undef X509_CERT_PAIR
#endif
#ifdef X509_EXTENSIONS
#undef X509_EXTENSIONS
#endif
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

struct x509_st {
#ifdef _WIN32
  PCCERT_CONTEXT cert_ctx = nullptr;
#else
  void* cert_ctx = nullptr;
#endif
  std::vector<unsigned char> der;
  std::string pem;
  int refs = 1;
  x509_name_st subject_name;
  x509_name_st issuer_name;
  asn1_string_st serial;
  asn1_time_st not_before;
  asn1_time_st not_after;

  ~x509_st() {
#ifdef _WIN32
    if (cert_ctx) CertFreeCertificateContext(cert_ctx);
#endif
  }
};

struct x509_store_st {
  std::vector<X509*> certs;
  unsigned long flags = 0;
  stack_st_X509_OBJECT object_cache;
#ifdef _WIN32
  HCERTSTORE store = nullptr;
#endif

  x509_store_st() {
#ifdef _WIN32
    store = CertOpenStore(CERT_STORE_PROV_MEMORY,
                          X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                          0,
                          CERT_STORE_CREATE_NEW_FLAG,
                          nullptr);
#endif
  }

  ~x509_store_st() {
    for (auto* cert : certs) {
      if (cert) X509_free(cert);
    }
#ifdef _WIN32
    if (store) CertCloseStore(store, 0);
#endif
  }
};

struct bio_method_st {
  int kind;
};

enum class BioKind { Socket, Memory };

struct bio_st {
  BioKind kind = BioKind::Memory;
  int fd = -1;
  bool close_on_free = false;
  std::vector<unsigned char> data;
  size_t offset = 0;
};

struct evp_pkey_st {
#ifdef _WIN32
  HCRYPTPROV hprov = 0;
  DWORD keyspec = AT_KEYEXCHANGE;
  NCRYPT_KEY_HANDLE nkey = 0;
  bool use_ncrypt = false;
  DWORD provider_type = PROV_RSA_AES;
  std::string provider_name = MS_ENH_RSA_AES_PROV_A;
  std::string container_name;
#endif
  bool has_key = false;
  std::string pem;
  std::vector<unsigned char> pkcs8_der;

  ~evp_pkey_st() {
#ifdef _WIN32
    if (use_ncrypt && nkey) {
      NCryptFreeObject(nkey);
      nkey = 0;
    }
    if (hprov) {
      CryptReleaseContext(hprov, 0);
      hprov = 0;
    }
#endif
  }
};

struct evp_md_st {
#ifdef _WIN32
  LPCWSTR algorithm = nullptr;
  ULONG digest_len = 0;
#else
  int algorithm = 0;
  unsigned int digest_len = 0;
#endif
};

struct evp_md_ctx_st {
#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::vector<unsigned char> hash_object;
#endif
  const EVP_MD* current = nullptr;

  ~evp_md_ctx_st() {
#ifdef _WIN32
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
#endif
  }
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

  void* passwd_userdata = nullptr;

  X509_STORE* cert_store = nullptr;
  stack_st_X509_NAME* client_ca_list = nullptr;

  X509* own_cert = nullptr;
  EVP_PKEY* own_key = nullptr;

  std::vector<std::string> alpn_protocols;
  std::vector<unsigned char> alpn_wire;

  bool use_system_roots = false;

  ~ssl_ctx_st() {
    if (client_ca_list) sk_X509_NAME_pop_free(client_ca_list, X509_NAME_free);
    if (cert_store) X509_STORE_free(cert_store);
    if (own_cert) X509_free(own_cert);
    if (own_key) EVP_PKEY_free(own_key);
  }
};

struct ssl_st {
  SSL_CTX* ctx = nullptr;

  int fd = -1;
  BIO* rbio = nullptr;
  BIO* wbio = nullptr;

  int verify_mode = SSL_VERIFY_NONE;
  int (*verify_callback)(int, X509_STORE_CTX*) = nullptr;

  int last_error = SSL_ERROR_NONE;
  int last_ret = 1;

  std::string hostname;
  std::string selected_alpn;
  x509_verify_param_st param;

  std::vector<unsigned char> peeked_plaintext;

  long verify_result = X509_V_OK;

#ifdef _WIN32
  CredHandle cred{};
  bool cred_valid = false;
  CtxtHandle ctxt{};
  bool ctxt_valid = false;
  bool handshake_started = false;
  bool handshake_done = false;

  SecPkgContext_StreamSizes sizes{};
  bool have_sizes = false;

  std::vector<unsigned char> incoming_encrypted;
  std::vector<unsigned char> decrypted;
  size_t decrypted_offset = 0;

  std::vector<unsigned char> pending_send;
  size_t pending_send_offset = 0;
  int pending_write_plaintext_result = 0;

  bool shutdown_sent = false;
  bool handshake_needs_finish = false;
#endif

  X509* peer_cert = nullptr;

  ~ssl_st() {
    if (peer_cert) X509_free(peer_cert);
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
#ifdef _WIN32
    if (ctxt_valid) {
      DeleteSecurityContext(&ctxt);
      ctxt_valid = false;
    }
    if (cred_valid) {
      FreeCredentialsHandle(&cred);
      cred_valid = false;
    }
#endif
  }
};

const bio_method_st g_mem_method{1};

#ifdef _WIN32
const EVP_MD g_md5{BCRYPT_MD5_ALGORITHM, 16};
const EVP_MD g_sha256{BCRYPT_SHA256_ALGORITHM, 32};
const EVP_MD g_sha512{BCRYPT_SHA512_ALGORITHM, 64};
#else
const EVP_MD g_md5{};
const EVP_MD g_sha256{};
const EVP_MD g_sha512{};
#endif

#ifdef _WIN32
std::string wide_to_utf8(const std::wstring& ws) {
  if (ws.empty()) return {};
  int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (len <= 1) return {};
  std::string out(static_cast<size_t>(len - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, out.data(), len, nullptr, nullptr);
  return out;
}

std::wstring utf8_to_wide(const std::string& s) {
  if (s.empty()) return {};
  int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
  if (len <= 1) return {};
  std::wstring out(static_cast<size_t>(len - 1), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), len);
  return out;
}

std::string read_file_text(const char* path) {
  if (!path) return {};
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) return {};
  std::string out((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
  return out;
}

bool decode_pem_block_to_der(const std::string& pem, std::vector<unsigned char>& der) {
  DWORD der_len = 0;
  if (!CryptStringToBinaryA(pem.c_str(), static_cast<DWORD>(pem.size()),
                            CRYPT_STRING_BASE64HEADER,
                            nullptr,
                            &der_len,
                            nullptr,
                            nullptr)) {
    return false;
  }

  der.resize(der_len);
  if (!CryptStringToBinaryA(pem.c_str(), static_cast<DWORD>(pem.size()),
                            CRYPT_STRING_BASE64HEADER,
                            der.data(),
                            &der_len,
                            nullptr,
                            nullptr)) {
    der.clear();
    return false;
  }
  der.resize(der_len);
  return true;
}

std::string base64_encode(const unsigned char* data, DWORD len) {
  if (!data || len == 0) return {};
  DWORD out_len = 0;
  if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            nullptr, &out_len)) {
    return {};
  }
  std::string out(out_len, '\0');
  if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            out.data(), &out_len)) {
    return {};
  }
  while (!out.empty() && (out.back() == '\0' || out.back() == '\r' || out.back() == '\n')) {
    out.pop_back();
  }
  return out;
}

std::string wrap_pem(const char* tag, const unsigned char* data, DWORD len) {
  if (!tag || !data || len == 0) return {};
  auto b64 = base64_encode(data, len);
  if (b64.empty()) return {};

  std::string out;
  out += "-----BEGIN ";
  out += tag;
  out += "-----\n";
  for (size_t i = 0; i < b64.size(); i += 64) {
    out.append(b64.substr(i, std::min<size_t>(64, b64.size() - i)));
    out.push_back('\n');
  }
  out += "-----END ";
  out += tag;
  out += "-----\n";
  return out;
}

time_t filetime_to_time_t(const FILETIME& ft) {
  ULARGE_INTEGER ui{};
  ui.LowPart = ft.dwLowDateTime;
  ui.HighPart = ft.dwHighDateTime;
  if (ui.QuadPart == 0) return 0;
  constexpr ULONGLONG kUnixEpoch = 116444736000000000ULL; // 1601 -> 1970 in 100ns
  if (ui.QuadPart < kUnixEpoch) return 0;
  ULONGLONG unix_100ns = ui.QuadPart - kUnixEpoch;
  return static_cast<time_t>(unix_100ns / 10000000ULL);
}

std::string cert_name_to_string(PCERT_NAME_BLOB blob) {
  if (!blob || !blob->pbData || blob->cbData == 0) return {};
  DWORD flags = CERT_X500_NAME_STR;
  DWORD n = CertNameToStrA(X509_ASN_ENCODING, blob, flags, nullptr, 0);
  if (n <= 1) return {};
  std::string out(static_cast<size_t>(n - 1), '\0');
  CertNameToStrA(X509_ASN_ENCODING, blob, flags, out.data(), n);
  return out;
}

std::string cert_get_cn(PCCERT_CONTEXT ctx, bool issuer) {
  if (!ctx) return {};
  DWORD flags = issuer ? CERT_NAME_ISSUER_FLAG : 0;
  char buf[512] = {0};
  DWORD n = CertGetNameStringA(ctx,
                               CERT_NAME_ATTR_TYPE,
                               flags,
                               const_cast<char*>(szOID_COMMON_NAME),
                               buf,
                               static_cast<DWORD>(sizeof(buf)));
  if (n <= 1) return {};
  return std::string(buf);
}

void refresh_x509_fields(X509* x) {
  if (!x || !x->cert_ctx || !x->cert_ctx->pCertInfo) return;

  x->subject_name.text = cert_name_to_string(&x->cert_ctx->pCertInfo->Subject);
  x->subject_name.common_name = cert_get_cn(x->cert_ctx, false);
  if (x->subject_name.common_name.empty()) {
    x->subject_name.common_name = extract_dn_component(x->subject_name.text, "CN");
  }

  x->issuer_name.text = cert_name_to_string(&x->cert_ctx->pCertInfo->Issuer);
  x->issuer_name.common_name = cert_get_cn(x->cert_ctx, true);
  if (x->issuer_name.common_name.empty()) {
    x->issuer_name.common_name = extract_dn_component(x->issuer_name.text, "CN");
  }

  x->serial.bytes.clear();
  const auto& serial = x->cert_ctx->pCertInfo->SerialNumber;
  x->serial.bytes.reserve(serial.cbData);
  // CERT_INFO serial bytes are little-endian.
  for (DWORD i = 0; i < serial.cbData; ++i) {
    x->serial.bytes.push_back(serial.pbData[serial.cbData - 1 - i]);
  }

  x->not_before.epoch = filetime_to_time_t(x->cert_ctx->pCertInfo->NotBefore);
  x->not_after.epoch = filetime_to_time_t(x->cert_ctx->pCertInfo->NotAfter);
}

X509* x509_from_der(const unsigned char* der, size_t len) {
  if (!der || len == 0) return nullptr;
  PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                     der,
                                                     static_cast<DWORD>(len));
  if (!cert) return nullptr;

  auto* x = new X509();
  x->cert_ctx = cert;
  x->der.assign(der, der + len);
  refresh_x509_fields(x);
  return x;
}

X509* x509_from_context(PCCERT_CONTEXT cert) {
  if (!cert || !cert->pbCertEncoded || cert->cbCertEncoded == 0) return nullptr;
  return x509_from_der(cert->pbCertEncoded, cert->cbCertEncoded);
}

struct key_import_target {
  std::string container;
  std::string provider;
  DWORD provider_type = PROV_RSA_AES;
  HCRYPTPROV hprov = 0;
};

BOOL CALLBACK resolve_hprov_for_pkcs8(CRYPT_PRIVATE_KEY_INFO* /*pki*/,
                                      HCRYPTPROV* phprov,
                                      LPVOID pvoid) {
  if (!phprov || !pvoid) return FALSE;
  auto* t = static_cast<key_import_target*>(pvoid);

  if (!CryptAcquireContextA(phprov,
                            t->container.c_str(),
                            t->provider.c_str(),
                            t->provider_type,
                            CRYPT_NEWKEYSET)) {
    auto err = GetLastError();
    if (err != NTE_EXISTS ||
        !CryptAcquireContextA(phprov,
                              t->container.c_str(),
                              t->provider.c_str(),
                              t->provider_type,
                              0)) {
      return FALSE;
    }
  }

  t->hprov = *phprov;
  return TRUE;
}

bool import_private_key_pkcs8(const std::vector<unsigned char>& der, EVP_PKEY* out) {
  if (!out || der.empty()) return false;

  out->hprov = 0;
  out->keyspec = AT_KEYEXCHANGE;
  out->nkey = 0;
  out->use_ncrypt = false;
  out->provider_type = PROV_RSA_AES;
  out->provider_name = MS_ENH_RSA_AES_PROV_A;
  out->container_name.clear();

  static std::atomic<unsigned long> counter{1};
  key_import_target target;
  target.provider = out->provider_name;
  target.provider_type = out->provider_type;
  target.container = "native_tls_shim_" + std::to_string(GetCurrentProcessId()) + "_" +
                     std::to_string(counter.fetch_add(1));

  CRYPT_PKCS8_IMPORT_PARAMS params{};
  params.PrivateKey.pbData = const_cast<BYTE*>(der.data());
  params.PrivateKey.cbData = static_cast<DWORD>(der.size());
  params.pResolvehCryptProvFunc = resolve_hprov_for_pkcs8;
  params.pVoidResolveFunc = &target;

  HCRYPTPROV hprov = 0;
  if (!CryptImportPKCS8(params, CRYPT_EXPORTABLE, &hprov, nullptr) || !hprov) {
    return false;
  }

  DWORD spec = 0;
  HCRYPTKEY hkey = 0;
  if (CryptGetUserKey(hprov, AT_KEYEXCHANGE, &hkey)) {
    CryptDestroyKey(hkey);
    spec = AT_KEYEXCHANGE;
  } else if (CryptGetUserKey(hprov, AT_SIGNATURE, &hkey)) {
    CryptDestroyKey(hkey);
    spec = AT_SIGNATURE;
  }
  if (spec == 0) {
    CryptReleaseContext(hprov, 0);
    return false;
  }

  out->hprov = hprov;
  out->keyspec = spec;
  out->container_name = target.container;
  return true;
}

bool attach_private_key_to_cert(X509* cert, EVP_PKEY* pkey) {
  if (!cert || !cert->cert_ctx || !pkey || !pkey->has_key) return false;
  if (!pkey->use_ncrypt && !pkey->hprov) return false;
  if (pkey->use_ncrypt && !pkey->nkey) return false;

  if (pkey->use_ncrypt) {
    CERT_KEY_CONTEXT key_ctx{};
    key_ctx.cbSize = sizeof(key_ctx);
    key_ctx.hNCryptKey = pkey->nkey;
    key_ctx.dwKeySpec = CERT_NCRYPT_KEY_SPEC;

    CertSetCertificateContextProperty(cert->cert_ctx,
                                      CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                                      0,
                                      &pkey->nkey);

    if (!CertSetCertificateContextProperty(cert->cert_ctx,
                                           CERT_KEY_CONTEXT_PROP_ID,
                                           CERT_SET_KEY_CONTEXT_PROP_ID,
                                           &key_ctx)) {
      set_error_message("CertSetCertificateContextProperty(CERT_KEY_CONTEXT_PROP_ID) failed: " +
                        std::to_string(GetLastError()));
      return false;
    }

    return true;
  }

  DWORD prov_type = pkey->provider_type;
  std::string cont_str = pkey->container_name;
  std::string prov_str = pkey->provider_name;

  if (cont_str.empty() || prov_str.empty()) {
    DWORD cb_prov_type = sizeof(prov_type);
    std::array<char, 256> cont{};
    DWORD cb_cont = static_cast<DWORD>(cont.size());
    std::array<char, 256> prov{};
    DWORD cb_prov = static_cast<DWORD>(prov.size());

    if (CryptGetProvParam(pkey->hprov, PP_PROVTYPE,
                          reinterpret_cast<BYTE*>(&prov_type),
                          &cb_prov_type, 0) &&
        CryptGetProvParam(pkey->hprov, PP_CONTAINER,
                          reinterpret_cast<BYTE*>(cont.data()),
                          &cb_cont, 0) &&
        CryptGetProvParam(pkey->hprov, PP_NAME,
                          reinterpret_cast<BYTE*>(prov.data()),
                          &cb_prov, 0)) {
      cont_str = cont.data();
      prov_str = prov.data();
    }
  }

  if (cont_str.empty() || prov_str.empty()) {
    set_error_message("provider/container info missing for private key");
    return false;
  }

  std::wstring wcont = utf8_to_wide(cont_str);
  std::wstring wprov = utf8_to_wide(prov_str);
  CRYPT_KEY_PROV_INFO info{};
  info.pwszContainerName = wcont.empty() ? nullptr : const_cast<wchar_t*>(wcont.c_str());
  info.pwszProvName = wprov.empty() ? nullptr : const_cast<wchar_t*>(wprov.c_str());
  info.dwProvType = prov_type;
  info.dwFlags = 0;
  info.cProvParam = 0;
  info.rgProvParam = nullptr;
  info.dwKeySpec = pkey->keyspec;

  if (!CertSetCertificateContextProperty(cert->cert_ctx,
                                         CERT_KEY_PROV_INFO_PROP_ID,
                                         0,
                                         &info)) {
    set_error_message("CertSetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID) failed: " +
                      std::to_string(GetLastError()));
    return false;
  }

  return true;
}

int map_sec_error_to_ssl_error(SECURITY_STATUS st) {
  switch (st) {
    case SEC_E_OK: return SSL_ERROR_NONE;
    case SEC_I_CONTEXT_EXPIRED: return SSL_ERROR_ZERO_RETURN;
    case SEC_E_INCOMPLETE_MESSAGE: return SSL_ERROR_WANT_READ;
    default: return SSL_ERROR_SSL;
  }
}

bool is_socket_would_block() {
  int err = WSAGetLastError();
  return err == WSAEWOULDBLOCK;
}

bool flush_pending_send(SSL* ssl) {
  if (!ssl) return false;
  while (ssl->pending_send_offset < ssl->pending_send.size()) {
    int to_send = static_cast<int>(ssl->pending_send.size() - ssl->pending_send_offset);
    int rc = send(ssl->fd,
                  reinterpret_cast<const char*>(ssl->pending_send.data() + ssl->pending_send_offset),
                  to_send,
                  0);
    if (rc < 0) {
      if (is_socket_would_block()) {
        ssl->last_error = SSL_ERROR_WANT_WRITE;
        ssl->last_ret = -1;
        return false;
      }
      ssl->last_error = SSL_ERROR_SYSCALL;
      ssl->last_ret = -1;
      set_error_message("socket send failed");
      return false;
    }
    if (rc == 0) {
      ssl->last_error = SSL_ERROR_ZERO_RETURN;
      ssl->last_ret = 0;
      return false;
    }
    ssl->pending_send_offset += static_cast<size_t>(rc);
  }

  ssl->pending_send.clear();
  ssl->pending_send_offset = 0;
  return true;
}

bool recv_into_handshake_buffer(SSL* ssl) {
  if (!ssl) return false;
  if (ssl->incoming_encrypted.size() > (1u << 20)) {
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    set_error_message("incoming TLS buffer overflow");
    return false;
  }

  std::array<unsigned char, 16 * 1024> tmp{};
  int rc = recv(ssl->fd, reinterpret_cast<char*>(tmp.data()), static_cast<int>(tmp.size()), 0);
  if (rc < 0) {
    if (is_socket_would_block()) {
      ssl->last_error = SSL_ERROR_WANT_READ;
      ssl->last_ret = -1;
      return false;
    }
    ssl->last_error = SSL_ERROR_SYSCALL;
    ssl->last_ret = -1;
    set_error_message("socket recv failed");
    return false;
  }
  if (rc == 0) {
    ssl->last_error = SSL_ERROR_ZERO_RETURN;
    ssl->last_ret = 0;
    return false;
  }

  ssl->incoming_encrypted.insert(ssl->incoming_encrypted.end(), tmp.data(), tmp.data() + rc);
  return true;
}

DWORD tls_protocol_flags(const SSL_CTX* ctx, bool client) {
  if (!ctx) return 0;
  DWORD p = 0;

  int minv = ctx->min_proto_version;
  if (client) {
#ifdef SP_PROT_TLS1_3_CLIENT
    if (minv <= TLS1_2_VERSION) p |= SP_PROT_TLS1_3_CLIENT;
    if (minv <= TLS1_3_VERSION && minv > TLS1_2_VERSION) p |= SP_PROT_TLS1_3_CLIENT;
#endif
#ifdef SP_PROT_TLS1_2_CLIENT
    if (minv <= TLS1_2_VERSION) p |= SP_PROT_TLS1_2_CLIENT;
#endif
#ifdef SP_PROT_TLS1_1_CLIENT
    if (minv <= TLS1_1_VERSION) p |= SP_PROT_TLS1_1_CLIENT;
#endif
#ifdef SP_PROT_TLS1_CLIENT
    if (minv <= TLS1_VERSION) p |= SP_PROT_TLS1_CLIENT;
#endif
  } else {
#ifdef SP_PROT_TLS1_3_SERVER
    if (minv <= TLS1_2_VERSION) p |= SP_PROT_TLS1_3_SERVER;
    if (minv <= TLS1_3_VERSION && minv > TLS1_2_VERSION) p |= SP_PROT_TLS1_3_SERVER;
#endif
#ifdef SP_PROT_TLS1_2_SERVER
    if (minv <= TLS1_2_VERSION) p |= SP_PROT_TLS1_2_SERVER;
#endif
#ifdef SP_PROT_TLS1_1_SERVER
    if (minv <= TLS1_1_VERSION) p |= SP_PROT_TLS1_1_SERVER;
#endif
#ifdef SP_PROT_TLS1_SERVER
    if (minv <= TLS1_VERSION) p |= SP_PROT_TLS1_SERVER;
#endif
  }

  if (p == 0) {
#ifdef SP_PROT_TLS1_2_CLIENT
    if (client) p = SP_PROT_TLS1_2_CLIENT;
#endif
#ifdef SP_PROT_TLS1_2_SERVER
    if (!client) p = SP_PROT_TLS1_2_SERVER;
#endif
  }

  return p;
}

bool ensure_credentials(SSL* ssl) {
  if (!ssl || !ssl->ctx) return false;
  if (ssl->cred_valid) return true;

  SCHANNEL_CRED cred{};
  cred.dwVersion = SCHANNEL_CRED_VERSION;
  cred.dwFlags = SCH_USE_STRONG_CRYPTO;
  if (ssl->ctx->is_client) {
    cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
  }
  cred.grbitEnabledProtocols = tls_protocol_flags(ssl->ctx, ssl->ctx->is_client);

  PCCERT_CONTEXT cert_ctx = nullptr;
  if (ssl->ctx->own_cert && ssl->ctx->own_cert->cert_ctx) {
    cert_ctx = ssl->ctx->own_cert->cert_ctx;
  }

  if (!ssl->ctx->is_client) {
    if (!cert_ctx) {
      set_error_message("server credential requires certificate");
      ssl->last_error = SSL_ERROR_SSL;
      ssl->last_ret = -1;
      return false;
    }
  }

  if (cert_ctx) {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD key_spec = 0;
    BOOL free_key = FALSE;
    if (!CryptAcquireCertificatePrivateKey(cert_ctx,
                                           CRYPT_ACQUIRE_CACHE_FLAG,
                                           nullptr,
                                           &key,
                                           &key_spec,
                                           &free_key)) {
      set_error_message("server certificate has no accessible private key: " +
                        std::to_string(GetLastError()));
      ssl->last_error = SSL_ERROR_SSL;
      ssl->last_ret = -1;
      return false;
    }
    if (free_key) {
      if (key_spec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(key);
      else CryptReleaseContext(key, 0);
    }

    cred.cCreds = 1;
    cred.paCred = &cert_ctx;
  }

  TimeStamp ts{};
  SECURITY_STATUS st = AcquireCredentialsHandleA(nullptr,
                                                 const_cast<char*>(UNISP_NAME_A),
                                                 ssl->ctx->is_client ? SECPKG_CRED_OUTBOUND : SECPKG_CRED_INBOUND,
                                                 nullptr,
                                                 &cred,
                                                 nullptr,
                                                 nullptr,
                                                 &ssl->cred,
                                                 &ts);
  if (st != SEC_E_OK) {
    set_error_message("AcquireCredentialsHandle failed: " + std::to_string(static_cast<long>(st)));
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    return false;
  }

  ssl->cred_valid = true;
  return true;
}

bool query_stream_sizes(SSL* ssl) {
  if (!ssl || !ssl->ctxt_valid) return false;
  SECURITY_STATUS st = QueryContextAttributes(&ssl->ctxt, SECPKG_ATTR_STREAM_SIZES, &ssl->sizes);
  if (st != SEC_E_OK) {
    set_error_message("QueryContextAttributes(SECPKG_ATTR_STREAM_SIZES) failed");
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    return false;
  }
  ssl->have_sizes = true;
  return true;
}

void query_selected_alpn(SSL* ssl) {
  if (!ssl || !ssl->ctxt_valid) return;
#if defined(SECPKG_ATTR_APPLICATION_PROTOCOL)
  SecPkgContext_ApplicationProtocol proto{};
  SECURITY_STATUS st = QueryContextAttributes(&ssl->ctxt,
                                              SECPKG_ATTR_APPLICATION_PROTOCOL,
                                              &proto);
  if (st == SEC_E_OK) {
    if (proto.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success &&
        proto.ProtocolIdSize > 0 && proto.ProtocolIdSize <= 255) {
      ssl->selected_alpn.assign(reinterpret_cast<const char*>(proto.ProtocolId),
                                reinterpret_cast<const char*>(proto.ProtocolId) + proto.ProtocolIdSize);
    }
  }
#endif
}

long map_chain_status_to_verify_error(DWORD status, PCCERT_CONTEXT cert) {
  if (status == 0) return X509_V_OK;

  if (status & CERT_TRUST_IS_NOT_TIME_VALID) {
    LONG tv = CertVerifyTimeValidity(nullptr, cert->pCertInfo);
    if (tv > 0) return X509_V_ERR_CERT_HAS_EXPIRED;
    if (tv < 0) return X509_V_ERR_CERT_NOT_YET_VALID;
    return X509_V_ERR_CERT_HAS_EXPIRED;
  }

  if (status & CERT_TRUST_IS_REVOKED) return X509_V_ERR_CERT_REVOKED;

  if (status & (CERT_TRUST_IS_UNTRUSTED_ROOT | CERT_TRUST_IS_PARTIAL_CHAIN)) {
    return X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
  }

  return X509_V_ERR_UNSPECIFIED;
}

long map_policy_error_to_verify_error(DWORD err) {
  if (err == 0) return X509_V_OK;
  if (err == CERT_E_CN_NO_MATCH) return X509_V_ERR_HOSTNAME_MISMATCH;
  if (err == CERT_E_EXPIRED) return X509_V_ERR_CERT_HAS_EXPIRED;
  if (err == CERT_E_UNTRUSTEDROOT || err == CERT_E_CHAINING) {
    return X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
  }
  return X509_V_ERR_UNSPECIFIED;
}

long verify_peer_chain(SSL* ssl, PCCERT_CONTEXT peer_cert, bool verify_peer) {
  if (!ssl || !ssl->ctx || !peer_cert) return X509_V_ERR_UNSPECIFIED;

  if (!verify_peer) return X509_V_OK;

  bool has_custom_roots =
      ssl->ctx->cert_store && ssl->ctx->cert_store->store && !ssl->ctx->cert_store->certs.empty();

  HCERTCHAINENGINE engine = HCCE_CURRENT_USER;
  bool free_engine = false;

  if (has_custom_roots) {
    CERT_CHAIN_ENGINE_CONFIG cfg{};
    cfg.cbSize = sizeof(cfg);
    cfg.hExclusiveRoot = ssl->ctx->cert_store->store;
    cfg.hExclusiveTrustedPeople = ssl->ctx->cert_store->store;
    if (!CertCreateCertificateChainEngine(&cfg, &engine)) {
      return X509_V_ERR_UNSPECIFIED;
    }
    free_engine = true;
  }

  CERT_CHAIN_PARA chain_para{};
  chain_para.cbSize = sizeof(chain_para);

  PCCERT_CHAIN_CONTEXT chain = nullptr;
  if (!CertGetCertificateChain(engine,
                               peer_cert,
                               nullptr,
                               has_custom_roots ? ssl->ctx->cert_store->store : nullptr,
                               &chain_para,
                               0,
                               nullptr,
                               &chain)) {
    if (free_engine) CertFreeCertificateChainEngine(engine);
    return X509_V_ERR_UNSPECIFIED;
  }

  long result = map_chain_status_to_verify_error(chain->TrustStatus.dwErrorStatus, peer_cert);

  if (result == X509_V_OK) {
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA extra{};
    extra.cbSize = sizeof(extra);
    extra.dwAuthType = ssl->ctx->is_client ? AUTHTYPE_SERVER : AUTHTYPE_CLIENT;

    std::wstring whost;
    if (ssl->ctx->is_client) {
      std::string host = !ssl->param.host.empty() ? ssl->param.host : ssl->hostname;
      if (!host.empty()) {
        whost = utf8_to_wide(host);
        if (!whost.empty()) {
          extra.pwszServerName = const_cast<wchar_t*>(whost.c_str());
        }
      }
    }

    CERT_CHAIN_POLICY_PARA policy_para{};
    policy_para.cbSize = sizeof(policy_para);
    policy_para.pvExtraPolicyPara = &extra;

    CERT_CHAIN_POLICY_STATUS policy_status{};
    policy_status.cbSize = sizeof(policy_status);

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
                                          chain,
                                          &policy_para,
                                          &policy_status)) {
      result = X509_V_ERR_UNSPECIFIED;
    } else {
      result = map_policy_error_to_verify_error(policy_status.dwError);
    }
  }

  CertFreeCertificateChain(chain);
  if (free_engine) CertFreeCertificateChainEngine(engine);
  return result;
}

int run_verify_callback_if_any(SSL* ssl) {
  if (!ssl || !ssl->ctx) return 1;
  auto* cb = ssl->verify_callback ? ssl->verify_callback : ssl->ctx->verify_callback;
  if (!cb) return 1;

  x509_store_ctx_st verify_ctx;
  verify_ctx.ssl = ssl;
  verify_ctx.current_cert = ssl->peer_cert;
  verify_ctx.depth = 0;
  verify_ctx.error = static_cast<int>(ssl->verify_result);

  int preverify = (ssl->verify_result == X509_V_OK) ? 1 : 0;
  int rc = cb(preverify, &verify_ctx);
  if (rc != 0 && preverify == 0) {
    // OpenSSL allows callback to override verification failure.
    ssl->verify_result = X509_V_OK;
  }
  return rc;
}

bool post_handshake_verify(SSL* ssl) {
  if (!ssl || !ssl->ctxt_valid || !ssl->ctx) return false;

  auto effective_verify_mode = ssl->verify_mode ? ssl->verify_mode : ssl->ctx->verify_mode;

  PCCERT_CONTEXT remote = nullptr;
  SECURITY_STATUS st = QueryContextAttributes(&ssl->ctxt,
                                              SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                              &remote);

  if (ssl->peer_cert) {
    X509_free(ssl->peer_cert);
    ssl->peer_cert = nullptr;
  }

  if (st == SEC_E_OK && remote) {
    ssl->peer_cert = x509_from_context(remote);
    CertFreeCertificateContext(remote);
  }

  bool has_custom_roots =
      ssl->ctx->cert_store && ssl->ctx->cert_store->store && !ssl->ctx->cert_store->certs.empty();
  bool should_verify = (effective_verify_mode & SSL_VERIFY_PEER) != 0;
  if (!should_verify && ssl->ctx->is_client && (has_custom_roots || ssl->ctx->use_system_roots)) {
    should_verify = true;
  }

  if (!should_verify) {
    ssl->verify_result = X509_V_OK;
    return run_verify_callback_if_any(ssl) != 0;
  }

  if (!ssl->peer_cert || !ssl->peer_cert->cert_ctx) {
    if (!ssl->ctx->is_client && (effective_verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
      ssl->verify_result = X509_V_ERR_UNSPECIFIED;
      set_error_message("peer certificate required but not provided");
      ssl->last_error = SSL_ERROR_SSL;
      ssl->last_ret = -1;
      return false;
    }
    ssl->verify_result = X509_V_OK;
    return run_verify_callback_if_any(ssl) != 0;
  }

  ssl->verify_result = verify_peer_chain(ssl, ssl->peer_cert->cert_ctx, should_verify);

  if (run_verify_callback_if_any(ssl) == 0) {
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    set_error_message("verify callback rejected certificate");
    return false;
  }

  if (ssl->verify_result != X509_V_OK) {
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    set_error_message("certificate verification failed",
                      static_cast<int>(ssl->verify_result));
    return false;
  }

  return true;
}

bool schannel_handshake(SSL* ssl) {
  if (!ssl || !ssl->ctx) return false;

  if (ssl->handshake_done) return true;

  if (ssl->handshake_needs_finish) {
    if (!flush_pending_send(ssl)) return false;
    if (!query_stream_sizes(ssl)) return false;
    query_selected_alpn(ssl);
    if (!post_handshake_verify(ssl)) return false;
    ssl->handshake_done = true;
    ssl->handshake_needs_finish = false;
    ssl->last_error = SSL_ERROR_NONE;
    ssl->last_ret = 1;
    return true;
  }

  if (!ensure_credentials(ssl)) return false;

  for (;;) {
    if (!flush_pending_send(ssl)) {
      return false;
    }

    SecBuffer in_buffers[2] = {};
    SecBufferDesc in_desc{};
    SecBufferDesc* in_ptr = nullptr;

    bool provide_input = false;
    if (ssl->ctx->is_client) {
      provide_input = ssl->handshake_started;
    } else {
      provide_input = true;
    }

    if (provide_input) {
      if (ssl->incoming_encrypted.empty()) {
        if (!recv_into_handshake_buffer(ssl)) return false;
      }
      in_buffers[0].BufferType = SECBUFFER_TOKEN;
      in_buffers[0].pvBuffer = ssl->incoming_encrypted.data();
      in_buffers[0].cbBuffer = static_cast<unsigned long>(ssl->incoming_encrypted.size());
      in_buffers[1].BufferType = SECBUFFER_EMPTY;
      in_desc.ulVersion = SECBUFFER_VERSION;
      in_desc.cBuffers = 2;
      in_desc.pBuffers = in_buffers;
      in_ptr = &in_desc;
    }

    SecBuffer out_buffer{};
    out_buffer.BufferType = SECBUFFER_TOKEN;
    SecBufferDesc out_desc{};
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_buffer;

    ULONG attrs = 0;
    TimeStamp ts{};

    SECURITY_STATUS st = SEC_E_INTERNAL_ERROR;
    if (ssl->ctx->is_client) {
      DWORD flags = ISC_REQ_ALLOCATE_MEMORY |
                    ISC_REQ_CONFIDENTIALITY |
                    ISC_REQ_REPLAY_DETECT |
                    ISC_REQ_SEQUENCE_DETECT |
                    ISC_REQ_STREAM;
      st = InitializeSecurityContextA(
          &ssl->cred,
          ssl->handshake_started ? &ssl->ctxt : nullptr,
          ssl->handshake_started ? nullptr
                                 : const_cast<char*>(ssl->hostname.empty() ? nullptr : ssl->hostname.c_str()),
          flags,
          0,
          0,
          in_ptr,
          0,
          ssl->handshake_started ? nullptr : &ssl->ctxt,
          &out_desc,
          &attrs,
          &ts);
    } else {
      DWORD flags = ASC_REQ_ALLOCATE_MEMORY |
                    ASC_REQ_CONFIDENTIALITY |
                    ASC_REQ_REPLAY_DETECT |
                    ASC_REQ_SEQUENCE_DETECT |
                    ASC_REQ_STREAM;
      auto effective_verify_mode = ssl->verify_mode ? ssl->verify_mode : ssl->ctx->verify_mode;
      if (effective_verify_mode & SSL_VERIFY_PEER) {
        flags |= ASC_REQ_MUTUAL_AUTH;
      }
      st = AcceptSecurityContext(
          &ssl->cred,
          ssl->handshake_started ? &ssl->ctxt : nullptr,
          in_ptr,
          flags,
          SECURITY_NATIVE_DREP,
          ssl->handshake_started ? nullptr : &ssl->ctxt,
          &out_desc,
          &attrs,
          &ts);
    }

    ssl->handshake_started = true;
    ssl->ctxt_valid = true;

    if (out_buffer.pvBuffer && out_buffer.cbBuffer) {
      auto* p = static_cast<unsigned char*>(out_buffer.pvBuffer);
      ssl->pending_send.insert(ssl->pending_send.end(), p, p + out_buffer.cbBuffer);
      FreeContextBuffer(out_buffer.pvBuffer);
    }

    if (provide_input) {
      if (st == SEC_E_INCOMPLETE_MESSAGE) {
        // Keep buffered bytes and append more on the next recv.
      } else if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
        size_t extra = static_cast<size_t>(in_buffers[1].cbBuffer);
        size_t used = ssl->incoming_encrypted.size() - extra;
        std::memmove(ssl->incoming_encrypted.data(),
                     ssl->incoming_encrypted.data() + used,
                     extra);
        ssl->incoming_encrypted.resize(extra);
      } else {
        ssl->incoming_encrypted.clear();
      }
    }

    if (st == SEC_E_OK) {
      if (!flush_pending_send(ssl)) {
        if (ssl->last_error == SSL_ERROR_WANT_WRITE) {
          ssl->handshake_needs_finish = true;
        }
        return false;
      }
      if (!query_stream_sizes(ssl)) return false;
      query_selected_alpn(ssl);
      if (!post_handshake_verify(ssl)) return false;
      ssl->handshake_done = true;
      ssl->handshake_needs_finish = false;
      ssl->last_error = SSL_ERROR_NONE;
      ssl->last_ret = 1;
      return true;
    }

    if (st == SEC_I_CONTINUE_NEEDED || st == SEC_I_COMPLETE_AND_CONTINUE || st == SEC_I_COMPLETE_NEEDED) {
      if (st == SEC_I_COMPLETE_AND_CONTINUE || st == SEC_I_COMPLETE_NEEDED) {
        CompleteAuthToken(&ssl->ctxt, &out_desc);
      }
      if (!ssl->pending_send.empty() && !flush_pending_send(ssl)) return false;
      continue;
    }

    if (st == SEC_E_INCOMPLETE_MESSAGE) {
      if (!recv_into_handshake_buffer(ssl)) return false;
      continue;
    }

    if (st == SEC_I_CONTEXT_EXPIRED) {
      ssl->last_error = SSL_ERROR_ZERO_RETURN;
      ssl->last_ret = 0;
      return false;
    }

    ssl->last_error = map_sec_error_to_ssl_error(st);
    ssl->last_ret = -1;
    set_error_message("TLS handshake failed: " + std::to_string(static_cast<long>(st)));
    return false;
  }
}

bool ensure_decrypted_data(SSL* ssl) {
  if (!ssl || !ssl->ctxt_valid) return false;

  for (;;) {
    if (ssl->decrypted_offset < ssl->decrypted.size()) return true;
    ssl->decrypted.clear();
    ssl->decrypted_offset = 0;

    if (ssl->incoming_encrypted.empty()) {
      if (!recv_into_handshake_buffer(ssl)) {
        return false;
      }
    }

    SecBuffer bufs[4] = {};
    bufs[0].BufferType = SECBUFFER_DATA;
    bufs[0].pvBuffer = ssl->incoming_encrypted.data();
    bufs[0].cbBuffer = static_cast<unsigned long>(ssl->incoming_encrypted.size());
    bufs[1].BufferType = SECBUFFER_EMPTY;
    bufs[2].BufferType = SECBUFFER_EMPTY;
    bufs[3].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc desc{};
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = bufs;

    SECURITY_STATUS st = DecryptMessage(&ssl->ctxt, &desc, 0, nullptr);

    if (st == SEC_E_INCOMPLETE_MESSAGE) {
      if (!recv_into_handshake_buffer(ssl)) return false;
      continue;
    }

    if (st == SEC_I_CONTEXT_EXPIRED) {
      ssl->last_error = SSL_ERROR_ZERO_RETURN;
      ssl->last_ret = 0;
      return false;
    }

    if (st == SEC_I_RENEGOTIATE) {
      ssl->last_error = SSL_ERROR_WANT_READ;
      ssl->last_ret = -1;
      return false;
    }

    if (st != SEC_E_OK) {
      ssl->last_error = SSL_ERROR_SSL;
      ssl->last_ret = -1;
      set_error_message("DecryptMessage failed: " + std::to_string(static_cast<long>(st)));
      return false;
    }

    SecBuffer* data_buf = nullptr;
    SecBuffer* extra_buf = nullptr;
    for (auto& b : bufs) {
      if (b.BufferType == SECBUFFER_DATA) data_buf = &b;
      if (b.BufferType == SECBUFFER_EXTRA) extra_buf = &b;
    }

    if (data_buf && data_buf->pvBuffer && data_buf->cbBuffer > 0) {
      auto* p = static_cast<unsigned char*>(data_buf->pvBuffer);
      ssl->decrypted.assign(p, p + data_buf->cbBuffer);
      ssl->decrypted_offset = 0;
    }

    size_t extra = extra_buf ? static_cast<size_t>(extra_buf->cbBuffer) : 0;
    if (extra > 0) {
      size_t used = ssl->incoming_encrypted.size() - extra;
      std::memmove(ssl->incoming_encrypted.data(),
                   ssl->incoming_encrypted.data() + used,
                   extra);
      ssl->incoming_encrypted.resize(extra);
    } else {
      ssl->incoming_encrypted.clear();
    }

    if (!ssl->decrypted.empty()) return true;
  }
}

bool send_close_notify(SSL* ssl) {
  if (!ssl || !ssl->ctxt_valid || ssl->fd < 0) return false;

  if (!ssl->pending_send.empty()) {
    if (!flush_pending_send(ssl)) return false;
  }

  if (!ssl->have_sizes) {
    if (!query_stream_sizes(ssl)) return false;
  }

  DWORD shutdown_token = SCHANNEL_SHUTDOWN;
  SecBuffer ctrl_buf{};
  ctrl_buf.BufferType = SECBUFFER_TOKEN;
  ctrl_buf.cbBuffer = sizeof(shutdown_token);
  ctrl_buf.pvBuffer = &shutdown_token;
  SecBufferDesc ctrl_desc{};
  ctrl_desc.ulVersion = SECBUFFER_VERSION;
  ctrl_desc.cBuffers = 1;
  ctrl_desc.pBuffers = &ctrl_buf;

  SECURITY_STATUS st = ApplyControlToken(&ssl->ctxt, &ctrl_desc);
  if (st != SEC_E_OK) {
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    set_error_message("ApplyControlToken(SCHANNEL_SHUTDOWN) failed: " +
                      std::to_string(static_cast<long>(st)));
    return false;
  }

  std::vector<unsigned char> packet(ssl->sizes.cbHeader + ssl->sizes.cbTrailer);
  SecBuffer out_buf{};
  out_buf.BufferType = SECBUFFER_TOKEN;
  out_buf.pvBuffer = packet.data();
  out_buf.cbBuffer = static_cast<unsigned long>(packet.size());
  SecBufferDesc out_desc{};
  out_desc.ulVersion = SECBUFFER_VERSION;
  out_desc.cBuffers = 1;
  out_desc.pBuffers = &out_buf;

  st = EncryptMessage(&ssl->ctxt, 0, &out_desc, 0);
  if (st != SEC_E_OK) {
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    set_error_message("EncryptMessage(close_notify) failed: " +
                      std::to_string(static_cast<long>(st)));
    return false;
  }

  if (out_buf.cbBuffer == 0) return true;

  ssl->pending_send.assign(packet.begin(), packet.begin() + out_buf.cbBuffer);
  ssl->pending_send_offset = 0;
  return flush_pending_send(ssl);
}

bool add_cert_to_store(X509_STORE* store, X509* cert, bool allow_duplicate_error) {
  if (!store || !cert || !cert->cert_ctx) return false;

  for (auto* existing : store->certs) {
    if (!existing) continue;
    if (existing->der.size() == cert->der.size() && !existing->der.empty() &&
        std::memcmp(existing->der.data(), cert->der.data(), cert->der.size()) == 0) {
      if (!allow_duplicate_error) return true;
      set_error_message("certificate already in store", X509_R_CERT_ALREADY_IN_HASH_TABLE);
      return false;
    }
  }

  if (!CertAddCertificateContextToStore(store->store,
                                        cert->cert_ctx,
                                        CERT_STORE_ADD_ALWAYS,
                                        nullptr)) {
    set_error_message("CertAddCertificateContextToStore failed");
    return false;
  }

  X509_up_ref(cert);
  store->certs.push_back(cert);
  return true;
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
  if (end < text.size() && text[end] == '\r') ++end;
  if (end < text.size() && text[end] == '\n') ++end;

  out_block = text.substr(begin, end - begin);
  bio->offset = end;
  return true;
}

bool load_ca_file_into_store(X509_STORE* store, const char* file) {
  if (!store || !file || !*file) return false;
  auto pem = read_file_text(file);
  if (pem.empty()) return false;

  auto* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return false;

  bool loaded = false;
  while (true) {
    auto* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) break;
    if (add_cert_to_store(store, cert, false)) loaded = true;
    X509_free(cert);
  }
  BIO_free(bio);
  return loaded;
}

bool load_ca_path_into_store(X509_STORE* store, const char* ca_path) {
  if (!store || !ca_path || !*ca_path) return false;
  bool loaded = false;
  std::error_code ec;
  for (auto const& entry : std::filesystem::directory_iterator(ca_path, ec)) {
    if (ec) break;
    if (!entry.is_regular_file()) continue;
    auto p = entry.path().string();
    if (load_ca_file_into_store(store, p.c_str())) loaded = true;
  }
  return loaded;
}

bool cert_matches_hostname(const X509* cert, const std::string& host, bool check_ip) {
  if (!cert) return false;

  auto names = static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(const_cast<X509*>(cert), NID_subject_alt_name, nullptr, nullptr));
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

#else
// Non-Windows build placeholder helpers.
#endif

extern "C" {

#include "tls_shared_exports.inl"

/* ===== BIO ===== */
long BIO_get_mem_data(BIO* bio, char** pp) {
  if (!bio || bio->kind != BioKind::Memory) {
    if (pp) *pp = nullptr;
    return 0;
  }
  if (pp) {
    *pp = reinterpret_cast<char*>(bio->data.data() + bio->offset);
  }
  return static_cast<long>(bio->data.size() - bio->offset);
}

int BIO_free(BIO* a) {
  if (!a) return 0;
  if (a->kind == BioKind::Socket && a->close_on_free && a->fd >= 0) {
    close_socket_fd(a->fd);
  }
  delete a;
  return 1;
}

/* ===== EVP ===== */
int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void* /*engine*/) {
#ifdef _WIN32
  if (!ctx || !type || !type->algorithm) return 0;

  if (ctx->hash) {
    BCryptDestroyHash(ctx->hash);
    ctx->hash = nullptr;
  }
  if (ctx->alg) {
    BCryptCloseAlgorithmProvider(ctx->alg, 0);
    ctx->alg = nullptr;
  }
  ctx->hash_object.clear();

  NTSTATUS st = BCryptOpenAlgorithmProvider(&ctx->alg, type->algorithm, nullptr, 0);
  if (st != 0 || !ctx->alg) return 0;

  DWORD obj_len = 0;
  DWORD cb = 0;
  st = BCryptGetProperty(ctx->alg,
                         BCRYPT_OBJECT_LENGTH,
                         reinterpret_cast<PUCHAR>(&obj_len),
                         sizeof(obj_len),
                         &cb,
                         0);
  if (st != 0 || obj_len == 0) return 0;

  ctx->hash_object.resize(obj_len);
  st = BCryptCreateHash(ctx->alg,
                        &ctx->hash,
                        ctx->hash_object.data(),
                        static_cast<ULONG>(ctx->hash_object.size()),
                        nullptr,
                        0,
                        0);
  if (st != 0 || !ctx->hash) return 0;

  ctx->current = type;
  return 1;
#else
  (void)ctx;
  (void)type;
  return 0;
#endif
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) {
#ifdef _WIN32
  if (!ctx || !ctx->hash || (!d && cnt > 0)) return 0;
  NTSTATUS st = BCryptHashData(ctx->hash,
                               const_cast<PUCHAR>(static_cast<const unsigned char*>(d)),
                               static_cast<ULONG>(cnt),
                               0);
  return st == 0 ? 1 : 0;
#else
  (void)ctx;
  (void)d;
  (void)cnt;
  return 0;
#endif
}

int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s) {
#ifdef _WIN32
  if (!ctx || !ctx->hash || !ctx->current || !md) return 0;
  NTSTATUS st = BCryptFinishHash(ctx->hash, md, ctx->current->digest_len, 0);
  if (st != 0) return 0;
  if (s) *s = ctx->current->digest_len;
  return 1;
#else
  (void)ctx;
  (void)md;
  if (s) *s = 0;
  return 0;
#endif
}

void EVP_PKEY_free(EVP_PKEY* pkey) { delete pkey; }

/* ===== X509 ===== */
int i2d_X509(const X509* x, unsigned char** out) {
  if (!x || x->der.empty()) return -1;
  int len = static_cast<int>(x->der.size());
  if (!out) return len;
  std::memcpy(*out, x->der.data(), x->der.size());
  *out += x->der.size();
  return len;
}

/* ===== X509 store ===== */
void* X509_get_ext_d2i(X509* x, int nid, int* /*crit*/, int* /*idx*/) {
#ifdef _WIN32
  if (!x || !x->cert_ctx || nid != NID_subject_alt_name) return nullptr;
  if (!x->cert_ctx->pCertInfo) return nullptr;

  auto* ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
                                x->cert_ctx->pCertInfo->cExtension,
                                x->cert_ctx->pCertInfo->rgExtension);
  if (!ext) {
    ext = CertFindExtension(szOID_SUBJECT_ALT_NAME,
                            x->cert_ctx->pCertInfo->cExtension,
                            x->cert_ctx->pCertInfo->rgExtension);
  }
  if (!ext) return nullptr;

  CERT_ALT_NAME_INFO* alt = nullptr;
  DWORD alt_len = 0;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                           X509_ALTERNATE_NAME,
                           ext->Value.pbData,
                           ext->Value.cbData,
                           CRYPT_DECODE_ALLOC_FLAG,
                           nullptr,
                           &alt,
                           &alt_len) ||
      !alt) {
    return nullptr;
  }

  auto* out = new STACK_OF_GENERAL_NAME();

  for (DWORD i = 0; i < alt->cAltEntry; ++i) {
    const auto& e = alt->rgAltEntry[i];
    auto* gn = new GENERAL_NAME();
    gn->type = GEN_OTHERNAME;
    gn->d.ptr = new ASN1_STRING();

    bool used = false;
    switch (e.dwAltNameChoice) {
      case CERT_ALT_NAME_DNS_NAME: {
        std::wstring ws = e.pwszDNSName ? e.pwszDNSName : L"";
        auto s = wide_to_utf8(ws);
        gn->type = GEN_DNS;
        gn->d.ptr->bytes.assign(s.begin(), s.end());
        gn->d.dNSName = gn->d.ptr;
        used = true;
        break;
      }
      case CERT_ALT_NAME_IP_ADDRESS: {
        gn->type = GEN_IPADD;
        gn->d.ptr->bytes.assign(e.IPAddress.pbData, e.IPAddress.pbData + e.IPAddress.cbData);
        gn->d.iPAddress = gn->d.ptr;
        used = true;
        break;
      }
      case CERT_ALT_NAME_RFC822_NAME: {
        std::wstring ws = e.pwszRfc822Name ? e.pwszRfc822Name : L"";
        auto s = wide_to_utf8(ws);
        gn->type = GEN_EMAIL;
        gn->d.ptr->bytes.assign(s.begin(), s.end());
        gn->d.rfc822Name = gn->d.ptr;
        used = true;
        break;
      }
      case CERT_ALT_NAME_URL: {
        std::wstring ws = e.pwszURL ? e.pwszURL : L"";
        auto s = wide_to_utf8(ws);
        gn->type = GEN_URI;
        gn->d.ptr->bytes.assign(s.begin(), s.end());
        gn->d.uniformResourceIdentifier = gn->d.ptr;
        used = true;
        break;
      }
      default:
        break;
    }

    if (used) {
      out->names.push_back(gn);
    } else {
      GENERAL_NAME_free(gn);
    }
  }

  LocalFree(alt);

  if (out->names.empty()) {
    delete out;
    return nullptr;
  }

  return out;
#else
  (void)x;
  (void)nid;
  return nullptr;
#endif
}

/* ===== PEM ===== */
X509* PEM_read_bio_X509(BIO* bp, X509** x, void* /*cb*/, void* /*u*/) {
#ifdef _WIN32
  if (!bp) return nullptr;

  std::string pem;
  if (!next_pem_block(bp, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", pem)) {
    return nullptr;
  }

  std::vector<unsigned char> der;
  if (!decode_pem_block_to_der(pem, der)) {
    return nullptr;
  }

  auto* cert = x509_from_der(der.data(), der.size());
  if (!cert) return nullptr;
  cert->pem = pem;
  if (x) *x = cert;
  return cert;
#else
  (void)bp;
  (void)x;
  return nullptr;
#endif
}

EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, EVP_PKEY** x, void* /*cb*/, void* /*u*/) {
#ifdef _WIN32
  if (!bp) return nullptr;

  std::string pem;
  if (!next_pem_block(bp,
                      "-----BEGIN PRIVATE KEY-----",
                      "-----END PRIVATE KEY-----",
                      pem)) {
    return nullptr;
  }

  std::vector<unsigned char> der;
  if (!decode_pem_block_to_der(pem, der)) return nullptr;

  auto* pkey = new EVP_PKEY();
  if (!import_private_key_pkcs8(der, pkey)) {
    delete pkey;
    set_error_message("failed to import PKCS#8 private key");
    return nullptr;
  }
  pkey->pkcs8_der = std::move(der);
  pkey->pem = std::move(pem);
  pkey->has_key = true;

  if (x) *x = pkey;
  return pkey;
#else
  (void)bp;
  (void)x;
  return nullptr;
#endif
}

int PEM_write_bio_X509(BIO* bp, X509* x) {
#ifdef _WIN32
  if (!bp || !x || bp->kind != BioKind::Memory || x->der.empty()) return 0;

  std::string pem = x->pem;
  if (pem.empty()) {
    pem = wrap_pem("CERTIFICATE", x->der.data(), static_cast<DWORD>(x->der.size()));
  }
  if (pem.empty()) return 0;

  bp->data.insert(bp->data.end(), pem.begin(), pem.end());
  if (!pem.empty() && pem.back() != '\n') bp->data.push_back('\n');
  return 1;
#else
  (void)bp;
  (void)x;
  return 0;
#endif
}

int PEM_write_bio_PrivateKey(BIO* bp, EVP_PKEY* x, const void* /*enc*/, unsigned char* /*kstr*/,
                             int /*klen*/, void* /*cb*/, void* /*u*/) {
#ifdef _WIN32
  if (!bp || !x || bp->kind != BioKind::Memory || !x->has_key) return 0;

  std::string pem = x->pem;
  if (pem.empty() && !x->pkcs8_der.empty()) {
    pem = wrap_pem("PRIVATE KEY",
                   x->pkcs8_der.data(),
                   static_cast<DWORD>(x->pkcs8_der.size()));
  }
  if (pem.empty()) return 0;

  bp->data.insert(bp->data.end(), pem.begin(), pem.end());
  if (!pem.empty() && pem.back() != '\n') bp->data.push_back('\n');
  return 1;
#else
  (void)bp;
  (void)x;
  return 0;
#endif
}

/* ===== SSL methods/context ===== */
SSL_CTX* SSL_CTX_new(const SSL_METHOD* method) {
  auto* ctx = new SSL_CTX();
  ctx->is_client = !(method && method->endpoint == 1);
  ctx->verify_mode = SSL_VERIFY_NONE;
  ctx->cert_store = X509_STORE_new();
  return ctx;
}

void SSL_CTX_set_verify(SSL_CTX* ctx, int mode,
                        int (*verify_callback)(int, X509_STORE_CTX*)) {
  if (!ctx) return;
  ctx->verify_mode = mode;
  ctx->verify_callback = verify_callback;
}

static bool add_cipher_from_token(const std::string& token) {
  if (token == "ECDHE-ECDSA-AES128-GCM-SHA256") return true;
  if (token == "ECDHE-ECDSA-AES256-GCM-SHA384") return true;
  if (token == "ECDHE-RSA-AES128-GCM-SHA256") return true;
  if (token == "ECDHE-RSA-AES256-GCM-SHA384") return true;
  if (token == "DHE-RSA-AES128-GCM-SHA256") return true;
  if (token == "DHE-RSA-AES256-GCM-SHA384") return true;
  if (token == "AES128-GCM-SHA256") return true;
  if (token == "AES256-GCM-SHA384") return true;
  if (token == "ECDHE-ECDSA-CHACHA20-POLY1305" ||
      token == "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256") {
    return true;
  }
  if (token == "ECDHE-RSA-CHACHA20-POLY1305" ||
      token == "ECDHE-RSA-CHACHA20-POLY1305-SHA256") {
    return true;
  }
  return false;
}

static bool parse_cipher_list_string(const char* str) {
  if (!str) return false;
  std::string input(str);
  if (input.empty()) return false;

  bool any = false;
  std::string token;
  auto flush = [&]() {
    if (token.empty()) return;
    std::string normalized = native_tls::normalize(token);
    token.clear();
    if (normalized.empty()) return;
    if (normalized[0] == '!') return;
    if (normalized == "DEFAULT" || normalized == "HIGH" || normalized == "SECURE") {
      any = true;
      return;
    }
    if (add_cipher_from_token(normalized)) any = true;
  };

  for (char ch : input) {
    if (ch == ':' || ch == ',' || ch == ';' || std::isspace(static_cast<unsigned char>(ch))) {
      flush();
    } else {
      token.push_back(ch);
    }
  }
  flush();
  return any;
}

int SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* str) {
  if (!ctx || !str) return 0;
  if (!parse_cipher_list_string(str)) {
    set_error_message("SSL_CTX_set_cipher_list: no matching cipher suites");
    return 0;
  }
  return 1;
}

int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* ca_file, const char* ca_path) {
#ifdef _WIN32
  if (!ctx || !ctx->cert_store) return 0;

  bool loaded = false;
  if (ca_file && *ca_file) {
    loaded = load_ca_file_into_store(ctx->cert_store, ca_file) || loaded;
  }
  if (ca_path && *ca_path) {
    loaded = load_ca_path_into_store(ctx->cert_store, ca_path) || loaded;
  }
  return loaded ? 1 : 0;
#else
  (void)ctx;
  (void)ca_file;
  (void)ca_path;
  return 0;
#endif
}

int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx) {
  if (!ctx) return 0;
  ctx->use_system_roots = true;
  return 1;
}

int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int /*type*/) {
  if (!ctx || !file) return 0;
  auto pem = read_file_text(file);
  if (pem.empty()) return 0;

  auto* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return 0;
  auto* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!cert) return 0;

  if (ctx->own_cert) X509_free(ctx->own_cert);
  ctx->own_cert = cert;

#ifdef _WIN32
  if (ctx->own_cert && ctx->own_key) {
    if (!attach_private_key_to_cert(ctx->own_cert, ctx->own_key)) {
      if (ERR_peek_last_error() == 0) {
        set_error_message("failed to bind private key to certificate");
      }
      return 0;
    }
  }
#endif

  return 1;
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file) {
  return SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int /*type*/) {
  if (!ctx || !file) return 0;
  auto pem = read_file_text(file);
  if (pem.empty()) return 0;

  auto* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return 0;
  auto* pkey = PEM_read_bio_PrivateKey(bio,
                                       nullptr,
                                       nullptr,
                                       ctx->passwd_userdata);
  BIO_free(bio);
  if (!pkey) return 0;

  if (ctx->own_key) EVP_PKEY_free(ctx->own_key);
  ctx->own_key = pkey;

#ifdef _WIN32
  if (ctx->own_cert && ctx->own_key) {
    if (!attach_private_key_to_cert(ctx->own_cert, ctx->own_key)) {
      if (ERR_peek_last_error() == 0) {
        set_error_message("failed to bind private key to certificate");
      }
      return 0;
    }
  }
#endif

  return 1;
}

int SSL_CTX_use_certificate(SSL_CTX* ctx, X509* x) {
  if (!ctx || !x) return 0;
  if (ctx->own_cert) X509_free(ctx->own_cert);
  X509_up_ref(x);
  ctx->own_cert = x;
#ifdef _WIN32
  if (ctx->own_cert && ctx->own_key) {
    if (!attach_private_key_to_cert(ctx->own_cert, ctx->own_key)) return 0;
  }
#endif
  return 1;
}

int SSL_CTX_use_PrivateKey(SSL_CTX* ctx, EVP_PKEY* pkey) {
  if (!ctx || !pkey || !pkey->has_key) return 0;
  if (ctx->own_key) EVP_PKEY_free(ctx->own_key);
  auto* dup = new EVP_PKEY();
#ifdef _WIN32
  if (!pkey->pkcs8_der.empty()) {
    if (!import_private_key_pkcs8(pkey->pkcs8_der, dup)) {
      delete dup;
      return 0;
    }
  } else {
    delete dup;
    return 0;
  }
#endif
  dup->has_key = pkey->has_key;
  dup->pem = pkey->pem;
  dup->pkcs8_der = pkey->pkcs8_der;
  ctx->own_key = dup;

#ifdef _WIN32
  if (ctx->own_cert && ctx->own_key) {
    if (!attach_private_key_to_cert(ctx->own_cert, ctx->own_key)) return 0;
  }
#endif

  return 1;
}

int SSL_CTX_check_private_key(const SSL_CTX* ctx) {
#ifdef _WIN32
  if (!ctx || !ctx->own_cert || !ctx->own_key) return 0;
  if (!ctx->own_cert->cert_ctx) return 0;

  if (ctx->own_key->use_ncrypt) {
    return 0;
  }
  if (!ctx->own_key->hprov) return 0;

  DWORD len = 0;
  if (!CryptExportPublicKeyInfo(ctx->own_key->hprov,
                                ctx->own_key->keyspec,
                                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                nullptr,
                                &len)) {
    return 0;
  }

  std::vector<unsigned char> buf(len);
  auto* info = reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(buf.data());
  if (!CryptExportPublicKeyInfo(ctx->own_key->hprov,
                                ctx->own_key->keyspec,
                                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                info,
                                &len)) {
    return 0;
  }

  BOOL ok = CertComparePublicKeyInfo(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                     &ctx->own_cert->cert_ctx->pCertInfo->SubjectPublicKeyInfo,
                                     info);
  return ok ? 1 : 0;
#else
  (void)ctx;
  return 0;
#endif
}

void SSL_CTX_set_cert_store(SSL_CTX* ctx, X509_STORE* store) {
  if (!ctx || !store) return;
  if (ctx->cert_store == store) return;
  if (ctx->cert_store) X509_STORE_free(ctx->cert_store);
  ctx->cert_store = store;
}

int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version) {
  if (!ctx) return 0;
  ctx->min_proto_version = version;
  return 1;
}

int SSL_CTX_set_alpn_protos(SSL_CTX* ctx, const unsigned char* protos, unsigned int len) {
  if (!ctx || !protos || len == 0) return 1;

  ctx->alpn_protocols.clear();
  ctx->alpn_wire.assign(protos, protos + len);

  size_t i = 0;
  while (i < len) {
    unsigned int l = protos[i++];
    if (l == 0 || i + l > len) break;
    ctx->alpn_protocols.emplace_back(reinterpret_cast<const char*>(protos + i), l);
    i += l;
  }

  return 0;
}

/* ===== SSL object ===== */
SSL* SSL_new(SSL_CTX* ctx) {
  if (!ctx) return nullptr;
  auto* ssl = new SSL();
  ssl->ctx = ctx;
  ssl->verify_mode = ctx->verify_mode;
  ssl->verify_callback = ctx->verify_callback;
  ssl->verify_result = X509_V_OK;
  return ssl;
}

int SSL_set_fd(SSL* ssl, int fd) {
  if (!ssl) return 0;
  ssl->fd = fd;
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
  ssl->wbio = wbio;

  if (rbio && rbio->kind == BioKind::Socket) {
    ssl->fd = rbio->fd;
  }
}

int SSL_set_tlsext_host_name(SSL* ssl, const char* name) {
  if (!ssl || !name) return 0;
  ssl->hostname = name;
  return 1;
}

void SSL_set_verify(SSL* ssl, int mode,
                    int (*verify_callback)(int, X509_STORE_CTX*)) {
  if (!ssl) return;
  ssl->verify_mode = mode;
  ssl->verify_callback = verify_callback;
}

int SSL_connect(SSL* ssl) {
#ifdef _WIN32
  if (!ssl || !ssl->ctx || !ssl->ctx->is_client) return -1;
  if (ssl->fd < 0) {
    ssl->last_error = SSL_ERROR_SYSCALL;
    ssl->last_ret = -1;
    set_error_message("SSL_connect with invalid socket");
    return -1;
  }

  if (!ssl->param.host.empty() && ssl->hostname.empty()) {
    ssl->hostname = ssl->param.host;
  }

  if (ssl->handshake_done) {
    ssl->last_error = SSL_ERROR_NONE;
    ssl->last_ret = 1;
    return 1;
  }

  if (schannel_handshake(ssl)) {
    ssl->last_error = SSL_ERROR_NONE;
    ssl->last_ret = 1;
    return 1;
  }

  if (ssl->last_error == SSL_ERROR_WANT_READ ||
      ssl->last_error == SSL_ERROR_WANT_WRITE ||
      ssl->last_error == SSL_ERROR_ZERO_RETURN) {
    return -1;
  }
  return -1;
#else
  (void)ssl;
  return -1;
#endif
}

int SSL_accept(SSL* ssl) {
#ifdef _WIN32
  if (!ssl || !ssl->ctx || ssl->ctx->is_client) return -1;
  if (ssl->fd < 0) {
    ssl->last_error = SSL_ERROR_SYSCALL;
    ssl->last_ret = -1;
    set_error_message("SSL_accept with invalid socket");
    return -1;
  }

  if (ssl->handshake_done) {
    ssl->last_error = SSL_ERROR_NONE;
    ssl->last_ret = 1;
    return 1;
  }

  if (schannel_handshake(ssl)) {
    ssl->last_error = SSL_ERROR_NONE;
    ssl->last_ret = 1;
    return 1;
  }

  if (ssl->last_error == SSL_ERROR_WANT_READ ||
      ssl->last_error == SSL_ERROR_WANT_WRITE ||
      ssl->last_error == SSL_ERROR_ZERO_RETURN) {
    return -1;
  }
  return -1;
#else
  (void)ssl;
  return -1;
#endif
}

int SSL_read(SSL* ssl, void* buf, int num) {
#ifdef _WIN32
  if (!ssl || !buf || num <= 0) return -1;

  if (!ssl->handshake_done) {
    int hr = ssl->ctx->is_client ? SSL_connect(ssl) : SSL_accept(ssl);
    if (hr != 1) return -1;
  }

  if (!ssl->peeked_plaintext.empty()) {
    int n = std::min<int>(num, static_cast<int>(ssl->peeked_plaintext.size()));
    std::memcpy(buf, ssl->peeked_plaintext.data(), static_cast<size_t>(n));
    ssl->peeked_plaintext.erase(ssl->peeked_plaintext.begin(), ssl->peeked_plaintext.begin() + n);
    ssl->last_ret = n;
    ssl->last_error = SSL_ERROR_NONE;
    return n;
  }

  if (!ensure_decrypted_data(ssl)) {
    if (ssl->last_error == SSL_ERROR_ZERO_RETURN) return 0;
    return -1;
  }

  int avail = static_cast<int>(ssl->decrypted.size() - ssl->decrypted_offset);
  int n = std::min(num, avail);
  std::memcpy(buf, ssl->decrypted.data() + ssl->decrypted_offset, static_cast<size_t>(n));
  ssl->decrypted_offset += static_cast<size_t>(n);
  if (ssl->decrypted_offset >= ssl->decrypted.size()) {
    ssl->decrypted.clear();
    ssl->decrypted_offset = 0;
  }

  ssl->last_ret = n;
  ssl->last_error = SSL_ERROR_NONE;
  return n;
#else
  (void)ssl;
  (void)buf;
  (void)num;
  return -1;
#endif
}

int SSL_write(SSL* ssl, const void* buf, int num) {
#ifdef _WIN32
  if (!ssl || !buf || num <= 0) return -1;

  if (!ssl->handshake_done) {
    int hr = ssl->ctx->is_client ? SSL_connect(ssl) : SSL_accept(ssl);
    if (hr != 1) return -1;
  }

  if (!ssl->pending_send.empty()) {
    if (!flush_pending_send(ssl)) {
      return -1;
    }
    if (ssl->pending_write_plaintext_result > 0) {
      int done = ssl->pending_write_plaintext_result;
      ssl->pending_write_plaintext_result = 0;
      ssl->last_ret = done;
      ssl->last_error = SSL_ERROR_NONE;
      return done;
    }
  }

  if (!ssl->have_sizes) {
    if (!query_stream_sizes(ssl)) return -1;
  }

  int use = std::min<int>(num, static_cast<int>(ssl->sizes.cbMaximumMessage));
  size_t total = ssl->sizes.cbHeader + use + ssl->sizes.cbTrailer;
  std::vector<unsigned char> packet(total);

  SecBuffer bufs[4] = {};
  bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
  bufs[0].pvBuffer = packet.data();
  bufs[0].cbBuffer = ssl->sizes.cbHeader;

  bufs[1].BufferType = SECBUFFER_DATA;
  bufs[1].pvBuffer = packet.data() + ssl->sizes.cbHeader;
  bufs[1].cbBuffer = static_cast<unsigned long>(use);
  std::memcpy(bufs[1].pvBuffer, buf, static_cast<size_t>(use));

  bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
  bufs[2].pvBuffer = packet.data() + ssl->sizes.cbHeader + use;
  bufs[2].cbBuffer = ssl->sizes.cbTrailer;

  bufs[3].BufferType = SECBUFFER_EMPTY;

  SecBufferDesc desc{};
  desc.ulVersion = SECBUFFER_VERSION;
  desc.cBuffers = 4;
  desc.pBuffers = bufs;

  SECURITY_STATUS st = EncryptMessage(&ssl->ctxt, 0, &desc, 0);
  if (st != SEC_E_OK) {
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    set_error_message("EncryptMessage failed: " + std::to_string(static_cast<long>(st)));
    return -1;
  }

  size_t encrypted_len = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
  ssl->pending_send.assign(packet.begin(), packet.begin() + encrypted_len);
  ssl->pending_send_offset = 0;
  ssl->pending_write_plaintext_result = use;

  if (!flush_pending_send(ssl)) {
    return -1;
  }

  int done = ssl->pending_write_plaintext_result;
  ssl->pending_write_plaintext_result = 0;
  ssl->last_ret = done;
  ssl->last_error = SSL_ERROR_NONE;
  return done;
#else
  (void)ssl;
  (void)buf;
  (void)num;
  return -1;
#endif
}

int SSL_peek(SSL* ssl, void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;

  if (ssl->peeked_plaintext.empty()) {
    std::vector<unsigned char> tmp(static_cast<size_t>(num));
    int ret = SSL_read(ssl, tmp.data(), num);
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
#ifdef _WIN32
  return static_cast<int>(ssl->peeked_plaintext.size()) +
         static_cast<int>(ssl->decrypted.size() - ssl->decrypted_offset);
#else
  return static_cast<int>(ssl->peeked_plaintext.size());
#endif
}

int SSL_shutdown(SSL* ssl) {
#ifdef _WIN32
  if (!ssl) return 0;

  if (!ssl->shutdown_sent && ssl->fd >= 0) {
    if (ssl->ctxt_valid) {
      if (!send_close_notify(ssl)) {
        return 0;
      }
    }
    shutdown(ssl->fd, SD_SEND);
    ssl->shutdown_sent = true;
  }

  ssl->last_ret = 1;
  ssl->last_error = SSL_ERROR_NONE;
  return 1;
#else
  (void)ssl;
  return 1;
#endif
}

X509* SSL_get_peer_certificate(const SSL* ssl) {
  if (!ssl || !ssl->peer_cert) return nullptr;
  if (ssl->peer_cert->der.empty()) return nullptr;
  return x509_from_der(ssl->peer_cert->der.data(), ssl->peer_cert->der.size());
}

long SSL_get_verify_result(const SSL* ssl) {
  if (!ssl) return X509_V_ERR_UNSPECIFIED;
  return ssl->verify_result;
}

const char* SSL_get_servername(const SSL* ssl, const int type) {
  if (!ssl || type != TLSEXT_NAMETYPE_host_name) return nullptr;
  return ssl->hostname.empty() ? nullptr : ssl->hostname.c_str();
}

void SSL_clear_mode(SSL* ssl, long mode) {
  if (!ssl || !ssl->ctx) return;
  ssl->ctx->mode &= ~mode;
}

STACK_OF_X509_NAME* SSL_load_client_CA_file(const char* file) {
  if (!file) return nullptr;
  auto pem = read_file_text(file);
  if (pem.empty()) return nullptr;

  auto* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return nullptr;

  auto* list = sk_X509_NAME_new_null();
  while (true) {
    auto* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) break;
    auto* dup = X509_NAME_dup(X509_get_subject_name(cert));
    if (dup) sk_X509_NAME_push(list, dup);
    X509_free(cert);
  }
  BIO_free(bio);

  if (sk_X509_NAME_num(list) == 0) {
    sk_X509_NAME_free(list);
    return nullptr;
  }
  return list;
}

} // extern "C"

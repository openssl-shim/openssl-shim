#include "tls_common.hpp"

#include "openssl/bio.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <Security/CipherSuite.h>
#include <Security/SecRandom.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <climits>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include <unordered_set>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

using native_tls::clear_error_message;
using native_tls::close_socket_fd;
using native_tls::extract_dn_component;
using native_tls::is_ip_literal;
using native_tls::set_error_message;
using native_tls::set_fd_nonblocking;
using native_tls::trim;
using native_tls::wildcard_match;

using socket_len_t = socklen_t;

bool is_fd_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return (flags & O_NONBLOCK) != 0;
}

std::string cfstring_to_utf8(CFStringRef s) {
  if (!s) return {};
  CFIndex len = CFStringGetLength(s);
  if (len == 0) return {};
  CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
  std::string out(static_cast<size_t>(max), '\0');
  if (!CFStringGetCString(s, out.data(), max, kCFStringEncodingUTF8)) return {};
  out.resize(std::strlen(out.c_str()));
  return out;
}

std::string cferror_to_string(OSStatus status) {
  CFStringRef err = SecCopyErrorMessageString(status, nullptr);
  std::string out = err ? cfstring_to_utf8(err) : std::string();
  if (err) CFRelease(err);
  if (out.empty()) {
    out = "OSStatus=" + std::to_string(static_cast<int>(status));
  }
  return out;
}

std::string read_file_text(const char* path) {
  if (!path) return {};
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) return {};
  std::string out((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
  return out;
}

int base64_index(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

bool base64_decode(const std::string& input, std::vector<unsigned char>& out) {
  int val = 0;
  int valb = -8;
  for (unsigned char c : input) {
    if (std::isspace(c)) continue;
    if (c == '=') break;
    int d = base64_index(c);
    if (d < 0) continue;
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return !out.empty();
}

std::string base64_encode(const unsigned char* data, size_t len) {
  static const char* alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    unsigned int v = data[i];
    v = (v << 8) | (i + 1 < len ? data[i + 1] : 0);
    v = (v << 8) | (i + 2 < len ? data[i + 2] : 0);

    out.push_back(alphabet[(v >> 18) & 0x3F]);
    out.push_back(alphabet[(v >> 12) & 0x3F]);
    if (i + 1 < len)
      out.push_back(alphabet[(v >> 6) & 0x3F]);
    else
      out.push_back('=');
    if (i + 2 < len)
      out.push_back(alphabet[v & 0x3F]);
    else
      out.push_back('=');
  }
  return out;
}

std::string wrap_pem(const char* tag, const unsigned char* data, size_t len) {
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

bool pem_block_to_der(const std::string& pem, std::vector<unsigned char>& der) {
  auto begin = pem.find("-----BEGIN");
  auto end = pem.find("-----END");
  if (begin == std::string::npos || end == std::string::npos) return false;
  auto body_start = pem.find('\n', begin);
  if (body_start == std::string::npos) return false;
  auto body_end = pem.rfind("-----END");
  if (body_end == std::string::npos || body_end <= body_start) return false;
  auto body = pem.substr(body_start + 1, body_end - body_start - 1);
  return base64_decode(body, der);
}

std::string random_password_hex(size_t bytes) {
  if (bytes == 0) return {};
  std::vector<unsigned char> buf(bytes);
  if (SecRandomCopyBytes(kSecRandomDefault, buf.size(), buf.data()) != errSecSuccess) {
    for (size_t i = 0; i < buf.size(); ++i) {
      buf[i] = static_cast<unsigned char>(arc4random() & 0xFF);
    }
  }
  static const char* hex = "0123456789abcdef";
  std::string out;
  out.reserve(buf.size() * 2);
  for (auto b : buf) {
    out.push_back(hex[(b >> 4) & 0x0F]);
    out.push_back(hex[b & 0x0F]);
  }
  return out;
}

std::string make_temp_keychain_path() {
  std::string dir;
  try {
    dir = std::filesystem::temp_directory_path().string();
  } catch (...) {
    dir = "/tmp";
  }
  if (dir.empty()) dir = "/tmp";

  std::string tmpl = dir + "/native_tls_shim_keychain_XXXXXX";
  std::vector<char> path(tmpl.begin(), tmpl.end());
  path.push_back('\0');
  int fd = mkstemp(path.data());
  if (fd < 0) return {};
  ::close(fd);
  ::unlink(path.data());
  return std::string(path.data());
}

struct x509_st {
  SecCertificateRef cert = nullptr;
  std::vector<unsigned char> der;
  std::string pem;
  int refs = 1;
  x509_name_st subject_name;
  x509_name_st issuer_name;
  asn1_string_st serial;
  asn1_time_st not_before;
  asn1_time_st not_after;

  ~x509_st() {
    if (cert) CFRelease(cert);
  }
};

struct x509_store_st {
  std::vector<X509*> certs;
  unsigned long flags = 0;
  stack_st_X509_OBJECT object_cache;
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

enum class DigestKind { Md5, Sha256, Sha512 };

struct evp_pkey_st {
  SecKeyRef key = nullptr;
  bool has_key = false;
  std::string pem;
  int refs = 1;

  ~evp_pkey_st() {
    if (key) CFRelease(key);
  }
};

struct evp_md_st {
  DigestKind kind;
  unsigned int digest_len;
};

struct evp_md_ctx_st {
  DigestKind kind = DigestKind::Md5;
  bool setup = false;
  union {
    CC_MD5_CTX md5;
    CC_SHA256_CTX sha256;
    CC_SHA512_CTX sha512;
  } u;
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

  X509* own_cert = nullptr;
  EVP_PKEY* own_key = nullptr;
  std::vector<SecCertificateRef> own_chain;

  SecIdentityRef identity = nullptr;
  SecKeychainRef keychain = nullptr;
  std::string keychain_path;

  std::vector<std::string> alpn_protocols;

  std::vector<SSLCipherSuite> cipher_suites;
  bool cipher_suites_set = false;

  bool use_system_roots = false;

  ~ssl_ctx_st() {
    if (client_ca_list) sk_X509_NAME_pop_free(client_ca_list, X509_NAME_free);
    if (cert_store) X509_STORE_free(cert_store);
    if (own_cert) X509_free(own_cert);
    if (own_key) EVP_PKEY_free(own_key);
    for (auto* c : own_chain) {
      if (c) CFRelease(c);
    }
    if (identity) CFRelease(identity);
    if (keychain) {
      SecKeychainDelete(keychain);
      CFRelease(keychain);
    }
    if (!keychain_path.empty()) {
      std::error_code ec;
      std::filesystem::remove(keychain_path, ec);
    }
  }
};

struct ssl_st {
  SSL_CTX* ctx = nullptr;
  SSLContextRef ssl = nullptr;
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

  std::vector<unsigned char> peeked_plaintext;

  long verify_result = X509_V_OK;

  X509* peer_cert = nullptr;

  int io_want = SSL_ERROR_NONE;
  bool handshake_done = false;
  bool trust_evaluated = false;

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
    if (ssl) {
      SSLClose(ssl);
      CFRelease(ssl);
    }
  }
};

const bio_method_st g_mem_method{1};

const EVP_MD g_md5{DigestKind::Md5, CC_MD5_DIGEST_LENGTH};
const EVP_MD g_sha256{DigestKind::Sha256, CC_SHA256_DIGEST_LENGTH};
const EVP_MD g_sha512{DigestKind::Sha512, CC_SHA512_DIGEST_LENGTH};

std::string label_to_short_name(const std::string& label) {
  if (label == "Common Name") return "CN";
  if (label == "Organization") return "O";
  if (label == "Organizational Unit") return "OU";
  if (label == "Country") return "C";
  if (label == "State/Province") return "ST";
  if (label == "Locality") return "L";
  return label;
}

bool copy_name_info(SecCertificateRef cert, CFStringRef oid,
                    std::string& text_out, std::string* cn_out) {
  if (!cert || !oid) return false;
  const void* key_list[] = { oid };
  CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault,
                                 key_list,
                                 1,
                                 &kCFTypeArrayCallBacks);
  if (!keys) return false;
  CFDictionaryRef values = SecCertificateCopyValues(cert, keys, nullptr);
  CFRelease(keys);
  if (!values) return false;

  auto* name_dict = static_cast<CFDictionaryRef>(CFDictionaryGetValue(values, oid));
  if (!name_dict) {
    CFRelease(values);
    return false;
  }

  auto* val = static_cast<CFArrayRef>(CFDictionaryGetValue(name_dict, kSecPropertyKeyValue));
  if (!val) {
    CFRelease(values);
    return false;
  }

  std::string out;
  CFIndex count = CFArrayGetCount(val);
  for (CFIndex i = 0; i < count; ++i) {
    auto* entry = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(val, i));
    if (!entry) continue;
    auto* label = static_cast<CFStringRef>(CFDictionaryGetValue(entry, kSecPropertyKeyLabel));
    auto* value = CFDictionaryGetValue(entry, kSecPropertyKeyValue);
    std::string label_str = label ? cfstring_to_utf8(label) : std::string();
    std::string value_str;
    if (value) {
      if (CFGetTypeID(value) == CFStringGetTypeID()) {
        value_str = cfstring_to_utf8(static_cast<CFStringRef>(value));
      } else {
        CFStringRef desc = CFCopyDescription(value);
        value_str = desc ? cfstring_to_utf8(desc) : std::string();
        if (desc) CFRelease(desc);
      }
    }
    if (label_str == "Common Name" && cn_out) {
      *cn_out = value_str;
    }
    if (!label_str.empty() && !value_str.empty()) {
      if (!out.empty()) out += ", ";
      out += label_to_short_name(label_str);
      out += "=";
      out += value_str;
    }
  }

  if (!out.empty()) text_out = out;
  CFRelease(values);
  return !text_out.empty();
}

time_t cfdate_to_time_t(CFDateRef date) {
  if (!date) return 0;
  CFAbsoluteTime at = CFDateGetAbsoluteTime(date);
  return static_cast<time_t>(at + kCFAbsoluteTimeIntervalSince1970);
}

bool extract_validity_time(SecCertificateRef cert, CFStringRef oid, time_t& out_time) {
  const void* key_list[] = { oid };
  CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault,
                                 key_list,
                                 1,
                                 &kCFTypeArrayCallBacks);
  if (!keys) return false;
  CFDictionaryRef values = SecCertificateCopyValues(cert, keys, nullptr);
  CFRelease(keys);
  if (!values) return false;
  auto* item = static_cast<CFDictionaryRef>(CFDictionaryGetValue(values, oid));
  if (!item) {
    CFRelease(values);
    return false;
  }
  auto* val = CFDictionaryGetValue(item, kSecPropertyKeyValue);
  if (!val) {
    CFRelease(values);
    return false;
  }
  if (CFGetTypeID(val) == CFDateGetTypeID()) {
    out_time = cfdate_to_time_t(static_cast<CFDateRef>(val));
    CFRelease(values);
    return true;
  }
  if (CFGetTypeID(val) == CFStringGetTypeID()) {
    // Fallback: parse as absolute time string not easily, skip
    out_time = 0;
  }
  CFRelease(values);
  return out_time != 0;
}

void refresh_x509_fields(X509* x) {
  if (!x || !x->cert) return;

  std::string subject_text;
  std::string issuer_text;
  std::string issuer_cn;

  copy_name_info(x->cert, kSecOIDX509V1SubjectName, subject_text, &x->subject_name.common_name);
  copy_name_info(x->cert, kSecOIDX509V1IssuerName, issuer_text, &issuer_cn);

  if (x->subject_name.common_name.empty()) {
    CFStringRef cn = nullptr;
    if (SecCertificateCopyCommonName(x->cert, &cn) == errSecSuccess && cn) {
      x->subject_name.common_name = cfstring_to_utf8(cn);
      CFRelease(cn);
    }
  }

  x->issuer_name.common_name = issuer_cn;

  x->subject_name.text = subject_text;
  x->issuer_name.text = issuer_text;

  if (x->subject_name.text.empty() && !x->subject_name.common_name.empty()) {
    x->subject_name.text = "CN=" + x->subject_name.common_name;
  }
  if (x->issuer_name.text.empty() && !x->issuer_name.common_name.empty()) {
    x->issuer_name.text = "CN=" + x->issuer_name.common_name;
  }

  x->serial.bytes.clear();
#if defined(__MAC_10_12)
  CFErrorRef error = nullptr;
  CFDataRef serial = SecCertificateCopySerialNumberData(x->cert, &error);
  if (serial) {
    auto* p = CFDataGetBytePtr(serial);
    auto len = CFDataGetLength(serial);
    x->serial.bytes.assign(p, p + len);
    CFRelease(serial);
  }
  if (error) CFRelease(error);
#endif
  if (x->serial.bytes.empty()) {
    const void* key_list[] = { kSecOIDX509V1SerialNumber };
    CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault,
                                   key_list,
                                   1,
                                   &kCFTypeArrayCallBacks);
    if (keys) {
      CFDictionaryRef values = SecCertificateCopyValues(x->cert, keys, nullptr);
      CFRelease(keys);
      if (values) {
        auto* item = static_cast<CFDictionaryRef>(CFDictionaryGetValue(values, kSecOIDX509V1SerialNumber));
        if (item) {
          auto* val = CFDictionaryGetValue(item, kSecPropertyKeyValue);
          if (val && CFGetTypeID(val) == CFDataGetTypeID()) {
            auto* p = CFDataGetBytePtr(static_cast<CFDataRef>(val));
            auto len = CFDataGetLength(static_cast<CFDataRef>(val));
            x->serial.bytes.assign(p, p + len);
          }
        }
        CFRelease(values);
      }
    }
  }

  time_t nb = 0;
  time_t na = 0;
  extract_validity_time(x->cert, kSecOIDX509V1ValidityNotBefore, nb);
  extract_validity_time(x->cert, kSecOIDX509V1ValidityNotAfter, na);
  x->not_before.epoch = nb;
  x->not_after.epoch = na;
}

X509* x509_from_der(const unsigned char* der, size_t len) {
  if (!der || len == 0) return nullptr;
  CFDataRef data = CFDataCreate(kCFAllocatorDefault, der, static_cast<CFIndex>(len));
  if (!data) return nullptr;
  SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, data);
  CFRelease(data);
  if (!cert) return nullptr;

  auto* x = new X509();
  x->cert = cert;
  x->der.assign(der, der + len);
  refresh_x509_fields(x);
  return x;
}

X509* x509_clone(const X509* in) {
  if (!in || in->der.empty()) return nullptr;
  return x509_from_der(in->der.data(), in->der.size());
}

X509* x509_from_sec_cert(SecCertificateRef cert) {
  if (!cert) return nullptr;
  CFRetain(cert);
  auto* x = new X509();
  x->cert = cert;
  CFDataRef data = SecCertificateCopyData(cert);
  if (data) {
    auto* p = CFDataGetBytePtr(data);
    auto len = CFDataGetLength(data);
    x->der.assign(p, p + len);
    CFRelease(data);
  }
  refresh_x509_fields(x);
  return x;
}

bool add_cert_to_store(X509_STORE* store, X509* cert, bool allow_duplicate_error) {
  if (!store || !cert) return false;

  for (auto* existing : store->certs) {
    if (!existing) continue;
    if (existing->der.size() == cert->der.size() && !existing->der.empty() &&
        std::memcmp(existing->der.data(), cert->der.data(), cert->der.size()) == 0) {
      if (!allow_duplicate_error) return true;
      set_error_message("certificate already in store", X509_R_CERT_ALREADY_IN_HASH_TABLE);
      return false;
    }
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

bool is_socket_would_block() {
  return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS;
}

bool has_ssl_transport(const SSL* ssl) {
  if (!ssl) return false;
  if (ssl->rbio || ssl->wbio) return true;
  return ssl->fd >= 0;
}

bool uses_socket_transport(const SSL* ssl) {
  if (!ssl) return false;
  if (ssl->rbio && ssl->rbio->kind == BioKind::Socket) return true;
  if (ssl->wbio && ssl->wbio->kind == BioKind::Socket) return true;
  return ssl->fd >= 0;
}

bool uses_blocking_transport(const SSL* ssl) {
  return ssl && uses_socket_transport(ssl) && ssl->fd >= 0 && !is_fd_nonblocking(ssl->fd);
}

OSStatus ssl_read_cb(SSLConnectionRef connection, void* data, size_t* len) {
  auto* ssl = reinterpret_cast<SSL*>(const_cast<void*>(connection));
  if (!ssl || !data || !len) return errSSLInternal;
  if (*len == 0) return noErr;

  int rc = -1;
  bool socket_transport = false;
  int requested = static_cast<int>((std::min)(*len, static_cast<size_t>(INT_MAX)));

  if (ssl->rbio) {
    socket_transport = ssl->rbio->kind == BioKind::Socket;
    rc = BIO_read(ssl->rbio, data, requested);
  } else if (ssl->fd >= 0) {
    socket_transport = true;
    rc = static_cast<int>(recv(ssl->fd, data, static_cast<size_t>(requested), 0));
  } else {
    ssl->io_want = SSL_ERROR_SYSCALL;
    return errSSLInternal;
  }

  if (rc > 0) {
    *len = static_cast<size_t>(rc);
    if (rc < requested) {
      ssl->io_want = SSL_ERROR_WANT_READ;
      return errSSLWouldBlock;
    }
    return noErr;
  }

  *len = 0;
  if (rc == 0) {
    if (socket_transport) return errSSLClosedGraceful;
    ssl->io_want = SSL_ERROR_WANT_READ;
    return errSSLWouldBlock;
  }

  if (socket_transport) {
    if (is_socket_would_block()) {
      ssl->io_want = SSL_ERROR_WANT_READ;
      return errSSLWouldBlock;
    }
    if (errno == ECONNRESET) return errSSLClosedAbort;
    ssl->io_want = SSL_ERROR_SYSCALL;
    return errSecIO;
  }

  ssl->io_want = SSL_ERROR_WANT_READ;
  return errSSLWouldBlock;
}

OSStatus ssl_write_cb(SSLConnectionRef connection, const void* data, size_t* len) {
  auto* ssl = reinterpret_cast<SSL*>(const_cast<void*>(connection));
  if (!ssl || !data || !len) return errSSLInternal;
  if (*len == 0) return noErr;

  int rc = -1;
  bool socket_transport = false;
  int requested = static_cast<int>((std::min)(*len, static_cast<size_t>(INT_MAX)));

  if (ssl->wbio) {
    socket_transport = ssl->wbio->kind == BioKind::Socket;
    rc = BIO_write(ssl->wbio, data, requested);
  } else if (ssl->fd >= 0) {
    socket_transport = true;
    rc = static_cast<int>(send(ssl->fd, data, static_cast<size_t>(requested), 0));
  } else {
    ssl->io_want = SSL_ERROR_SYSCALL;
    return errSSLInternal;
  }

  if (rc > 0) {
    *len = static_cast<size_t>(rc);
    if (rc < requested) {
      ssl->io_want = SSL_ERROR_WANT_WRITE;
      return errSSLWouldBlock;
    }
    return noErr;
  }

  *len = 0;
  if (rc == 0) {
    if (socket_transport) return errSSLClosedGraceful;
    ssl->io_want = SSL_ERROR_WANT_WRITE;
    return errSSLWouldBlock;
  }

  if (socket_transport) {
    if (is_socket_would_block()) {
      ssl->io_want = SSL_ERROR_WANT_WRITE;
      return errSSLWouldBlock;
    }
    if (errno == ECONNRESET) return errSSLClosedAbort;
    ssl->io_want = SSL_ERROR_SYSCALL;
    return errSecIO;
  }

  ssl->io_want = SSL_ERROR_WANT_WRITE;
  return errSSLWouldBlock;
}

SSLProtocol protocol_from_version(int version) {
  switch (version) {
    case TLS1_VERSION: return kTLSProtocol1;
    case TLS1_1_VERSION: return kTLSProtocol11;
    case TLS1_2_VERSION: return kTLSProtocol12;
#ifdef kTLSProtocol13
    case TLS1_3_VERSION: return kTLSProtocol13;
#endif
    default: return kTLSProtocol12;
  }
}

static std::vector<SSLCipherSuite> default_cipher_suites() {
  std::vector<SSLCipherSuite> ciphers;
#ifdef TLS_AES_128_GCM_SHA256
  ciphers.push_back(TLS_AES_128_GCM_SHA256);
#endif
#ifdef TLS_AES_256_GCM_SHA384
  ciphers.push_back(TLS_AES_256_GCM_SHA384);
#endif
#ifdef TLS_CHACHA20_POLY1305_SHA256
  ciphers.push_back(TLS_CHACHA20_POLY1305_SHA256);
#endif
#ifdef TLS_AES_128_CCM_SHA256
  ciphers.push_back(TLS_AES_128_CCM_SHA256);
#endif
#ifdef TLS_AES_128_CCM_8_SHA256
  ciphers.push_back(TLS_AES_128_CCM_8_SHA256);
#endif
  ciphers.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
  ciphers.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
  ciphers.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
  ciphers.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  return ciphers;
}

static std::vector<SSLCipherSuite> filter_supported_ciphers(
    SSLContextRef ctx, const std::vector<SSLCipherSuite>& desired) {
  if (!ctx || desired.empty()) return {};
  size_t count = 0;
  if (SSLGetNumberSupportedCiphers(ctx, &count) != noErr || count == 0) return {};
  std::vector<SSLCipherSuite> supported(count);
  if (SSLGetSupportedCiphers(ctx, supported.data(), &count) != noErr || count == 0) return {};
  supported.resize(count);

  std::unordered_set<SSLCipherSuite> supported_set(supported.begin(), supported.end());
  std::unordered_set<SSLCipherSuite> added;
  std::vector<SSLCipherSuite> out;
  out.reserve(desired.size());
  for (auto cipher : desired) {
    if (supported_set.count(cipher) && !added.count(cipher)) {
      out.push_back(cipher);
      added.insert(cipher);
    }
  }
  return out;
}

bool apply_trusted_roots(SSL* /*ssl*/) {
  return true;
}

bool ensure_identity(SSL_CTX* ctx);

bool configure_ssl_instance(SSL* ssl) {
  if (!ssl || !ssl->ctx) return false;

  ssl->ssl = SSLCreateContext(kCFAllocatorDefault,
                              ssl->ctx->is_client ? kSSLClientSide : kSSLServerSide,
                              kSSLStreamType);
  if (!ssl->ssl) {
    set_error_message("SSLCreateContext failed");
    return false;
  }

  OSStatus st = SSLSetIOFuncs(ssl->ssl, ssl_read_cb, ssl_write_cb);
  if (st != noErr) {
    set_error_message("SSLSetIOFuncs failed: " + cferror_to_string(st));
    return false;
  }
  st = SSLSetConnection(ssl->ssl, ssl);
  if (st != noErr) {
    set_error_message("SSLSetConnection failed: " + cferror_to_string(st));
    return false;
  }
  st = SSLSetProtocolVersionMin(ssl->ssl, protocol_from_version(ssl->ctx->min_proto_version));
  if (st != noErr) {
    set_error_message("SSLSetProtocolVersionMin failed: " + cferror_to_string(st));
    return false;
  }
  int max_version = ssl->ctx->max_proto_version;
  if (max_version == 0) max_version = TLS1_3_VERSION;
  if (ssl->ctx->min_proto_version > max_version) {
    max_version = ssl->ctx->min_proto_version;
  }
  SSLProtocol max_proto = protocol_from_version(max_version);
  st = SSLSetProtocolVersionMax(ssl->ssl, max_proto);
  if (st != noErr) {
    set_error_message("SSLSetProtocolVersionMax failed: " + cferror_to_string(st));
    return false;
  }

  if (!ssl->hostname.empty() && !is_ip_literal(ssl->hostname)) {
    st = SSLSetPeerDomainName(ssl->ssl, ssl->hostname.c_str(), ssl->hostname.size());
    if (st != noErr) {
      set_error_message("SSLSetPeerDomainName failed: " + cferror_to_string(st));
      return false;
    }
  }

  if (!ssl->ctx->alpn_protocols.empty()) {
    CFMutableArrayRef protos = CFArrayCreateMutable(kCFAllocatorDefault,
                                                    static_cast<CFIndex>(ssl->ctx->alpn_protocols.size()),
                                                    &kCFTypeArrayCallBacks);
    if (protos) {
      for (auto& p : ssl->ctx->alpn_protocols) {
        CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                                      reinterpret_cast<const UInt8*>(p.data()),
                                      static_cast<CFIndex>(p.size()));
        if (data) {
          CFArrayAppendValue(protos, data);
          CFRelease(data);
        }
      }
      SSLSetALPNProtocols(ssl->ssl, protos);
      CFRelease(protos);
    }
  }

  std::vector<SSLCipherSuite> desired_ciphers =
      ssl->ctx->cipher_suites_set ? ssl->ctx->cipher_suites : default_cipher_suites();
  if (!desired_ciphers.empty()) {
    auto enabled_ciphers = filter_supported_ciphers(ssl->ssl, desired_ciphers);
    if (!enabled_ciphers.empty()) {
      OSStatus st = SSLSetEnabledCiphers(ssl->ssl, enabled_ciphers.data(),
                                         static_cast<size_t>(enabled_ciphers.size()));
      if (st != noErr) {
        set_error_message("SSLSetEnabledCiphers failed: " + cferror_to_string(st));
        return false;
      }
    } else if (ssl->ctx->cipher_suites_set) {
      set_error_message("No supported cipher suites available");
      return false;
    }
  }

  if (!apply_trusted_roots(ssl)) return false;

  int effective_verify_mode = ssl->verify_mode ? ssl->verify_mode : ssl->ctx->verify_mode;
  bool verify_peer = (effective_verify_mode & SSL_VERIFY_PEER) != 0;
  bool has_custom_anchors = ssl->ctx->cert_store && !ssl->ctx->cert_store->certs.empty();
  bool need_manual_verify = !verify_peer || has_custom_anchors || !ssl->ctx->use_system_roots;

  if (ssl->ctx->is_client) {
    if (need_manual_verify) {
      OSStatus opt_st = SSLSetSessionOption(ssl->ssl, kSSLSessionOptionBreakOnServerAuth, true);
      if (opt_st != noErr) {
        set_error_message("SSLSetSessionOption(BreakOnServerAuth) failed: " +
                          cferror_to_string(opt_st));
        return false;
      }
    }
  } else if (verify_peer && need_manual_verify) {
    OSStatus opt_st = SSLSetSessionOption(ssl->ssl, kSSLSessionOptionBreakOnClientAuth, true);
    if (opt_st != noErr) {
      set_error_message("SSLSetSessionOption(BreakOnClientAuth) failed: " +
                        cferror_to_string(opt_st));
      return false;
    }
  }

  if (!ssl->ctx->is_client) {
    SSLAuthenticate auth = kNeverAuthenticate;
    if (verify_peer) {
      auth = (effective_verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                 ? kAlwaysAuthenticate
                 : kTryAuthenticate;
    }
    OSStatus auth_st = SSLSetClientSideAuthenticate(ssl->ssl, auth);
    if (auth_st != noErr) {
      set_error_message("SSLSetClientSideAuthenticate failed: " + cferror_to_string(auth_st));
      return false;
    }
  }

  if (ssl->ctx->own_cert && ssl->ctx->own_key) {
    if (!ensure_identity(ssl->ctx)) return false;
    if (ssl->ctx->identity) {
      CFMutableArrayRef certs = CFArrayCreateMutable(kCFAllocatorDefault, 0,
                                                     &kCFTypeArrayCallBacks);
      if (certs) {
        CFArrayAppendValue(certs, ssl->ctx->identity);
        for (auto* extra : ssl->ctx->own_chain) {
          if (extra) CFArrayAppendValue(certs, extra);
        }
        OSStatus st = SSLSetCertificate(ssl->ssl, certs);
        CFRelease(certs);
        if (st != noErr) {
          set_error_message("SSLSetCertificate failed: " + cferror_to_string(st));
          return false;
        }
      }
    }
  } else if (!ssl->ctx->is_client) {
    set_error_message("server credential requires certificate");
    return false;
  }

  ssl->ssl_setup = true;
  return true;
}

bool load_peer_certificate(SSL* ssl, SecTrustRef trust) {
  if (!ssl) return false;
  if (ssl->peer_cert) {
    X509_free(ssl->peer_cert);
    ssl->peer_cert = nullptr;
  }
  if (!trust) return false;
  CFIndex count = SecTrustGetCertificateCount(trust);
  if (count <= 0) return false;
  SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, 0);
  if (!cert) return false;
  ssl->peer_cert = x509_from_sec_cert(cert);
  return ssl->peer_cert != nullptr;
}

long map_trust_result_to_error(SecTrustRef trust) {
  if (!trust) return X509_V_ERR_UNSPECIFIED;

  SecTrustResultType result = kSecTrustResultInvalid;
  if (SecTrustEvaluate(trust, &result) != errSecSuccess) {
    return X509_V_ERR_UNSPECIFIED;
  }

  switch (result) {
    case kSecTrustResultProceed:
    case kSecTrustResultUnspecified:
      return X509_V_OK;
    case kSecTrustResultRecoverableTrustFailure:
      return X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
    case kSecTrustResultDeny:
    case kSecTrustResultFatalTrustFailure:
    default:
      return X509_V_ERR_UNSPECIFIED;
  }
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
    ssl->verify_result = X509_V_OK;
  }
  return rc;
}

bool evaluate_peer_trust(SSL* ssl, bool require_cert) {
  if (!ssl || !ssl->ctx || !ssl->ssl) return false;

  auto effective_verify_mode = ssl->verify_mode ? ssl->verify_mode : ssl->ctx->verify_mode;
  bool verify_peer = (effective_verify_mode & SSL_VERIFY_PEER) != 0;
  bool allow_unverified = !verify_peer && !require_cert;

  SecTrustRef trust = nullptr;
  OSStatus st = SSLCopyPeerTrust(ssl->ssl, &trust);
  if (st != noErr || !trust) {
    if (trust) CFRelease(trust);
    ssl->verify_result = X509_V_ERR_UNSPECIFIED;
    return allow_unverified ? (run_verify_callback_if_any(ssl) != 0) : false;
  }

  bool has_cert = load_peer_certificate(ssl, trust);
  if (!has_cert) {
    if (require_cert) {
      ssl->verify_result = X509_V_ERR_UNSPECIFIED;
      CFRelease(trust);
      return false;
    }
    ssl->verify_result = X509_V_OK;
    CFRelease(trust);
    return run_verify_callback_if_any(ssl) != 0;
  }

  bool has_custom_anchors = ssl->ctx->cert_store && !ssl->ctx->cert_store->certs.empty();
  bool should_evaluate = verify_peer || has_custom_anchors || ssl->ctx->use_system_roots;

  SecTrustRef eval_trust = trust;
  CFArrayRef certs = nullptr;
  SecPolicyRef policy = nullptr;

  if (should_evaluate) {
    CFIndex count = SecTrustGetCertificateCount(trust);
    if (count > 0) {
      CFMutableArrayRef cert_array = CFArrayCreateMutable(kCFAllocatorDefault,
                                                          count,
                                                          &kCFTypeArrayCallBacks);
      if (cert_array) {
        for (CFIndex i = 0; i < count; ++i) {
          SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, i);
          if (cert) CFArrayAppendValue(cert_array, cert);
        }
        certs = cert_array;
      }
    }

    policy = SecPolicyCreateBasicX509();

    if (certs && policy) {
      SecTrustRef new_trust = nullptr;
      if (SecTrustCreateWithCertificates(certs, policy, &new_trust) == errSecSuccess &&
          new_trust) {
        eval_trust = new_trust;
      } else if (policy) {
        SecTrustSetPolicies(eval_trust, policy);
      }
    } else if (policy) {
      SecTrustSetPolicies(eval_trust, policy);
    }
  }

  if (should_evaluate) {
    if (has_custom_anchors) {
      CFMutableArrayRef anchors = CFArrayCreateMutable(kCFAllocatorDefault,
                                                       static_cast<CFIndex>(ssl->ctx->cert_store->certs.size()),
                                                       &kCFTypeArrayCallBacks);
      if (anchors) {
        for (auto* cert : ssl->ctx->cert_store->certs) {
          if (cert && cert->cert) CFArrayAppendValue(anchors, cert->cert);
        }
        SecTrustSetAnchorCertificates(eval_trust, anchors);
        SecTrustSetAnchorCertificatesOnly(eval_trust, ssl->ctx->use_system_roots ? false : true);
        CFRelease(anchors);
      }
    } else if (!ssl->ctx->use_system_roots) {
      CFArrayRef empty = CFArrayCreate(kCFAllocatorDefault, nullptr, 0, &kCFTypeArrayCallBacks);
      if (empty) {
        SecTrustSetAnchorCertificates(eval_trust, empty);
        SecTrustSetAnchorCertificatesOnly(eval_trust, true);
        CFRelease(empty);
      }
    }

    bool trust_ok = false;
#if defined(__MAC_10_15)
    trust_ok = SecTrustEvaluateWithError(eval_trust, nullptr);
#endif
    ssl->verify_result = trust_ok ? X509_V_OK : map_trust_result_to_error(eval_trust);
  } else {
    ssl->verify_result = X509_V_OK;
  }

  if (policy) CFRelease(policy);
  if (certs) CFRelease(certs);
  if (eval_trust != trust) CFRelease(eval_trust);

  std::string host = ssl->param.host;
  if (ssl->verify_result == X509_V_OK && ssl->ctx->is_client && !host.empty()) {
    if (!ssl->peer_cert || !cert_matches_hostname(ssl->peer_cert, host, is_ip_literal(host))) {
      ssl->verify_result = X509_V_ERR_HOSTNAME_MISMATCH;
    }
  }

  CFRelease(trust);

  if (run_verify_callback_if_any(ssl) == 0) {
    ssl->verify_result = X509_V_ERR_UNSPECIFIED;
    return false;
  }

  if (allow_unverified) {
    return true;
  }

  return ssl->verify_result == X509_V_OK;
}

bool post_handshake_verify(SSL* ssl, bool require_cert) {
  if (!ssl) return false;
  if (ssl->trust_evaluated) return true;
  ssl->trust_evaluated = true;

  bool ok = evaluate_peer_trust(ssl, require_cert);
  if (!ok) {
    set_error_message("certificate verification failed",
                      static_cast<int>(ssl->verify_result));
    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
  }
  return ok;
}

void query_selected_alpn(SSL* ssl) {
  if (!ssl || !ssl->ssl) return;
  ssl->selected_alpn.clear();
  CFArrayRef protos = nullptr;
  if (SSLCopyALPNProtocols(ssl->ssl, &protos) == noErr && protos) {
    if (CFArrayGetCount(protos) > 0) {
      auto* data = static_cast<CFDataRef>(CFArrayGetValueAtIndex(protos, 0));
      if (data) {
        auto* p = CFDataGetBytePtr(data);
        auto len = CFDataGetLength(data);
        ssl->selected_alpn.assign(reinterpret_cast<const char*>(p),
                                  reinterpret_cast<const char*>(p) + len);
      }
    }
    CFRelease(protos);
  }
}

bool ensure_keychain(SSL_CTX* ctx) {
  if (!ctx) return false;
  if (ctx->keychain) return true;

  std::string path = make_temp_keychain_path();
  if (path.empty()) {
    set_error_message("failed to create temporary keychain path");
    return false;
  }

  std::string password = random_password_hex(32);
  if (password.empty()) {
    set_error_message("failed to generate keychain password");
    return false;
  }

  SecKeychainRef keychain = nullptr;
  OSStatus st = SecKeychainCreate(path.c_str(),
                                  static_cast<UInt32>(password.size()),
                                  password.c_str(),
                                  false,
                                  nullptr,
                                  &keychain);
  if (st != errSecSuccess || !keychain) {
    set_error_message("SecKeychainCreate failed: " + cferror_to_string(st));
    return false;
  }

  OSStatus unlock = SecKeychainUnlock(keychain,
                                      static_cast<UInt32>(password.size()),
                                      password.c_str(),
                                      true);
  if (unlock != errSecSuccess) {
    set_error_message("SecKeychainUnlock failed: " + cferror_to_string(unlock));
    CFRelease(keychain);
    return false;
  }

  chmod(path.c_str(), S_IRUSR | S_IWUSR);

  ctx->keychain = keychain;
  ctx->keychain_path = path;
  return true;
}

bool import_private_key_into_keychain(SSL_CTX* ctx, const std::string& pem) {
  if (!ctx || !ctx->keychain || pem.empty()) return false;

  CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                               reinterpret_cast<const UInt8*>(pem.data()),
                               static_cast<CFIndex>(pem.size()));
  if (!data) return false;

  SecExternalFormat format = kSecFormatUnknown;
  SecExternalItemType itemType = kSecItemTypePrivateKey;
  SecItemImportExportKeyParameters params{};
  params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  CFStringRef pass = nullptr;
  if (ctx->passwd_userdata) {
    pass = CFStringCreateWithCString(kCFAllocatorDefault,
                                     static_cast<const char*>(ctx->passwd_userdata),
                                     kCFStringEncodingUTF8);
    params.passphrase = pass;
  }

  CFArrayRef items = nullptr;
  OSStatus st = SecItemImport(data,
                              nullptr,
                              &format,
                              &itemType,
                              0,
                              &params,
                              ctx->keychain,
                              &items);
  if (pass) CFRelease(pass);
  CFRelease(data);

  if (st != errSecSuccess) {
    if (items) CFRelease(items);
    set_error_message("SecItemImport private key failed: " + cferror_to_string(st));
    return false;
  }

  if (items) CFRelease(items);
  return true;
}

bool add_cert_to_keychain(SSL_CTX* ctx, SecCertificateRef cert) {
  if (!ctx || !ctx->keychain || !cert) return false;
  CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                                          &kCFTypeDictionaryKeyCallBacks,
                                                          &kCFTypeDictionaryValueCallBacks);
  if (!attrs) return false;
  CFDictionarySetValue(attrs, kSecClass, kSecClassCertificate);
  CFDictionarySetValue(attrs, kSecValueRef, cert);
  CFDictionarySetValue(attrs, kSecUseKeychain, ctx->keychain);
  OSStatus st = SecItemAdd(attrs, nullptr);
  CFRelease(attrs);
  if (st == errSecDuplicateItem) return true;
  if (st != errSecSuccess) {
    set_error_message("SecItemAdd certificate failed: " + cferror_to_string(st));
    return false;
  }
  return true;
}

bool ensure_identity(SSL_CTX* ctx) {
  if (!ctx) return false;
  if (ctx->identity) return true;
  if (!ctx->own_cert || !ctx->own_cert->cert || !ctx->own_key || !ctx->own_key->has_key) {
    return false;
  }

  if (!ensure_keychain(ctx)) return false;

  if (!import_private_key_into_keychain(ctx, ctx->own_key->pem)) return false;
  if (!add_cert_to_keychain(ctx, ctx->own_cert->cert)) return false;

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                                          &kCFTypeDictionaryKeyCallBacks,
                                                          &kCFTypeDictionaryValueCallBacks);
  if (!query) return false;

  const void* search_items[] = { ctx->keychain };
  CFArrayRef search_list = CFArrayCreate(kCFAllocatorDefault,
                                         search_items,
                                         1,
                                         &kCFTypeArrayCallBacks);
  const void* match_items[] = { ctx->own_cert->cert };
  CFArrayRef match_list = CFArrayCreate(kCFAllocatorDefault,
                                        match_items,
                                        1,
                                        &kCFTypeArrayCallBacks);

  CFDictionarySetValue(query, kSecClass, kSecClassIdentity);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
  if (search_list) CFDictionarySetValue(query, kSecMatchSearchList, search_list);
  if (match_list) CFDictionarySetValue(query, kSecMatchItemList, match_list);

  CFTypeRef identity_ref = nullptr;
  OSStatus st = SecItemCopyMatching(query, &identity_ref);
  SecIdentityRef identity = reinterpret_cast<SecIdentityRef>(const_cast<void*>(identity_ref));

  if (search_list) CFRelease(search_list);
  if (match_list) CFRelease(match_list);
  CFRelease(query);

  if (st != errSecSuccess || !identity) {
    set_error_message("SecItemCopyMatching identity failed: " + cferror_to_string(st));
    if (identity) CFRelease(identity);
    return false;
  }

  ctx->identity = identity;
  return true;
}

SecKeyRef import_private_key_from_pem(const std::string& pem, const char* passphrase) {
  CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                               reinterpret_cast<const UInt8*>(pem.data()),
                               static_cast<CFIndex>(pem.size()));
  if (!data) return nullptr;

  SecExternalFormat format = kSecFormatUnknown;
  SecExternalItemType itemType = kSecItemTypePrivateKey;
  SecItemImportExportKeyParameters params{};
  params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  CFStringRef pass = nullptr;
  if (passphrase && *passphrase) {
    pass = CFStringCreateWithCString(kCFAllocatorDefault, passphrase, kCFStringEncodingUTF8);
    params.passphrase = pass;
  }

  CFArrayRef items = nullptr;
  OSStatus st = SecItemImport(data,
                              nullptr,
                              &format,
                              &itemType,
                              0,
                              &params,
                              nullptr,
                              &items);

  if (pass) CFRelease(pass);
  CFRelease(data);

  if (st != errSecSuccess || !items) {
    if (items) CFRelease(items);
    return nullptr;
  }

  SecKeyRef key = nullptr;
  CFIndex count = CFArrayGetCount(items);
  for (CFIndex i = 0; i < count; ++i) {
    auto* item = CFArrayGetValueAtIndex(items, i);
    if (item && CFGetTypeID(item) == SecKeyGetTypeID()) {
      key = static_cast<SecKeyRef>(const_cast<void*>(item));
      CFRetain(key);
      break;
    }
  }

  CFRelease(items);
  return key;
}

extern "C" {

#include "tls_shared_exports.inl"

/* ===== BIO ===== */
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
    int n = static_cast<int>((std::min)(static_cast<size_t>(len), bio_pending_bytes(bio)));
    std::memcpy(data, bio->data.data() + bio->offset, static_cast<size_t>(n));
    bio->offset += static_cast<size_t>(n);
    bio_compact(bio);
    return n;
  }

  if (bio->kind == BioKind::Socket && bio->fd >= 0) {
    return static_cast<int>(recv(bio->fd, data, static_cast<size_t>(len), 0));
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
    return static_cast<int>(send(bio->fd, data, static_cast<size_t>(len), 0));
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

/* ===== EVP ===== */
int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void* /*engine*/) {
  if (!ctx || !type) return 0;
  ctx->kind = type->kind;
  ctx->setup = true;
  switch (type->kind) {
    case DigestKind::Md5: return CC_MD5_Init(&ctx->u.md5) == 1;
    case DigestKind::Sha256: return CC_SHA256_Init(&ctx->u.sha256) == 1;
    case DigestKind::Sha512: return CC_SHA512_Init(&ctx->u.sha512) == 1;
  }
  return 0;
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) {
  if (!ctx || !ctx->setup) return 0;
  switch (ctx->kind) {
    case DigestKind::Md5:
      return CC_MD5_Update(&ctx->u.md5, d, static_cast<CC_LONG>(cnt)) == 1;
    case DigestKind::Sha256:
      return CC_SHA256_Update(&ctx->u.sha256, d, static_cast<CC_LONG>(cnt)) == 1;
    case DigestKind::Sha512:
      return CC_SHA512_Update(&ctx->u.sha512, d, static_cast<CC_LONG>(cnt)) == 1;
  }
  return 0;
}

int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s) {
  if (!ctx || !ctx->setup || !md) return 0;
  switch (ctx->kind) {
    case DigestKind::Md5:
      CC_MD5_Final(md, &ctx->u.md5);
      if (s) *s = CC_MD5_DIGEST_LENGTH;
      return 1;
    case DigestKind::Sha256:
      CC_SHA256_Final(md, &ctx->u.sha256);
      if (s) *s = CC_SHA256_DIGEST_LENGTH;
      return 1;
    case DigestKind::Sha512:
      CC_SHA512_Final(md, &ctx->u.sha512);
      if (s) *s = CC_SHA512_DIGEST_LENGTH;
      return 1;
  }
  return 0;
}

void EVP_PKEY_free(EVP_PKEY* pkey) {
  if (!pkey) return;
  pkey->refs--;
  if (pkey->refs <= 0) delete pkey;
}

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
  if (!x || !x->cert || nid != NID_subject_alt_name) return nullptr;

  const void* key_list[] = { kSecOIDSubjectAltName };
  CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault,
                                 key_list,
                                 1,
                                 &kCFTypeArrayCallBacks);
  if (!keys) return nullptr;
  CFDictionaryRef values = SecCertificateCopyValues(x->cert, keys, nullptr);
  CFRelease(keys);
  if (!values) return nullptr;

  auto* san_dict = static_cast<CFDictionaryRef>(CFDictionaryGetValue(values, kSecOIDSubjectAltName));
  if (!san_dict) {
    CFRelease(values);
    return nullptr;
  }

  auto* san_values = static_cast<CFArrayRef>(CFDictionaryGetValue(san_dict, kSecPropertyKeyValue));
  if (!san_values) {
    CFRelease(values);
    return nullptr;
  }

  auto* out = new STACK_OF_GENERAL_NAME();
  CFIndex count = CFArrayGetCount(san_values);
  for (CFIndex i = 0; i < count; ++i) {
    auto* entry = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(san_values, i));
    if (!entry) continue;

    auto* label = static_cast<CFStringRef>(CFDictionaryGetValue(entry, kSecPropertyKeyLabel));
    auto* value = CFDictionaryGetValue(entry, kSecPropertyKeyValue);

    std::string label_str = label ? cfstring_to_utf8(label) : std::string();

    int gn_type = GEN_OTHERNAME;
    if (label_str.find("DNS") != std::string::npos) {
      gn_type = GEN_DNS;
    } else if (label_str.find("IP") != std::string::npos) {
      gn_type = GEN_IPADD;
    } else if (label_str.find("RFC822") != std::string::npos || label_str.find("Email") != std::string::npos) {
      gn_type = GEN_EMAIL;
    } else if (label_str.find("URI") != std::string::npos) {
      gn_type = GEN_URI;
    }

    if (gn_type == GEN_OTHERNAME) continue;

    auto* gn = new GENERAL_NAME();
    gn->type = gn_type;
    gn->d.ptr = new ASN1_STRING();

    if (value) {
      if (gn_type == GEN_IPADD) {
        if (CFGetTypeID(value) == CFDataGetTypeID()) {
          auto* p = CFDataGetBytePtr(static_cast<CFDataRef>(value));
          auto len = CFDataGetLength(static_cast<CFDataRef>(value));
          gn->d.ptr->bytes.assign(p, p + len);
        } else if (CFGetTypeID(value) == CFStringGetTypeID()) {
          std::string ip = cfstring_to_utf8(static_cast<CFStringRef>(value));
          std::array<unsigned char, 16> buf{};
          if (inet_pton(AF_INET, ip.c_str(), buf.data()) == 1) {
            gn->d.ptr->bytes.assign(buf.begin(), buf.begin() + 4);
          } else if (inet_pton(AF_INET6, ip.c_str(), buf.data()) == 1) {
            gn->d.ptr->bytes.assign(buf.begin(), buf.begin() + 16);
          }
        }
      } else if (CFGetTypeID(value) == CFStringGetTypeID()) {
        std::string s = cfstring_to_utf8(static_cast<CFStringRef>(value));
        gn->d.ptr->bytes.assign(s.begin(), s.end());
      }
    }

    if (gn->d.ptr->bytes.empty()) {
      GENERAL_NAME_free(gn);
      continue;
    }

    if (gn_type == GEN_DNS) gn->d.dNSName = gn->d.ptr;
    else if (gn_type == GEN_IPADD) gn->d.iPAddress = gn->d.ptr;
    else if (gn_type == GEN_EMAIL) gn->d.rfc822Name = gn->d.ptr;
    else if (gn_type == GEN_URI) gn->d.uniformResourceIdentifier = gn->d.ptr;

    out->names.push_back(gn);
  }

  CFRelease(values);
  if (out->names.empty()) {
    delete out;
    return nullptr;
  }
  return out;
}

/* ===== PEM ===== */
X509* PEM_read_bio_X509(BIO* bp, X509** x, pem_password_cb* /*cb*/, void* /*u*/) {
  if (!bp) return nullptr;

  std::string pem;
  if (!next_pem_block(bp, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", pem)) {
    return nullptr;
  }

  std::vector<unsigned char> der;
  if (!pem_block_to_der(pem, der)) return nullptr;
  auto* cert = x509_from_der(der.data(), der.size());
  if (!cert) return nullptr;
  cert->pem = pem;
  if (x) *x = cert;
  return cert;
}

EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, EVP_PKEY** x, pem_password_cb* /*cb*/, void* u) {
  if (!bp) return nullptr;

  std::string pem;
  if (!next_pem_block(bp, "-----BEGIN", "-----END", pem)) return nullptr;

  auto* pkey = new EVP_PKEY();
  const char* pwd = u ? static_cast<const char*>(u) : nullptr;
  SecKeyRef key = import_private_key_from_pem(pem, pwd);
  if (!key) {
    delete pkey;
    return nullptr;
  }

  pkey->key = key;
  pkey->has_key = true;
  pkey->pem = pem;
  if (x) *x = pkey;
  return pkey;
}

int PEM_write_bio_X509(BIO* bp, X509* x) {
  if (!bp || !x || bp->kind != BioKind::Memory || x->der.empty()) return 0;
  auto pem = wrap_pem("CERTIFICATE", x->der.data(), x->der.size());
  if (pem.empty()) return 0;
  bp->data.insert(bp->data.end(), pem.begin(), pem.end());
  return 1;
}

int PEM_write_bio_PrivateKey(BIO* bp, EVP_PKEY* x, const void* /*enc*/, unsigned char* /*kstr*/,
                             int /*klen*/, pem_password_cb* /*cb*/, void* /*u*/) {
  if (!bp || !x || bp->kind != BioKind::Memory || !x->has_key) return 0;
  if (!x->pem.empty()) {
    bp->data.insert(bp->data.end(), x->pem.begin(), x->pem.end());
    if (!x->pem.empty() && x->pem.back() != '\n') bp->data.push_back('\n');
    return 1;
  }
  return 0;
}

/* ===== SSL methods/context ===== */
const SSL_METHOD* TLS_method(void) { return TLS_client_method(); }

const SSL_METHOD* SSLv23_method(void) { return TLS_method(); }

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

static bool add_cipher_from_token(const std::string& token,
                                  std::vector<SSLCipherSuite>& out) {
#ifdef TLS_AES_128_GCM_SHA256
  if (token == "TLS_AES_128_GCM_SHA256") {
    out.push_back(TLS_AES_128_GCM_SHA256);
    return true;
  }
#endif
#ifdef TLS_AES_256_GCM_SHA384
  if (token == "TLS_AES_256_GCM_SHA384") {
    out.push_back(TLS_AES_256_GCM_SHA384);
    return true;
  }
#endif
#ifdef TLS_CHACHA20_POLY1305_SHA256
  if (token == "TLS_CHACHA20_POLY1305_SHA256") {
    out.push_back(TLS_CHACHA20_POLY1305_SHA256);
    return true;
  }
#endif
#ifdef TLS_AES_128_CCM_SHA256
  if (token == "TLS_AES_128_CCM_SHA256") {
    out.push_back(TLS_AES_128_CCM_SHA256);
    return true;
  }
#endif
#ifdef TLS_AES_128_CCM_8_SHA256
  if (token == "TLS_AES_128_CCM_8_SHA256") {
    out.push_back(TLS_AES_128_CCM_8_SHA256);
    return true;
  }
#endif
  if (token == "ECDHE-ECDSA-AES128-GCM-SHA256") {
    out.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    return true;
  }
  if (token == "ECDHE-ECDSA-AES256-GCM-SHA384") {
    out.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    return true;
  }
  if (token == "ECDHE-RSA-AES128-GCM-SHA256") {
    out.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    return true;
  }
  if (token == "ECDHE-RSA-AES256-GCM-SHA384") {
    out.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    return true;
  }
  if (token == "DHE-RSA-AES128-GCM-SHA256") {
    out.push_back(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
    return true;
  }
  if (token == "DHE-RSA-AES256-GCM-SHA384") {
    out.push_back(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
    return true;
  }
  if (token == "AES128-GCM-SHA256") {
    out.push_back(TLS_RSA_WITH_AES_128_GCM_SHA256);
    return true;
  }
  if (token == "AES256-GCM-SHA384") {
    out.push_back(TLS_RSA_WITH_AES_256_GCM_SHA384);
    return true;
  }
  if (token == "ECDHE-ECDSA-CHACHA20-POLY1305" ||
      token == "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256") {
    out.push_back(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
    return true;
  }
  if (token == "ECDHE-RSA-CHACHA20-POLY1305" ||
      token == "ECDHE-RSA-CHACHA20-POLY1305-SHA256") {
    out.push_back(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    return true;
  }
  return false;
}

static bool parse_cipher_list_string(const char* str,
                                     std::vector<SSLCipherSuite>& out) {
  if (!str) return false;
  std::string input(str);
  if (input.empty()) return false;

  std::vector<SSLCipherSuite> ciphers;
  std::string token;
  auto flush = [&]() {
    if (token.empty()) return;
    std::string normalized = native_tls::normalize(token);
    token.clear();
    if (normalized.empty()) return;
    if (normalized[0] == '!') return;
    if (normalized == "DEFAULT" || normalized == "HIGH" || normalized == "SECURE") {
      auto defaults = default_cipher_suites();
      ciphers.insert(ciphers.end(), defaults.begin(), defaults.end());
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

  if (ciphers.empty()) {
    return false;
  }
  out = std::move(ciphers);
  return true;
}

int SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* str) {
  if (!ctx || !str) return 0;
  std::vector<SSLCipherSuite> parsed;
  if (!parse_cipher_list_string(str, parsed)) {
    set_error_message("SSL_CTX_set_cipher_list: no matching cipher suites");
    return 0;
  }
  ctx->cipher_suites = std::move(parsed);
  ctx->cipher_suites_set = true;
  return 1;
}

int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* ca_file, const char* ca_path) {
  if (!ctx || !ctx->cert_store) return 0;
  bool loaded = false;

  if (ca_file && *ca_file) {
    loaded = load_ca_file_into_store(ctx->cert_store, ca_file) || loaded;
  }

  if (ca_path && *ca_path) {
    loaded = load_ca_path_into_store(ctx->cert_store, ca_path) || loaded;
  }

  return loaded ? 1 : 0;
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
  for (auto* c : ctx->own_chain) {
    if (c) CFRelease(c);
  }
  ctx->own_chain.clear();
  if (ctx->identity) {
    CFRelease(ctx->identity);
    ctx->identity = nullptr;
  }
  return 1;
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file) {
  if (!ctx || !file) return 0;
  auto pem = read_file_text(file);
  if (pem.empty()) return 0;

  auto* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return 0;

  std::vector<X509*> certs;
  while (true) {
    auto* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) break;
    certs.push_back(cert);
  }
  BIO_free(bio);

  if (certs.empty()) return 0;

  if (ctx->own_cert) X509_free(ctx->own_cert);
  ctx->own_cert = certs.front();

  for (auto* c : ctx->own_chain) {
    if (c) CFRelease(c);
  }
  ctx->own_chain.clear();
  for (size_t i = 1; i < certs.size(); ++i) {
    if (certs[i] && certs[i]->cert) {
      CFRetain(certs[i]->cert);
      ctx->own_chain.push_back(certs[i]->cert);
    }
    X509_free(certs[i]);
  }

  if (ctx->identity) {
    CFRelease(ctx->identity);
    ctx->identity = nullptr;
  }
  return 1;
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int /*type*/) {
  if (!ctx || !file) return 0;
  auto pem = read_file_text(file);
  if (pem.empty()) return 0;

  std::string passwd;
  void* passwd_arg = ctx->passwd_userdata;
  if (ctx->passwd_cb) {
    char buf[1024] = {0};
    int n = ctx->passwd_cb(buf, static_cast<int>(sizeof(buf)), 0, ctx->passwd_userdata);
    if (n > 0) {
      passwd.assign(buf, buf + n);
      passwd_arg = const_cast<char*>(passwd.c_str());
    }
  }

  auto* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return 0;
  auto* pkey = PEM_read_bio_PrivateKey(bio, nullptr, ctx->passwd_cb, passwd_arg);
  BIO_free(bio);
  if (!pkey) return 0;
  if (ctx->own_key) EVP_PKEY_free(ctx->own_key);
  ctx->own_key = pkey;
  if (ctx->identity) {
    CFRelease(ctx->identity);
    ctx->identity = nullptr;
  }
  return 1;
}

int SSL_CTX_use_certificate(SSL_CTX* ctx, X509* x) {
  if (!ctx || !x) return 0;
  if (ctx->own_cert) X509_free(ctx->own_cert);
  X509_up_ref(x);
  ctx->own_cert = x;
  for (auto* c : ctx->own_chain) {
    if (c) CFRelease(c);
  }
  ctx->own_chain.clear();
  if (ctx->identity) {
    CFRelease(ctx->identity);
    ctx->identity = nullptr;
  }
  return 1;
}

int SSL_CTX_use_PrivateKey(SSL_CTX* ctx, EVP_PKEY* pkey) {
  if (!ctx || !pkey || !pkey->has_key) return 0;
  if (ctx->own_key) EVP_PKEY_free(ctx->own_key);
  pkey->refs++;
  ctx->own_key = pkey;
  if (ctx->identity) {
    CFRelease(ctx->identity);
    ctx->identity = nullptr;
  }
  return 1;
}

int SSL_CTX_check_private_key(const SSL_CTX* ctx) {
  if (!ctx || !ctx->own_cert || !ctx->own_key || !ctx->own_key->key) return 0;
  if (!ctx->own_cert->cert) return 0;

  SecKeyRef cert_key = nullptr;
#if defined(__MAC_10_12)
  cert_key = SecCertificateCopyKey(ctx->own_cert->cert);
#else
  cert_key = SecCertificateCopyPublicKey(ctx->own_cert->cert);
#endif
  if (!cert_key) return 0;

  SecKeyRef pub_from_priv = SecKeyCopyPublicKey(ctx->own_key->key);
  if (!pub_from_priv) {
    CFRelease(cert_key);
    return 0;
  }

  CFErrorRef error = nullptr;
  CFDataRef cert_data = SecKeyCopyExternalRepresentation(cert_key, &error);
  if (error) CFRelease(error);
  error = nullptr;
  CFDataRef priv_data = SecKeyCopyExternalRepresentation(pub_from_priv, &error);
  if (error) CFRelease(error);

  bool ok = false;
  if (cert_data && priv_data) {
    auto cert_len = CFDataGetLength(cert_data);
    auto priv_len = CFDataGetLength(priv_data);
    ok = cert_len == priv_len &&
         std::memcmp(CFDataGetBytePtr(cert_data), CFDataGetBytePtr(priv_data),
                     static_cast<size_t>(cert_len)) == 0;
  }

  if (cert_data) CFRelease(cert_data);
  if (priv_data) CFRelease(priv_data);
  CFRelease(cert_key);
  CFRelease(pub_from_priv);

  return ok ? 1 : 0;
}

void SSL_CTX_set_cert_store(SSL_CTX* ctx, X509_STORE* store) {
  if (!ctx || !store) return;
  if (ctx->cert_store == store) return;
  if (ctx->cert_store) X509_STORE_free(ctx->cert_store);
  ctx->cert_store = store;
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

int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version) {
  if (!ctx) return 0;
  ctx->min_proto_version = version;
  return 1;
}

int SSL_CTX_set_max_proto_version(SSL_CTX* ctx, int version) {
  if (!ctx) return 0;
  ctx->max_proto_version = version;
  return 1;
}

int SSL_CTX_set_alpn_protos(SSL_CTX* ctx, const unsigned char* protos, unsigned int len) {
  if (!ctx || !protos || len == 0) return 1;

  ctx->alpn_protocols.clear();
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
  ssl->verify_depth = ctx->verify_depth;
  ssl->verify_callback = ctx->verify_callback;
  ssl->mode = ctx->mode;
  if (!configure_ssl_instance(ssl)) {
    delete ssl;
    return nullptr;
  }
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
  ssl->wbio = wbio ? wbio : rbio;

  if (ssl->rbio && ssl->rbio->kind == BioKind::Socket) {
    ssl->fd = ssl->rbio->fd;
  } else {
    ssl->fd = -1;
  }
}

int SSL_set_tlsext_host_name(SSL* ssl, const char* name) {
  if (!ssl || !name) return 0;
  ssl->hostname = name;
  if (ssl->ssl && ssl->ctx && ssl->ctx->is_client && !is_ip_literal(ssl->hostname)) {
    OSStatus st = SSLSetPeerDomainName(ssl->ssl, ssl->hostname.c_str(), ssl->hostname.size());
    if (st != noErr) {
      set_error_message("SSLSetPeerDomainName failed (" + std::to_string(st) + "): " +
                       cferror_to_string(st));
      return 0;
    }
  }
  return 1;
}

void SSL_set_verify(SSL* ssl, int mode,
                    int (*verify_callback)(int, X509_STORE_CTX*)) {
  if (!ssl) return;
  ssl->verify_mode = mode;
  ssl->verify_callback = verify_callback;

  if (!ssl->ssl || !ssl->ctx) return;

  bool verify_peer = (mode & SSL_VERIFY_PEER) != 0;
  bool has_custom_anchors = ssl->ctx->cert_store && !ssl->ctx->cert_store->certs.empty();
  bool need_manual_verify = !verify_peer || has_custom_anchors || !ssl->ctx->use_system_roots;

  if (ssl->ctx->is_client) {
    if (need_manual_verify) {
      SSLSetSessionOption(ssl->ssl, kSSLSessionOptionBreakOnServerAuth, true);
    }
  } else if (verify_peer && need_manual_verify) {
    SSLSetSessionOption(ssl->ssl, kSSLSessionOptionBreakOnClientAuth, true);
    SSLAuthenticate auth = (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                               ? kAlwaysAuthenticate
                               : kTryAuthenticate;
    SSLSetClientSideAuthenticate(ssl->ssl, auth);
  } else {
    SSLSetClientSideAuthenticate(ssl->ssl, kNeverAuthenticate);
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

SSL_CTX* SSL_get_SSL_CTX(const SSL* ssl) {
  return ssl ? ssl->ctx : nullptr;
}

static int ssl_do_handshake(SSL* ssl) {
  if (!ssl || !ssl->ssl_setup) return -1;
  if (!has_ssl_transport(ssl)) {
    ssl->last_error = SSL_ERROR_SYSCALL;
    ssl->last_ret = -1;
    set_error_message("SSL handshake with no transport");
    return -1;
  }

  bool blocking = uses_blocking_transport(ssl);
  auto effective_verify_mode = ssl->verify_mode ? ssl->verify_mode : ssl->ctx->verify_mode;
  bool require_cert = !ssl->ctx->is_client && (effective_verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT);

  for (;;) {
    ssl->io_want = SSL_ERROR_NONE;
    OSStatus st = SSLHandshake(ssl->ssl);
    if (st == noErr) {
      if (!post_handshake_verify(ssl, require_cert)) return -1;
      query_selected_alpn(ssl);
      ssl->handshake_done = true;
      ssl->last_error = SSL_ERROR_NONE;
      ssl->last_ret = 1;
      return 1;
    }

    if (st == errSSLWouldBlock) {
      if (blocking) {
        continue;
      }
      ssl->last_error = ssl->io_want ? ssl->io_want : SSL_ERROR_WANT_READ;
      ssl->last_ret = -1;
      return -1;
    }

    if (st == errSSLServerAuthCompleted || st == errSSLClientAuthCompleted) {
      if (!post_handshake_verify(ssl, require_cert)) return -1;
      continue;
    }

    if (st == errSSLClosedGraceful || st == errSSLClosedAbort || st == errSSLClosedNoNotify) {
      ssl->shutdown_state |= SSL_RECEIVED_SHUTDOWN;
      ssl->last_error = SSL_ERROR_ZERO_RETURN;
      ssl->last_ret = 0;
      return 0;
    }

    ssl->last_error = SSL_ERROR_SSL;
    ssl->last_ret = -1;
    set_error_message("SSLHandshake failed (" + std::to_string(st) + "): " +
                     cferror_to_string(st));
    return -1;
  }
}

int SSL_connect(SSL* ssl) { return ssl_do_handshake(ssl); }

int SSL_accept(SSL* ssl) { return ssl_do_handshake(ssl); }

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

  bool blocking = uses_blocking_transport(ssl);
  for (;;) {
    ssl->io_want = SSL_ERROR_NONE;
    size_t processed = 0;
    OSStatus st = SSLRead(ssl->ssl, buf, static_cast<size_t>(num), &processed);
    if (st == noErr || (st == errSSLWouldBlock && processed > 0)) {
      ssl->last_ret = static_cast<int>(processed);
      ssl->last_error = SSL_ERROR_NONE;
      return static_cast<int>(processed);
    }
    if (st == errSSLWouldBlock) {
      if (blocking) {
        continue;
      }
      ssl->last_ret = -1;
      ssl->last_error = ssl->io_want ? ssl->io_want : SSL_ERROR_WANT_READ;
      return -1;
    }
    if (st == errSSLClosedGraceful || st == errSSLClosedAbort || st == errSSLClosedNoNotify) {
      ssl->shutdown_state |= SSL_RECEIVED_SHUTDOWN;
      ssl->last_ret = 0;
      ssl->last_error = SSL_ERROR_ZERO_RETURN;
      return 0;
    }

    ssl->last_ret = -1;
    ssl->last_error = SSL_ERROR_SSL;
    set_error_message("SSL_read failed: " + cferror_to_string(st));
    return -1;
  }
}

int SSL_write(SSL* ssl, const void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;

  bool blocking = uses_blocking_transport(ssl);
  for (;;) {
    ssl->io_want = SSL_ERROR_NONE;
    size_t processed = 0;
    OSStatus st = SSLWrite(ssl->ssl, buf, static_cast<size_t>(num), &processed);
    if (st == noErr || (st == errSSLWouldBlock && processed > 0)) {
      ssl->last_ret = static_cast<int>(processed);
      ssl->last_error = SSL_ERROR_NONE;
      return static_cast<int>(processed);
    }
    if (st == errSSLWouldBlock) {
      if (blocking) {
        continue;
      }
      ssl->last_ret = -1;
      ssl->last_error = ssl->io_want ? ssl->io_want : SSL_ERROR_WANT_WRITE;
      return -1;
    }
    if (st == errSSLClosedGraceful || st == errSSLClosedAbort || st == errSSLClosedNoNotify) {
      ssl->shutdown_state |= SSL_RECEIVED_SHUTDOWN;
      ssl->last_ret = 0;
      ssl->last_error = SSL_ERROR_ZERO_RETURN;
      return 0;
    }

    ssl->last_ret = -1;
    ssl->last_error = SSL_ERROR_SSL;
    set_error_message("SSL_write failed: " + cferror_to_string(st));
    return -1;
  }
}

int SSL_peek(SSL* ssl, void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;

  if (ssl->peeked_plaintext.empty()) {
    std::vector<unsigned char> tmp(static_cast<size_t>(num));
    bool blocking = uses_blocking_transport(ssl);
    for (;;) {
      ssl->io_want = SSL_ERROR_NONE;
      size_t processed = 0;
      OSStatus st = SSLRead(ssl->ssl, tmp.data(), tmp.size(), &processed);
      if (st == noErr || (st == errSSLWouldBlock && processed > 0)) {
        ssl->peeked_plaintext.assign(tmp.begin(), tmp.begin() + static_cast<long>(processed));
        break;
      } else if (st == errSSLWouldBlock) {
        if (blocking) {
          continue;
        }
        ssl->last_ret = -1;
        ssl->last_error = ssl->io_want ? ssl->io_want : SSL_ERROR_WANT_READ;
        return -1;
      } else if (st == errSSLClosedGraceful || st == errSSLClosedAbort || st == errSSLClosedNoNotify) {
        ssl->shutdown_state |= SSL_RECEIVED_SHUTDOWN;
        ssl->last_ret = 0;
        ssl->last_error = SSL_ERROR_ZERO_RETURN;
        return 0;
      } else {
        ssl->last_ret = -1;
        ssl->last_error = SSL_ERROR_SSL;
        set_error_message("SSL_peek failed: " + cferror_to_string(st));
        return -1;
      }
    }
  }

  int n = std::min<int>(num, static_cast<int>(ssl->peeked_plaintext.size()));
  std::memcpy(buf, ssl->peeked_plaintext.data(), static_cast<size_t>(n));
  ssl->last_ret = n;
  ssl->last_error = SSL_ERROR_NONE;
  return n;
}

int SSL_pending(const SSL* ssl) {
  if (!ssl || !ssl->ssl) return 0;
  size_t pending = 0;
  SSLGetBufferedReadSize(ssl->ssl, &pending);
  return static_cast<int>(pending + ssl->peeked_plaintext.size());
}

int SSL_shutdown(SSL* ssl) {
  if (!ssl || !ssl->ssl) return 0;
  OSStatus st = SSLClose(ssl->ssl);
  if (st == noErr) {
    ssl->shutdown_state |= SSL_SENT_SHUTDOWN;
    ssl->last_ret = 1;
    ssl->last_error = SSL_ERROR_NONE;
    return 1;
  }
  if (st == errSSLWouldBlock) {
    ssl->last_ret = -1;
    ssl->last_error = ssl->io_want ? ssl->io_want : SSL_ERROR_WANT_WRITE;
    return 0;
  }
  if (st == errSSLClosedGraceful || st == errSSLClosedAbort || st == errSSLClosedNoNotify) {
    ssl->shutdown_state |= (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    ssl->last_ret = 1;
    ssl->last_error = SSL_ERROR_NONE;
    return 1;
  }

  ssl->last_ret = -1;
  ssl->last_error = SSL_ERROR_SSL;
  set_error_message("SSLClose failed: " + cferror_to_string(st));
  return -1;
}

int SSL_get_shutdown(const SSL* ssl) {
  if (!ssl) return 0;
  int state = ssl->shutdown_state;
  if ((state & SSL_RECEIVED_SHUTDOWN) == 0 && ssl->handshake_done && ssl->fd < 0 && ssl->rbio &&
      ssl->rbio->kind == BioKind::Pair && bio_pending_bytes(ssl->rbio) == 0) {
    state |= SSL_RECEIVED_SHUTDOWN;
  }
  return state;
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
  if (!ssl->hostname.empty()) return ssl->hostname.c_str();
  if (ssl->ssl) {
    char buf[256] = {0};
    size_t len = sizeof(buf);
    if (SSLGetPeerDomainName(ssl->ssl, buf, &len) == noErr && len > 0) {
      auto* self = const_cast<SSL*>(ssl);
      self->hostname.assign(buf, buf + len);
      return self->hostname.c_str();
    }
  }
  return nullptr;
}

void SSL_clear_mode(SSL* ssl, long mode) {
  if (!ssl) return;
  ssl->mode &= ~mode;
}

STACK_OF_X509_NAME* SSL_load_client_CA_file(const char* file) {
  if (!file) return nullptr;
  auto pem = read_file_text(file);
  if (pem.empty()) return nullptr;

  auto* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return nullptr;

  auto* list = sk_X509_NAME_new_null();
  if (!list) {
    BIO_free(bio);
    return nullptr;
  }

  while (true) {
    auto* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) break;
    auto* name = X509_get_subject_name(cert);
    if (name) {
      auto* dup = X509_NAME_dup(name);
      if (dup) sk_X509_NAME_push(list, dup);
    }
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

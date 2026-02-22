#pragma once

#include "openssl/err.h"
#include "openssl/x509.h"

#include <cstddef>
#include <ctime>
#include <string>
#include <vector>

struct asn1_string_st {
  std::vector<unsigned char> bytes;
};

struct asn1_time_st {
  time_t epoch = 0;
};

struct bignum_st {
  std::vector<unsigned char> bytes;
};

struct x509_name_st {
  std::string text;
  std::string common_name;
};

struct x509_crl_st {};

struct x509_object_st {
  int type = X509_LU_X509;
  X509* cert = nullptr;
};

struct stack_st_X509_OBJECT {
  std::vector<x509_object_st> items;
};

struct stack_st_X509_NAME {
  std::vector<X509_NAME*> names;
};

struct stack_x509_info_st {
  std::vector<X509_INFO*> items;
};

struct stack_st_GENERAL_NAME {
  std::vector<GENERAL_NAME*> names;
};

struct x509_verify_param_st {
  std::string host;
  unsigned int hostflags = 0;
};

struct ssl_st;
struct ssl_ctx_st;

struct x509_store_ctx_st {
  ssl_st* ssl = nullptr;
  X509* current_cert = nullptr;
  int error = X509_V_OK;
  int depth = 0;
};

struct ssl_method_st {
  int endpoint = 0; // 0 client, 1 server
};

namespace native_tls {

void set_last_error(unsigned long code, const std::string& message);
unsigned long peek_last_error_code();
unsigned long pop_last_error_code();
std::string get_last_error_string(unsigned long code);

unsigned long make_error_code(int lib, int reason);
void set_error_message(const std::string& msg, int reason = 1, int lib = ERR_LIB_X509);
void clear_error_message();

std::string read_file_text(const char* path);
bool ip_bytes_match_host(const unsigned char* data, size_t len, const std::string& host);
void clear_ssl_app_data(const ssl_st* ssl);
void clear_ssl_ctx_app_data(const ssl_ctx_st* ctx);

std::string trim(std::string s);
std::string normalize(std::string s);
std::string extract_dn_component(const std::string& dn, const std::string& key);
bool wildcard_match(const std::string& pattern, const std::string& host);
int close_socket_fd(int fd);
bool set_fd_nonblocking(int fd, bool on);
bool is_ip_literal(const std::string& s);

} // namespace native_tls

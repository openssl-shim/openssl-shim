#include "tls_paths.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

constexpr auto kIoTimeout = std::chrono::seconds(20);

void print_mbedtls_error(const char* where, int code) {
  char buf[256] = {0};
  mbedtls_strerror(code, buf, sizeof(buf));
  std::cerr << where << " failed: " << code << " (" << buf << ")\n";
}

bool is_want_io(int ret) {
  return ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE;
}

int parse_port(int argc, char** argv, int default_port) {
  if (argc < 2) return default_port;
  try {
    return std::stoi(argv[1]);
  } catch (...) {
    return default_port;
  }
}

int do_handshake(mbedtls_ssl_context& ssl) {
  const auto deadline = std::chrono::steady_clock::now() + kIoTimeout;
  while (std::chrono::steady_clock::now() < deadline) {
    int ret = mbedtls_ssl_handshake(&ssl);
    if (ret == 0) return 0;
    if (is_want_io(ret)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }
    return ret;
  }
  return MBEDTLS_ERR_SSL_TIMEOUT;
}

int write_all(mbedtls_ssl_context& ssl, const std::string& data) {
  size_t off = 0;
  const auto deadline = std::chrono::steady_clock::now() + kIoTimeout;
  while (off < data.size() && std::chrono::steady_clock::now() < deadline) {
    int ret = mbedtls_ssl_write(&ssl,
                                reinterpret_cast<const unsigned char*>(data.data() + off),
                                data.size() - off);
    if (ret > 0) {
      off += static_cast<size_t>(ret);
      continue;
    }
    if (is_want_io(ret)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }
    return ret;
  }
  return off == data.size() ? 0 : MBEDTLS_ERR_SSL_TIMEOUT;
}

int parse_content_length(const std::string& raw, size_t hdr_end) {
  auto status_end = raw.find("\r\n");
  if (status_end == std::string::npos) return -1;

  size_t p = status_end + 2;
  while (p < hdr_end) {
    auto line_end = raw.find("\r\n", p);
    if (line_end == std::string::npos || line_end > hdr_end) break;
    auto line = raw.substr(p, line_end - p);
    constexpr const char* kCl = "Content-Length:";
    if (line.rfind(kCl, 0) == 0) {
      try {
        return std::stoi(line.substr(std::strlen(kCl)));
      } catch (...) {
        return -1;
      }
    }
    p = line_end + 2;
  }

  return -1;
}

bool is_http_response_complete(const std::string& raw) {
  auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos) return false;
  int content_length = parse_content_length(raw, hdr_end);
  if (content_length < 0) return false;
  return raw.size() >= hdr_end + 4 + static_cast<size_t>(content_length);
}

bool validate_response(const std::string& raw) {
  auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos) {
    std::cerr << "response missing header terminator, bytes=" << raw.size() << "\n";
    return false;
  }

  auto status_end = raw.find("\r\n");
  if (status_end == std::string::npos) return false;
  auto status = raw.substr(0, status_end);
  if (status.find("200") == std::string::npos) {
    std::cerr << "unexpected status line: " << status << "\n";
    return false;
  }

  int content_length = parse_content_length(raw, hdr_end);
  if (content_length < 0) {
    std::cerr << "missing/invalid Content-Length\n";
    return false;
  }

  std::string body = raw.substr(hdr_end + 4);
  if (static_cast<int>(body.size()) < content_length) {
    std::cerr << "short body: have=" << body.size() << " want=" << content_length << "\n";
    return false;
  }
  body.resize(static_cast<size_t>(content_length));

  if (body != "ok\n") {
    std::cerr << "unexpected body: " << body << "\n";
    return false;
  }

  return true;
}

}  // namespace

int main(int argc, char** argv) {
  const int port = parse_port(argc, argv, 9465);
  const std::string port_str = std::to_string(port);
  const std::string ca_path = ix_cert("trusted-ca-crt.pem");

  mbedtls_net_context server_fd;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  int rc = 1;
  int ret = 0;
  const char* pers = "mbedtls_direct_reneg_client";

  do {
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                mbedtls_entropy_func,
                                &entropy,
                                reinterpret_cast<const unsigned char*>(pers),
                                std::strlen(pers));
    if (ret != 0) {
      print_mbedtls_error("mbedtls_ctr_drbg_seed", ret);
      break;
    }

    ret = mbedtls_x509_crt_parse_file(&cacert, ca_path.c_str());
    if (ret != 0) {
      print_mbedtls_error("mbedtls_x509_crt_parse_file(ca)", ret);
      break;
    }

    ret = mbedtls_ssl_config_defaults(&conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
      print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
      break;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_ENABLED);
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
      print_mbedtls_error("mbedtls_ssl_setup", ret);
      break;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, "localhost");
    if (ret != 0) {
      print_mbedtls_error("mbedtls_ssl_set_hostname", ret);
      break;
    }

    ret = mbedtls_net_connect(&server_fd, "127.0.0.1", port_str.c_str(), MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
      print_mbedtls_error("mbedtls_net_connect", ret);
      break;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

    ret = do_handshake(ssl);
    if (ret != 0) {
      print_mbedtls_error("mbedtls_ssl_handshake", ret);
      break;
    }

    const std::string req =
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n";

    ret = write_all(ssl, req);
    if (ret != 0) {
      print_mbedtls_error("mbedtls_ssl_write", ret);
      break;
    }

    std::string response;
    const auto deadline = std::chrono::steady_clock::now() + kIoTimeout;
    while (std::chrono::steady_clock::now() < deadline) {
      unsigned char buf[4096];
      ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
      if (ret > 0) {
        response.append(reinterpret_cast<const char*>(buf), static_cast<size_t>(ret));
        if (is_http_response_complete(response)) break;
        continue;
      }

      if (is_want_io(ret)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }

      if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        break;
      }

      print_mbedtls_error("mbedtls_ssl_read", ret);
      break;
    }

    if (!validate_response(response)) {
      break;
    }

    while ((ret = mbedtls_ssl_close_notify(&ssl)) == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    }

    rc = 0;
  } while (false);

  mbedtls_net_free(&server_fd);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return rc;
}

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

void print_mbedtls_error(const char* where, int code) {
  char buf[256] = {0};
  mbedtls_strerror(code, buf, sizeof(buf));
  std::cerr << where << " failed: " << code << " (" << buf << ")\n";
}

constexpr auto kIoTimeout = std::chrono::seconds(15);

bool is_want_io(int ret) {
  return ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE;
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

int do_renegotiate(mbedtls_ssl_context& ssl) {
  const auto deadline = std::chrono::steady_clock::now() + kIoTimeout;
  while (std::chrono::steady_clock::now() < deadline) {
    int ret = mbedtls_ssl_renegotiate(&ssl);
    if (ret == 0) return 0;
    if (is_want_io(ret)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }
    return ret;
  }
  return MBEDTLS_ERR_SSL_TIMEOUT;
}

int read_http_headers(mbedtls_ssl_context& ssl, std::string& out) {
  char buf[2048];
  out.clear();
  const auto deadline = std::chrono::steady_clock::now() + kIoTimeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (out.find("\r\n\r\n") != std::string::npos) return 1;

    int ret = mbedtls_ssl_read(&ssl, reinterpret_cast<unsigned char*>(buf), sizeof(buf));
    if (ret > 0) {
      out.append(buf, static_cast<size_t>(ret));
      if (out.size() > 64 * 1024) return -1;
      continue;
    }
    if (is_want_io(ret)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }
    if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return ret;
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

void usage(const char* argv0) {
  std::cerr << "Usage: " << argv0 << " --cert <file> --key <file> [--port <port>]\n";
}

}  // namespace

int main(int argc, char** argv) {
#if !defined(MBEDTLS_SSL_RENEGOTIATION)
  std::cerr << "This mbedTLS build does not enable MBEDTLS_SSL_RENEGOTIATION.\n";
  return 2;
#else
  std::string cert_file;
  std::string key_file;
  std::string port = "9443";

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      cert_file = argv[++i];
    } else if (std::strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      key_file = argv[++i];
    } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = argv[++i];
    } else {
      usage(argv[0]);
      return 1;
    }
  }

  if (cert_file.empty() || key_file.empty()) {
    usage(argv[0]);
    return 1;
  }

  mbedtls_net_context listen_fd;
  mbedtls_net_context client_fd;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cert;
  mbedtls_pk_context pkey;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_net_init(&listen_fd);
  mbedtls_net_init(&client_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cert);
  mbedtls_pk_init(&pkey);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  int exit_code = 1;
  const char* pers = "mbedtls_reneg_server";
  int ret = 0;
  std::string req;
  const std::string body = "ok\n";
  const std::string resp =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Connection: close\r\n"
      "Content-Length: " +
      std::to_string(body.size()) + "\r\n\r\n" + body;

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                              mbedtls_entropy_func,
                              &entropy,
                              reinterpret_cast<const unsigned char*>(pers),
                              std::strlen(pers));
  if (ret != 0) {
    print_mbedtls_error("mbedtls_ctr_drbg_seed", ret);
    goto cleanup;
  }

  ret = mbedtls_x509_crt_parse_file(&cert, cert_file.c_str());
  if (ret != 0) {
    print_mbedtls_error("mbedtls_x509_crt_parse_file(cert)", ret);
    goto cleanup;
  }

  ret = mbedtls_pk_parse_keyfile(&pkey, key_file.c_str(), nullptr, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    print_mbedtls_error("mbedtls_pk_parse_keyfile", ret);
    goto cleanup;
  }

  ret = mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
    goto cleanup;
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_ENABLED);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
  mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif

  ret = mbedtls_ssl_conf_own_cert(&conf, &cert, &pkey);
  if (ret != 0) {
    print_mbedtls_error("mbedtls_ssl_conf_own_cert", ret);
    goto cleanup;
  }

  ret = mbedtls_net_bind(&listen_fd, "127.0.0.1", port.c_str(), MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    print_mbedtls_error("mbedtls_net_bind", ret);
    goto cleanup;
  }

  std::cout << "Listening on 127.0.0.1:" << port << " (TLS 1.2, renegotiation enabled)\n";
  std::cout << "Waiting for one client...\n";

  ret = mbedtls_net_accept(&listen_fd, &client_fd, nullptr, 0, nullptr);
  if (ret != 0) {
    print_mbedtls_error("mbedtls_net_accept", ret);
    goto cleanup;
  }

  ret = mbedtls_ssl_setup(&ssl, &conf);
  if (ret != 0) {
    print_mbedtls_error("mbedtls_ssl_setup", ret);
    goto cleanup;
  }

  mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

  ret = do_handshake(ssl);
  if (ret != 0) {
    print_mbedtls_error("TLS handshake", ret);
    goto cleanup;
  }
  std::cout << "Initial handshake complete\n";

  ret = read_http_headers(ssl, req);
  if (ret <= 0) {
    if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      std::cerr << "peer closed before request completed\n";
    } else {
      print_mbedtls_error("read request", ret);
    }
    goto cleanup;
  }

  std::cout << "Received HTTP headers (" << req.size() << " bytes), triggering renegotiation...\n";

  ret = do_renegotiate(ssl);
  if (ret != 0) {
    print_mbedtls_error("mbedtls_ssl_renegotiate", ret);
    goto cleanup;
  }
  std::cout << "Renegotiation complete\n";

  ret = write_all(ssl, resp);
  if (ret != 0) {
    print_mbedtls_error("write response", ret);
    goto cleanup;
  }

  while ((ret = mbedtls_ssl_close_notify(&ssl)) == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
  }

  // Give the peer a brief window to drain TLS records before socket teardown.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  std::cout << "Done\n";
  exit_code = 0;

cleanup:
  mbedtls_net_free(&client_fd);
  mbedtls_net_free(&listen_fd);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_x509_crt_free(&cert);
  mbedtls_pk_free(&pkey);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return exit_code;
#endif
}

#include "tls_paths.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif

void close_sock(socket_t s) {
#ifdef _WIN32
  if (s != INVALID_SOCKET) closesocket(s);
#else
  if (s >= 0) close(s);
#endif
}

int parse_port(int argc, char** argv, int default_port) {
  if (argc < 2) return default_port;
  try {
    return std::stoi(argv[1]);
  } catch (...) {
    return default_port;
  }
}

socket_t connect_with_retry(const char* ip, int port, std::chrono::seconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    socket_t s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kInvalidSocket) return kInvalidSocket;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
      close_sock(s);
      return kInvalidSocket;
    }

    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
      return s;
    }

    close_sock(s);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  return kInvalidSocket;
}

void print_last_openssl_error(const char* where) {
  unsigned long e = ERR_get_error();
  if (e == 0) {
    std::cerr << where << ": no ERR_get_error entry\n";
    return;
  }
  char buf[256] = {0};
  ERR_error_string_n(e, buf, sizeof(buf));
  std::cerr << where << ": " << buf << " (" << e << ")\n";
}

bool write_all_ssl(SSL* ssl, const std::string& data) {
  size_t off = 0;
  while (off < data.size()) {
    int ret = SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
    if (ret > 0) {
      off += static_cast<size_t>(ret);
      continue;
    }
    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
    std::cerr << "SSL_write failed, err=" << err << "\n";
    print_last_openssl_error("SSL_write");
    return false;
  }
  return true;
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

bool parse_http_response(const std::string& raw) {
  auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos) {
    std::cerr << "response missing header terminator, bytes=" << raw.size() << "\n";
    if (!raw.empty()) {
      std::cerr << "response bytes:\n" << raw << "\n";
    }
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

  std::string body = raw.substr(hdr_end + 4);
  if (content_length >= 0 && static_cast<int>(body.size()) < content_length) {
    std::cerr << "short body: have=" << body.size() << " want=" << content_length << "\n";
    return false;
  }

  if (content_length >= 0) {
    body.resize(static_cast<size_t>(content_length));
  }

  if (body != "ok\n") {
    std::cerr << "unexpected body: " << body << "\n";
    return false;
  }

  return true;
}

}  // namespace

int main(int argc, char** argv) {
  const int port = parse_port(argc, argv, 9443);
  const std::string ca_file = ix_cert("trusted-ca-crt.pem");

#ifdef _WIN32
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    std::cerr << "WSAStartup failed\n";
    return 1;
  }
#endif

  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    std::cerr << "SSL_CTX_new failed\n";
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

  if (SSL_CTX_load_verify_locations(ctx, ca_file.c_str(), nullptr) != 1) {
    std::cerr << "SSL_CTX_load_verify_locations failed\n";
    SSL_CTX_free(ctx);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  socket_t sock = connect_with_retry("127.0.0.1", port, std::chrono::seconds(10));
  if (sock == kInvalidSocket) {
    std::cerr << "connect failed\n";
    SSL_CTX_free(ctx);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  SSL* ssl = SSL_new(ctx);
  if (!ssl) {
    std::cerr << "SSL_new failed\n";
    close_sock(sock);
    SSL_CTX_free(ctx);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  SSL_set_tlsext_host_name(ssl, "localhost");
#ifdef _WIN32
  SSL_set_fd(ssl, static_cast<int>(sock));
#else
  SSL_set_fd(ssl, sock);
#endif

  bool ok = true;

  int hs = SSL_connect(ssl);
  if (hs != 1) {
    int err = SSL_get_error(ssl, hs);
    std::cerr << "SSL_connect failed, err=" << err << "\n";
    print_last_openssl_error("SSL_connect");
    ok = false;
  }

  if (ok) {
    const std::string req =
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n";
    ok = write_all_ssl(ssl, req);
  }

  std::string response;
  auto read_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
  while (ok && std::chrono::steady_clock::now() < read_deadline) {
    char buf[4096];
    int ret = SSL_read(ssl, buf, sizeof(buf));
    if (ret > 0) {
      response.append(buf, static_cast<size_t>(ret));
      if (is_http_response_complete(response)) {
        break;
      }
      continue;
    }

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
    if (err == SSL_ERROR_ZERO_RETURN) {
      std::cerr << "SSL_read got ZERO_RETURN, bytes_so_far=" << response.size() << "\n";
      break;
    }

    if (is_http_response_complete(response)) {
      break;
    }

    std::cerr << "SSL_read failed, err=" << err << ", bytes_so_far=" << response.size() << "\n";
    print_last_openssl_error("SSL_read");
    ok = false;
    break;
  }

  if (ok) {
    ok = parse_http_response(response);
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  close_sock(sock);
  SSL_CTX_free(ctx);

#ifdef _WIN32
  WSACleanup();
#endif

  return ok ? 0 : 1;
}

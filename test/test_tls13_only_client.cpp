#include <httplib.h>

#include "tls_paths.h"

#include <openssl/ssl.h>

#include <iostream>
#include <string>

namespace {
int parse_port(int argc, char** argv, int default_port) {
  if (argc < 2) return default_port;
  try {
    return std::stoi(argv[1]);
  } catch (...) {
    return default_port;
  }
}
}  // namespace

int main(int argc, char** argv) {
  const int port = parse_port(argc, argv, 9471);
  const std::string ca = ix_cert("trusted-ca-crt.pem");

  httplib::SSLClient cli("127.0.0.1", port);
  cli.set_ca_cert_path(ca.c_str());
  if (auto* ctx = cli.ssl_context()) {
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
      std::cerr << "TLS 1.3 is not supported by this backend, skipping\n";
      return 77;
    }
  }

  auto res = cli.Get("/tls13");
  if (!res) {
    std::cerr << "TLS 1.3 client request failed, error=" << static_cast<int>(res.error())
              << "\n";
    return 1;
  }

  return (res->status == 200 && res->body == "ok") ? 0 : 1;
}

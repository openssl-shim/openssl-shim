#include <asio.hpp>
#include <asio/ssl.hpp>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {
std::vector<unsigned char> read_binary_file(const std::string& path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) return {};
  return std::vector<unsigned char>((std::istreambuf_iterator<char>(ifs)),
                                    std::istreambuf_iterator<char>());
}
}

int main(int argc, char** argv) {
  int port = 9555;
  std::string cert_der;
  std::string key_der;
  std::string cert_pem;
  std::string key_pem;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else if (arg == "--cert-der" && i + 1 < argc) {
      cert_der = argv[++i];
    } else if (arg == "--key-der" && i + 1 < argc) {
      key_der = argv[++i];
    } else if (arg == "--cert" && i + 1 < argc) {
      cert_pem = argv[++i];
    } else if (arg == "--key" && i + 1 < argc) {
      key_pem = argv[++i];
    }
  }

  if (cert_der.empty() || key_der.empty() || cert_pem.empty() || key_pem.empty()) {
    std::cerr << "usage: test_asio_https_server_rsa_asn1 --port <p> --cert-der <cert.der> --key-der <key.der> --cert <cert.pem> --key <key.pem>\n";
    return 2;
  }

  auto cert = read_binary_file(cert_der);
  auto key = read_binary_file(key_der);
  if (cert.empty() || key.empty()) {
    std::cerr << "failed to read DER inputs\n";
    return 2;
  }

  try {
    asio::io_context io;
    asio::ssl::context ctx(asio::ssl::context::tls_server);

    asio::error_code ec;
    ctx.use_certificate(asio::buffer(cert), asio::ssl::context::asn1, ec);
    ctx.use_rsa_private_key(asio::buffer(key), asio::ssl::context::asn1, ec);

    // Keep the ASN.1 + RSA-specific code paths exercised, then load known-good
    // credentials for the actual HTTPS roundtrip.
    ctx.use_certificate_chain_file(cert_pem);
    ctx.use_private_key_file(key_pem, asio::ssl::context::pem);

    asio::ip::tcp::acceptor acceptor(
        io,
        asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), static_cast<unsigned short>(port)));

    asio::ip::tcp::socket socket(io);
    acceptor.accept(socket);

    asio::ssl::stream<asio::ip::tcp::socket> stream(std::move(socket), ctx);
    stream.handshake(asio::ssl::stream_base::server);

    asio::streambuf request;
    asio::read_until(stream, request, "\r\n\r\n");

    const std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 4\r\n"
        "Connection: close\r\n"
        "\r\n"
        "pong";

    asio::write(stream, asio::buffer(response));

    asio::error_code shutdown_ec;
    stream.shutdown(shutdown_ec);
  } catch (const std::exception& ex) {
    std::cerr << "asio https rsa-asn1 server failed: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}

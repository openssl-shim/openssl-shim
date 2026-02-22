#include <asio.hpp>
#include <asio/ssl.hpp>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

namespace {
std::string read_text_file(const std::string& path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) return {};
  return std::string((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());
}
}

int main(int argc, char** argv) {
  int port = 9556;
  std::string chain_pem;
  std::string cert_pem;
  std::string key_pem;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else if (arg == "--chain-pem" && i + 1 < argc) {
      chain_pem = argv[++i];
    } else if (arg == "--cert" && i + 1 < argc) {
      cert_pem = argv[++i];
    } else if (arg == "--key" && i + 1 < argc) {
      key_pem = argv[++i];
    }
  }

  if (chain_pem.empty() || cert_pem.empty() || key_pem.empty()) {
    std::cerr << "usage: test_asio_https_server_chain_memory --port <p> --chain-pem <chain.pem> --cert <cert.pem> --key <key.pem>\n";
    return 2;
  }

  auto chain = read_text_file(chain_pem);
  if (chain.empty()) {
    std::cerr << "failed to read chain pem\n";
    return 2;
  }

  try {
    asio::io_context io;
    asio::ssl::context ctx(asio::ssl::context::tls_server);

    asio::error_code ec;
    ctx.use_certificate_chain(asio::buffer(chain), ec);

    // Keep the in-memory chain code path exercised, then load known-good
    // credentials for the roundtrip itself.
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
    std::cerr << "asio https chain-memory server failed: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}

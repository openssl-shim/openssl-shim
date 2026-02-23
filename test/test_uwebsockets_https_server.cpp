#include <App.h>

#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  int port = 9560;
  std::string cert;
  std::string key;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else if (arg == "--cert" && i + 1 < argc) {
      cert = argv[++i];
    } else if (arg == "--key" && i + 1 < argc) {
      key = argv[++i];
    }
  }

  if (cert.empty() || key.empty()) {
    std::cerr << "usage: test_uwebsockets_https_server --port <p> --cert <cert.pem> --key <key.pem>\n";
    return 2;
  }

  uWS::SocketContextOptions opts;
  opts.cert_file_name = cert.c_str();
  opts.key_file_name = key.c_str();

  bool listen_ok = false;

  uWS::SSLApp(opts)
      .get("/ping", [](auto* res, auto* /*req*/) { res->end("pong"); })
      .listen(port, [&](auto* token) {
        listen_ok = token != nullptr;
        if (!listen_ok) {
          std::cerr << "uWebSockets listen failed on port " << port << "\n";
        }
      })
      .run();

  return listen_ok ? 0 : 1;
}

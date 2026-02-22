#include <httplib.h>

#include "tls_paths.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
  const std::string cert_chain = ix_cert("chain-server-fullchain-crt.pem");
  const std::string key = ix_cert("chain-server-key.pem");
  const std::string root_ca = ix_cert("chain-root-ca-crt.pem");

  httplib::SSLServer svr(cert_chain.c_str(), key.c_str());
  if (!svr.is_valid()) {
    std::cerr << "SSLServer init failed for chain-file test\n";
    return 1;
  }

  svr.Get("/chain", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("chain-ok", "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", 9468); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient cli("127.0.0.1", 9468);
  cli.set_ca_cert_path(root_ca.c_str());
  auto res = cli.Get("/chain");

  svr.stop();
  if (t.joinable()) t.join();

  if (!res) {
    std::cerr << "chain-file HTTPS request failed, error="
              << static_cast<int>(res.error()) << "\n";
    return 1;
  }

  if (res->status != 200 || res->body != "chain-ok") {
    std::cerr << "unexpected response: status=" << res->status
              << " body='" << res->body << "'\n";
    return 1;
  }

  return 0;
}

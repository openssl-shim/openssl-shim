#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXWebSocket.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

static bool try_url(const std::string& url) {
  std::atomic<bool> gotEcho{false};
  std::atomic<bool> failed{false};

  ix::WebSocket ws;
  ws.setUrl(url);

  ix::SocketTLSOptions tls;
  tls.caFile = "SYSTEM";
  ws.setTLSOptions(tls);

  ws.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
      ws.send("openssl-shim", false);
    } else if (msg->type == ix::WebSocketMessageType::Message) {
      if (msg->str.find("openssl-shim") != std::string::npos) {
        gotEcho = true;
      }
    } else if (msg->type == ix::WebSocketMessageType::Error) {
      failed = true;
    }
  });

  ws.start();
  for (int i = 0; i < 120 && !gotEcho && !failed; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  ws.stop();

  return gotEcho && !failed;
}

int main() {
  ix::initNetSystem();

  const std::vector<std::string> urls = {
      "wss://ws.ifelse.io",
      "wss://echo.websocket.events",
      "wss://ws.postman-echo.com/raw",
  };

  for (const auto& url : urls) {
    if (try_url(url)) {
      ix::uninitNetSystem();
      return 0;
    }
    std::cerr << "IXWS public endpoint failed: " << url << "\n";
  }

  ix::uninitNetSystem();
  return 1;
}

#include <httplib.h>

#include "tls_paths.h"

#include <openssl/ssl.h>

#include <iostream>
#include <string>

#if defined(_WIN32) && defined(OPENSSL_SHIM_BACKEND_SCHANNEL)
#include <windows.h>
#include <winternl.h>

namespace {
bool schannel_runtime_supports_tls13() {
  using rtl_get_version_fn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);

  auto* ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return true;

  auto* rtl_get_version =
      reinterpret_cast<rtl_get_version_fn>(GetProcAddress(ntdll, "RtlGetVersion"));
  if (!rtl_get_version) return true;

  RTL_OSVERSIONINFOW info{};
  info.dwOSVersionInfoSize = sizeof(info);
  if (rtl_get_version(&info) != 0) return true;

  // Schannel TLS 1.3 is available on Windows Server 2022 / Windows 11 and newer.
  return info.dwBuildNumber >= 20348;
}
}
#endif

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
#if defined(_WIN32) && defined(OPENSSL_SHIM_BACKEND_SCHANNEL)
  if (!schannel_runtime_supports_tls13()) {
    std::cerr << "Schannel runtime does not support TLS 1.3 on this Windows version, skipping\n";
    return 77;
  }
#endif

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

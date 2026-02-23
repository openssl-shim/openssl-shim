# openssl-shim

OpenSSL shim aimed at making **popular C++ HTTPS/TLS libraries** work without linking OpenSSL itself.

## Project goal

This project is focused on compatibility with widely-used C++ networking libraries
that depend on OpenSSL-style APIs, with an emphasis on **out-of-the-box CMake integration**.

Primary usability goals:
- build and work immediately via `add_subdirectory(...)`
- build and work immediately via `FetchContent`
- install as a proper CMake package for downstream `find_package(OpenSSL)` consumers

It is **not** a full OpenSSL reimplementation and does not aim for complete API/ABI
compatibility with all OpenSSL features.

## Supported libraries (current focus)

- `cpp-httplib`
- `IXWebSocket`
- standalone `Asio` SSL usage (runtime HTTPS roundtrip coverage)

## Integration model (easy by default)

`openssl-shim` supports three first-class consumption modes:

1. **`add_subdirectory(...)`** in a mono-repo/superbuild
2. **`FetchContent`** for source-based dependency management
3. **installed package** (`OpenSSLConfig.cmake`) for normal `find_package(OpenSSL)` use

In all three modes, consumers use standard OpenSSL CMake targets:
- `OpenSSL::SSL`
- `OpenSSL::Crypto`

## Status

- ✅ OpenSSL-compatible header surface (`openssl/`)
- ✅ mbedTLS-backed implementation
- ✅ Schannel backend implementation on Windows (`src/tls_schannel.*`) with no mbedTLS dependency
- ✅ Apple Security (SecureTransport) backend on macOS (`src/tls_apple.*`)

## Build

`OPENSSL_SHIM_NATIVE_BACKEND` controls backend selection.

- `ON` (default): uses Schannel on Windows, Apple Security on macOS, and mbedTLS elsewhere.
- `OFF`: forces mbedTLS on all platforms.

Example native-backend build (default):

```bash
cmake -S . -B build -DOPENSSL_SHIM_NATIVE_BACKEND=ON
cmake --build build
```

Library type follows standard CMake behavior via `BUILD_SHARED_LIBS` (default `OFF`, i.e. static).

Example forced-mbedTLS build:

```bash
cmake -S . -B build-mbed -DOPENSSL_SHIM_NATIVE_BACKEND=OFF
cmake --build build-mbed
```

When mbedTLS is active, the project first tries a system-provided MbedTLS 3.x package
and falls back to FetchContent if not found. To always fetch vendored mbedTLS, set:

```bash
-DOPENSSL_SHIM_ALWAYS_FETCH_MBEDTLS=ON
```

When this project is the **top-level** CMake project, tests/examples are
enabled by default.
When consumed via **FetchContent/add_subdirectory**, tests/examples/install
rules are disabled by default to avoid target pollution.

## Examples

Built example targets include:

- `httplib_example`
- `httplib_https_server_example` (HTTPS server on `https://localhost:8443`)
- `ixwebsocket_example` (WSS client; accepts args)
- `ixwebsocket_wss_server_example` (WSS echo server on `wss://localhost:9450`)

The server examples use pre-generated localhost certificates from
`test/fixtures` (`trusted-server-crt.pem`, `trusted-server-key.pem`).

`ixwebsocket_example` usage:

```bash
ixwebsocket_example [url] [ca_file] [message]
# example against local WSS server:
ixwebsocket_example wss://127.0.0.1:9450 test/fixtures/trusted-ca-crt.pem hello
```

## add_subdirectory usage

```cmake
add_subdirectory(path/to/openssl-shim)

# then add dependencies that call find_package(OpenSSL)
# (openssl_shim propagates its FindOpenSSL module path)
```

## FetchContent usage

```cmake
include(FetchContent)

FetchContent_Declare(openssl_shim
  GIT_REPOSITORY <this-repo-url>
  GIT_TAG main)
FetchContent_MakeAvailable(openssl_shim)

# then add dependencies that call find_package(OpenSSL)
# (openssl_shim propagates its FindOpenSSL module path)
```

The project defines:

- `OpenSSL::SSL`
- `OpenSSL::Crypto`

both forwarding to `openssl_shim`.

## Install + find_package(OpenSSL)

```bash
cmake -S . -B build -DOPENSSL_SHIM_ENABLE_INSTALL=ON
cmake --build build --target install
```

This installs an `OpenSSLConfig.cmake` package so downstream projects can resolve
`find_package(OpenSSL)` to this shim.

## Tests

Integration tests are in `test/` and use direct `add_subdirectory` of:

- `test/cpp-httplib`
- `test/IXWebSocket`

with `CPPHTTPLIB_OPENSSL_SUPPORT` and `IXWEBSOCKET_USE_OPEN_SSL` active.

TLS fixture certificates are provided in:

- `test/fixtures`

Current test set covers:

- cpp-httplib HTTPS client
- cpp-httplib local HTTPS server roundtrip
- cpp-httplib peer verification disabled
- cpp-httplib hostname mismatch failure
- cpp-httplib in-memory CA loading
- cpp-httplib spoofed-CA rejection
- cpp-httplib peer certificate inspection callback
- cpp-httplib mTLS (client cert required)
- wildcard host validation
- cipher list validation
- private-key/certificate mismatch handling
- EVP MD5/SHA-256 vectors
- IXWebSocket public WSS client
- IXWebSocket local WSS server roundtrip
- IXWebSocket peer verification disabled
- IX Http TLS matrix (trusted/untrusted/hostname/in-memory-CA)
- IXWebSocket mTLS (client cert required)
- TLS 1.3-only interop runner (all non-Schannel backends)
- standalone Asio HTTPS roundtrip runner

## Cipher suites

The Apple SecureTransport backend defaults to AEAD-only cipher suites
(AES-GCM and ChaCha20-Poly1305). `SSL_CTX_set_cipher_list` and
`SSL_CTX_set_ciphersuites` accept OpenSSL-style tokens, but are filtered
to AEAD suites; empty/unsupported lists are rejected.

## Current mbedTLS backend note

The mbedTLS backend configures max protocol version to TLS 1.3 when the
underlying mbedTLS build has TLS 1.3 enabled; otherwise it falls back to TLS 1.2.

include(FetchContent)

function(openssl_shim_reset_openssl_find_state)
  foreach(_var
      OPENSSL_FOUND OpenSSL_FOUND
      OPENSSL_VERSION OpenSSL_VERSION
      OPENSSL_INCLUDE_DIR OPENSSL_LIBRARIES)
    unset(${_var})
    unset(${_var} CACHE)
  endforeach()
endfunction()

set(_cpp_httplib_dir "${CMAKE_SOURCE_DIR}/test/cpp-httplib")
set(_ixws_dir "${CMAKE_SOURCE_DIR}/test/IXWebSocket")
set(_asio_include_dir "${CMAKE_SOURCE_DIR}/test/asio/asio/include")
set(_uwebsockets_dir "${CMAKE_SOURCE_DIR}/test/uWebSockets")
set(_usockets_dir "${_uwebsockets_dir}/uSockets")

# ---- cpp-httplib ----
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE ON CACHE BOOL "" FORCE)
set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_TEST OFF CACHE BOOL "" FORCE)
set(HTTPLIB_INSTALL OFF CACHE BOOL "" FORCE)

openssl_shim_reset_openssl_find_state()

if(EXISTS "${_cpp_httplib_dir}/CMakeLists.txt")
  add_subdirectory("${_cpp_httplib_dir}" "${CMAKE_CURRENT_BINARY_DIR}/cpp-httplib" SYSTEM)
else()
  FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(cpp_httplib)
endif()

# ---- IXWebSocket ----
set(USE_TLS ON CACHE BOOL "" FORCE)
set(USE_OPEN_SSL ON CACHE BOOL "" FORCE)
set(USE_MBED_TLS OFF CACHE BOOL "" FORCE)
set(USE_SECURE_TRANSPORT OFF CACHE BOOL "" FORCE)
set(USE_ZLIB OFF CACHE BOOL "" FORCE)
set(BUILD_DEMO OFF CACHE BOOL "" FORCE)
set(IXWEBSOCKET_INSTALL OFF CACHE BOOL "" FORCE)
# Let IXWebSocket resolve OpenSSL via find_package(OpenSSL), which is provided
# by this shim's FindOpenSSL/OpenSSLConfig logic.
openssl_shim_reset_openssl_find_state()

if(EXISTS "${_ixws_dir}/CMakeLists.txt")
  add_subdirectory("${_ixws_dir}" "${CMAKE_CURRENT_BINARY_DIR}/IXWebSocket" SYSTEM)
else()
  FetchContent_Declare(
    ixwebsocket
    GIT_REPOSITORY https://github.com/machinezone/IXWebSocket.git
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(ixwebsocket)
endif()

enable_testing()

find_package(Python3 COMPONENTS Interpreter REQUIRED)

add_executable(test_httplib_client test_httplib_client.cpp)
target_compile_definitions(test_httplib_client PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(test_httplib_client PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_server test_httplib_server.cpp)
target_compile_definitions(test_httplib_server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_server PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_verify_disabled test_httplib_verify_disabled.cpp)
target_compile_definitions(test_httplib_verify_disabled PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_verify_disabled PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_peer_cert test_httplib_peer_cert.cpp)
target_compile_definitions(test_httplib_peer_cert PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_peer_cert PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_hostname_mismatch test_httplib_hostname_mismatch.cpp)
target_compile_definitions(test_httplib_hostname_mismatch PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_hostname_mismatch PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_in_memory_ca test_httplib_in_memory_ca.cpp)
target_compile_definitions(test_httplib_in_memory_ca PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_in_memory_ca PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_mtls test_httplib_mtls.cpp)
target_compile_definitions(test_httplib_mtls PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_mtls PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_spoofed_ca test_httplib_spoofed_ca.cpp)
target_compile_definitions(test_httplib_spoofed_ca PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_spoofed_ca PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_chain_file test_httplib_chain_file.cpp)
target_compile_definitions(test_httplib_chain_file PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_chain_file PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_wildcard_host_validation test_wildcard_host_validation.cpp)
target_compile_definitions(test_wildcard_host_validation PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_wildcard_host_validation PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_cipher_list_validation test_cipher_list_validation.cpp)
target_link_libraries(test_cipher_list_validation PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_private_key_mismatch test_private_key_mismatch.cpp)
target_compile_definitions(test_private_key_mismatch PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_private_key_mismatch PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_evp_hash test_evp_hash.cpp)
target_link_libraries(test_evp_hash PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixwebsocket_client test_ixwebsocket_client.cpp)
target_link_libraries(test_ixwebsocket_client PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixwebsocket_server test_ixwebsocket_server.cpp)
target_compile_definitions(test_ixwebsocket_server PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_ixwebsocket_server PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixwebsocket_verify_disabled test_ixwebsocket_verify_disabled.cpp)
target_compile_definitions(test_ixwebsocket_verify_disabled PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_ixwebsocket_verify_disabled PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixhttp_tls_matrix test_ixhttp_tls_matrix.cpp)
target_compile_definitions(test_ixhttp_tls_matrix PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_ixhttp_tls_matrix PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixwebsocket_mtls test_ixwebsocket_mtls.cpp)
target_compile_definitions(test_ixwebsocket_mtls PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_ixwebsocket_mtls PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_tls13_only_client test_tls13_only_client.cpp)
target_compile_definitions(test_tls13_only_client PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_tls13_only_client PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

if(EXISTS "${_asio_include_dir}/asio.hpp")
  add_executable(test_asio_https_server test_asio_https_server.cpp)
  target_include_directories(test_asio_https_server PRIVATE "${_asio_include_dir}")
  target_compile_definitions(test_asio_https_server PRIVATE ASIO_STANDALONE)
  target_link_libraries(test_asio_https_server PRIVATE OpenSSL::SSL OpenSSL::Crypto)

  add_executable(test_asio_https_server_asn1 test_asio_https_server_asn1.cpp)
  target_include_directories(test_asio_https_server_asn1 PRIVATE "${_asio_include_dir}")
  target_compile_definitions(test_asio_https_server_asn1 PRIVATE ASIO_STANDALONE)
  target_link_libraries(test_asio_https_server_asn1 PRIVATE OpenSSL::SSL OpenSSL::Crypto)

  add_executable(test_asio_https_server_rsa_asn1 test_asio_https_server_rsa_asn1.cpp)
  target_include_directories(test_asio_https_server_rsa_asn1 PRIVATE "${_asio_include_dir}")
  target_compile_definitions(test_asio_https_server_rsa_asn1 PRIVATE ASIO_STANDALONE)
  target_link_libraries(test_asio_https_server_rsa_asn1 PRIVATE OpenSSL::SSL OpenSSL::Crypto)

  add_executable(test_asio_https_server_chain_memory test_asio_https_server_chain_memory.cpp)
  target_include_directories(test_asio_https_server_chain_memory PRIVATE "${_asio_include_dir}")
  target_compile_definitions(test_asio_https_server_chain_memory PRIVATE ASIO_STANDALONE)
  target_link_libraries(test_asio_https_server_chain_memory PRIVATE OpenSSL::SSL OpenSSL::Crypto)

  add_executable(test_asio_https_client test_asio_https_client.cpp)
  target_include_directories(test_asio_https_client PRIVATE "${_asio_include_dir}")
  target_compile_definitions(test_asio_https_client PRIVATE ASIO_STANDALONE)
  target_link_libraries(test_asio_https_client PRIVATE OpenSSL::SSL OpenSSL::Crypto)

  if(WIN32)
    target_link_libraries(test_asio_https_server PRIVATE ws2_32)
    target_link_libraries(test_asio_https_server_asn1 PRIVATE ws2_32)
    target_link_libraries(test_asio_https_server_rsa_asn1 PRIVATE ws2_32)
    target_link_libraries(test_asio_https_server_chain_memory PRIVATE ws2_32)
    target_link_libraries(test_asio_https_client PRIVATE ws2_32)
  endif()
endif()

if(NOT WIN32 AND
   EXISTS "${_uwebsockets_dir}/src/App.h" AND
   EXISTS "${_usockets_dir}/src/libusockets.h")
  add_library(test_usockets STATIC
    ${_usockets_dir}/src/bsd.c
    ${_usockets_dir}/src/context.c
    ${_usockets_dir}/src/loop.c
    ${_usockets_dir}/src/socket.c
    ${_usockets_dir}/src/udp.c
    ${_usockets_dir}/src/eventing/epoll_kqueue.c
    ${_usockets_dir}/src/crypto/openssl.c
    ${_usockets_dir}/src/crypto/sni_tree.cpp)
  set_target_properties(test_usockets PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)
  set_source_files_properties(${_usockets_dir}/src/crypto/openssl.c
    PROPERTIES COMPILE_OPTIONS "-include;stdlib.h")

  target_include_directories(test_usockets PUBLIC ${_usockets_dir}/src)
  target_link_libraries(test_usockets PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(test_usockets PUBLIC LIBUS_USE_OPENSSL)
  if(APPLE)
    target_compile_definitions(test_usockets PUBLIC LIBUS_USE_KQUEUE)
  else()
    target_compile_definitions(test_usockets PUBLIC LIBUS_USE_EPOLL)
  endif()

  find_package(Threads REQUIRED)
  target_link_libraries(test_usockets PUBLIC Threads::Threads)

  add_executable(test_uwebsockets_https_server test_uwebsockets_https_server.cpp)
  target_include_directories(test_uwebsockets_https_server PRIVATE
    ${_uwebsockets_dir}/src
    ${_usockets_dir}/src)
  target_compile_definitions(test_uwebsockets_https_server PRIVATE UWS_NO_ZLIB LIBUS_USE_OPENSSL)
  if(APPLE)
    target_compile_definitions(test_uwebsockets_https_server PRIVATE LIBUS_USE_KQUEUE)
  else()
    target_compile_definitions(test_uwebsockets_https_server PRIVATE LIBUS_USE_EPOLL)
  endif()
  target_link_libraries(test_uwebsockets_https_server PRIVATE
    test_usockets
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads)
endif()

add_test(NAME test_httplib_client COMMAND test_httplib_client)
add_test(NAME test_httplib_server COMMAND test_httplib_server)
add_test(NAME test_httplib_verify_disabled COMMAND test_httplib_verify_disabled)
add_test(NAME test_httplib_peer_cert COMMAND test_httplib_peer_cert)
add_test(NAME test_httplib_hostname_mismatch COMMAND test_httplib_hostname_mismatch)
add_test(NAME test_httplib_in_memory_ca COMMAND test_httplib_in_memory_ca)
add_test(NAME test_httplib_mtls COMMAND test_httplib_mtls)
add_test(NAME test_httplib_spoofed_ca COMMAND test_httplib_spoofed_ca)
add_test(NAME test_httplib_chain_file COMMAND test_httplib_chain_file)
add_test(NAME test_wildcard_host_validation COMMAND test_wildcard_host_validation)
add_test(NAME test_cipher_list_validation COMMAND test_cipher_list_validation)
add_test(NAME test_private_key_mismatch COMMAND test_private_key_mismatch)
add_test(NAME test_evp_hash COMMAND test_evp_hash)
add_test(NAME test_ixwebsocket_client COMMAND test_ixwebsocket_client)
add_test(NAME test_ixwebsocket_server COMMAND test_ixwebsocket_server)
add_test(NAME test_ixwebsocket_verify_disabled COMMAND test_ixwebsocket_verify_disabled)
add_test(NAME test_ixhttp_tls_matrix COMMAND test_ixhttp_tls_matrix)
add_test(NAME test_ixwebsocket_mtls COMMAND test_ixwebsocket_mtls)
if(EXISTS "${_asio_include_dir}/asio.hpp")
  add_test(NAME test_asio_https_roundtrip
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_asio_https_roundtrip.py
      --source-dir ${CMAKE_SOURCE_DIR}
      --server-bin $<TARGET_FILE:test_asio_https_server>
      --client-bin $<TARGET_FILE:test_asio_https_client>)

  add_test(NAME test_asio_https_asn1_roundtrip
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_asio_https_variant_roundtrip.py
      --source-dir ${CMAKE_SOURCE_DIR}
      --port 9554
      --server-bin $<TARGET_FILE:test_asio_https_server_asn1>
      --client-bin $<TARGET_FILE:test_asio_https_client>
      --server-cert ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-server-crt.pem
      --server-key ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-server-key.pem
      --server-cert-der ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-server-crt.der
      --server-key-der ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-server-key.der
      --client-ca ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-ca-crt.pem)

  add_test(NAME test_asio_https_rsa_asn1_roundtrip
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_asio_https_variant_roundtrip.py
      --source-dir ${CMAKE_SOURCE_DIR}
      --port 9555
      --server-bin $<TARGET_FILE:test_asio_https_server_rsa_asn1>
      --client-bin $<TARGET_FILE:test_asio_https_client>
      --server-cert ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-server-crt.pem
      --server-key ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-server-key.pem
      --server-cert-der ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-server-crt.der
      --server-key-der ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-server-key.der
      --client-ca ${CMAKE_SOURCE_DIR}/test/fixtures/trusted-ca-crt.pem)

  add_test(NAME test_asio_https_chain_memory_roundtrip
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_asio_https_variant_roundtrip.py
      --source-dir ${CMAKE_SOURCE_DIR}
      --port 9556
      --server-bin $<TARGET_FILE:test_asio_https_server_chain_memory>
      --client-bin $<TARGET_FILE:test_asio_https_client>
      --server-chain-pem ${CMAKE_SOURCE_DIR}/test/fixtures/chain-server-fullchain-crt.pem
      --server-cert ${CMAKE_SOURCE_DIR}/test/fixtures/chain-server-fullchain-crt.pem
      --server-key ${CMAKE_SOURCE_DIR}/test/fixtures/chain-server-key.pem
      --client-ca ${CMAKE_SOURCE_DIR}/test/fixtures/chain-root-ca-crt.pem)

  if(TARGET test_uwebsockets_https_server AND TARGET test_asio_https_client)
    add_test(NAME test_uwebsockets_https_roundtrip
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_uwebsockets_https_roundtrip.py
        --source-dir ${CMAKE_SOURCE_DIR}
        --port 9560
        --server-bin $<TARGET_FILE:test_uwebsockets_https_server>
        --client-bin $<TARGET_FILE:test_asio_https_client>)
  endif()

  set_tests_properties(
    test_asio_https_roundtrip
    test_asio_https_asn1_roundtrip
    test_asio_https_rsa_asn1_roundtrip
    test_asio_https_chain_memory_roundtrip
    PROPERTIES TIMEOUT 60)

  if(TEST test_uwebsockets_https_roundtrip)
    set_tests_properties(test_uwebsockets_https_roundtrip PROPERTIES TIMEOUT 60)
  endif()
endif()
if(NOT OPENSSL_SHIM_EFFECTIVE_BACKEND STREQUAL "SCHANNEL")
  if(CMAKE_CONFIGURATION_TYPES)
    add_test(NAME test_tls13_only
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_tls13_only_test.py
        --build-dir ${CMAKE_BINARY_DIR}
        --source-dir ${CMAKE_SOURCE_DIR}
        --client-bin $<TARGET_FILE:test_tls13_only_client>
        --cmake-generator ${CMAKE_GENERATOR}
        --cmake-generator-platform ${CMAKE_GENERATOR_PLATFORM}
        --cmake-generator-toolset ${CMAKE_GENERATOR_TOOLSET}
        --multi-config 1
        --config $<CONFIG>)
  else()
    add_test(NAME test_tls13_only
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_tls13_only_test.py
        --build-dir ${CMAKE_BINARY_DIR}
        --source-dir ${CMAKE_SOURCE_DIR}
        --client-bin $<TARGET_FILE:test_tls13_only_client>
        --cmake-generator ${CMAKE_GENERATOR}
        --cmake-generator-platform ${CMAKE_GENERATOR_PLATFORM}
        --cmake-generator-toolset ${CMAKE_GENERATOR_TOOLSET}
        --multi-config 0)
  endif()
  set_tests_properties(test_tls13_only PROPERTIES TIMEOUT 120)
endif()

add_executable(debug_schannel_init debug_schannel_init.cpp)
target_compile_definitions(debug_schannel_init PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(debug_schannel_init PRIVATE OpenSSL::SSL OpenSSL::Crypto)

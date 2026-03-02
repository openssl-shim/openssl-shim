include(FetchContent)

if(WIN32)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS=1 _CRT_NONSTDC_NO_WARNINGS=1)
endif()

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

add_executable(test_reneg_client test_reneg_client.cpp)
target_compile_definitions(test_reneg_client PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_reneg_client PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(OPENSSL_SHIM_TEST_MBEDTLS_TARGETS)
  add_executable(test_mbedtls_reneg_server test_mbedtls_reneg_server.cpp)
  target_link_libraries(test_mbedtls_reneg_server PRIVATE ${OPENSSL_SHIM_TEST_MBEDTLS_TARGETS})

  add_executable(test_mbedtls_tls13_server test_mbedtls_tls13_server.cpp)
  target_link_libraries(test_mbedtls_tls13_server PRIVATE ${OPENSSL_SHIM_TEST_MBEDTLS_TARGETS})

  add_executable(test_mbedtls_direct_reneg_client test_mbedtls_direct_reneg_client.cpp)
  target_compile_definitions(test_mbedtls_direct_reneg_client PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
  target_link_libraries(test_mbedtls_direct_reneg_client PRIVATE ${OPENSSL_SHIM_TEST_MBEDTLS_TARGETS})

  if(WIN32)
    target_link_libraries(test_mbedtls_reneg_server PRIVATE ws2_32)
    target_link_libraries(test_mbedtls_tls13_server PRIVATE ws2_32)
    target_link_libraries(test_mbedtls_direct_reneg_client PRIVATE ws2_32)
  endif()
endif()

if(EXISTS "${_asio_include_dir}/asio.hpp")
  add_library(asio_standalone INTERFACE)
  target_include_directories(asio_standalone INTERFACE "${_asio_include_dir}")
  target_compile_definitions(asio_standalone INTERFACE ASIO_STANDALONE _WIN32_WINNT=0x0601)
  target_link_libraries(asio_standalone INTERFACE OpenSSL::SSL OpenSSL::Crypto)
  if(WIN32)
    target_link_libraries(asio_standalone INTERFACE ws2_32)
  endif()

  add_executable(test_asio_https_server test_asio_https_server.cpp)
  target_link_libraries(test_asio_https_server PRIVATE asio_standalone)

  add_executable(test_asio_https_server_asn1 test_asio_https_server_asn1.cpp)
  target_link_libraries(test_asio_https_server_asn1 PRIVATE asio_standalone)

  add_executable(test_asio_https_server_rsa_asn1 test_asio_https_server_rsa_asn1.cpp)
  target_link_libraries(test_asio_https_server_rsa_asn1 PRIVATE asio_standalone)

  add_executable(test_asio_https_server_chain_memory test_asio_https_server_chain_memory.cpp)
  target_link_libraries(test_asio_https_server_chain_memory PRIVATE asio_standalone)

  add_executable(test_asio_https_client test_asio_https_client.cpp)
  target_link_libraries(test_asio_https_client PRIVATE asio_standalone)
endif()

if(EXISTS "${_uwebsockets_dir}/src/App.h" AND
   EXISTS "${_usockets_dir}/src/libusockets.h")
  set(_usockets_sources
    ${_usockets_dir}/src/bsd.c
    ${_usockets_dir}/src/context.c
    ${_usockets_dir}/src/loop.c
    ${_usockets_dir}/src/socket.c
    ${_usockets_dir}/src/udp.c
    ${_usockets_dir}/src/crypto/openssl.c
    ${_usockets_dir}/src/crypto/sni_tree.cpp)

  set(_usockets_event_backend_def)
  set(_usockets_extra_link_libs)

  if(WIN32)
    list(APPEND _usockets_sources ${_usockets_dir}/src/eventing/libuv.c)

    set(_libuv_dir "${CMAKE_SOURCE_DIR}/test/libuv")
    if(EXISTS "${_libuv_dir}/CMakeLists.txt")
      add_subdirectory("${_libuv_dir}" "${CMAKE_CURRENT_BINARY_DIR}/libuv" SYSTEM)
    else()
      FetchContent_Declare(
        libuv
        GIT_REPOSITORY https://github.com/libuv/libuv.git
        GIT_TAG v1.49.2
        GIT_SHALLOW TRUE)
      set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
      set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)
      set(LIBUV_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
      FetchContent_MakeAvailable(libuv)
    endif()

    if(TARGET uv_a)
      set(_libuv_target uv_a)
    elseif(TARGET uv)
      set(_libuv_target uv)
    elseif(TARGET libuv::uv_a)
      set(_libuv_target libuv::uv_a)
    elseif(TARGET libuv::uv)
      set(_libuv_target libuv::uv)
    else()
      message(FATAL_ERROR "Unable to resolve libuv target for test_usockets on Windows")
    endif()

    set(_usockets_event_backend_def LIBUS_USE_LIBUV)
    list(APPEND _usockets_extra_link_libs ${_libuv_target} ws2_32 iphlpapi userenv psapi)
  else()
    list(APPEND _usockets_sources ${_usockets_dir}/src/eventing/epoll_kqueue.c)
    if(APPLE)
      set(_usockets_event_backend_def LIBUS_USE_KQUEUE)
    else()
      set(_usockets_event_backend_def LIBUS_USE_EPOLL)
    endif()
  endif()

  add_library(test_usockets STATIC ${_usockets_sources})
  set_target_properties(test_usockets PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)

  if(NOT MSVC)
    set_source_files_properties(${_usockets_dir}/src/crypto/openssl.c
      PROPERTIES COMPILE_OPTIONS "-include;stdlib.h")
  endif()

  target_include_directories(test_usockets PUBLIC ${_usockets_dir}/src)
  target_link_libraries(test_usockets PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  if(_usockets_extra_link_libs)
    target_link_libraries(test_usockets PUBLIC ${_usockets_extra_link_libs})
  endif()
  target_compile_definitions(test_usockets PUBLIC LIBUS_USE_OPENSSL ${_usockets_event_backend_def})

  find_package(Threads REQUIRED)
  target_link_libraries(test_usockets PUBLIC Threads::Threads)

  add_executable(test_uwebsockets_https_server test_uwebsockets_https_server.cpp)
  target_include_directories(test_uwebsockets_https_server PRIVATE
    ${_uwebsockets_dir}/src
    ${_usockets_dir}/src)
  target_compile_definitions(test_uwebsockets_https_server PRIVATE
    UWS_NO_ZLIB
    LIBUS_USE_OPENSSL
    ${_usockets_event_backend_def})
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
if(TARGET asio_standalone)
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
if(NOT OPENSSL_SHIM_EFFECTIVE_BACKEND STREQUAL "SCHANNEL" AND
   TARGET test_mbedtls_tls13_server)
  add_test(NAME test_tls13_only
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_tls13_only_test.py
      --source-dir ${CMAKE_SOURCE_DIR}
      --server-bin $<TARGET_FILE:test_mbedtls_tls13_server>
      --client-bin $<TARGET_FILE:test_tls13_only_client>)
  set_tests_properties(test_tls13_only PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
endif()

if(TARGET test_mbedtls_reneg_server AND TARGET test_reneg_client)
  add_test(NAME test_reneg_roundtrip
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_mbedtls_reneg_roundtrip.py
      --source-dir ${CMAKE_SOURCE_DIR}
      --server-bin $<TARGET_FILE:test_mbedtls_reneg_server>
      --client-bin $<TARGET_FILE:test_reneg_client>)
  set_tests_properties(test_reneg_roundtrip PROPERTIES TIMEOUT 90)

  if(TARGET test_mbedtls_direct_reneg_client)
    add_test(NAME test_mbedtls_direct_reneg_roundtrip
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/run_mbedtls_reneg_roundtrip.py
        --source-dir ${CMAKE_SOURCE_DIR}
        --server-bin $<TARGET_FILE:test_mbedtls_reneg_server>
        --client-bin $<TARGET_FILE:test_mbedtls_direct_reneg_client>
        --port 9466)
    set_tests_properties(test_mbedtls_direct_reneg_roundtrip PROPERTIES TIMEOUT 90)
  endif()
endif()

add_executable(debug_schannel_init debug_schannel_init.cpp)
target_compile_definitions(debug_schannel_init PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(debug_schannel_init PRIVATE OpenSSL::SSL OpenSSL::Crypto)

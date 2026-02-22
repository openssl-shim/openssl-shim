cmake_minimum_required(VERSION 3.21)
project(tls13_only_server LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(NTS_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

set(NATIVE_TLS_SHIM_NATIVE_BACKEND OFF CACHE BOOL "" FORCE)
set(NATIVE_TLS_SHIM_ALWAYS_FETCH_MBEDTLS ON CACHE BOOL "" FORCE)
set(NATIVE_TLS_SHIM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(NATIVE_TLS_SHIM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(NATIVE_TLS_SHIM_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

add_subdirectory("${NTS_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/native_tls_shim" EXCLUDE_FROM_ALL)

include(FetchContent)
set(_cpp_httplib_dir "${NTS_SOURCE_DIR}/test/cpp-httplib")
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE ON CACHE BOOL "" FORCE)
set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_TEST OFF CACHE BOOL "" FORCE)
set(HTTPLIB_INSTALL OFF CACHE BOOL "" FORCE)

if(EXISTS "${_cpp_httplib_dir}/CMakeLists.txt")
  add_subdirectory("${_cpp_httplib_dir}" "${CMAKE_CURRENT_BINARY_DIR}/cpp-httplib" SYSTEM)
else()
  FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(cpp_httplib)
endif()

add_executable(tls13_only_server main.cpp)
target_compile_definitions(tls13_only_server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(tls13_only_server PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

cmake_minimum_required(VERSION 3.21)
project(native_tls_shim VERSION 0.1.0 LANGUAGES C CXX)

set(NATIVE_TLS_SHIM_OPENSSL_VERSION "3.0.0")

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
# When embedded via FetchContent/add_subdirectory, propagate the module path so
# sibling dependencies can transparently resolve find_package(OpenSSL).
if(NOT PROJECT_IS_TOP_LEVEL)
  set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" PARENT_SCOPE)
endif()

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
option(NATIVE_TLS_SHIM_NATIVE_BACKEND "Use platform-native backend (Schannel/Apple) when available; OFF forces MbedTLS" ON)
option(NATIVE_TLS_SHIM_ALWAYS_FETCH_MBEDTLS "Always fetch MbedTLS with FetchContent" OFF)
option(NATIVE_TLS_SHIM_BUILD_TESTS "Build integration tests" ${PROJECT_IS_TOP_LEVEL})
option(NATIVE_TLS_SHIM_BUILD_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(NATIVE_TLS_SHIM_ENABLE_INSTALL "Enable install/export rules" ${PROJECT_IS_TOP_LEVEL})

if(NATIVE_TLS_SHIM_NATIVE_BACKEND)
  if(WIN32)
    set(_backend "SCHANNEL")
  elseif(APPLE)
    set(_backend "APPLE")
  else()
    set(_backend "MBEDTLS")
  endif()
else()
  set(_backend "MBEDTLS")
endif()

set(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND "${_backend}")


add_library(native_tls_shim
  src/tls_common.cpp
  src/tls_common.hpp
  src/tls_shared_exports.inl
)

if(WIN32 AND BUILD_SHARED_LIBS)
  set_target_properties(native_tls_shim PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

add_library(native_tls_shim::native_tls_shim ALIAS native_tls_shim)

target_include_directories(native_tls_shim
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_definitions(native_tls_shim
  PUBLIC
    OPENSSL_VERSION_NUMBER=0x30000000L
)

# Windows requires ws2_32 for tls_common.cpp
if(WIN32)
  target_link_libraries(native_tls_shim PRIVATE ws2_32)
endif()

if(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND STREQUAL "MBEDTLS")
  message(STATUS "MbedTLS backend selected")

  set(_mbedtls_use_fetch ${NATIVE_TLS_SHIM_ALWAYS_FETCH_MBEDTLS})
  if(NOT _mbedtls_use_fetch)
    # Prefer an already-installed MbedTLS 3.x when available.
    find_package(MbedTLS 3...<4 QUIET)
    if(NOT (TARGET mbedtls AND TARGET mbedx509 AND TARGET mbedcrypto) AND
       NOT (TARGET MbedTLS::mbedtls AND TARGET MbedTLS::mbedx509 AND TARGET MbedTLS::mbedcrypto))
      set(_mbedtls_use_fetch ON)
    endif()
  endif()

  if(_mbedtls_use_fetch)
    include(FetchContent)
    FetchContent_Declare(
      mbedtls
      GIT_REPOSITORY https://github.com/mrexodia/mbedtls.git
      GIT_TAG cmake-fixes-3.6
      GIT_SHALLOW TRUE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
    # Ensure vendored mbedTLS exports and installs a proper CMake package.
    set(DISABLE_PACKAGE_CONFIG_AND_INSTALL OFF CACHE BOOL "" FORCE)
    # mrexodia/mbedtls cmake-fixes-3.6 uses generated sources on Windows.
    set(GEN_FILES ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(mbedtls)
  endif()

  if(TARGET mbedtls AND TARGET mbedx509 AND TARGET mbedcrypto)
    set(_mbedtls_targets mbedtls mbedx509 mbedcrypto)
  elseif(TARGET MbedTLS::mbedtls AND TARGET MbedTLS::mbedx509 AND TARGET MbedTLS::mbedcrypto)
    set(_mbedtls_targets MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
  else()
    message(FATAL_ERROR "Unable to resolve MbedTLS targets")
  endif()

  target_sources(native_tls_shim PRIVATE src/tls_mbedtls.cpp)
  target_link_libraries(native_tls_shim PRIVATE
    $<BUILD_INTERFACE:${_mbedtls_targets}>
    $<INSTALL_INTERFACE:MbedTLS::mbedtls;MbedTLS::mbedx509;MbedTLS::mbedcrypto>)
  target_compile_definitions(native_tls_shim PUBLIC NATIVE_TLS_SHIM_BACKEND_MBEDTLS)

elseif(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND STREQUAL "SCHANNEL")
  message(STATUS "Schannel backend selected")
  target_sources(native_tls_shim PRIVATE src/tls_schannel.cpp)
  target_compile_definitions(native_tls_shim PUBLIC NATIVE_TLS_SHIM_BACKEND_SCHANNEL)
  if(WIN32)
    target_link_libraries(native_tls_shim PRIVATE secur32 ncrypt crypt32 bcrypt)
  endif()

elseif(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND STREQUAL "APPLE")
  message(STATUS "Apple backend selected")
  target_sources(native_tls_shim PRIVATE src/tls_apple.cpp)
  target_compile_definitions(native_tls_shim PUBLIC NATIVE_TLS_SHIM_BACKEND_APPLE)
  target_link_libraries(native_tls_shim PRIVATE
    "$<LINK_LIBRARY:FRAMEWORK,Security>"
    "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")

else()
  message(FATAL_ERROR "Unsupported backend: ${NATIVE_TLS_SHIM_EFFECTIVE_BACKEND}")
endif()

add_library(openssl_ssl INTERFACE)
add_library(openssl_crypto INTERFACE)

target_link_libraries(openssl_ssl INTERFACE native_tls_shim)
target_link_libraries(openssl_crypto INTERFACE native_tls_shim)

set_target_properties(openssl_ssl PROPERTIES EXPORT_NAME SSL)
set_target_properties(openssl_crypto PROPERTIES EXPORT_NAME Crypto)

if(NOT TARGET OpenSSL::SSL)
  add_library(OpenSSL::SSL ALIAS openssl_ssl)
endif()
if(NOT TARGET OpenSSL::Crypto)
  add_library(OpenSSL::Crypto ALIAS openssl_crypto)
endif()

if(NATIVE_TLS_SHIM_BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

if(NATIVE_TLS_SHIM_BUILD_EXAMPLES)
  add_subdirectory(example)
endif()

if(NATIVE_TLS_SHIM_ENABLE_INSTALL)
  include(CMakePackageConfigHelpers)

  install(TARGETS native_tls_shim openssl_ssl openssl_crypto
    EXPORT NativeTLSShimTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

  install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(EXPORT NativeTLSShimTargets
    FILE NativeTLSShimTargets.cmake
    NAMESPACE OpenSSL::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenSSL)

  configure_package_config_file(
    cmake/OpenSSLConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSLConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenSSL)

  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSLConfigVersion.cmake
    VERSION ${NATIVE_TLS_SHIM_OPENSSL_VERSION}
    COMPATIBILITY AnyNewerVersion)

  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSLConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSLConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenSSL)

endif()

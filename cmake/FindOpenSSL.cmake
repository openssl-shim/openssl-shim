# native-tls-shim OpenSSL override module

set(_native_tls_shim_openssl_version "3.0.0")

function(_native_tls_shim_openssl_version_matches out_var)
  set(_ok TRUE)

  # native-tls-shim intentionally exposes OpenSSL 3.x semantics only.
  if(DEFINED OpenSSL_FIND_VERSION_MAJOR AND OpenSSL_FIND_VERSION_MAJOR LESS 3)
    set(_ok FALSE)
  elseif(DEFINED OpenSSL_FIND_VERSION)
    if(OpenSSL_FIND_VERSION_EXACT)
      if(NOT _native_tls_shim_openssl_version VERSION_EQUAL OpenSSL_FIND_VERSION)
        set(_ok FALSE)
      endif()
    elseif(_native_tls_shim_openssl_version VERSION_LESS OpenSSL_FIND_VERSION)
      set(_ok FALSE)
    endif()
  endif()

  set(${out_var} ${_ok} PARENT_SCOPE)
endfunction()

_native_tls_shim_openssl_version_matches(_native_tls_shim_version_ok)
if(NOT _native_tls_shim_version_ok)
  if(OpenSSL_FIND_REQUIRED)
    message(FATAL_ERROR
      "native-tls-shim provides OpenSSL ${_native_tls_shim_openssl_version}; "
      "requested OpenSSL version '${OpenSSL_FIND_VERSION}' is incompatible")
  endif()
  set(OPENSSL_FOUND FALSE)
  set(OpenSSL_FOUND FALSE)
  return()
endif()

if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
  set(OPENSSL_FOUND TRUE)
  set(OpenSSL_FOUND TRUE)
  set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/../include")
  set(OPENSSL_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
  set(OPENSSL_VERSION "${_native_tls_shim_openssl_version}")
  set(OpenSSL_VERSION "${_native_tls_shim_openssl_version}")
  return()
endif()

# Fallback to config mode for installed package usage.
find_package(OpenSSL CONFIG QUIET)
if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
  set(OPENSSL_FOUND TRUE)
  set(OpenSSL_FOUND TRUE)
  set(OPENSSL_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
  set(OPENSSL_VERSION "${_native_tls_shim_openssl_version}")
  set(OpenSSL_VERSION "${_native_tls_shim_openssl_version}")
endif()

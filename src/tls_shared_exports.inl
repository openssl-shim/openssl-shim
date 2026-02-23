BIO* BIO_new_socket(int sock, int close_flag) {
  auto* bio = new BIO();
  bio->kind = BioKind::Socket;
  bio->fd = sock;
  bio->close_on_free = close_flag != BIO_NOCLOSE;
  return bio;
}

void BIO_set_nbio(BIO* bio, long on) {
  if (!bio || bio->kind != BioKind::Socket || bio->fd < 0) return;
  set_fd_nonblocking(bio->fd, on != 0);
}

BIO* BIO_new_mem_buf(const void* buf, int len) {
  auto* bio = new BIO();
  bio->kind = BioKind::Memory;
  if (buf) {
    if (len < 0) {
      auto* c = static_cast<const char*>(buf);
      len = static_cast<int>(std::strlen(c));
    }
    bio->data.assign(static_cast<const unsigned char*>(buf),
                     static_cast<const unsigned char*>(buf) + len);
  }
  return bio;
}

BIO* BIO_new(const BIO_METHOD* method) {
  if (!method || method != &g_mem_method) return nullptr;
  return BIO_new_mem_buf(nullptr, 0);
}

BIO* BIO_new_file(const char* filename, const char* mode) {
  if (!filename || !mode || std::strchr(mode, 'r') == nullptr) return nullptr;
  auto bytes = openssl_shim::read_file_text(filename);
  if (bytes.empty()) return nullptr;
  return BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size()));
}

const BIO_METHOD* BIO_s_mem(void) { return &g_mem_method; }

void BIO_free_all(BIO* a) { (void)BIO_free(a); }

EVP_MD_CTX* EVP_MD_CTX_new(void) { return new EVP_MD_CTX(); }

void EVP_MD_CTX_free(EVP_MD_CTX* ctx) { delete ctx; }

const EVP_MD* EVP_md5(void) { return &g_md5; }

const EVP_MD* EVP_sha256(void) { return &g_sha256; }

const EVP_MD* EVP_sha512(void) { return &g_sha512; }

X509* d2i_X509(X509** px, const unsigned char** in, int len) {
  if (!in || !*in || len <= 0) return nullptr;
  auto* out = x509_from_der(*in, static_cast<size_t>(len));
  if (!out) return nullptr;
  *in += len;
  if (px) *px = out;
  return out;
}

void X509_free(X509* cert) {
  if (!cert) return;
  cert->refs--;
  if (cert->refs <= 0) {
    delete cert;
  }
}

int X509_up_ref(X509* cert) {
  if (!cert) return 0;
  cert->refs++;
  return 1;
}

X509_NAME* X509_get_subject_name(const X509* x) {
  if (!x) return nullptr;
  return const_cast<X509_NAME*>(&x->subject_name);
}

X509_NAME* X509_get_issuer_name(const X509* x) {
  if (!x) return nullptr;
  return const_cast<X509_NAME*>(&x->issuer_name);
}

ASN1_INTEGER* X509_get_serialNumber(X509* x) {
  if (!x) return nullptr;
  return &x->serial;
}

const ASN1_TIME* X509_get0_notBefore(const X509* x) {
  if (!x) return nullptr;
  return &x->not_before;
}

const ASN1_TIME* X509_get0_notAfter(const X509* x) {
  if (!x) return nullptr;
  return &x->not_after;
}

int X509_check_host(X509* x, const char* chk, size_t chklen,
                    unsigned int /*flags*/, char** peername) {
  if (!x || !chk) return 0;
  std::string host = chklen ? std::string(chk, chklen) : std::string(chk);
  bool ok = cert_matches_hostname(x, host, false);
  if (ok && peername) {
    auto* out = static_cast<char*>(OPENSSL_malloc(host.size() + 1));
    if (out) {
      std::memcpy(out, host.data(), host.size());
      out[host.size()] = '\0';
      *peername = out;
    }
  }
  return ok ? 1 : 0;
}

int X509_check_ip_asc(X509* x, const char* ipasc, unsigned int /*flags*/) {
  if (!x || !ipasc) return 0;
  return cert_matches_hostname(x, ipasc, true) ? 1 : 0;
}

X509_STORE* X509_STORE_new(void) { return new X509_STORE(); }

void X509_STORE_free(X509_STORE* store) { delete store; }

int X509_STORE_add_cert(X509_STORE* store, X509* cert) {
  return add_cert_to_store(store, cert, true) ? 1 : 0;
}

int X509_STORE_add_crl(X509_STORE* /*store*/, X509_CRL* /*crl*/) { return 1; }

void X509_STORE_set_flags(X509_STORE* store, unsigned long flags) {
  if (store) store->flags |= flags;
}

STACK_OF_X509_OBJECT* X509_STORE_get0_objects(const X509_STORE* store) {
  if (!store) return nullptr;
  auto* s = const_cast<X509_STORE*>(store);
  s->object_cache.items.clear();
  s->object_cache.items.reserve(s->certs.size());
  for (auto* cert : s->certs) {
    s->object_cache.items.push_back({X509_LU_X509, cert});
  }
  return &s->object_cache;
}

void SSL_CTX_free(SSL_CTX* ctx) {
  if (!ctx) return;
  openssl_shim::clear_ssl_ctx_app_data(ctx);
  delete ctx;
}

void SSL_CTX_set_verify_depth(SSL_CTX* ctx, int depth) {
  if (ctx) ctx->verify_depth = depth;
}

long SSL_CTX_set_mode(SSL_CTX* ctx, long mode) {
  if (!ctx) return 0;
  ctx->mode |= mode;
  return ctx->mode;
}

long SSL_CTX_clear_mode(SSL_CTX* ctx, long mode) {
  if (!ctx) return 0;
  ctx->mode &= ~mode;
  return ctx->mode;
}

long SSL_CTX_set_options(SSL_CTX* ctx, long options) {
  if (!ctx) return 0;
  ctx->options |= options;
  return ctx->options;
}

int SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, int mode) {
  if (!ctx) return 0;
  ctx->session_cache_mode = mode;
  return mode;
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX* ctx, void* u) {
  if (ctx) ctx->passwd_userdata = u;
}

X509_STORE* SSL_CTX_get_cert_store(const SSL_CTX* ctx) {
  return ctx ? ctx->cert_store : nullptr;
}

void SSL_CTX_set_client_CA_list(SSL_CTX* ctx, STACK_OF_X509_NAME* list) {
  if (!ctx) return;
  if (ctx->client_ca_list) sk_X509_NAME_pop_free(ctx->client_ca_list, X509_NAME_free);
  ctx->client_ca_list = list;
}

void SSL_free(SSL* ssl) {
  if (!ssl) return;
  openssl_shim::clear_ssl_app_data(ssl);
  delete ssl;
}

BIO* SSL_get_rbio(const SSL* ssl) { return ssl ? ssl->rbio : nullptr; }

long SSL_ctrl(SSL* ssl, int cmd, long larg, void* parg) {
  if (!ssl) return 0;
  if (cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME && larg == TLSEXT_NAMETYPE_host_name) {
    return SSL_set_tlsext_host_name(ssl, static_cast<const char*>(parg));
  }
  return 0;
}

int SSL_get_error(const SSL* ssl, int /*ret*/) {
  if (!ssl) return SSL_ERROR_SSL;
  return ssl->last_error;
}

X509* SSL_get1_peer_certificate(const SSL* ssl) { return SSL_get_peer_certificate(ssl); }

X509_VERIFY_PARAM* SSL_get0_param(SSL* ssl) {
  if (!ssl) return nullptr;
  return &ssl->param;
}

void SSL_get0_alpn_selected(const SSL* ssl, const unsigned char** data, unsigned int* len) {
  if (data) *data = nullptr;
  if (len) *len = 0;
  if (!ssl || ssl->selected_alpn.empty()) return;
  if (data) *data = reinterpret_cast<const unsigned char*>(ssl->selected_alpn.data());
  if (len) *len = static_cast<unsigned int>(ssl->selected_alpn.size());
}

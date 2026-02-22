#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;

#define BIO_NOCLOSE 0

BIO* BIO_new_socket(int sock, int close_flag);
void BIO_set_nbio(BIO* bio, long on);

BIO* BIO_new_mem_buf(const void* buf, int len);
BIO* BIO_new(const BIO_METHOD* method);
BIO* BIO_new_file(const char* filename, const char* mode);
int  BIO_new_bio_pair(BIO** bio1, size_t writebuf1, BIO** bio2, size_t writebuf2);
const BIO_METHOD* BIO_s_mem(void);

int    BIO_read(BIO* bio, void* data, int len);
int    BIO_write(BIO* bio, const void* data, int len);
size_t BIO_ctrl_pending(BIO* bio);
size_t BIO_wpending(BIO* bio);
long   BIO_get_mem_data(BIO* bio, char** pp);

int  BIO_free(BIO* a);
void BIO_free_all(BIO* a);

#ifdef __cplusplus
}
#endif

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;

#define BIO_NOCLOSE 0

#define BIO_TYPE_MEM 1

#define BIO_CTRL_FLUSH 11

#define BIO_FLAGS_READ 0x01
#define BIO_FLAGS_WRITE 0x02
#define BIO_FLAGS_SHOULD_RETRY 0x08

BIO* BIO_new_socket(int sock, int close_flag);
void BIO_set_nbio(BIO* bio, long on);

BIO* BIO_new_mem_buf(const void* buf, int len);
BIO* BIO_new(const BIO_METHOD* method);
BIO* BIO_new_file(const char* filename, const char* mode);
int  BIO_new_bio_pair(BIO** bio1, size_t writebuf1, BIO** bio2, size_t writebuf2);
const BIO_METHOD* BIO_s_mem(void);

BIO_METHOD* BIO_meth_new(int type, const char* name);
void        BIO_meth_free(BIO_METHOD* biom);
int         BIO_meth_set_create(BIO_METHOD* biom, int (*create)(BIO*));
int         BIO_meth_set_write(BIO_METHOD* biom, int (*write)(BIO*, const char*, int));
int         BIO_meth_set_read(BIO_METHOD* biom, int (*read)(BIO*, char*, int));
int         BIO_meth_set_ctrl(BIO_METHOD* biom, long (*ctrl)(BIO*, int, long, void*));

void  BIO_set_data(BIO* bio, void* data);
void* BIO_get_data(BIO* bio);
void  BIO_set_init(BIO* bio, int init);
int   BIO_get_init(BIO* bio);
void  BIO_set_flags(BIO* bio, int flags);
int   BIO_up_ref(BIO* bio);

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

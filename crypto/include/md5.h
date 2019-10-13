#ifndef __MD5_H__
#define __MD5_H__

#include <stdint.h>

#define MD5_CBLOCK      (64)
#define MD5_LBLOCK      (MD5_CBLOCK/4)
#define MD5_DIGEST_LENGTH  (16)

typedef struct MD5_st {
    uint32_t A, B, C, D;
    uint32_t Nl, Nh;
    uint32_t data[MD5_LBLOCK];
    uint32_t num;
} MD5_CTX;

int MD5_Init(MD5_CTX *c);
int MD5_Update(MD5_CTX *c, const void *_data, uint32_t len);
int MD5_Final(unsigned char *md, MD5_CTX *c);
unsigned char *MD5(const unsigned char *d, uint32_t n, unsigned char *md);


#endif // __MD5_H__

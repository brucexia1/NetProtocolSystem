#ifndef __SHA_H__
#define __SHA_H__

#include <stdint.h>

#ifndef NULL
#define NULL 0
#endif

#define U64(C)  C##ULL

#define SHA_LBLOCK      (16)
#define SHA_CBLOCK      (SHA_LBLOCK*4)/* SHA treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
#define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
#define SHA_DIGEST_LENGTH (20)

typedef struct SHA_st {
    uint32_t h0, h1, h2, h3, h4;
    uint32_t Nl, Nh;
    uint32_t data[SHA_LBLOCK];
    uint32_t num;
} SHA_CTX;

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *_data, uint32_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, uint32_t n, unsigned char *md);



#define SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
typedef struct SHA256state_st {
    uint32_t h[8];
    uint32_t Nl, Nh;
    uint32_t data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, uint32_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, uint32_t n, unsigned char *md);
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, uint32_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, uint32_t n, unsigned char *md);

# define SHA224_DIGEST_LENGTH    28
# define SHA256_DIGEST_LENGTH    32
# define SHA384_DIGEST_LENGTH    48
# define SHA512_DIGEST_LENGTH    64



/*
 * SHA-512 treats input data as a
 * contiguous array of 64 bit
 * wide big-endian values.
 */
# define SHA512_CBLOCK   (SHA_LBLOCK*8)
typedef struct SHA512state_st {
    uint64_t h[8];
    uint64_t Nl, Nh;
    union {
        uint64_t d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, uint32_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, uint32_t n, unsigned char *md);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, uint32_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA512(const unsigned char *d, uint32_t n, unsigned char *md);

#endif // __SHA_H__

#ifndef __AES_H__
#define __AES_H__


struct aes_key_st {
# ifdef AES_LONG
   unsigned long rd_key[4 * 15];
# else
   unsigned int rd_key[4 * 15];
# endif
   int rounds;
};
typedef struct aes_key_st AES_KEY;



void aes_cbc(const unsigned char *in, unsigned char *out,
         size_t len, const unsigned char *key, int keylen,
         unsigned char *ivec, const int enc);

#endif // __AES_H__

#include <memory.h>

#include "sha.h"

/*
 * Implemented from RFC3174 The SHA1 Message-Digest Algorithm
 */

#define DATA_ORDER_IS_BIG_ENDIAN   //sha1 and sha2 use BIG_ENDIAN

#include "internal/md32_common.h"

#define INIT_DATA_h0 0x67452301UL
#define INIT_DATA_h1 0xefcdab89UL
#define INIT_DATA_h2 0x98badcfeUL
#define INIT_DATA_h3 0x10325476UL
#define INIT_DATA_h4 0xc3d2e1f0UL

int SHA1_Init(SHA_CTX *c)
{
    memset(c, 0, sizeof(*c));
    c->h0 = INIT_DATA_h0;
    c->h1 = INIT_DATA_h1;
    c->h2 = INIT_DATA_h2;
    c->h3 = INIT_DATA_h3;
    c->h4 = INIT_DATA_h4;

    return 1;
}


#define K_00_19 0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

/*
 * As pointed out by Wei Dai, F() below can be simplified to the code in
 * F_00_19.  Wei attributes these optimizations to Peter Gutmann's SHS code,
 * and he attributes it to Rich Schroeppel.
 *      #define F(x,y,z) (((x) & (y)) | ((~(x)) & (z)))
 * I've just become aware of another tweak to be made, again from Wei Dai,
 * in F_40_59, (x&a)|(y&a) -> (x|y)&a
 */
#define F_00_19(b,c,d)  ((((c) ^ (d)) & (b)) ^ (d))
#define F_20_39(b,c,d)  ((b) ^ (c) ^ (d))
#define F_40_59(b,c,d)  (((b) & (c)) | (((b)|(c)) & (d)))
#define F_60_79(b,c,d)  F_20_39(b,c,d)

#define Xupdate(a,ix,ia,ib,ic,id)       ( (a)=(ia^ib^ic^id),    \
                                          ix=(a)=ROTATE((a),1)  \
                                        )

#define BODY_00_15(i,a,b,c,d,e,f,xi) \
        (f)=xi+(e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d)); \
        (b)=ROTATE((b),30);

#define BODY_16_19(i,a,b,c,d,e,f,xi,xa,xb,xc,xd) \
        Xupdate(f,xi,xa,xb,xc,xd); \
        (f)+=(e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d)); \
        (b)=ROTATE((b),30);

#define BODY_20_31(i,a,b,c,d,e,f,xi,xa,xb,xc,xd) \
        Xupdate(f,xi,xa,xb,xc,xd); \
        (f)+=(e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d)); \
        (b)=ROTATE((b),30);

#define BODY_32_39(i,a,b,c,d,e,f,xa,xb,xc,xd) \
        Xupdate(f,xa,xa,xb,xc,xd); \
        (f)+=(e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d)); \
        (b)=ROTATE((b),30);

#define BODY_40_59(i,a,b,c,d,e,f,xa,xb,xc,xd) \
        Xupdate(f,xa,xa,xb,xc,xd); \
        (f)+=(e)+K_40_59+ROTATE((a),5)+F_40_59((b),(c),(d)); \
        (b)=ROTATE((b),30);

#define BODY_60_79(i,a,b,c,d,e,f,xa,xb,xc,xd) \
        Xupdate(f,xa,xa,xb,xc,xd); \
        (f)=xa+(e)+K_60_79+ROTATE((a),5)+F_60_79((b),(c),(d)); \
        (b)=ROTATE((b),30);

static inline void
SHA1_Transform(SHA_CTX *c, const unsigned char *p, uint32_t num)
{
    const unsigned char *data = p;
    register uint32_t A, B, C, D, E, T, l;
    uint32_t XX[16];
    #define X(i)   XX[i]

    A = c->h0;
    B = c->h1;
    C = c->h2;
    D = c->h3;
    E = c->h4;

    for(;num--;) {
        (void)HOST_c2l(data, l);
        X(0) = l;
        (void)HOST_c2l(data, l);
        X(1) = l;
        BODY_00_15(0, A, B, C, D, E, T, X(0));
        (void)HOST_c2l(data, l);
        X(2) = l;
        BODY_00_15(1, T, A, B, C, D, E, X(1));
        (void)HOST_c2l(data, l);
        X(3) = l;
        BODY_00_15(2, E, T, A, B, C, D, X(2));
        (void)HOST_c2l(data, l);
        X(4) = l;
        BODY_00_15(3, D, E, T, A, B, C, X(3));
        (void)HOST_c2l(data, l);
        X(5) = l;
        BODY_00_15(4, C, D, E, T, A, B, X(4));
        (void)HOST_c2l(data, l);
        X(6) = l;
        BODY_00_15(5, B, C, D, E, T, A, X(5));
        (void)HOST_c2l(data, l);
        X(7) = l;
        BODY_00_15(6, A, B, C, D, E, T, X(6));
        (void)HOST_c2l(data, l);
        X(8) = l;
        BODY_00_15(7, T, A, B, C, D, E, X(7));
        (void)HOST_c2l(data, l);
        X(9) = l;
        BODY_00_15(8, E, T, A, B, C, D, X(8));
        (void)HOST_c2l(data, l);
        X(10) = l;
        BODY_00_15(9, D, E, T, A, B, C, X(9));
        (void)HOST_c2l(data, l);
        X(11) = l;
        BODY_00_15(10, C, D, E, T, A, B, X(10));
        (void)HOST_c2l(data, l);
        X(12) = l;
        BODY_00_15(11, B, C, D, E, T, A, X(11));
        (void)HOST_c2l(data, l);
        X(13) = l;
        BODY_00_15(12, A, B, C, D, E, T, X(12));
        (void)HOST_c2l(data, l);
        X(14) = l;
        BODY_00_15(13, T, A, B, C, D, E, X(13));
        (void)HOST_c2l(data, l);
        X(15) = l;
        BODY_00_15(14, E, T, A, B, C, D, X(14));
        BODY_00_15(15, D, E, T, A, B, C, X(15));

        BODY_16_19(16, C, D, E, T, A, B, X(0), X(0), X(2), X(8), X(13));
        BODY_16_19(17, B, C, D, E, T, A, X(1), X(1), X(3), X(9), X(14));
        BODY_16_19(18, A, B, C, D, E, T, X(2), X(2), X(4), X(10), X(15));
        BODY_16_19(19, T, A, B, C, D, E, X(3), X(3), X(5), X(11), X(0));

        BODY_20_31(20, E, T, A, B, C, D, X(4), X(4), X(6), X(12), X(1));
        BODY_20_31(21, D, E, T, A, B, C, X(5), X(5), X(7), X(13), X(2));
        BODY_20_31(22, C, D, E, T, A, B, X(6), X(6), X(8), X(14), X(3));
        BODY_20_31(23, B, C, D, E, T, A, X(7), X(7), X(9), X(15), X(4));
        BODY_20_31(24, A, B, C, D, E, T, X(8), X(8), X(10), X(0), X(5));
        BODY_20_31(25, T, A, B, C, D, E, X(9), X(9), X(11), X(1), X(6));
        BODY_20_31(26, E, T, A, B, C, D, X(10), X(10), X(12), X(2), X(7));
        BODY_20_31(27, D, E, T, A, B, C, X(11), X(11), X(13), X(3), X(8));
        BODY_20_31(28, C, D, E, T, A, B, X(12), X(12), X(14), X(4), X(9));
        BODY_20_31(29, B, C, D, E, T, A, X(13), X(13), X(15), X(5), X(10));
        BODY_20_31(30, A, B, C, D, E, T, X(14), X(14), X(0), X(6), X(11));
        BODY_20_31(31, T, A, B, C, D, E, X(15), X(15), X(1), X(7), X(12));

        BODY_32_39(32, E, T, A, B, C, D, X(0), X(2), X(8), X(13));
        BODY_32_39(33, D, E, T, A, B, C, X(1), X(3), X(9), X(14));
        BODY_32_39(34, C, D, E, T, A, B, X(2), X(4), X(10), X(15));
        BODY_32_39(35, B, C, D, E, T, A, X(3), X(5), X(11), X(0));
        BODY_32_39(36, A, B, C, D, E, T, X(4), X(6), X(12), X(1));
        BODY_32_39(37, T, A, B, C, D, E, X(5), X(7), X(13), X(2));
        BODY_32_39(38, E, T, A, B, C, D, X(6), X(8), X(14), X(3));
        BODY_32_39(39, D, E, T, A, B, C, X(7), X(9), X(15), X(4));

        BODY_40_59(40, C, D, E, T, A, B, X(8), X(10), X(0), X(5));
        BODY_40_59(41, B, C, D, E, T, A, X(9), X(11), X(1), X(6));
        BODY_40_59(42, A, B, C, D, E, T, X(10), X(12), X(2), X(7));
        BODY_40_59(43, T, A, B, C, D, E, X(11), X(13), X(3), X(8));
        BODY_40_59(44, E, T, A, B, C, D, X(12), X(14), X(4), X(9));
        BODY_40_59(45, D, E, T, A, B, C, X(13), X(15), X(5), X(10));
        BODY_40_59(46, C, D, E, T, A, B, X(14), X(0), X(6), X(11));
        BODY_40_59(47, B, C, D, E, T, A, X(15), X(1), X(7), X(12));
        BODY_40_59(48, A, B, C, D, E, T, X(0), X(2), X(8), X(13));
        BODY_40_59(49, T, A, B, C, D, E, X(1), X(3), X(9), X(14));
        BODY_40_59(50, E, T, A, B, C, D, X(2), X(4), X(10), X(15));
        BODY_40_59(51, D, E, T, A, B, C, X(3), X(5), X(11), X(0));
        BODY_40_59(52, C, D, E, T, A, B, X(4), X(6), X(12), X(1));
        BODY_40_59(53, B, C, D, E, T, A, X(5), X(7), X(13), X(2));
        BODY_40_59(54, A, B, C, D, E, T, X(6), X(8), X(14), X(3));
        BODY_40_59(55, T, A, B, C, D, E, X(7), X(9), X(15), X(4));
        BODY_40_59(56, E, T, A, B, C, D, X(8), X(10), X(0), X(5));
        BODY_40_59(57, D, E, T, A, B, C, X(9), X(11), X(1), X(6));
        BODY_40_59(58, C, D, E, T, A, B, X(10), X(12), X(2), X(7));
        BODY_40_59(59, B, C, D, E, T, A, X(11), X(13), X(3), X(8));

        BODY_60_79(60, A, B, C, D, E, T, X(12), X(14), X(4), X(9));
        BODY_60_79(61, T, A, B, C, D, E, X(13), X(15), X(5), X(10));
        BODY_60_79(62, E, T, A, B, C, D, X(14), X(0), X(6), X(11));
        BODY_60_79(63, D, E, T, A, B, C, X(15), X(1), X(7), X(12));
        BODY_60_79(64, C, D, E, T, A, B, X(0), X(2), X(8), X(13));
        BODY_60_79(65, B, C, D, E, T, A, X(1), X(3), X(9), X(14));
        BODY_60_79(66, A, B, C, D, E, T, X(2), X(4), X(10), X(15));
        BODY_60_79(67, T, A, B, C, D, E, X(3), X(5), X(11), X(0));
        BODY_60_79(68, E, T, A, B, C, D, X(4), X(6), X(12), X(1));
        BODY_60_79(69, D, E, T, A, B, C, X(5), X(7), X(13), X(2));
        BODY_60_79(70, C, D, E, T, A, B, X(6), X(8), X(14), X(3));
        BODY_60_79(71, B, C, D, E, T, A, X(7), X(9), X(15), X(4));
        BODY_60_79(72, A, B, C, D, E, T, X(8), X(10), X(0), X(5));
        BODY_60_79(73, T, A, B, C, D, E, X(9), X(11), X(1), X(6));
        BODY_60_79(74, E, T, A, B, C, D, X(10), X(12), X(2), X(7));
        BODY_60_79(75, D, E, T, A, B, C, X(11), X(13), X(3), X(8));
        BODY_60_79(76, C, D, E, T, A, B, X(12), X(14), X(4), X(9));
        BODY_60_79(77, B, C, D, E, T, A, X(13), X(15), X(5), X(10));
        BODY_60_79(78, A, B, C, D, E, T, X(14), X(0), X(6), X(11));
        BODY_60_79(79, T, A, B, C, D, E, X(15), X(1), X(7), X(12));

        c->h0 += E;
        c->h1 += T;
        c->h2 += A;
        c->h3 += B;
        c->h4 += C;

        A = c->h0;
        B = c->h1;
        C = c->h2;
        D = c->h3;
        E = c->h4;
    }
}

int SHA1_Update(SHA_CTX *c, const void *_data, uint32_t len)
{
    const unsigned char *data = _data;
    unsigned char *p;
    uint32_t l;
    uint32_t n;

    if (len == 0)
        return 1;

    l = (c->Nl + (((uint32_t) len) << 3)) & 0xffffffffUL;
    if (l < c->Nl)              /* overflow */
        c->Nh++;
    c->Nh += (uint32_t) (len >> 29); /* might cause compiler warning on
                                       * 16-bit */
    c->Nl = l;

    n = c->num;
    if (n != 0) {
        p = (unsigned char *)c->data;

        if (len >= SHA_CBLOCK || len + n >= SHA_CBLOCK) {
            memcpy(p + n, data, SHA_CBLOCK - n);
            SHA1_Transform(c, p, 1);
            n = SHA_CBLOCK - n;
            data += n;
            len -= n;
            c->num = 0;
            memset(p, 0, SHA_CBLOCK); /* keep it zeroed */
        } else {
            memcpy(p + n, data, len);
            c->num += (unsigned int)len;
            return 1;
        }
    }

    n = len / SHA_CBLOCK;
    if (n > 0) {
        SHA1_Transform(c, data, n);
        n *= SHA_CBLOCK;
        data += n;
        len -= n;
    }

    if (len != 0) {
        p = (unsigned char *)c->data;
        c->num = (unsigned int)len;
        memcpy(p, data, len);
    }
    return 1;
}

int SHA1_Final(unsigned char *md, SHA_CTX *c)
{
    unsigned char *p = (unsigned char *)c->data;
    size_t n = c->num;

    p[n] = 0x80;                /* there is always room for one */
    n++;

    if (n > (SHA_CBLOCK - 8)) {
        memset(p + n, 0, SHA_CBLOCK - n);
        n = 0;
        SHA1_Transform(c, p, 1);
    }
    memset(p + n, 0, SHA_CBLOCK - 8 - n);

    p += SHA_CBLOCK - 8;
#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
    (void)HOST_l2c(c->Nh, p);
    (void)HOST_l2c(c->Nl, p);
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
    (void)HOST_l2c(c->Nl, p);
    (void)HOST_l2c(c->Nh, p);
#endif

    p -= SHA_CBLOCK;
    SHA1_Transform(c, p, 1);
    c->num = 0;

    HOST_l2c(c->h0, md);
    HOST_l2c(c->h1, md);
    HOST_l2c(c->h2, md);
    HOST_l2c(c->h3, md);
    HOST_l2c(c->h4, md);
    return 1;
}

unsigned char * SHA1(const unsigned char *d, uint32_t n, unsigned char *md)
{
    SHA_CTX c;
    static unsigned char m[SHA_DIGEST_LENGTH];

    if (md == NULL)
        md = m; //not thread safety in this case

    SHA1_Init(&c);
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);

    return md;
}


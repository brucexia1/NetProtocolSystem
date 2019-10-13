#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"
#include "sha.h"

static inline void
Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )
{
    int  i;
    char szTmp[512] = {0};

    for( i = 0; i < nSrcLen; i++ )
    {
        sprintf( szTmp + i*2, "%02X", (unsigned char) sSrc[i] );
    }
    memcpy(sDest, szTmp, (i+1)*2);
}

struct hash_test{
    char* data;
    char* digest;
};

#define TEST2_2a \
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
#define TEST2_2b \
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
#define TEST2_2  TEST2_2a TEST2_2b

struct hash_test rfc1321_md5[7] =
{
    {
        "","D41D8CD98F00B204E9800998ECF8427E"
    },
    {
        "a","0CC175B9C0F1B6A831C399E269772661"
    },
    {
        "abc","900150983CD24FB0D6963F7D28E17F72"
    },
    {
        "message digest",
        "F96B697D7CB7938D525A2F31AAF161D0"
    },
    {
        "abcdefghijklmnopqrstuvwxyz",
        "C3FCD3D76192E4007DFB496CCA67E13B"
    },
    {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "D174AB98D277D9F5A5611C2C9F419D9F"
    },
    {
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "57EDF4A22BE3C955AC49DA2E2107B67A"
    }
};

struct hash_test rfc3174_sha1[2] =
{
    {
        "abc","A9993E364706816ABA3E25717850C26C9CD0D89D"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
    }
};

struct hash_test rfc4634_sha224[2] =
{
    {
        "abc","23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525"
    }
};
struct hash_test rfc4634_sha256[2] =
{
    {
        "abc","BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
    }
};

struct hash_test rfc4634_sha384[2] =
{
    {
        "abc",
        "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED163"
        "1A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"
    },
    {
        TEST2_2,
        "09330C33F71147E83D192FC782CD1B4753111B173B3B05D2"
        "2FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039"
    }
};
struct hash_test rfc4634_sha512[2] =
{
    {
        "abc",
        "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA2"
        "0A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD"
        "454D4423643CE80E2A9AC94FA54CA49F"
    },
    {
        TEST2_2,
        "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA1"
        "7299AEADB6889018501D289E4900F7E4331B99DEC4B5433A"
        "C7D329EEB6DD26545E96E55B874BE909"
    }
};

static void md5_test()
{
    int i;
    unsigned char md[16];
    char digest[128];

    for(i=0; i<(sizeof(rfc1321_md5)/sizeof(rfc1321_md5[0])); i++) {
        MD5(rfc1321_md5[i].data, strlen(rfc1321_md5[i].data), md);
        Hex2Str(md, digest, 16);
        if(memcmp(digest, rfc1321_md5[i].digest, 16*2)) {
            printf("MD5 test %d Fail.\n", i);
            printf("digest %s, right is %s\n", digest, rfc1321_md5[i].digest);
        } else
            printf("MD5 test %d OK.\n", i);
    }
}

static void sha1_test()
{
    int i;
    unsigned char md[20];
    char digest[128];

    for(i=0; i<(sizeof(rfc3174_sha1)/sizeof(rfc3174_sha1[0])); i++) {
        SHA1(rfc3174_sha1[i].data, strlen(rfc3174_sha1[i].data), md);
        Hex2Str(md, digest, 20);
        if(memcmp(digest, rfc3174_sha1[i].digest, 20*2)) {
            printf("SHA1 test %d Fail.\n", i);
            printf("digest %s, right is %s\n", digest, rfc3174_sha1[i].digest);
        } else
            printf("SHA1 test %d OK.\n", i);
    }
}

static void sha224_test()
{
    int i;
    unsigned char md[28];
    char digest[128];

    for(i=0; i<(sizeof(rfc4634_sha224)/sizeof(rfc4634_sha224[0])); i++) {
        SHA224(rfc4634_sha224[i].data, strlen(rfc4634_sha224[i].data), md);
        Hex2Str(md, digest, 28);
        if(memcmp(digest, rfc4634_sha224[i].digest, 28*2)) {
            printf("SHA224 test %d Fail.\n", i);
            printf("digest %s, right is %s\n", digest, rfc4634_sha224[i].digest);
        } else
            printf("SHA224 test %d OK.\n", i);
    }
}
static void sha256_test()
{
    int i;
    unsigned char md[32];
    char digest[128];

    for(i=0; i<(sizeof(rfc4634_sha256)/sizeof(rfc4634_sha256[0])); i++) {
        SHA256(rfc4634_sha256[i].data, strlen(rfc4634_sha256[i].data), md);
        Hex2Str(md, digest, 32);
        if(memcmp(digest, rfc4634_sha256[i].digest, 32*2)) {
            printf("SHA256 test %d Fail.\n", i);
            printf("digest %s, right is %s\n", digest, rfc4634_sha256[i].digest);
        } else
            printf("SHA256 test %d OK.\n", i);
    }
}

static void sha384_test()
{
    int i;
    unsigned char md[48];
    char digest[128];

    for(i=0; i<(sizeof(rfc4634_sha384)/sizeof(rfc4634_sha384[0])); i++) {
        SHA384(rfc4634_sha384[i].data, strlen(rfc4634_sha384[i].data), md);
        Hex2Str(md, digest, 48);
        if(memcmp(digest, rfc4634_sha384[i].digest, 48*2)) {
            printf("SHA384 test %d Fail.\n", i);
            printf("digest %s, right is %s\n", digest, rfc4634_sha384[i].digest);
        } else
            printf("SHA384 test %d OK.\n", i);
    }
}
static void sha512_test()
{
    int i;
    unsigned char md[64];
    char digest[128];

    for(i=0; i<(sizeof(rfc4634_sha512)/sizeof(rfc4634_sha512[0])); i++) {
        SHA512(rfc4634_sha512[i].data, strlen(rfc4634_sha512[i].data), md);
        Hex2Str(md, digest, 64);
        if(memcmp(digest, rfc4634_sha512[i].digest, 64*2)) {
            printf("SHA512 test %d Fail.\n", i);
            printf("digest %s, right is %s\n", digest, rfc4634_sha512[i].digest);
        } else
            printf("SHA512 test %d OK.\n", i);
    }
}

void hash_test()
{
    md5_test();
    sha1_test();
    sha224_test();
    sha256_test();
    sha384_test();
    sha512_test();
}

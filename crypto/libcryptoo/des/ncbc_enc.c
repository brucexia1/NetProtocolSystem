#include "des_loc.h"

void DES_ncbc_encrypt(const unsigned char *in, unsigned char *out,
                      long length, DES_key_schedule *_schedule,
                      DES_cblock *ivec, int enc)
{
    register DES_LONG tin0, tin1;
    register DES_LONG tout0, tout1, xor0, xor1;
    register long l = length;
    DES_LONG tin[2];
    unsigned char *iv;

    iv = &(*ivec)[0];

    if (enc) {
        c2l(iv, tout0);
        c2l(iv, tout1);
        for (l -= 8; l >= 0; l -= 8) {
            c2l(in, tin0);
            c2l(in, tin1);
            tin0 ^= tout0;
            tin[0] = tin0;
            tin1 ^= tout1;
            tin[1] = tin1;
            DES_encrypt1((DES_LONG *)tin, _schedule, DES_ENCRYPT);
            tout0 = tin[0];
            l2c(tout0, out);
            tout1 = tin[1];
            l2c(tout1, out);
        }
        if (l != -8) {
            c2ln(in, tin0, tin1, l + 8);
            tin0 ^= tout0;
            tin[0] = tin0;
            tin1 ^= tout1;
            tin[1] = tin1;
            DES_encrypt1((DES_LONG *)tin, _schedule, DES_ENCRYPT);
            tout0 = tin[0];
            l2c(tout0, out);
            tout1 = tin[1];
            l2c(tout1, out);
        }
        iv = &(*ivec)[0];
        l2c(tout0, iv);
        l2c(tout1, iv);
    } else {
        c2l(iv, xor0);
        c2l(iv, xor1);
        for (l -= 8; l >= 0; l -= 8) {
            c2l(in, tin0);
            tin[0] = tin0;
            c2l(in, tin1);
            tin[1] = tin1;
            DES_encrypt1((DES_LONG *)tin, _schedule, DES_DECRYPT);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2c(tout0, out);
            l2c(tout1, out);
            xor0 = tin0;
            xor1 = tin1;
        }
        if (l != -8) {
            c2l(in, tin0);
            tin[0] = tin0;
            c2l(in, tin1);
            tin[1] = tin1;
            DES_encrypt1((DES_LONG *)tin, _schedule, DES_DECRYPT);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2cn(tout0, tout1, out, l + 8);
            xor0 = tin0;
            xor1 = tin1;
        }
        iv = &(*ivec)[0];
        l2c(xor0, iv);
        l2c(xor1, iv);
    }
    tin0 = tin1 = tout0 = tout1 = xor0 = xor1 = 0;
    tin[0] = tin[1] = 0;
}




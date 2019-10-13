#ifndef __DES_H__
#define __DES_H__


typedef unsigned int DES_LONG;
typedef unsigned char DES_cblock[8];
typedef /* const */ unsigned char const_DES_cblock[8];

typedef struct DES_ks {
    union {
        DES_cblock cblock;
        /*
         * make sure things are correct size on machines with 8 byte longs
         */
        DES_LONG deslong[2];
    } ks[16];
} DES_key_schedule;

#define DES_KEY_SZ      (sizeof(DES_cblock))
#define DES_SCHEDULE_SZ (sizeof(DES_key_schedule))

#define DES_ENCRYPT     1
#define DES_DECRYPT     0


int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule);
int DES_key_sched(const_DES_cblock *key, DES_key_schedule *schedule);


/* DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. */
void DES_cbc_encrypt(const unsigned char *input, unsigned char *output,
                     long length, DES_key_schedule *schedule,
                     DES_cblock *ivec, int enc);
void DES_ncbc_encrypt(const unsigned char *input, unsigned char *output,
                      long length, DES_key_schedule *schedule,
                      DES_cblock *ivec, int enc);


void DES_encrypt1(DES_LONG *data, DES_key_schedule *ks, int enc);

void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc);

void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1,
                DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1,
                  DES_key_schedule *ks2, DES_key_schedule *ks3);



#endif //__DES_H__

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdbool.h>
#include <stdint.h>

unsigned char buffer_to_encoded_base58(unsigned char *in, unsigned char length,
                         unsigned char *out,
                         unsigned char maxoutlen);

void array_hexstr(char *strbuf, const void *bin, unsigned int len);

char* i64toa(int64_t i, char b[]);

bool tlvTryDecode(uint8_t *buffer, uint32_t bufferLength, uint32_t *fieldLenght, bool *valid);

unsigned char check_canonical(uint8_t *rs);

int ecdsa_der_to_sig(const uint8_t *der, uint8_t *sig);

void rng_rfc6979(unsigned char *rnd,
                 unsigned char *h1,
                 unsigned char *x, unsigned int x_len,
                 unsigned char *q, unsigned int q_len,
                 unsigned char *V, unsigned char *K);

#endif
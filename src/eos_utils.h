#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdbool.h>
#include <stdint.h>

unsigned char buffer_to_encoded_base58(unsigned char *in, unsigned char length,
                         unsigned char *out,
                         unsigned char maxoutlen);

void array_hexstr(char *strbuf, const void *bin, unsigned int len);

bool tlvTryDecode(uint8_t *buffer, uint32_t bufferLength, uint32_t *fieldLenght, bool *valid);

#endif
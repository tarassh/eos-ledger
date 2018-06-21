
#ifndef __UTILS_H__
#define __UTILS_H__

unsigned char buffer_to_encoded_base58(unsigned char *in, unsigned char length,
                         unsigned char *out,
                         unsigned char maxoutlen);

void array_hexstr(char *strbuf, const void *bin, unsigned int len);

#endif
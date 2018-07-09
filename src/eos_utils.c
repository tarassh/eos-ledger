/*******************************************************************************
*   Taras Shchybovyk
*   (c) 2018 Taras Shchybovyk
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "eos_utils.h"
#include "os.h"


unsigned char const BASE58ALPHABET[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};


unsigned char buffer_to_encoded_base58(unsigned char *in, unsigned char length,
                         unsigned char *out,
                         unsigned char maxoutlen) {
    unsigned char tmp[164];
    unsigned char buffer[164];
    unsigned char j;
    unsigned char startAt;
    unsigned char zeroCount = 0;
    if (length > sizeof(tmp)) {
        THROW(INVALID_PARAMETER);
    }
    os_memmove(tmp, in, length);
    while ((zeroCount < length) && (tmp[zeroCount] == 0)) {
        ++zeroCount;
    }
    j = 2 * length;
    startAt = zeroCount;
    while (startAt < length) {
        unsigned short remainder = 0;
        unsigned char divLoop;
        for (divLoop = startAt; divLoop < length; divLoop++) {
            unsigned short digit256 = (unsigned short)(tmp[divLoop] & 0xff);
            unsigned short tmpDiv = remainder * 256 + digit256;
            tmp[divLoop] = (unsigned char)(tmpDiv / 58);
            remainder = (tmpDiv % 58);
        }
        if (tmp[startAt] == 0) {
            ++startAt;
        }
        buffer[--j] = (unsigned char)BASE58ALPHABET[remainder];
    }
    while ((j < (2 * length)) && (buffer[j] == BASE58ALPHABET[0])) {
        ++j;
    }
    while (zeroCount-- > 0) {
        buffer[--j] = BASE58ALPHABET[0];
    }
    length = 2 * length - j;
    if (maxoutlen < length) {
        THROW(EXCEPTION_OVERFLOW);
    }
    os_memmove(out, (buffer + j), length);
    return length;
}

const unsigned char hex_digits[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void array_hexstr(char *strbuf, const void *bin, unsigned int len) {
    while (len--) {
        *strbuf++ = hex_digits[((*((char *)bin)) >> 4) & 0xF];
        *strbuf++ = hex_digits[(*((char *)bin)) & 0xF];
        bin = (const void *)((unsigned int)bin + 1);
    }
    *strbuf = 0; // EOS
}

char* i64toa(int64_t i, char b[]) {
    char const digit[] = "0123456789";
    char* p = b;
    if(i<0){
        *p++ = '-';
        i *= -1;
    }
    int64_t shifter = i;
    do{ //Move to where representation ends
        ++p;
        shifter = shifter/10;
    }while(shifter);
    *p = '\0';
    do{ //Move back, inserting digits as u go
        *--p = digit[i%10];
        i = i/10;
    }while(i);
    return b;
}

/**
 * Decodes tag according to ASN1 standard.
*/
static void decodeTag(uint8_t byte, uint8_t *cls, uint8_t *type, uint8_t *nr) {
    *cls = byte & 0xc0;
    *type = byte & 0x20;
    *nr = byte & 0x1f;
}

/**
 * Decoder supports only 'OctetString' from DER encoding.
 * To get more information about DER encoding go to
 * http://luca.ntop.org/Teaching/Appunti/asn1.html.
*/

#define NUMBER_OCTET_STRING 0x04

/**
 * tlv buffer is 5 bytes long. First byte is used for tag.
 * Next, up to four bytes could be used to to encode length.
*/
bool tlvTryDecode(uint8_t *buffer, uint32_t bufferLength, uint32_t *fieldLenght, bool *valid) {
    uint8_t class, type, number;
    decodeTag(*buffer, &class, &type, &number);
    
    if (number != NUMBER_OCTET_STRING) {
        *valid = false;
        return false;
    }

    if (bufferLength < 2) {
        *valid = true;
        return false;
    }
    bufferLength--;
    buffer++;
    // Read length
    uint32_t length;
    uint8_t byte = *buffer;
    if (byte & 0x80) {
        uint8_t i;
        uint8_t count = byte & 0x7f;
        if (count > 4) {
            // Its allowed to have up to 4 bytes for length
            // [.] Tag
            //    [. . . .] Length
            *valid = false;
            return false;
        }
        
        if (count > bufferLength) {
            *valid = true;
            return false;
        }
        
        length = 0;
        for (i = 0; i < count; ++i) {
            length = (length << 8) | *(buffer + i);
        }
    } else {
        length = byte;
    }
    *fieldLenght = length;
    *valid = true;

    return true;
}

/**
 * EOS way to check if a signature is canonical :/
*/
unsigned char check_canonical(uint8_t *rs)
{
    return !(rs[0] & 0x80) 
        && !(rs[0] == 0 
        && !(rs[1] & 0x80)) 
        && !(rs[32] & 0x80) 
        && !(rs[32] == 0 && !(rs[33] & 0x80));
}

int ecdsa_der_to_sig(const uint8_t *der, uint8_t *sig)
{
    int length;
    int offset = 2;
    int delta = 0;
    if (der[offset + 2] == 0)
    {
        length = der[offset + 1] - 1;
        offset += 3;
    }
    else
    {
        length = der[offset + 1];
        offset += 2;
    }
    if ((length < 0) || (length > 32))
    {
        return 0;
    }
    while ((length + delta) < 32)
    {
        sig[delta++] = 0;
    }
    os_memmove(sig + delta, der + offset, length);

    delta = 0;
    offset += length;
    if (der[offset + 2] == 0)
    {
        length = der[offset + 1] - 1;
        offset += 3;
    }
    else
    {
        length = der[offset + 1];
        offset += 2;
    }
    if ((length < 0) || (length > 32))
    {
        return 0;
    }
    while ((length + delta) < 32)
    {
        sig[32 + delta++] = 0;
    }
    os_memmove(sig + 32 + delta, der + offset, length);

    return 1;
}

/**
 * The nonce generated by internal library CX_RND_RFC6979 is not compatible
 * with EOS. So this is the way to generate nonve for EOS.
*/
void rng_rfc6979(unsigned char *rnd,
                 unsigned char *h1,
                 unsigned char *x, unsigned int x_len,
                 unsigned char *q, unsigned int q_len,
                 unsigned char *V, unsigned char *K)
{
    unsigned int h_len, offset, found, i;
    cx_hmac_sha256_t hmac;

    h_len = 32;
    //a. h1 as input

    //loop for a candidate
    found = 0;
    while (!found)
    {
        if (x)
        {
            //b.  Set:          V = 0x01 0x01 0x01 ... 0x01
            os_memset(V, 0x01, h_len);
            //c. Set: K = 0x00 0x00 0x00 ... 0x00
            os_memset(K, 0x00, h_len);
            //d.  Set: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
            V[h_len] = 0;
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, 0, V, h_len + 1, K);
            cx_hmac(&hmac, 0, x, x_len, K);
            cx_hmac(&hmac, CX_LAST, h1, h_len, K);
            //e.  Set: V = HMAC_K(V)
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac((cx_hmac_t *)&hmac, CX_LAST, V, h_len, V);
            //f.  Set:  K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
            V[h_len] = 1;
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, 0, V, h_len + 1, K);
            cx_hmac(&hmac, 0, x, x_len, K);
            cx_hmac(&hmac, CX_LAST, h1, h_len, K);
            //g. Set: V = HMAC_K(V) --
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, CX_LAST, V, h_len, V);
            // initial setup only once
            x = NULL;
        }
        else
        {
            // h.3  K = HMAC_K(V || 0x00)
            V[h_len] = 0;
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, CX_LAST, V, h_len + 1, K);
            // h.3 V = HMAC_K(V)
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, CX_LAST, V, h_len, V);
        }

        //generate candidate
        /* Shortcut: As only secp256k1/sha256 is supported, the step h.2 :
         *   While tlen < qlen, do the following:
         *     V = HMAC_K(V)
         *     T = T || V
         * is replace by 
         *     V = HMAC_K(V)
         */
        x_len = q_len;
        offset = 0;
        while (x_len)
        {
            if (x_len < h_len)
            {
                h_len = x_len;
            }
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, CX_LAST, V, h_len, V);
            os_memmove(rnd + offset, V, h_len);
            x_len -= h_len;
        }

        // h.3 Check T is < n
        for (i = 0; i < q_len; i++)
        {
            if (V[i] < q[i])
            {
                found = 1;
                break;
            }
        }
    }
}

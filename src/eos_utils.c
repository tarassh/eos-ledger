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

static void decodeTag(uint8_t byte, uint8_t *cls, uint8_t *type, uint8_t *nr) {
    *cls = byte & 0xc0;
    *type = byte & 0x20;
    *nr = byte & 0x1f;
}

/**
 * Decoder supports only two numbers from BER-DER encoding: 'OctetString' and 'Sequence'.
*/

#define NUMBER_OCTET_STRING 0x04
#define NUMBER_SEQUENCE 0x10

bool tlvTryDecode(uint8_t *buffer, uint32_t bufferLength, uint32_t *fieldLenght, bool *sequence,  bool *valid) {
    uint8_t class, type, number;
    decodeTag(*buffer, &class, &type, &number);
    
    if (number != NUMBER_OCTET_STRING && number != NUMBER_SEQUENCE) {
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
    *sequence = number == NUMBER_SEQUENCE;
    *valid = true;

    return true;
}
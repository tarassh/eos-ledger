#ifndef __EOS_TYPES_H__
#define __EOS_TYPES_H__

#include <stdint.h>

typedef uint32_t fc_unsigned_int_t;
typedef uint64_t name_t;
typedef uint64_t symbol_t;
typedef uint8_t checksum256[32];

typedef struct transaction_header_t {
    uint32_t expiration;
    uint16_t ref_block_num;
    uint32_t ref_block_prefix;
    fc_unsigned_int_t max_net_usage_words;
    uint8_t max_cpu_usage_ms;
    fc_unsigned_int_t delay_sec;
} transaction_header_t;

typedef struct action_t {
    name_t account;
    name_t name;
    // vector<permission_level> autorization;
    // vector<char> bytes;
} action_t;

typedef struct permisssion_level_t {
    name_t actor;
    name_t permission;
} permisssion_level_t;

typedef struct asset_t {
    int64_t amount;
    symbol_t symbol;
} asset_t;

uint8_t pack_fc_unsigned_int(fc_unsigned_int_t value, uint8_t *out);
uint32_t unpack_fc_unsigned_int(uint8_t *in, uint32_t length, fc_unsigned_int_t *value);

name_t buffer_to_name_type(uint8_t *in, uint32_t size);
uint8_t name_to_string(name_t value, char *out, uint32_t size);

uint8_t asset_to_string(asset_t *asset, char *out, uint32_t size);

#endif // __EOS_TYPES_H__
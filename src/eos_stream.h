#ifndef __EOS_STREAM_H__
#define __EOS_STREAM_H__

#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include "eos_types.h"

typedef struct txProcessingContent_t {
    char accountName[14];
    char actionName[14];
    char actionData[512];
    transaction_header_t header;
} txProcessingContent_t;

typedef enum txProcessingState_e {
    TLV_TX_NONE = 0x0, 
    TLV_TX_CHAIN_ID = 0x1,
    TLV_TX_HEADER_EXPITATION,
    TLV_TX_HEADER_REF_BLOCK_NUM,
    TLV_TX_HEADER_REF_BLOCK_PREFIX,
    TLV_TX_HEADER_MAX_NET_USAGE_WORDS,
    TLV_TX_HEADER_MAX_CPU_USAGE_MS,
    TLV_TX_HEADER_DELAY_SEC,
    TLV_TX_CONTEXT_FREE_ACTIONS,
    TLV_TX_ACTIONS,
    TLV_TX_TRANSACTION_EXTENSIONS,
    TLV_TX_CONTEXT_FREE_DATA,
    TLV_TX_DONE
} txProcessingState_e;

typedef struct txProcessingContext_t {
    txProcessingState_e state;
    cx_sha256_t *sha256;
    uint32_t currentFieldLength;
    uint32_t currentFieldPos;
    bool processingField;
    bool isSequence;
    uint8_t tlvBuffer[4];
    uint32_t tlvBufferPos;
    fc_unsigned_int_t tempHeaderValue;
    uint8_t *workBuffer;
    uint32_t commandLength;
    txProcessingContent_t *content;
} txProcessingContext_t;

typedef enum parserStatus_e {
    STREAM_PROCESSING,
    STREAM_FINISHED,
    STREAM_FAULT
} parserStatus_e;

void initTxContext(txProcessingContext_t *context, cx_sha256_t *sha256, txProcessingContent_t *processingContent);
parserStatus_e parseTx(txProcessingContext_t *context, uint8_t *buffer, uint32_t length);

#endif // __EOS_STREAM_H__

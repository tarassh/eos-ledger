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
} txProcessingContent_t;

typedef enum txProcessingState_e {
    TLV_NONE = 0x0, 
    TLV_CHAIN_ID = 0x1,
    TLV_HEADER_EXPITATION,
    TLV_HEADER_REF_BLOCK_NUM,
    TLV_HEADER_REF_BLOCK_PREFIX,
    TLV_HEADER_MAX_NET_USAGE_WORDS,
    TLV_HEADER_MAX_CPU_USAGE_MS,
    TLV_HEADER_DELAY_SEC,
    TLV_CFA_LIST_SIZE,
    TLV_ACTION_LIST_SIZE,
    TLV_ACTION_ACCOUNT,
    TLV_ACTION_NAME,
    TLV_AUTHORIZATION_LIST_SIZE,
    TLV_AUTHORIZATION_ACTOR,
    TLV_AUTHORIZATION_PERMISSION,
    // TLV_ACTION_DATA_TYPES,
    TLV_ACTION_DATA_SIZE,
    TLV_ACTION_DATA,
    TLV_TX_EXTENSION_LIST_SIZE,
    TLV_CONTEXT_FREE_DATA,
    TLV_DONE
} txProcessingState_e;

typedef struct txProcessingContext_t {
    txProcessingState_e state;
    cx_sha256_t *sha256;
    uint32_t currentFieldLength;
    uint32_t currentFieldPos;
    uint32_t currentActionIndex;
    uint32_t currentActionNumber;
    uint32_t currentAutorizationIndex;
    uint32_t currentAutorizationNumber;
    uint32_t currentActionDataTypeNumber;
    uint32_t currentActionDataTypeIndex;
    bool processingField;
    uint8_t tlvBuffer[5];
    uint32_t tlvBufferPos;
    uint8_t *workBuffer;
    uint32_t commandLength;
    uint8_t nameTypeBuffer[8];
    uint8_t sizeBuffer[12];
    uint8_t dataTypeBuffer[16];
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

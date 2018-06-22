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
    TX_NONE = 0x0, 
    TX_CHAIN_ID = 0x1,
    TX_HEADER,
    TX_CONTEXT_FREE_ACTIONS,
    TX_ACTIONS,
    TX_TRANSACTION_EXTENSIONS,
    TX_CONTEXT_FREE_DATA,
    TX_DONE
} txProcessingState_e;

typedef struct txProcessingContext_t {
    txProcessingState_e state;
    uint32_t bytesLeftForState;
    uint32_t bufferIndex;
    cx_sha256_t *sha256;
    txProcessingContent_t *content;
    transaction_header_t header;
    bool cfaSizeRead;
    bool actionSizeRead;
    bool teSizeRead;
} txProcessingContext_t;

typedef enum parserStatus_e {
    STREAM_PROCESSING,
    STREAM_FINISHED,
    STREAM_FAULT
} parserStatus_e;

void initTxContext(txProcessingContext_t *context, cx_sha256_t *sha256, txProcessingContent_t *processingContent);
parserStatus_e parseTx(txProcessingContext_t *context, uint8_t *in, uint32_t size);

#endif // __EOS_STREAM_H__

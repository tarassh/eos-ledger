#include "eos_stream.h"
#include "os.h"
#include "cx.h"
#include "eos_types.h"

void initTxContext(txProcessingContext_t *context, 
                   cx_sha256_t *sha256, 
                   txProcessingContent_t *processingContent) {
    os_memset(context, 0, sizeof(txProcessingContext_t));
    context->sha256 = sha256;
    context->content = processingContent;
    context->state = TX_CHAIN_ID;
    cx_sha256_init(context->sha256);
}

uint8_t readTxByte(txProcessingContext_t *context) {
    uint8_t data;
    if (context->commandLength < 1) {
        PRINTF("readTxByte Underflow\n");
        THROW(EXCEPTION);
    }
    data = *context->workBuffer;
    context->workBuffer++;
    context->commandLength--;
    return data;
}

static void hashTxData(txProcessingContext_t *context, uint8_t *buffer, uint32_t length) {
    cx_hash(&context->sha256->header, 0, buffer, length, NULL, 0);
}

bool tlvValidate(txProcessingContext_t *context) {
    uint16_t length;
    os_memmove(&length, context->tlvBuffer + 1, 2);
    switch (context->tlvBuffer[0]) {
    case TX_CHAIN_ID:
        if (sizeof(chain_id_t) != length) {
            PRINTF("tlvValidate Invalid chain id size\n");
            return false;
        }
        break;
    case TX_HEADER:
        if (sizeof(transaction_header_t) != length) {
            PRINTF("tlvValidate Invalid transaction header size\n");
            return false;
        }
        break;
    case TX_CONTEXT_FREE_ACTIONS:
        if (length != 0) {
            PRINTF("tlvValidate Context free actions are not supported\n");
            return false;
        }
        break;
    case TX_ACTIONS:
        if (length == 0) {
            PRINTF("tlvValidate empty action is not allowed\n");
            return false;
        }
        break;
    case TX_TRANSACTION_EXTENSIONS:
        if (length != 0) {
            PRINTF("tlvValidate transaction extensions are not supported\n");
            return false;
        }
        break;
    case TX_CONTEXT_FREE_DATA:
        if (length != 0) {
            PRINTF("tlvValidate context free data is not supported\n");
            return false;
        }
    default:
        PRINTF("Invalid Tag\n");
        return false;
    }

    return true;
}

static void processChainId(txProcessingContext_t *context) {
    uint16_t length;
    os_memmove(&length, context->tlvBuffer + 1, 2);
    if (context->state != TX_CHAIN_ID) {
        PRINTF("processChainId Invalid Tag\n");
        THROW(EXCEPTION);
    }

    if (sizeof(chain_id_t) != length) {
        PRINTF("processChainId Invalid chain id size\n");
        THROW(EXCEPTION);
    }

    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);
        
        hashTxData(context, context->workBuffer, length);
        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->state++;
        context->processingField = false;
    }
}

static void processHeader(txProcessingContext_t *context) {
    uint16_t length;
    os_memmove(&length, context->tlvBuffer + 1, 2);
    if (context->state != TX_CHAIN_ID) {
        PRINTF("processChainId Invalid Tag\n");
        THROW(EXCEPTION);
    }

    if (sizeof(chain_id_t) != length) {
        PRINTF("processChainId Invalid chain id size\n");
        THROW(EXCEPTION);
    }

    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);
        
        uint8_t * pHeader = (char *)(&context->content->header);
        os_memmove(pHeader + context->currentFieldLength, context->workBuffer, length);
        
        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        transaction_header_t *header = &context->content->header;
        uint8_t tmp[16] = { 0 };
        uint8_t packedBytes;

        hashTxData(context, (uint8_t *)&header->expiration, sizeof(header->expiration));
        hashTxData(context, (uint8_t *)&header->ref_block_num, sizeof(header->ref_block_num));
        hashTxData(context, (uint8_t *)&header->ref_block_prefix, sizeof(header->ref_block_prefix));
        packedBytes = pack_fc_unsigned_int(header->max_net_usage_words, tmp);
        hashTxData(context, tmp, packedBytes);
        hashTxData(context, (uint8_t *)&header->max_cpu_usage_ms, sizeif(header->max_cpu_usage_ms));
        packedBytes = pack_fc_unsigned_int(header->delay_sec, tmp);
        hashTxData(context, tmp, packedBytes);

        context->state++;
        context->processingField = false;
    }
}

static parserStatus_e processTxInternal(txProcessingContext_t *context) {
    for(;;) {
        if (context->state == TX_DONE) {
            return STREAM_FINISHED;
        }
        if (context->commandLength == 0) {
            return STREAM_PROCESSING;
        }
        if (!context->processingField) {
            // While we are not processing a field, we should TLV parameters
            bool canDecode = false;
            while (context->commandLength != 0) {
                // Feed the TLV buffer until the length can be decoded
                context->tlvBuffer[context->tlvBufferPos++] =
                    readTxByte(context);
                
                if (context->tlvBufferPos == sizeof(context->tlvBuffer)) {
                    canDecode = true;
                    break;
                }
            }
            if (!canDecode) {
                return STREAM_PROCESSING;
            }
            context->currentFieldPos = 0;
            context->tlvBufferPos = 0;
            context->processingField = true;
        }
        switch (context->state) {
        case TX_CHAIN_ID:
            processChainId(context);
            break;
        case TX_HEADER:
            break;
        case TX_CONTEXT_FREE_ACTIONS:
            break;
        case TX_ACTIONS:
            break;
        case TX_TRANSACTION_EXTENSIONS:
            break;
        case TX_CONTEXT_FREE_DATA:
            break;
        default:
            PRINTF("Invalid RLP decoder context\n");
            return STREAM_FAULT;
        }
    }
}

parserStatus_e parseTx(txProcessingContext_t *context, uint8_t *buffer, uint32_t length) {
    parserStatus_e result;
    BEGIN_TRY {
        TRY {
            context->workBuffer = buffer;
            context->commandLength = length;
            result = processTxInternal(context);
        }
        CATCH_OTHER(e) {
            result = STREAM_FAULT;
        }
        FINALLY {
        }
    }
    END_TRY;
    return result;
}
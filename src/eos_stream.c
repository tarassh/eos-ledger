#include "eos_stream.h"
#include "os.h"
#include "cx.h"
#include "eos_types.h"
#include "eos_utils.h"

void initTxContext(txProcessingContext_t *context, 
                   cx_sha256_t *sha256, 
                   txProcessingContent_t *processingContent) {
    os_memset(context, 0, sizeof(txProcessingContext_t));
    context->sha256 = sha256;
    context->content = processingContent;
    context->state = TLV_TX_CHAIN_ID;
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
/**
 * Sequentially hash an incoming data.
 * Hash functionality is moved out here in order to reduce 
 * dependencies on specific hash implementation.
*/
static void hashTxData(txProcessingContext_t *context, uint8_t *buffer, uint32_t length) {
    cx_hash(&context->sha256->header, 0, buffer, length, NULL, 0);
}

/**
 * Process all fields that do not requre any processing except hashing.
 * The data comes in by chucks, so it may happen that buffer may contain 
 * incomplete data for particular field. Function designed to process 
 * everything until it receives all data for a particular field 
 * and after that will move to next field.
*/
static void processField(txProcessingContext_t *context) {
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

/**
 * Process Context Free Action Number Field. Except hashing the data, function
 * caches an incomming data. So, when all bytes for particulat field are received
 * do additional processing: Read actual number of actions encoded in buffer.
 * Throw exception if number is not '0'.
*/
static void processCtxFreeActionNumber(txProcessingContext_t *context) {
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);

        // Store data into a buffer
        os_memmove(context->sizeBuffer + context->sizeBufferPos, context->workBuffer, length);
        context->sizeBufferPos += length;

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        if (unpack_fc_unsigned_int(context->sizeBuffer, context->sizeBufferPos + 1) != 0) {
            PRINTF("processCtxFreeAction Action Number must be 0\n");
            THROW(EXCEPTION);
        }
        // Reset size buffer
        context->sizeBufferPos = 0;
        os_memset(context->sizeBuffer, 0, sizeof(context->sizeBuffer));

        // Move to next state
        context->state++;
        context->processingField = false;
    }
}

/**
 * Process Action Number Field. Except hashing the data, function
 * caches an incomming data. So, when all bytes for particulat field are received
 * do additional processing: Read actual number of actions encoded in buffer.
 * Throw exception if number is not '1'.
*/
static void processActionNumber(txProcessingContext_t *context) {
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);

        // Store data into a buffer
        os_memmove(context->sizeBuffer + context->sizeBufferPos, context->workBuffer, length);
        context->sizeBufferPos += length;

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentActionNumber = unpack_fc_unsigned_int(context->sizeBuffer, context->sizeBufferPos + 1);
        if (context->currentActionNumber != 1) {
            PRINTF("processActionNumber Action Number must be 1\n");
            THROW(EXCEPTION);
        }
        // Reset size buffer
        context->currentActionIndex = 0;
        context->sizeBufferPos = 0;
        os_memset(context->sizeBuffer, 0, sizeof(context->sizeBuffer));

        context->state++;
        context->processingField = false;
    }
}

/**
 * Process Action Account Field. Cache a data of the field in order to 
 * display it for validation.
*/
static void processActionAccount(txProcessingContext_t *context) {
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);
        uint8_t *pointer = ((uint8_t *)(&context->nameTypeBuffer)) + context->currentFieldPos;
        os_memmove(pointer, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->state++;
        context->processingField = false;

        name_to_string(context->nameTypeBuffer, context->content->accountName, sizeof(context->content->accountName));
    }
}

/**
 * Process Action Name Field. Cache a data of the field in order to 
 * display it for validation.
*/
static void processActionName(txProcessingContext_t *context) {
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);
        uint8_t *pointer = ((uint8_t *)(&context->nameTypeBuffer)) + context->currentFieldPos;
        os_memmove(pointer, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->state++;
        context->processingField = false;

        name_to_string(context->nameTypeBuffer, context->content->actionName, sizeof(context->content->actionName));
    }
}

/**
 * Process Authorization Number Field. Initializa context action number 
 * index and context action number. 
*/
static void processAuthorizastionNumber(txProcessingContext_t *context) {
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);

        // Store data into a buffer
        os_memmove(context->sizeBuffer + context->sizeBufferPos, context->workBuffer, length);
        context->sizeBufferPos += length;

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentAutorizationNumber = unpack_fc_unsigned_int(context->sizeBuffer, context->sizeBufferPos + 1);
        context->currentAutorizationIndex = 0;
        // Reset size buffer
        context->sizeBufferPos = 0;
        os_memset(context->sizeBuffer, 0, sizeof(context->sizeBuffer));

        // Move to next state
        context->state++;
        context->processingField = false;
    }
}

/**
 * Process Authorization Permission Field. When the field is processed 
 * start over authorization processing if the there is data for that.
*/
static void processAuthorizationPermission(txProcessingContext_t *context) {
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
        context->currentAutorizationIndex++;
        // Reset size buffer
        context->sizeBufferPos = 0;
        os_memset(context->sizeBuffer, 0, sizeof(context->sizeBuffer));

        // Start over reading Authorization data or move to the next state
        // if all authorization data have beed read
        if (context->currentAutorizationIndex != context->currentAutorizationNumber) {
            context->state = TLV_AUTH_ACTOR;
        } else {
            context->state++;
        }
        context->processingField = false;
    }
}

/**
 * Process current action data field and store in into data buffer.
*/
static void processActionData(txProcessingContext_t *context) {
    if (context->currentFieldLength > 512) {
        PRINTF("processActionData data overflow\n");
        THROW(EXCEPTION);
    }

    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);
        os_memmove(context->content->actionData + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        // We processed last action field
        context->currentActionIndex = 0;
        context->currentActionNumber = 0;

        context->state++;
        context->processingField = false;
    }
}

/**
 * Transaction extensions are not supported. Decision has been made based on
 * observations. Nevertheless, the '0' size value should be hashed as it is
 * a part of signing infornation.
*/
static void processTxExtensions(txProcessingContext_t *context) {
    if (context->currentFieldLength != 0) {
        PRINTF("processTxExtensions Transaction extensions are not supported\n");
        THROW(EXCEPTION);
    }

    uint8_t tmp[16] = {0};
    uint8_t packedBytes = pack_fc_unsigned_int(0, tmp);
    hashTxData(context, tmp, packedBytes);

    // Move to next state
    context->state++;
    context->processingField = false;
}

/**
 * Context free actions are not supported and a corresponding data as well.
 * Hash 32 bytes long '0' value buffer instead.
*/
static void processCtxFreeData(txProcessingContext_t *context) {
    if (context->currentFieldLength != 0) {
        PRINTF("processCtxFreeData Context free data is not supported\n");
        THROW(EXCEPTION);
    }

    uint8_t empty[32] = {0};
    hashTxData(context, empty, sizeof(empty));

    // Move to next state
    context->state++;
    context->processingField = false;
}

static parserStatus_e processTxInternal(txProcessingContext_t *context) {
    for(;;) {
        if (context->state == TLV_TX_DONE) {
            return STREAM_FINISHED;
        }
        if (context->commandLength == 0) {
            return STREAM_PROCESSING;
        }
        if (!context->processingField) {
            // While we are not processing a field, we should TLV parameters
            bool decoded = false;
            while (context->commandLength != 0) {
                bool valid;
                // Feed the TLV buffer until the length can be decoded
                context->tlvBuffer[context->tlvBufferPos++] =
                    readTxByte(context);

                decoded = tlvTryDecode(context->tlvBuffer, context->tlvBufferPos, 
                    &context->currentFieldLength, &valid);

                if (!valid) {
                    PRINTF("TLV decoding error\n");
                    return STREAM_FAULT;
                }
                if (decoded) {
                    break;
                }

                // Cannot decode yet
                // Sanity check
                if (context->tlvBufferPos == sizeof(context->tlvBuffer)) {
                    PRINTF("TLV pre-decode logic error\n");
                    return STREAM_FAULT;
                }
            }
            if (!decoded) {
                return STREAM_PROCESSING;
            }
            context->currentFieldPos = 0;
            context->tlvBufferPos = 0;
            context->processingField = true;
        }
        switch (context->state) {
        case TLV_TX_CHAIN_ID:
        case TLV_TX_HEADER_EXPITATION:
        case TLV_TX_HEADER_REF_BLOCK_NUM:
        case TLV_TX_HEADER_REF_BLOCK_PREFIX:
        case TLV_TX_HEADER_MAX_CPU_USAGE_MS:
        case TLV_TX_HEADER_MAX_NET_USAGE_WORDS:
        case TLV_TX_HEADER_DELAY_SEC:
            processField(context);
            break;

        case TLV_TX_CONTEXT_FREE_ACTION_NUMBER:
            processCtxFreeActionNumber(context);
            break;

        case TLV_ACTION_NUMBER:
            processActionNumber(context);
            break;

        case TLV_ACTION_ACCOUNT:
            processActionAccount(context);
            break;

        case TLV_ACTION_NAME:
            processActionName(context);
            break;

        case TLV_AUTH_NUMBER:
            processAuthorizastionNumber(context);
            break;

        case TLV_AUTH_ACTOR:
            processField(context);
            break;
        case TLV_AUTH_PERMISSION:
            processAuthorizationPermission(context);
            break;
        
        case TLV_ACTION_DATA:
            processActionData(context);
            break;

        case TLV_TX_TRANSACTION_EXTENSION_NUMBER:
            processField(context);
            break;

        case TLV_TX_CONTEXT_FREE_DATA:
            processCtxFreeData(context);
            break;
            
        default:
            PRINTF("Invalid TLV decoder context\n");
            return STREAM_FAULT;
        }
    }
}

/**
 * Transaction processing should be done in a most efficient
 * way as possible, as EOS transaction size isn't fixed
 * and depends on action size. 
 * Also, Ledger Nano S have limited RAM resource, so data caching
 * could be very expencive. Due to these features and limitations
 * only some fields are cached before processing.
*/
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
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
    context->state = TLV_CHAIN_ID;
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

static void parseActionData(txProcessingContext_t *context) {
    uint32_t i = 0;
    uint32_t fieldLength = 0;
    uint32_t displayBufferLength = sizeof(context->content->actionData);
    char *displayBuffer = context->content->actionData;

    os_memset(displayBuffer, 0, displayBufferLength);

    while (i < context->currentActionDataTypeNumber) {
        uint8_t type = context->actionDataTypeBuffer[i++];
        uint8_t offset = context->actionDataTypeBuffer[i++];
        uint32_t bufferLength = context->currentActionDataBufferLength - offset;
        uint8_t *buffer = context->actionDataBuffer + offset;

        switch (type) {
        case NAME_TYPE:
            {
                if (bufferLength < 8) {
                    PRINTF("parseActionData Insufficient buffer\n");
                    THROW(EXCEPTION);
                }

                // Parse data from buffer
                name_t name = buffer_to_name_type(buffer, 8);

                // Write parsed data to dispaly buffer
                fieldLength = name_to_string(name, displayBuffer, displayBufferLength);
            }
            break;
        case STRING_TYPE:
            {
                uint32_t read = unpack_fc_unsigned_int(buffer, bufferLength, &fieldLength);
                if (bufferLength < fieldLength) {
                    PRINTF("parseActionData Insufficient buffer\n");
                    THROW(EXCEPTION);
                }

                os_memmove(displayBuffer, buffer + read, fieldLength);
            }
            break;
        case ASSET_TYPE: 
            {
                asset_t asset;
                if (bufferLength < sizeof(asset)) {
                    PRINTF("parseActionData Insufficient buffer\n");
                    THROW(EXCEPTION);
                }

                os_memmove(&asset, buffer, sizeof(asset));

                // write data to buffer
                fieldLength = asset_to_string(&asset, displayBuffer, displayBufferLength);
            }
            break;
        case PUBLIC_KEY_TYPE:
            {
                if (bufferLength < 33) {
                    PRINTF("parseActionData Insufficient buffer\n");
                    THROW(EXCEPTION);
                }

                fieldLength = public_key_to_wif(buffer, bufferLength, displayBuffer, displayBufferLength);
            }
            break;
        default:
            PRINTF("parseActionData Unimplemented type\n");
            THROW(EXCEPTION);
        }
        displayBuffer += fieldLength;
        displayBufferLength -= fieldLength;

        if (i < context->currentActionDataTypeNumber) {
            *displayBuffer = ' ';
            displayBuffer++;
            displayBufferLength--;
        } 

    }
}

/**
 * Sequentially hash an incoming data.
 * Hash functionality is moved out here in order to reduce 
 * dependencies on specific hash implementation.
*/
static void hashTxData(txProcessingContext_t *context, uint8_t *buffer, uint32_t length) {
    cx_hash(&context->sha256->header, 0, buffer, length, NULL);
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
 * Process Size fields that are expected to have Zero value. Except hashing the data, function
 * caches an incomming data. So, when all bytes for particulat field are received
 * do additional processing: Read actual number of actions encoded in buffer.
 * Throw exception if number is not '0'.
*/
static void processZeroSizeField(txProcessingContext_t *context) {
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);

        // Store data into a buffer
        os_memmove(context->sizeBuffer + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        uint32_t sizeValue = 0;
        unpack_fc_unsigned_int(context->sizeBuffer, context->currentFieldPos + 1, &sizeValue);
        if (sizeValue != 0) {
            PRINTF("processCtxFreeAction Action Number must be 0\n");
            THROW(EXCEPTION);
        }
        // Reset size buffer
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
static void processActionListSizeField(txProcessingContext_t *context) {
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);

        // Store data into a buffer
        os_memmove(context->sizeBuffer + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        unpack_fc_unsigned_int(context->sizeBuffer, context->currentFieldPos + 1, &context->currentActionNumber);
        if (context->currentActionNumber != 1) {
            PRINTF("processActionListSizeField Action Number must be 1\n");
            THROW(EXCEPTION);
        }
        // Reset size buffer
        context->currentActionIndex = 0;
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
        os_memmove(context->nameTypeBuffer + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->state++;
        context->processingField = false;

        // TODO: MAYBE THAT WITH REAL TX IT WILL not reverse
        name_t account = buffer_to_name_type(context->nameTypeBuffer, sizeof(context->nameTypeBuffer));
        os_memset(context->content->accountName, 0, sizeof(context->content->accountName));
        name_to_string(account, context->content->accountName, sizeof(context->content->accountName));
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
        os_memmove(context->nameTypeBuffer + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->state++;
        context->processingField = false;

        // TODO: Maybe with real tx it will be not reverse
        name_t name = buffer_to_name_type(context->nameTypeBuffer, sizeof(context->nameTypeBuffer));
        os_memset(context->content->actionName, 0, sizeof(context->content->actionName));
        name_to_string(name, context->content->actionName, sizeof(context->content->actionName));
    }
}

/**
 * Process Authorization Number Field. Initializa context action number 
 * index and context action number. 
*/
static void processAuthorizationListSizeField(txProcessingContext_t *context) {
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);

        hashTxData(context, context->workBuffer, length);

        // Store data into a buffer
        os_memmove(context->sizeBuffer + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        unpack_fc_unsigned_int(context->sizeBuffer, context->currentFieldPos + 1, &context->currentAutorizationNumber);
        context->currentAutorizationIndex = 0;
        // Reset size buffer
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
        os_memset(context->sizeBuffer, 0, sizeof(context->sizeBuffer));

        // Start over reading Authorization data or move to the next state
        // if all authorization data have beed read
        if (context->currentAutorizationIndex != context->currentAutorizationNumber) {
            context->state = TLV_AUTHORIZATION_ACTOR;
        } else {
            context->state++;
        }
        context->processingField = false;
    }
}

/**
 * Process data types that should be used in order to parse data.
 * This data isn't used for hashing.
*/
static void processActionDataTypes(txProcessingContext_t *context) {
    if (context->currentFieldLength > sizeof(context->actionDataTypeBuffer)) {
        PRINTF("processActionDataTypes data overflow\n");
        THROW(EXCEPTION);
    }

    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t length = 
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                ? context->commandLength
                : context->currentFieldLength - context->currentFieldPos);
        
        os_memmove(context->actionDataTypeBuffer + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentActionDataTypeNumber = context->currentFieldLength;

        parseActionData(context);

        context->state++;
        context->processingField = false;        
    }
}

/**
 * Process current action data field and store in into data buffer.
*/
static void processActionData(txProcessingContext_t *context) {
    if (context->currentFieldLength > sizeof(context->actionDataBuffer) - 1) {
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
        os_memmove(context->actionDataBuffer + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentActionIndex++;
        if (context->currentActionIndex == context->currentActionNumber) {
            // We processed last action field
            context->currentActionNumber = 0;
            context->currentActionIndex = 0;
            context->currentActionDataBufferLength = context->currentFieldLength;

            context->state++;
        } else {
            // still iterating
            context->state = TLV_ACTION_DATA;
        }
        
        context->processingField = false;
    }
}

static parserStatus_e processTxInternal(txProcessingContext_t *context) {
    for(;;) {
        if (context->state == TLV_DONE) {
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
        case TLV_CHAIN_ID:
        case TLV_HEADER_EXPITATION:
        case TLV_HEADER_REF_BLOCK_NUM:
        case TLV_HEADER_REF_BLOCK_PREFIX:
        case TLV_HEADER_MAX_CPU_USAGE_MS:
        case TLV_HEADER_MAX_NET_USAGE_WORDS:
        case TLV_HEADER_DELAY_SEC:
            processField(context);
            break;

        case TLV_CFA_LIST_SIZE:
            processZeroSizeField(context);
            break;

        case TLV_ACTION_LIST_SIZE:
            processActionListSizeField(context);
            break;

        case TLV_ACTION_ACCOUNT:
            processActionAccount(context);
            break;

        case TLV_ACTION_NAME:
            processActionName(context);
            break;

        case TLV_AUTHORIZATION_LIST_SIZE:
            processAuthorizationListSizeField(context);
            break;

        case TLV_AUTHORIZATION_ACTOR:
            processField(context);
            break;

        case TLV_AUTHORIZATION_PERMISSION:
            processAuthorizationPermission(context);
            break;
        
        case TLV_ACTION_DATA_SIZE:
            processField(context);
            break;
        
        case TLV_ACTION_DATA:
            processActionData(context);
            break;

        case TLV_ACTION_DATA_TYPES:
            processActionDataTypes(context);
            break;

        case TLV_TX_EXTENSION_LIST_SIZE:
            processZeroSizeField(context);
            break;

        case TLV_CONTEXT_FREE_DATA:
            processField(context);
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
 * All data is encoded by DER.ASN1 rules in plain way and serialized as a flat map.
 * 
 * Flat map is used in order to avoid nesting complexity.
 * 
 * Buffer serialization example:
 * [chain id][header][action number (N)][action 0][action 1]...[action N][]
 * Each field is encoded by DER rules.
 * Chain id field will be encoded next way:
 *  [Tag][Length][Value]
 * [0x04][ 0x20 ][chain id as octet string]
 * 
 * More infomation about DER Tag Length Value encoding is here: http://luca.ntop.org/Teaching/Appunti/asn1.html.
 * Only octet tag number is allowed. 
 * Value is encoded as octet string.
 * The length of the string is stored in Length byte(s)
 * 
 * Detailed flat map representation of incoming data:
 * [CHAIN ID][HEADER][CTX_FREE_ACTION_NUMBER][ACTION_NUMBER][ACTION 0][TX_EXTENSION_NUMBER][CTX_FREE_ACTION_DATA_NUMBER]
 * 
 * CHAIN ID:
 * [32 BYTES]
 * 
 * HEADER size may vary due to MAX_NET_USAGE_WORDS and DELAY_SEC serialization:
 * [EXPIRATION][REF_BLOCK_NUM][REF_BLOCK_PREFIX][MAX_NET_USAGE_WORDS][MAX_CPU_USAGE_MS][DELAY_SEC]
 * 
 * CTX_FREE_ACTION_NUMBER theoretically is not fixed due to serialization. Ledger accepts only 0 as encoded value.
 * ACTION_NUMBER theoretically is not fixed due to serialization. Ledger accepts only 1 as encoded value.
 * 
 * ACTION size may vary as authorization list and action data is dynamic:
 * [ACCOUNT][NAME][AUTHORIZATION_NUMBER][AUTHORIZATION 0][AUTHORIZATION 1]..[AUTHORIZATION N][ACTION_DATA]
 * ACCOUNT and NAME are 8 bytes long, both.
 * AUTHORIZATION_NUMBER theoretically is not fixed due to serialization.
 * ACTION_DATA is octet string of bytes.
 *  
 * AUTHORIZATION is 16 bytes long:
 * [ACTOR][PERMISSION]
 * ACTOR and PERMISSION are 8 bites long, both.
 * 
 * TX_EXTENSION_NUMBER theoretically is not fixed due to serialization. Ledger accepts only 0 as encoded value.
 * CTX_FREE_ACTION_DATA_NUMBER theoretically is not fixed due to serialization. Ledger accepts only 0 as encoded value.
*/
parserStatus_e parseTx(txProcessingContext_t *context, uint8_t *buffer, uint32_t length) {
    parserStatus_e result;
#ifdef DEBUG_APP
    // Do not catch exceptions.
    context->workBuffer = buffer;
    context->commandLength = length;
    result = processTxInternal(context);
#else
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
#endif
    return result;
}
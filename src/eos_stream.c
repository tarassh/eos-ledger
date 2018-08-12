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

#include <string.h>
#include "eos_stream.h"
#include "os.h"
#include "cx.h"
#include "eos_types.h"
#include "eos_utils.h"

#define EOSIO_TOKEN          0x5530EA033482A600
#define EOSIO_TOKEN_TRANSFER 0xCDCD3C2D57000000

#define EOSIO                0x5530EA0000000000
#define EOSIO_DELEGATEBW     0x4AA2A61B2A3F0000
#define EOSIO_UNDELEGATEBW   0xD4D2A8A986CA8FC0
#define EOSIO_VOTEPRODUCER   0xDD32AADE89D21570
#define EOSIO_BUYRAM         0x3EBD734800000000


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

static void parseNameField2(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(name_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));
    
    os_memmove(arg->label, fieldName, labelLength);
    name_t name = buffer_to_name_type(in, sizeof(name_t));
    uint32_t writtenToBuff = name_to_string(name, arg->data, sizeof(arg->data)-1);

    *read = sizeof(name_t);
    *written = writtenToBuff;
}

static void parseAssetField2(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(asset_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }

    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);
    asset_t asset;
    os_memmove(&asset, in, sizeof(asset));
    uint32_t writtenToBuff = asset_to_string(&asset, arg->data, sizeof(arg->data)-1); 

    *read = sizeof(asset_t);
    *written = writtenToBuff;
}

static void parseStringField2(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);

    uint32_t fieldLength = 0;
    uint32_t readFromBuffer = unpack_fc_unsigned_int(in, inLength, &fieldLength);
    if (fieldLength > sizeof(arg->data) - 1) {
        PRINTF("parseActionData Insufficient bufferg\n");
        THROW(EXCEPTION);
    } 

    if (inLength < fieldLength) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }

    in += readFromBuffer;
    inLength -= readFromBuffer;

    os_memmove(arg->data, in, fieldLength);

    in += fieldLength;
    inLength -= fieldLength;

    *read = readFromBuffer + fieldLength;
    *written = fieldLength;
}

static void appendNameToArgument(uint8_t *in, uint32_t inLength, actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(name_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }

    uint32_t dataLength = strlen(arg->data);
    uint32_t bytesLeft = sizeof(arg->data) - 1 - dataLength;
    if (bytesLeft == 0) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    
    name_t name = buffer_to_name_type(in, sizeof(name_t));
    uint32_t writtenToBuff = name_to_string(name, arg->data + dataLength, bytesLeft - 1);

    *read = sizeof(name_t);
    *written = writtenToBuff;
}

static void appendStringArgument(char *in, actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    uint32_t inLength = strlen(in);
    uint32_t dataLength = strlen(arg->data);
    uint32_t bytesLeft = sizeof(arg->data) - 1 - dataLength;
    if (bytesLeft == 0) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }

    if (inLength > bytesLeft) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }

    os_memmove(arg->data + dataLength, in, inLength);

    *read = inLength;
    *written = inLength;
}

/**
 * Parse eosio.token transfer action
*/
static void parseEosioTokenTransfer2(txProcessingContext_t *context) {

    uint32_t bufferLength = context->currentActionDataBufferLength;
    uint8_t *buffer = context->actionDataBuffer;

    uint32_t read = 0;
    uint32_t written = 0;

    parseNameField2(buffer, bufferLength, "From", &context->content->arg0, &read, &written);
    buffer += read; bufferLength -= read;

    parseNameField2(buffer, bufferLength, "To", &context->content->arg1, &read, &written);
    buffer += read; bufferLength -= read;

    parseAssetField2(buffer, bufferLength, "Quantity", &context->content->arg2, &read, &written);
    buffer += read; bufferLength -= read;
    
    parseStringField2(buffer, bufferLength, "Memo", &context->content->arg3, &read, &written);

    context->content->activeBuffers = 4;
}

static void parseEosioDelegateUndlegate2(txProcessingContext_t *context) {
    uint32_t bufferLength = context->currentActionDataBufferLength;
    uint8_t *buffer = context->actionDataBuffer;

    uint32_t read = 0;
    uint32_t written = 0;

    parseNameField2(buffer, bufferLength, "From", &context->content->arg0, &read, &written);
    buffer += read; bufferLength -= read;
    
    parseNameField2(buffer, bufferLength, "Receiver", &context->content->arg1, &read, &written);
    buffer += read; bufferLength -= read;
    
    parseAssetField2(buffer, bufferLength, "Network", &context->content->arg2, &read, &written);
    buffer += read; bufferLength -= read;
    
    parseAssetField2(buffer, bufferLength, "CPU", &context->content->arg3, &read, &written);

    context->content->activeBuffers = 4;
}

static void parseEosioBuyRam(txProcessingContext_t *context) {
    uint32_t bufferLength = context->currentActionDataBufferLength;
    uint8_t *buffer = context->actionDataBuffer;

    uint32_t read = 0;
    uint32_t written = 0;

    parseNameField2(buffer, bufferLength, "Buyer", &context->content->arg0, &read, &written);
    buffer += read; bufferLength -= read;

    parseNameField2(buffer, bufferLength, "Receiver", &context->content->arg1, &read, &written);
    buffer += read; bufferLength -= read;

    parseAssetField2(buffer, bufferLength, "Tokens", &context->content->arg2, &read, &written);

    context->content->activeBuffers = 3;
}

static void parseEosioVoteProducer(txProcessingContext_t *context) {
    uint32_t bufferLength = context->currentActionDataBufferLength;
    uint8_t *buffer = context->actionDataBuffer;

    uint32_t read = 0;
    uint32_t written = 0;

    parseNameField2(buffer, bufferLength, "Account", &context->content->arg0, &read, &written);
    buffer += read; bufferLength -= read;
    
    // Skip proxy
    buffer += read; bufferLength -= read;
    
    context->content->activeBuffers = 1;

    uint32_t totalProducers = 0;
    read = unpack_fc_unsigned_int(buffer, bufferLength, &totalProducers);
    buffer += read; bufferLength -= read;
    uint32_t loop = totalProducers > 8 ? 8 : totalProducers;
    uint32_t pages = (totalProducers / 8) + (totalProducers % 8 > 0 ? 1 : 0);

    char label[14];
    snprintf(label, sizeof(label), "[%d] .. %d", 1, pages);
    parseStringField2("", 0, label, &context->content->arg1, &read, &written);

    for (uint32_t i = 0; i < loop; ++i) {
        appendNameToArgument(buffer, bufferLength, &context->content->arg1, &read, &written);
        buffer += read; bufferLength -= read;
        appendStringArgument(" ", &context->content->arg1, &read, &written);
    }

    context->content->activeBuffers += 1;
    uint32_t producersLeft = totalProducers - loop;
    
    if (producersLeft > 0) {
        loop = producersLeft > 8 ? 8 : producersLeft;
        snprintf(label, sizeof(label), "1 [%d] .. %d", 2, pages);
        parseStringField2("", 0, label, &context->content->arg2, &read, &written);
        
        for (uint32_t i = 0; i < loop; ++i) {
            appendNameToArgument(buffer, bufferLength, &context->content->arg2, &read, &written);
            buffer += read; bufferLength -= read;
            appendStringArgument(" ", &context->content->arg2, &read, &written);
        }
        
        producersLeft -= loop;
        context->content->activeBuffers += 1;
    }
    
    if (producersLeft > 0) {
        loop = producersLeft > 8 ? 8 : producersLeft;
        snprintf(label, sizeof(label), "1 2 [%d] .. %d", 3, pages);
        parseStringField2("", 0, label, &context->content->arg3, &read, &written);
        
        for (uint32_t i = 0; i < loop; ++i) {
            appendNameToArgument(buffer, bufferLength, &context->content->arg3, &read, &written);
            buffer += read; bufferLength -= read;
            appendStringArgument(" ", &context->content->arg3, &read, &written);
        }
        
        producersLeft -= loop;
        context->content->activeBuffers += 1;
    }
    
    if (producersLeft > 0) {
        loop = producersLeft > 8 ? 8 : producersLeft;
        snprintf(label, sizeof(label), "1 2 3 [%d]", 4);
        parseStringField2("", 0, label, &context->content->arg4, &read, &written);
        
        for (uint32_t i = 0; i < loop; ++i) {
            appendNameToArgument(buffer, bufferLength, &context->content->arg4, &read, &written);
            buffer += read; bufferLength -= read;
            appendStringArgument(" ", &context->content->arg4, &read, &written);
        }
        
        producersLeft -= loop;
        context->content->activeBuffers += 1;
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
        uint32_t sizeValue = 0;
        unpack_fc_unsigned_int(context->sizeBuffer, context->currentFieldPos + 1, &sizeValue);
        if (sizeValue != 1) {
            PRINTF("processActionListSizeField Action Number must be 1\n");
            THROW(EXCEPTION);
        }
        // Reset size buffer
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
        
        uint8_t *pContract = (uint8_t *)&context->contractName;
        os_memmove(pContract + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->state++;
        context->processingField = false;

        os_memset(context->content->contract, 0, sizeof(context->content->contract));
        name_to_string(context->contractName, context->content->contract, sizeof(context->content->contract));
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

        uint8_t *pAction = (uint8_t *)&context->contractActionName;
        os_memmove(pAction + context->currentFieldPos, context->workBuffer, length);

        context->workBuffer += length;
        context->commandLength -= length;
        context->currentFieldPos += length;
    }

    if (context->currentFieldPos == context->currentFieldLength) {
        context->state++;
        context->processingField = false;

        os_memset(context->content->action, 0, sizeof(context->content->action));
        name_to_string(context->contractActionName, context->content->action, sizeof(context->content->action));
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
        context->currentActionDataBufferLength = context->currentFieldLength;

        if (context->contractActionName == EOSIO_TOKEN_TRANSFER) {
            parseEosioTokenTransfer2(context);
        } else if (context->contractName == EOSIO &&
                  (context->contractActionName == EOSIO_DELEGATEBW || 
                   context->contractActionName == EOSIO_UNDELEGATEBW)) {
            parseEosioDelegateUndlegate2(context);
        } else if (context->contractName == EOSIO && 
                   context->contractActionName == EOSIO_VOTEPRODUCER) {
            parseEosioVoteProducer(context);
        } else if (context->contractName == EOSIO && 
                   context->contractActionName == EOSIO_BUYRAM) {
            parseEosioBuyRam(context);
        } else {
            THROW(EXCEPTION);
        }
        context->state = TLV_TX_EXTENSION_LIST_SIZE;
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
 * [chain id][header][action number (1)][action 0][...]
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

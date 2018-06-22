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
    context->bytesLeftForState = sizeof(chain_id_t);
    cx_sha256_init(context->sha256);
}

/**
 * Raw Tx format:
 * 1. chain id. 
 * 2. header.
 * 3. context free actions
 * 4. actions
 * 5. transaction extensions
 * 6. context free data1
*/

/** 
 * Processing should be optimal. As we are accepting a chunks of data, so buffer size could
 * vary, depending on action data. 
 * Try to cache as little as possible as the RAM capasity isn't so big. 
 */
parserStatus_e parseTx(txProcessingContext_t *context, uint8_t *in, uint32_t size) {
    return 0;
}
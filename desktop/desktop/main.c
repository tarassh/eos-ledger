//
//  main.c
//  desktop
//
//  Created by Taras Shchybovyk on 8/10/18.
//  Copyright © 2018 Taras Shchybovyk. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "eos_types.h"
#include "eos_types.h"
#include "eos_stream.h"

txProcessingContext_t txProcessingCtx;
txProcessingContent_t txContent;
cx_sha256_t sha256;

static int hex_to_bytes(
                 const char *hex,
                 size_t hex_len,
                 uint8_t *buffer,
                 size_t buffer_len
                 ) {
    if (hex_len % 2 != 0) {
        return -1;
    }
    
    if (hex_len / 2 != buffer_len) {
        return -1;
    }
    
    const char *pos = hex;
    
    for (size_t count = 0; count < hex_len / 2; ++count) {
        sscanf(pos, "%2hhx", &buffer[count]);
        pos += 2;
    }
    return 0;
}

int main(int argc, const char * argv[]) {
#ifdef GOOD
    const char tx[] = "0420cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f0404d0d3495b040227190404f0f48eb204010004010004010004010004010104080000000000ea305504087015d289deaa32dd040101040810fc7566d15cfd45040800000000a8ed3232040179047910fc7566d15cfd4500000000000000000d80a932d3e5a9d8351030555d4db7b23b10f0a42ed25cfd45206952ea2e413055204dba2a63693055104208c1386c3055e0b3bbb4656d3055500f9bee3975305590293dd37577305500118d472d833055202932c94c833055301b9a744e83305550cf55d3a888305504010004200000000000000000000000000000000000000000000000000000000000000000";
#else
   const char tx[] = "0420cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f0404d0d3495b040227190404f0f48eb204010004010004010004010004010104080000000000ea305504087015d289deaa32dd040101040810fc7566d15cfd45040800000000a8ed32320402a1010481a110fc7566d15cfd4500000000000000001280a932d3e5a9d8351030555d4db7b23b10f0a42ed25cfd45206952ea2e413055204dba2a63693055104208c1386c3055e0b3bbb4656d3055500f9bee3975305590293dd37577305500118d472d833055202932c94c833055301b9a744e83305550cf55d3a888305570d5be0a239330558021a2b761b7305580af9134fbb830551029adee50dd3055e0b3dbe632ec305504010004200000000000000000000000000000000000000000000000000000000000000000";
#endif
    
    uint8_t buffer[strlen(tx)/2];
    hex_to_bytes(tx, strlen(tx), buffer, sizeof(buffer));
    
    initTxContext(&txProcessingCtx, &sha256, &txContent);
    parseTx(&txProcessingCtx, buffer, sizeof(buffer));
    
    puts(txContent.arg0.label);
    puts(txContent.arg0.data);
    puts(txContent.arg1.label);
    puts(txContent.arg1.data);
    puts(txContent.arg2.label);
    puts(txContent.arg2.data);
    puts(txContent.arg3.label);
    puts(txContent.arg3.data);
    puts(txContent.arg4.label);
    puts(txContent.arg4.data);
    
    return 0;
}

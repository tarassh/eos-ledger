//
//  cx.h
//  desktop
//
//  Created by Taras Shchybovyk on 8/10/18.
//  Copyright © 2018 Taras Shchybovyk. All rights reserved.
//

#ifndef cx_h
#define cx_h

typedef struct {
    int header;
} cx_sha256_t;

typedef struct {
    int header;
} cx_ripemd160_t;

typedef struct {
    
} cx_hmac_sha256_t;

typedef struct {
    
} cx_hmac_t;

#define cx_hash(x, y, z, l, m)
#define cx_hmac(x, y, z, l, m);
#define cx_hmac_sha256_init(x, y, z)
#define cx_ripemd160_init(x)
#define cx_sha256_init(x)

#define CX_LAST 0

#endif /* cx_h */

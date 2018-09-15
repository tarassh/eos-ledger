#pragma once

#include "os.h"

typedef struct internalStorage_t
{
    uint8_t dataAllowed;
    uint8_t initialized;
} internalStorage_t;

extern WIDE internalStorage_t N_storage_real;
#define N_storage (*(WIDE internalStorage_t *)PIC(&N_storage_real))

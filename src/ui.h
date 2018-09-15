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

#pragma once

// #include "os.h"
// #include "cx.h"
// #include <stdbool.h>

// #include "os_io_seproxyhal.h"
// #include "string.h"
// #include "eos_utils.h"
// #include "eos_stream.h"

// #include "glyphs.h"

// unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

// unsigned int io_seproxyhal_touch_settings(const bagl_element_t *e);
// unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
// unsigned int io_seproxyhal_touch_tx_ok(const bagl_element_t *e);
// unsigned int io_seproxyhal_touch_tx_cancel(const bagl_element_t *e);
// unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e);
// unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e);
void ui_idle(void);

// uint32_t set_result_get_publicKey(void);

// #define MAX_BIP32_PATH 10

// #define CLA 0xD4
// #define INS_GET_PUBLIC_KEY 0x02
// #define INS_SIGN 0x04
// #define INS_GET_APP_CONFIGURATION 0x06
// #define P1_CONFIRM 0x01
// #define P1_NON_CONFIRM 0x00
// #define P2_NO_CHAINCODE 0x00
// #define P2_CHAINCODE 0x01
// #define P1_FIRST 0x00
// #define P1_MORE 0x80

// #define OFFSET_CLA 0
// #define OFFSET_INS 1
// #define OFFSET_P1 2
// #define OFFSET_P2 3
// #define OFFSET_LC 4
// #define OFFSET_CDATA 5

void ui_address_display(void);
void ui_approval_display(void);

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

#include "os.h"
#include "cx.h"
#include <stdbool.h>

#include "os_io_seproxyhal.h"
#include "string.h"
#include "eos_utils.h"
#include "eos_stream.h"

#include "glyphs.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

unsigned int io_seproxyhal_touch_settings(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_tx_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_tx_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e);
void ui_idle(void);

uint32_t set_result_get_publicKey(void);

#define MAX_BIP32_PATH 10

#define CLA 0xE0
#define INS_GET_PUBLIC_KEY 0x02
#define INS_SIGN 0x04
#define INS_GET_APP_CONFIGURATION 0x06
#define P1_CONFIRM 0x01
#define P1_NON_CONFIRM 0x00
#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE 0x01
#define P1_FIRST 0x00
#define P1_MORE 0x80

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

const uint8_t SECP256K1_N[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                               0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                               0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

typedef struct publicKeyContext_t
{
    cx_ecfp_public_key_t publicKey;
    char address[60];
    uint8_t chainCode[32];
    bool getChaincode;
} publicKeyContext_t;

typedef struct transactionContext_t
{
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t hash[32];
} transactionContext_t;

cx_sha256_t sha256;

union {
    publicKeyContext_t publicKeyContext;
    transactionContext_t transactionContext;
} tmpCtx;

txProcessingContext_t txProcessingCtx;
txProcessingContent_t txContent;

volatile uint8_t dataAllowed;
volatile char fullAddress[60];
volatile bool dataPresent;
volatile bool skipWarning;

bagl_element_t tmp_element;

ux_state_t ux;
// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

typedef struct internalStorage_t
{
    uint8_t dataAllowed;
    uint8_t initialized;
} internalStorage_t;

WIDE internalStorage_t N_storage_real;
#define N_storage (*(WIDE internalStorage_t *)PIC(&N_storage_real))

const bagl_element_t *ui_menu_item_out_over(const bagl_element_t *e)
{
    // the selection rectangle is after the none|touchable
    e = (const bagl_element_t *)(((unsigned int)e) + sizeof(bagl_element_t));
    return e;
}

const ux_menu_entry_t menu_main[];
const ux_menu_entry_t menu_settings[];
const ux_menu_entry_t menu_settings_data[];

#ifdef HAVE_U2F

// change the setting
void menu_settings_data_change(unsigned int enabled)
{
    uint8_t dataAllowed = enabled;
    nvm_write(&N_storage.dataAllowed, (void *)&dataAllowed, sizeof(uint8_t));
    // go back to the menu entry
    UX_MENU_DISPLAY(0, menu_settings, NULL);
}

// show the currently activated entry
void menu_settings_data_init(unsigned int ignored) {
  UNUSED(ignored);
  UX_MENU_DISPLAY(N_storage.dataAllowed?1:0, menu_settings_data, NULL);
}

const ux_menu_entry_t menu_settings_data[] = {
    {NULL, menu_settings_data_change, 0, NULL, "No", NULL, 0, 0},
    {NULL, menu_settings_data_change, 1, NULL, "Yes", NULL, 0, 0},
    UX_MENU_END};

const ux_menu_entry_t menu_settings[] = {
    // {NULL, menu_settings_data_init, 0, NULL, "Arbitrary data", NULL, 0, 0},
    {menu_main, NULL, 1, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};
#endif // HAVE_U2F

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
    {menu_main, NULL, 2, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_main[] = {
    {NULL, NULL, 0, &C_nanos_badge_eos, "Use wallet to",
     "view accounts", 33, 12},
    {menu_settings, NULL, 0, NULL, "Settings", NULL, 0, 0},
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

const bagl_element_t ui_address_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  31,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_EYE_BADGE  }, NULL, 0, 0, 0,
    //NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Public Key",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Public Key",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     (char *)fullAddress,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_address_prepro(const bagl_element_t *element)
{
    if (element->component.userid > 0)
    {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display)
        {
            switch (element->component.userid)
            {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter);

const bagl_element_t ui_approval_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "action",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "WARNING",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Data present",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x03, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Contract",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x03, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     (char *)txContent.contract,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x04, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Action",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x04, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 50},
     (char *)txContent.action,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x05, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Data",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x05, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     (char *)txContent.data,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};

unsigned int ui_approval_prepro(const bagl_element_t *element)
{
    unsigned int display = 1;
    if (element->component.userid > 0)
    {
        display = (ux_step == element->component.userid - 1);
        if (display)
        {
            switch (element->component.userid)
            {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                if (dataPresent)
                {
                    UX_CALLBACK_SET_INTERVAL(3000);
                }
                else
                {
                    display = 0;
                    ux_step++; // display the next step
                }
                break;
            case 3:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            case 4:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            case 5:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
    }
    return display;
}

unsigned int ui_approval_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter);

void ui_idle(void)
{
    skipWarning = false;
    UX_MENU_DISPLAY(0, menu_main, NULL);
}

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e)
{
    // Go back to the dashboard
    os_sched_exit(0);
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e)
{
    uint32_t tx = set_result_get_publicKey();
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e)
{
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter)
{
    switch (button_mask)
    {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_address_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
    { // OK
        io_seproxyhal_touch_address_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned int io_seproxyhal_touch_tx_ok(const bagl_element_t *e)
{
    uint8_t privateKeyData[64];
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;
    uint8_t V[33];
    uint8_t K[32];
    int tries = 0;

    os_perso_derive_node_bip32(
        CX_CURVE_256K1, tmpCtx.transactionContext.bip32Path,
        tmpCtx.transactionContext.pathLength, privateKeyData, NULL);
    cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
    os_memset(privateKeyData, 0, sizeof(privateKeyData));

    // Loop until a candidate matching the canonical signature is found

    for (;;)
    {
        if (tries == 0)
        {
            rng_rfc6979(G_io_apdu_buffer + 100, tmpCtx.transactionContext.hash, privateKey.d, privateKey.d_len, SECP256K1_N, 32, V, K);
        }
        else
        {
            rng_rfc6979(G_io_apdu_buffer + 100, tmpCtx.transactionContext.hash, NULL, 0, SECP256K1_N, 32, V, K);
        }
        uint32_t infos;
        tx = cx_ecdsa_sign(&privateKey, CX_NO_CANONICAL | CX_RND_PROVIDED | CX_LAST, CX_SHA256,
                           tmpCtx.transactionContext.hash,
                           32, G_io_apdu_buffer + 100, &infos);
        if ((infos & CX_ECCINFO_PARITY_ODD) != 0)
        {
            G_io_apdu_buffer[100] |= 0x01;
        }
        G_io_apdu_buffer[0] = 27 + 4 + (G_io_apdu_buffer[100] & 0x01);
        ecdsa_der_to_sig(G_io_apdu_buffer + 100, G_io_apdu_buffer + 1);
        if (check_canonical(G_io_apdu_buffer + 1))
        {
            tx = 1 + 64;
            break;
        }
        else
        {
            tries++;
        }
    }

    os_memset(&privateKey, 0, sizeof(privateKey));
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();

    return 0; // do not redraw the widge
}

unsigned int io_seproxyhal_touch_tx_cancel(const bagl_element_t *e)
{
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int ui_approval_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter)
{
    switch (button_mask)
    {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_tx_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
    {
        io_seproxyhal_touch_tx_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len)
{
    switch (channel & ~(IO_FLAGS))
    {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len)
        {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED)
            {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        }
        else
        {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

uint32_t set_result_get_publicKey()
{
    uint32_t tx = 0;
    G_io_apdu_buffer[tx++] = 65;
    os_memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.publicKey.W, 65);
    tx += 65;

    uint32_t addressLength = strlen(tmpCtx.publicKeyContext.address);

    G_io_apdu_buffer[tx++] = addressLength;
    os_memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.address, addressLength);
    tx += addressLength;
    if (tmpCtx.publicKeyContext.getChaincode)
    {
        os_memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.chainCode,
                   32);
        tx += 32;
    }
    return tx;
}

void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                        uint16_t dataLength, volatile unsigned int *flags,
                        volatile unsigned int *tx)
{
    UNUSED(dataLength);
    uint8_t privateKeyData[32];
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint32_t i;
    uint8_t bip32PathLength = *(dataBuffer++);
    cx_ecfp_private_key_t privateKey;

    if ((bip32PathLength < 0x01) || (bip32PathLength > MAX_BIP32_PATH))
    {
        PRINTF("Invalid path\n");
        THROW(0x6a80);
    }
    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM))
    {
        THROW(0x6B00);
    }
    if ((p2 != P2_CHAINCODE) && (p2 != P2_NO_CHAINCODE))
    {
        THROW(0x6B00);
    }
    for (i = 0; i < bip32PathLength; i++)
    {
        bip32Path[i] = (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
                       (dataBuffer[2] << 8) | (dataBuffer[3]);
        dataBuffer += 4;
    }
    tmpCtx.publicKeyContext.getChaincode = (p2 == P2_CHAINCODE);
    os_perso_derive_node_bip32(CX_CURVE_256K1, bip32Path, bip32PathLength,
                               privateKeyData,
                               (tmpCtx.publicKeyContext.getChaincode
                                    ? tmpCtx.publicKeyContext.chainCode
                                    : NULL));
    cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &tmpCtx.publicKeyContext.publicKey,
                          &privateKey, 1);
    os_memset(&privateKey, 0, sizeof(privateKey));
    os_memset(privateKeyData, 0, sizeof(privateKeyData));
    public_key_to_wif(tmpCtx.publicKeyContext.publicKey.W, sizeof(tmpCtx.publicKeyContext.publicKey.W),
                      tmpCtx.publicKeyContext.address, sizeof(tmpCtx.publicKeyContext.address));
    if (p1 == P1_NON_CONFIRM)
    {
        *tx = set_result_get_publicKey();
        THROW(0x9000);
    }
    else
    {
        // prepare for a UI based reply
        skipWarning = false;
        snprintf(fullAddress, sizeof(fullAddress), "%.*s", strlen(tmpCtx.publicKeyContext.address),
                 tmpCtx.publicKeyContext.address);
        ux_step = 0;
        ux_step_count = 2;
        UX_DISPLAY(ui_address_nanos, ui_address_prepro);

        *flags |= IO_ASYNCH_REPLY;
    }
}

void handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                               uint16_t dataLength,
                               volatile unsigned int *flags,
                               volatile unsigned int *tx)
{
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);
    UNUSED(flags);
    G_io_apdu_buffer[0] = (N_storage.dataAllowed ? 0x01 : 0x00);
    G_io_apdu_buffer[1] = LEDGER_MAJOR_VERSION;
    G_io_apdu_buffer[2] = LEDGER_MINOR_VERSION;
    G_io_apdu_buffer[3] = LEDGER_PATCH_VERSION;
    *tx = 4;
    THROW(0x9000);
}

void handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                uint16_t dataLength, volatile unsigned int *flags,
                volatile unsigned int *tx)
{
    uint32_t i;
    parserStatus_e txResult;
    if (p1 == P1_FIRST)
    {
        tmpCtx.transactionContext.pathLength = workBuffer[0];
        if ((tmpCtx.transactionContext.pathLength < 0x01) ||
            (tmpCtx.transactionContext.pathLength > MAX_BIP32_PATH))
        {
            PRINTF("Invalid path\n");
            THROW(0x6a80);
        }
        workBuffer++;
        dataLength--;
        for (i = 0; i < tmpCtx.transactionContext.pathLength; i++)
        {
            tmpCtx.transactionContext.bip32Path[i] =
                (workBuffer[0] << 24) | (workBuffer[1] << 16) |
                (workBuffer[2] << 8) | (workBuffer[3]);
            workBuffer += 4;
            dataLength -= 4;
        }
        dataPresent = false;
        initTxContext(&txProcessingCtx, &sha256, &txContent);
    }
    else if (p1 != P1_MORE)
    {
        THROW(0x6B00);
    }
    if (p2 != 0)
    {
        THROW(0x6B00);
    }
    if (txProcessingCtx.state == TLV_NONE)
    {
        PRINTF("Parser not initialized\n");
        THROW(0x6985);
    }
    txResult = parseTx(&txProcessingCtx, workBuffer, dataLength);
    switch (txResult)
    {
    case STREAM_FINISHED:
        break;
    case STREAM_PROCESSING:
        THROW(0x9000);
    case STREAM_FAULT:
        THROW(0x6A80);
    default:
        PRINTF("Unexpected parser status\n");
        THROW(0x6A80);
    }

    // store hash
    cx_hash(&sha256.header, CX_LAST, tmpCtx.transactionContext.hash, 0,
            tmpCtx.transactionContext.hash);

    skipWarning = !dataPresent;
    ux_step = 0;
    ux_step_count = 5;
    UX_DISPLAY(ui_approval_nanos, ui_approval_prepro);

    *flags |= IO_ASYNCH_REPLY;
}

void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx)
{
    unsigned short sw = 0;

    BEGIN_TRY
    {
        TRY
        {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA)
            {
                THROW(0x6E00);
            }

            switch (G_io_apdu_buffer[OFFSET_INS])
            {
            case INS_GET_PUBLIC_KEY:
                handleGetPublicKey(G_io_apdu_buffer[OFFSET_P1],
                                   G_io_apdu_buffer[OFFSET_P2],
                                   G_io_apdu_buffer + OFFSET_CDATA,
                                   G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            case INS_SIGN:
                handleSign(G_io_apdu_buffer[OFFSET_P1],
                           G_io_apdu_buffer[OFFSET_P2],
                           G_io_apdu_buffer + OFFSET_CDATA,
                           G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            case INS_GET_APP_CONFIGURATION:
                handleGetAppConfiguration(
                    G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
                    G_io_apdu_buffer + OFFSET_CDATA,
                    G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            default:
                THROW(0x6D00);
                break;
            }
        }
        CATCH(EXCEPTION_IO_RESET)
        {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e)
        {
            switch (e & 0xF000)
            {
            case 0x6000:
                // Wipe the transaction context and report the exception
                sw = e;
                break;
            case 0x9000:
                // All is well
                sw = e;
                break;
            default:
                // Internal error
                sw = 0x6800 | (e & 0x7FF);
                break;
            }
            // Unexpected exception => report
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY
        {
        }
    }
    END_TRY;
}

void sample_main(void)
{
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;)
    {
        volatile unsigned short sw = 0;

        BEGIN_TRY
        {
            TRY
            {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0)
                {
                    THROW(0x6982);
                }

                handleApdu(&flags, &tx);
            }
            CATCH(EXCEPTION_IO_RESET)
            {
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e)
            {
                switch (e & 0xF000)
                {
                case 0x6000:
                    // Wipe the transaction context and report the exception
                    sw = e;
                    break;
                case 0x9000:
                    // All is well
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY
            {
            }
        }
        END_TRY;
    }

    // return_to_dashboard:
    return;
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element)
{
    io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel)
{
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0])
    {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED))
        {
            THROW(EXCEPTION_IO_RESET);
        }
    // no break is intentional
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            if (UX_ALLOWED)
            {
                if (skipWarning && (ux_step == 0))
                {
                    ux_step++;
                }

                if (ux_step_count)
                {
                    // prepare next screen
                    ux_step = (ux_step + 1) % ux_step_count;
                    // redisplay screen
                    UX_REDISPLAY();
                }
            }
        });
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent())
    {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void app_exit(void)
{
    BEGIN_TRY_L(exit)
    {
        TRY_L(exit)
        {
            os_sched_exit(-1);
        }
        FINALLY_L(exit)
        {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void)
{
    // exit critical section
    __asm volatile("cpsie i");

    for (;;)
    {
        UX_INIT();

        // ensure exception will work as planned
        os_boot();

        BEGIN_TRY
        {
            TRY
            {
                io_seproxyhal_init();

                if (N_storage.initialized != 0x01)
                {
                    internalStorage_t storage;
                    storage.dataAllowed = 0x00;
                    storage.initialized = 0x01;
                    nvm_write(&N_storage, (void *)&storage,
                              sizeof(internalStorage_t));
                }

                USB_power(0);
                USB_power(1);

                ui_idle();

                sample_main();
            }
            CATCH(EXCEPTION_IO_RESET)
            {
                // reset IO and UX before continuing
                continue;
            }
            CATCH_ALL
            {
                break;
            }
            FINALLY
            {
            }
        }
        END_TRY;
    }
    app_exit();

    return 0;
}

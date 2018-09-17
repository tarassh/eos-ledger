#include "ui.h"

#include "os_io_seproxyhal.h"
#include "glyphs.h"

#define SHOW_TEST_ADDRESS false
#define SHOW_TEST_TRANSACTION false

#ifdef TARGET_BLUE

#define COLOR_TOP_BG                0x443F54
#define COLOR_TOP_TEXT              0xFFFFFF
#define COLOR_MAIN_BG               0xF9F9F9
#define COLOR_ITEM_LABEL            0x999999
#define COLOR_ITEM_TEXT             0x000000
#define COLOR_REJECT_BUTTON_UP      0xB7B7B7
#define COLOR_REJECT_BUTTON_DOWN    0xCCCCCC
#define COLOR_CONFIRM_BUTTON_UP     0x71698c
#define COLOR_CONFIRM_BUTTON_DOWN   0x5a5470

#define UI_BUTTON_STYLE (BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE)

#define FONT_ITEM_LABEL             BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX
#define FONT_ITEM_TEXT              BAGL_FONT_OPEN_SANS_REGULAR_10_13PX
#define FONT_ITEM_TEXT_AVG_WIDTH    8

static const bagl_element_t *ui_details_display(const bagl_element_t *element);
static const bagl_element_t *ui_details_return(const bagl_element_t *element);

static bagl_element_t tmp_element;

ux_state_t ux;
txProcessingContent_t txContent;

#define TX_CONTENT_ARG(arg)     (&txContent.arg0 + (arg))

// TODO: actual font metrics, this method (which is used in a lot of the ledger apps) is not so great
#define MAX_CHAR_PER_LINE 28
static char displayLine[MAX_CHAR_PER_LINE+1];

#define MAX_ADDRESS_LEN         59
static size_t fullAddressLen;
static char fullAddress[MAX_ADDRESS_LEN + 1];

static uint8_t ui_details_arg_number;
static size_t ui_details_arg_data_len;

#define UI_BACKGROUND                                                                                   \
    /* content area background */                                                                       \
    {                                                                                                   \
        {BAGL_RECTANGLE, 0x00, 0, 68, 320, 412, 0, 0, BAGL_FILL,                                        \
            COLOR_MAIN_BG, COLOR_MAIN_BG, 0, 0},                                                        \
        NULL, 0, 0, 0, NULL, NULL, NULL,                                                                \
    },                                                                                                  \
    /* status bar background */                                                                         \
    {                                                                                                   \
        {BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL,                                         \
            COLOR_TOP_BG, COLOR_TOP_BG, 0, 0},                                                          \
        NULL, 0, 0, 0, NULL, NULL, NULL,                                                                \
    }

#define UI_STATUS_BAR_TEXT(text, id, font)                                                              \
    {                                                                                                   \
        {BAGL_LABELINE, id, 0, 45, 320, 60, 0, 0, BAGL_FILL,                                            \
            COLOR_TOP_TEXT, COLOR_TOP_BG, font | BAGL_FONT_ALIGNMENT_CENTER, 0},                        \
        text, 0, 0, 0, NULL, NULL, NULL,                                                                \
    }

#define UI_TOP_LEFT_BUTTON(symbol, callback)                                                            \
    {                                                                                                   \
        {BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 19, 56, 44, 0, 0, BAGL_FILL,                    \
            COLOR_TOP_BG, COLOR_TOP_TEXT,                                                               \
        BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0},              \
        symbol, 0, COLOR_TOP_BG, 0xFFFFFF, callback, NULL, NULL                                         \
    }

#define UI_BACK_BUTTON(back_cb)                                                                         \
    UI_TOP_LEFT_BUTTON(BAGL_FONT_SYMBOLS_0_LEFT, back_cb)

#define UI_TOP_RIGHT_BUTTON(symbol, callback)                                                           \
    {                                                                                                   \
        {BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0, BAGL_FILL,                  \
            COLOR_TOP_BG, COLOR_TOP_TEXT,                                                               \
            BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0},          \
        symbol, 0, COLOR_TOP_BG, 0xFFFFFF, io_seproxyhal_touch_exit, NULL, NULL                         \
    }

#define UI_EXIT_BUTTON                                                                                  \
    UI_TOP_RIGHT_BUTTON(BAGL_FONT_SYMBOLS_0_DASHBOARD, io_seproxyhal_touch_exit)

#define UI_REJECT_CONFIRM_BUTTONS(y, reject_cb, confirm_cb)                                             \
    {                                                                                                   \
        {BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 40, y, 115, 36, 0, 18, BAGL_FILL,                  \
            COLOR_REJECT_BUTTON_UP, COLOR_MAIN_BG, UI_BUTTON_STYLE, 0},                                 \
        "REJECT", 0, COLOR_REJECT_BUTTON_DOWN, COLOR_MAIN_BG, reject_cb, NULL, NULL                     \
    },                                                                                                  \
    {                                                                                                   \
        {BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 165, y, 115, 36, 0, 18, BAGL_FILL,                 \
            COLOR_CONFIRM_BUTTON_UP, COLOR_MAIN_BG, UI_BUTTON_STYLE, 0},                                \
        "CONFIRM", 0, COLOR_CONFIRM_BUTTON_DOWN, COLOR_MAIN_BG, confirm_cb, NULL, NULL                  \
    }

#define UI_ITEM_LABEL(y, id, text)                                                                      \
    {                                                                                                   \
        {BAGL_LABELINE, id << 4, 30, y, 320, 30, 0, 0, BAGL_FILL, COLOR_ITEM_LABEL, COLOR_MAIN_BG,      \
        FONT_ITEM_LABEL, 0},                                                                            \
        text, 0, 0, 0, NULL, NULL, NULL                                                                 \
    }

#define UI_ITEM_TEXT_Y(item_y, line)    ((item_y) + 20 + (line) * 20)

#define UI_ITEM_TEXT(item_y, id, line, text)                                                            \
    {                                                                                                   \
        {BAGL_LABELINE, (id << 4) | line, 30, UI_ITEM_TEXT_Y(item_y, line), 260, 30, 0, 0, BAGL_FILL,   \
            COLOR_ITEM_TEXT, COLOR_MAIN_BG, FONT_ITEM_TEXT, 0},                                         \
        text, 0, 0, 0, NULL, NULL, NULL                                                                 \
    } 

#define UI_ITEM_MULTILINE_TEXT(item_y, id, line)                                                        \
    UI_ITEM_TEXT(item_y, id, line, displayLine)

#define UI_ITEM_TEXT_ID(element)   (element->component.userid >> 4)
#define UI_ITEM_TEXT_LINE(element) (element->component.userid & 0x0f)

#define UI_ITEM_TEXT_WITH_DETAILS(item_y, id, text)                                                     \
    UI_ITEM_TEXT(item_y, id, 0, text),                                                                  \
    {                                                                                                   \
        {BAGL_LABELINE, 0xff, 284, UI_ITEM_TEXT_Y(item_y, 0), 6, 16, 0, 0, BAGL_FILL,                   \
            COLOR_ITEM_LABEL, COLOR_MAIN_BG, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},       \
        BAGL_FONT_SYMBOLS_0_MINIRIGHT, 0, 0, 0, NULL, NULL, NULL,                                       \
    },                                                                                                  \
    {                                                                                                   \
        {BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0xfe, 0, UI_ITEM_TEXT_Y(item_y, 0)-21, 320, 34, 0, 9,         \
            BAGL_FILL, 0xFFFFFF, 0x000000, 0, 0},                                                       \
        NULL, 0, 0xEEEEEE, 0x000000, ui_details_display, NULL, NULL                            \
    }

static void ui_item_text_populate(uint8_t item_id, const bagl_element_t *element, const char* string, size_t string_len) {
    if (UI_ITEM_TEXT_ID(element) == item_id) {
        uint16_t line = UI_ITEM_TEXT_LINE(element);
        uint16_t offset = line * MAX_CHAR_PER_LINE;
        
        os_memset(displayLine, 0, sizeof(displayLine));
        
        if (offset < string_len) {
            os_memcpy(displayLine, string + offset, MIN(MAX_CHAR_PER_LINE, string_len - offset));
        }
    }
}

static const bagl_element_t const ui_idle_blue[] = {
    UI_BACKGROUND,
    UI_STATUS_BAR_TEXT("EOS", 0, BAGL_FONT_OPEN_SANS_LIGHT_14px),
    // UI_TOP_LEFT_BUTTON(BAGL_FONT_SYMBOLS_0_SETTINGS, io_seproxyhal_touch_settings),

    {
        {BAGL_ICON, 0x00, 135, 178, 50, 50, 0, 0, BAGL_FILL, 0, COLOR_MAIN_BG, 0, 0},
        &C_blue_badge_eos, 0, 0, 0, NULL, NULL, NULL
    },
    {
        {BAGL_LABELINE, 0x00, 0, 270, 320, 30, 0, 0, BAGL_FILL, 0x000000, COLOR_MAIN_BG, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX|BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Open your wallet", 0, 0, 0, NULL, NULL, NULL
    },
    {
        {BAGL_LABELINE, 0x00, 0, 308, 320, 30, 0, 0, BAGL_FILL, 0x000000, COLOR_MAIN_BG, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX|BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Connect your Ledger Blue and open your", 0, 0, 0, NULL, NULL, NULL
    },
    {
        {BAGL_LABELINE, 0x00, 0, 331, 320, 30, 0, 0, BAGL_FILL, 0x000000, COLOR_MAIN_BG, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX|BAGL_FONT_ALIGNMENT_CENTER, 0},
        "preferred wallet to view your accounts.", 0, 0, 0, NULL, NULL, NULL
    },


    UI_EXIT_BUTTON
};

static unsigned int ui_idle_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return 0;
}

static const bagl_element_t const ui_address_blue[] = {
    UI_BACKGROUND,
    UI_STATUS_BAR_TEXT("Confirm Address", 0, BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX),

    UI_ITEM_LABEL(106, 0, "Public Key"),
    UI_ITEM_MULTILINE_TEXT(106, 1, 0),
    UI_ITEM_MULTILINE_TEXT(106, 1, 1),
    UI_ITEM_MULTILINE_TEXT(106, 1, 2),

    UI_REJECT_CONFIRM_BUTTONS(414, io_seproxyhal_touch_address_cancel, io_seproxyhal_touch_address_ok),

#if SHOW_TEST_ADDRESS
    UI_EXIT_BUTTON,
#endif
};

static unsigned int ui_address_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return 0;
}

static const bagl_element_t *ui_address_prepro(const bagl_element_t *element) {
    ui_item_text_populate(1, element, fullAddress, fullAddressLen);

    return element;
}

static const bagl_element_t const ui_approval_blue[] = {
    UI_BACKGROUND,
    UI_STATUS_BAR_TEXT("Confirm Transaction", 0, BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX),

    UI_ITEM_LABEL(106, 0, "Contract/Action"),
    UI_ITEM_TEXT(106, 7, 0, displayLine),

    UI_ITEM_LABEL(158, 1, txContent.arg0.label),
    UI_ITEM_TEXT_WITH_DETAILS(158, 1, txContent.arg0.data),

    UI_ITEM_LABEL(210, 2, txContent.arg1.label),
    UI_ITEM_TEXT_WITH_DETAILS(210, 2, txContent.arg1.data),

    UI_ITEM_LABEL(262, 3, txContent.arg2.label),
    UI_ITEM_TEXT_WITH_DETAILS(262, 3, txContent.arg2.data),

    UI_ITEM_LABEL(314, 4, txContent.arg3.label),
    UI_ITEM_TEXT_WITH_DETAILS(314, 4, txContent.arg3.data),

    UI_ITEM_LABEL(366, 5, txContent.arg4.label),
    UI_ITEM_TEXT_WITH_DETAILS(366, 5, txContent.arg4.data),

    // TODO view for more tx details - longer "data" fields, and the rest of them

    UI_REJECT_CONFIRM_BUTTONS(414, io_seproxyhal_touch_tx_cancel, io_seproxyhal_touch_tx_ok),

#if SHOW_TEST_TRANSACTION
    UI_EXIT_BUTTON,
#endif
};

static unsigned int ui_approval_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return 0;
}

static const bagl_element_t *ui_approval_prepro(const bagl_element_t *element) {
    const size_t overflow_size_reduce = 18;

    if (element->component.userid & 0xf0 == 0xf0) {
        const bagl_element_t *text_element = element + (int8_t) element->component.userid;

        if (UI_ITEM_TEXT_ID(text_element) > txContent.activeBuffers) {
            return NULL;
        }

        size_t text_len = strlen(text_element->text) * FONT_ITEM_TEXT_AVG_WIDTH;
        if (text_len < text_element->component.width) {
            return NULL;
        }
    } else if (UI_ITEM_TEXT_ID(element) == 7) {
        // the "contract/action" item
        snprintf(displayLine, MAX_CHAR_PER_LINE, "%s/%s", txContent.contract, txContent.action);
    } else if (UI_ITEM_TEXT_ID(element) > txContent.activeBuffers) {
        // an 'arg#' item that is not in use
        return NULL;
    } else if (UI_ITEM_TEXT_ID(element) > 0) {
        // an 'arg#' item that might overflow
        size_t text_len = strlen(element->text) * FONT_ITEM_TEXT_AVG_WIDTH;
        if (text_len >= element->component.width) {
            os_memcpy(&tmp_element, element, sizeof(tmp_element));
            tmp_element.component.width -= overflow_size_reduce;
            return &tmp_element;
        }
    }

    return element;
}

static const bagl_element_t const ui_details_blue[] = {
    UI_BACKGROUND,
    UI_STATUS_BAR_TEXT(displayLine, 0x01, BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX),
    UI_BACK_BUTTON(ui_details_return),

    UI_ITEM_MULTILINE_TEXT(86, 1, 0),
    UI_ITEM_MULTILINE_TEXT(86, 1, 1),
    UI_ITEM_MULTILINE_TEXT(86, 1, 2),
    UI_ITEM_MULTILINE_TEXT(86, 1, 3),
    UI_ITEM_MULTILINE_TEXT(86, 1, 4),

#if SHOW_TEST_TRANSACTION
    UI_EXIT_BUTTON,
#endif
};

static unsigned int ui_details_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return 0;
}

static const bagl_element_t *ui_details_prepro(const bagl_element_t *element) {
    const actionArgument_t *arg = TX_CONTENT_ARG(ui_details_arg_number - 1);

    if (ui_details_arg_number < 1) arg = NULL; // reserved for txContent.data if present (not yet implemented)
    if (ui_details_arg_number > 5) arg = NULL; // arg# out of range

    if (element->component.userid == 0x01) {
        // title bar
        const char *title = arg ? arg->label : "BORKED";
        os_memset(displayLine, 0, sizeof(displayLine));
        os_memcpy(displayLine, title, strlen(title));
    } else if (arg) {
        ui_item_text_populate(1, element, arg->data, ui_details_arg_data_len);
    }

    return element;
}

static const bagl_element_t *ui_details_return(const bagl_element_t *element) {
    UX_DISPLAY(ui_approval_blue, ui_approval_prepro);

    return NULL;
}

void ui_idle(void) {
    UX_SET_STATUS_BAR_COLOR(0xFFFFFF, COLOR_TOP_BG);

#if SHOW_TEST_ADDRESS
    // public key of "eos" account at time of writing
    ui_address_display("EOS8M5bo7oz2bNU9hVHD97abxWN1ttgfFQFBWVvWV54vDHAyjfKAA");

#elif SHOW_TEST_TRANSACTION
    // a test transaction with maximum possible length for several fields
    strcpy(txContent.contract, "contract12345");
    strcpy(txContent.action, "action1234567");

    txContent.activeBuffers=5;
    strcpy(txContent.arg0.label, "thingythingy1");
    strcpy(txContent.arg0.data, "this is the data from arg0. it is 127 bytes long. well, it will be when i'm done typing it. it's still not done. ok now it is!!");

    strcpy(txContent.arg1.label, "item 2");
    strcpy(txContent.arg1.data, "item 2 isn't as long");

    strcpy(txContent.arg2.label, "thing 3");
    strcpy(txContent.arg2.data, "123456789012345678901234567890123456");

    strcpy(txContent.arg3.label, "another");
    strcpy(txContent.arg3.data, "illilililillillillillillllillilillil");

    strcpy(txContent.arg4.label, "the last one");
    strcpy(txContent.arg4.data, "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww");

    ui_approval_display(false);
#else
    UX_DISPLAY(ui_idle_blue, NULL);
#endif
}

void ui_settings_display(void) {
    // TODO
}

void ui_address_display(const char *address) {
    fullAddressLen = strlen(address);
    if (fullAddressLen >= MAX_ADDRESS_LEN) {
        fullAddressLen = MAX_ADDRESS_LEN;
    }
    strncpy(fullAddress, address, fullAddressLen);
    fullAddress[MAX_ADDRESS_LEN] = '\0';

    UX_DISPLAY(ui_address_blue, ui_address_prepro);
}

void ui_approval_display(bool dataPresent) {
    UX_DISPLAY(ui_approval_blue, ui_approval_prepro);
}

static const bagl_element_t *ui_details_display(const bagl_element_t *element) {
    const bagl_element_t *text_element = element - 2;

    // arg = 1 to 5. reserving 0 for later when dataPresent can be true
    uint8_t arg = UI_ITEM_TEXT_ID(text_element);
    ui_details_arg_number = arg;

    if (arg > 0 && arg <= 5) {
        ui_details_arg_data_len = strlen(TX_CONTENT_ARG(arg - 1)->data);
        UX_DISPLAY(ui_details_blue, ui_details_prepro);
    }

    return NULL;
}

bool ui_needs_redisplay(void) {
    return true;
}

#endif // TARGET_BLUE

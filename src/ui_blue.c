#include "ui.h"

#include "os_io_seproxyhal.h"

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

ux_state_t ux;
txProcessingContent_t txContent;

#define MAX_CHAR_PER_LINE 28
static char displayLine[MAX_CHAR_PER_LINE+1];

#define MAX_ADDRESS_LEN         59
size_t fullAddressLen;
char fullAddress[MAX_ADDRESS_LEN + 1];

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

#define UI_STATUS_BAR_TEXT(text, font)                                                                  \
    {                                                                                                   \
        {BAGL_LABELINE, 0x00, 0, 45, 320, 60, 0, 0, BAGL_FILL,                                          \
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

#define UI_EXIT_BUTTON                                                                                  \
    {                                                                                                   \
        {BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0, BAGL_FILL,                  \
         COLOR_TOP_BG, COLOR_TOP_TEXT,                                                                  \
        BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0},              \
        BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, COLOR_TOP_BG, 0xFFFFFF, io_seproxyhal_touch_exit, NULL, NULL  \
    }

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

#define UI_ITEM_LABEL(y, text)                                                                          \
    {                                                                                                   \
        {BAGL_LABELINE, 0x00, 30, y, 320, 30, 0, 0, BAGL_FILL, COLOR_ITEM_LABEL, COLOR_MAIN_BG,         \
        BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},                                                        \
        text, 0, 0, 0, NULL, NULL, NULL                                                                 \
    }

#define UI_ITEM_TEXT_Y(item_y, line)    ((item_y) + 30 + (line) * 23)

#define _UI_ITEM_TEXT(item_y, id, line, text)                                                           \
    {                                                                                                   \
        {BAGL_LABELINE, id, 30, UI_ITEM_TEXT_Y(item_y, line), 260, 30, 0, 0, BAGL_FILL,                 \
            COLOR_ITEM_TEXT, COLOR_MAIN_BG, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},                    \
        text, 0, 0, 0, NULL, NULL, NULL                                                                 \
    } 

#define UI_ITEM_TEXT(item_y, text)                                                                      \
    _UI_ITEM_TEXT(item_y, 0, 0, text)

#define UI_ITEM_MULTILINE_TEXT(item_y, id, line)                                                        \
    _UI_ITEM_TEXT(item_y, (id << 4) | line, line, displayLine)

#define UI_ITEM_TEXT_ID(element)   (element->component.userid >> 4)
#define UI_ITEM_TEXT_LINE(element) (element->component.userid & 0x0f)

void ui_item_text_populate(uint8_t item_id, const bagl_element_t *element, const char* string, size_t string_len) {
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
    UI_STATUS_BAR_TEXT("EOS", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    UI_TOP_LEFT_BUTTON(BAGL_FONT_SYMBOLS_0_SETTINGS, io_seproxyhal_touch_settings),
    UI_EXIT_BUTTON
};

unsigned int ui_idle_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return 0;
}

static const bagl_element_t const ui_address_blue[] = {
    UI_BACKGROUND,
    UI_STATUS_BAR_TEXT("Confirm Address", BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX),

    UI_ITEM_LABEL(106, "Public Key"),
    UI_ITEM_MULTILINE_TEXT(106, 1, 0),
    UI_ITEM_MULTILINE_TEXT(106, 1, 1),
    UI_ITEM_MULTILINE_TEXT(106, 1, 2),

    UI_REJECT_CONFIRM_BUTTONS(414, io_seproxyhal_touch_address_cancel, io_seproxyhal_touch_address_ok),
};

unsigned int ui_address_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t *ui_address_prepro(const bagl_element_t *element) {
    ui_item_text_populate(1, element, fullAddress, fullAddressLen);

    return element;
}

static const bagl_element_t const ui_approval_blue[] = {
    UI_BACKGROUND,
    UI_STATUS_BAR_TEXT("Confirm Transaction", BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX),

    UI_ITEM_LABEL(106, "Contract"),
    UI_ITEM_TEXT(106, txContent.contract),

    UI_ITEM_LABEL(175, "Action"),
    UI_ITEM_TEXT(175, txContent.action),

    UI_ITEM_LABEL(244, txContent.arg0.label),
    UI_ITEM_TEXT(244, txContent.arg0.data),

    UI_ITEM_LABEL(313, txContent.arg1.label),
    UI_ITEM_TEXT(313, txContent.arg1.data),

    UI_ITEM_LABEL(382, txContent.arg2.label),
    UI_ITEM_TEXT(382, txContent.arg2.data),

    // TODO view for more tx details - longer "data" fields, and the rest of them

    UI_REJECT_CONFIRM_BUTTONS(414, io_seproxyhal_touch_tx_cancel, io_seproxyhal_touch_tx_ok),
    UI_EXIT_BUTTON,
};

unsigned int ui_approval_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t *ui_approval_prepro(const bagl_element_t *element) {
    ui_item_text_populate(1, element, "test12345123", 12);
    ui_item_text_populate(2, element, "eosio.token", 11);

    return element;
}


void ui_idle(void) {
    UX_SET_STATUS_BAR_COLOR(0xFFFFFF, COLOR_TOP_BG);
    UX_DISPLAY(ui_idle_blue, NULL);
    // UX_DISPLAY(ui_approval_blue, ui_approval_prepro);
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

bool ui_needs_redisplay(void) {
    return true;
}

#endif // TARGET_BLUE

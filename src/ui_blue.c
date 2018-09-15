#include "ui.h"

#include "os_io_seproxyhal.h"

#ifdef TARGET_BLUE

ux_state_t ux;
txProcessingContent_t txContent;
char fullAddress[60];

static const bagl_element_t const ui_main_blue[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
         0xf9f9f9, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028,
         0x1d2028, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
         BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
        "Hello EOS",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 225, 120, 40, 0, 6,
         BAGL_FILL, 0x41ccb4, 0xF9F9F9, BAGL_FONT_OPEN_SANS_LIGHT_14px |
         BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
        "EXIT",
        0,
        0x37ae99,
        0xF9F9F9,
        io_seproxyhal_touch_exit,
        NULL,
        NULL,
    },
};

unsigned int ui_main_blue_button(
	unsigned int button_mask,
	unsigned int button_mask_counter) {
	return 0;
}

void ui_idle(void) {
    UX_DISPLAY(ui_main_blue, NULL);
}

void ui_address_display(const char *address) {
    snprintf((char *)fullAddress, sizeof(fullAddress), "%.*s", strlen(address), address);

    // UX_DISPLAY(ui_address_blue, ui_address_prepro);
}

void ui_approval_display(bool dataPresent) {
    // UX_DISPLAY(ui_approval_blue, ui_approval_prepro);
}

bool ui_needs_redisplay(void) {
    return true;
}

#endif // TARGET_BLUE

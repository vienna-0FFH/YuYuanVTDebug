/*
 * HvUsbHid.c — PS/2 set-1 scancode → USB HID Usage ID 翻译表
 *
 * 给 Layer 4 (HvUsbXhci.c) 的注入路径用。GUI 把按键意图编码成 PS/2 scancode
 * (兼容 v1-v3 path),Layer 4 在调 HvUsbXhciSendKeyboard 之前用这张表把 PS/2
 * scancode 翻译成 HID Usage ID 填进 HID Boot Keyboard Report.Keys[]。
 *
 * 数据源:
 *   - PS/2 set 1 make codes:Microsoft "Keyboard Scan Code Specification"
 *   - HID usage IDs:USB HID Usage Tables 1.21,Section 10 Keyboard/Keypad
 *
 * 注意:HID 把 modifier (Ctrl/Shift/Alt/GUI) 放在 report 的 Modifier byte (bit 0..7),
 *       不放在 Keys[] 数组。因此本文件提供两个函数:
 *       (1) HvUsbHidTranslateScancode  → 普通按键的 HID Usage ID (0 = unmapped)
 *       (2) HvUsbHidScancodeToModifier → 若是 modifier,返回 HID_MOD_* 位掩码
 */

#include <ntddk.h>
#include "HvUsbXhci.h"

// ============================================================
// 普通按键: PS/2 set-1 scancode → HID Usage ID
// ============================================================

// 非扩展 (没有 E0 前缀) 的 set-1 scancode 0x00..0x58
// 留 0 = 无映射 / modifier / 不支持
static const UCHAR g_Ps2ToHid[0x60] = {
    /* 0x00 */ 0x00,
    /* 0x01 */ 0x29,  // Esc
    /* 0x02 */ 0x1E,  // 1
    /* 0x03 */ 0x1F,  // 2
    /* 0x04 */ 0x20,  // 3
    /* 0x05 */ 0x21,  // 4
    /* 0x06 */ 0x22,  // 5
    /* 0x07 */ 0x23,  // 6
    /* 0x08 */ 0x24,  // 7
    /* 0x09 */ 0x25,  // 8
    /* 0x0A */ 0x26,  // 9
    /* 0x0B */ 0x27,  // 0
    /* 0x0C */ 0x2D,  // -
    /* 0x0D */ 0x2E,  // =
    /* 0x0E */ 0x2A,  // Backspace
    /* 0x0F */ 0x2B,  // Tab
    /* 0x10 */ 0x14,  // Q
    /* 0x11 */ 0x1A,  // W
    /* 0x12 */ 0x08,  // E
    /* 0x13 */ 0x15,  // R
    /* 0x14 */ 0x17,  // T
    /* 0x15 */ 0x1C,  // Y
    /* 0x16 */ 0x18,  // U
    /* 0x17 */ 0x0C,  // I
    /* 0x18 */ 0x12,  // O
    /* 0x19 */ 0x13,  // P
    /* 0x1A */ 0x2F,  // [
    /* 0x1B */ 0x30,  // ]
    /* 0x1C */ 0x28,  // Enter
    /* 0x1D */ 0x00,  // LCtrl  (modifier — by HvUsbHidScancodeToModifier)
    /* 0x1E */ 0x04,  // A
    /* 0x1F */ 0x16,  // S
    /* 0x20 */ 0x07,  // D
    /* 0x21 */ 0x09,  // F
    /* 0x22 */ 0x0A,  // G
    /* 0x23 */ 0x0B,  // H
    /* 0x24 */ 0x0D,  // J
    /* 0x25 */ 0x0E,  // K
    /* 0x26 */ 0x0F,  // L
    /* 0x27 */ 0x33,  // ;
    /* 0x28 */ 0x34,  // '
    /* 0x29 */ 0x35,  // `  (Grave)
    /* 0x2A */ 0x00,  // LShift (modifier)
    /* 0x2B */ 0x31,  // backslash
    /* 0x2C */ 0x1D,  // Z
    /* 0x2D */ 0x1B,  // X
    /* 0x2E */ 0x06,  // C
    /* 0x2F */ 0x19,  // V
    /* 0x30 */ 0x05,  // B
    /* 0x31 */ 0x11,  // N
    /* 0x32 */ 0x10,  // M
    /* 0x33 */ 0x36,  // ,
    /* 0x34 */ 0x37,  // .
    /* 0x35 */ 0x38,  // /
    /* 0x36 */ 0x00,  // RShift (modifier)
    /* 0x37 */ 0x55,  // KP *  (PrintScreen 走 E0 path 不走这里)
    /* 0x38 */ 0x00,  // LAlt (modifier)
    /* 0x39 */ 0x2C,  // Space
    /* 0x3A */ 0x39,  // CapsLock
    /* 0x3B */ 0x3A,  // F1
    /* 0x3C */ 0x3B,  // F2
    /* 0x3D */ 0x3C,  // F3
    /* 0x3E */ 0x3D,  // F4
    /* 0x3F */ 0x3E,  // F5
    /* 0x40 */ 0x3F,  // F6
    /* 0x41 */ 0x40,  // F7
    /* 0x42 */ 0x41,  // F8
    /* 0x43 */ 0x42,  // F9
    /* 0x44 */ 0x43,  // F10
    /* 0x45 */ 0x53,  // NumLock
    /* 0x46 */ 0x47,  // ScrollLock
    /* 0x47 */ 0x5F,  // KP 7
    /* 0x48 */ 0x60,  // KP 8
    /* 0x49 */ 0x61,  // KP 9
    /* 0x4A */ 0x56,  // KP -
    /* 0x4B */ 0x5C,  // KP 4
    /* 0x4C */ 0x5D,  // KP 5
    /* 0x4D */ 0x5E,  // KP 6
    /* 0x4E */ 0x57,  // KP +
    /* 0x4F */ 0x59,  // KP 1
    /* 0x50 */ 0x5A,  // KP 2
    /* 0x51 */ 0x5B,  // KP 3
    /* 0x52 */ 0x62,  // KP 0
    /* 0x53 */ 0x63,  // KP .
    /* 0x54 */ 0x00,
    /* 0x55 */ 0x00,
    /* 0x56 */ 0x64,  // Non-US backslash (102nd key)
    /* 0x57 */ 0x44,  // F11
    /* 0x58 */ 0x45,  // F12
    /* 0x59-0x5F */ 0,0,0,0,0,0,0,
};

// E0-prefixed (extended) PS/2 scancodes
// 比较常见的方向键、Home/End、KP_Enter、Right modifier 等
static UCHAR HvUsbHidExtendedToHid(UCHAR scancode)
{
    switch (scancode) {
        case 0x1C: return 0x58;  // KP Enter (E0 1C)
        case 0x1D: return 0x00;  // RCtrl    — modifier
        case 0x35: return 0x54;  // KP /
        case 0x37: return 0x46;  // PrintScreen (E0 37, sometimes E0 2A E0 37)
        case 0x38: return 0x00;  // RAlt     — modifier
        case 0x46: return 0x48;  // Pause / Break (rare encoding)
        case 0x47: return 0x4A;  // Home
        case 0x48: return 0x52;  // UpArrow
        case 0x49: return 0x4B;  // PageUp
        case 0x4B: return 0x50;  // LeftArrow
        case 0x4D: return 0x4F;  // RightArrow
        case 0x4F: return 0x4D;  // End
        case 0x50: return 0x51;  // DownArrow
        case 0x51: return 0x4E;  // PageDown
        case 0x52: return 0x49;  // Insert
        case 0x53: return 0x4C;  // Delete
        case 0x5B: return 0x00;  // LGui     — modifier
        case 0x5C: return 0x00;  // RGui     — modifier
        case 0x5D: return 0x65;  // Application (menu)
        default:   return 0x00;
    }
}

UCHAR HvUsbHidTranslateScancode(UCHAR scancode, BOOLEAN isExtended)
{
    if (isExtended) {
        return HvUsbHidExtendedToHid(scancode);
    }
    if (scancode < ARRAYSIZE(g_Ps2ToHid)) {
        return g_Ps2ToHid[scancode];
    }
    return 0;
}

// ============================================================
// Modifier 判定: 若是 modifier,返回 HID_MOD_* 位;否则 0
// ============================================================
UCHAR HvUsbHidScancodeToModifier(UCHAR scancode, BOOLEAN isExtended)
{
    if (!isExtended) {
        switch (scancode) {
            case 0x1D: return HID_MOD_LCTRL;
            case 0x2A: return HID_MOD_LSHIFT;
            case 0x36: return HID_MOD_RSHIFT;
            case 0x38: return HID_MOD_LALT;
            default:   return 0;
        }
    } else {
        switch (scancode) {
            case 0x1D: return HID_MOD_RCTRL;
            case 0x38: return HID_MOD_RALT;
            case 0x5B: return HID_MOD_LGUI;
            case 0x5C: return HID_MOD_RGUI;
            default:   return 0;
        }
    }
}

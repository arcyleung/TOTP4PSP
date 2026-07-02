#include <pspkernel.h>
#include <pspdebug.h>
#include <pspdisplay.h>
#include <pspctrl.h>
#include <pspgu.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "base32/base32.h"
#include "common/callback.h"
#include "totp_core.h"
#include "intrafont031g/libraries/graphics.h"
#include "intrafont031g/intraFont.h"

#define VERS 1
#define REVS 0

/* otpauth:// query param names hashed via lookup() (modified djb2). */
#define ALG 70
#define DIG 67
#define ISS 26
#define PER 66
#define SEC 133

PSP_MODULE_INFO("TOTP", PSP_MODULE_USER, VERS, REVS);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER);
PSP_HEAP_THRESHOLD_SIZE_KB(0);

#define printf pspDebugScreenPrintf

struct OTPKey {
    char *name;
    char *issuer;
    char *algorithm;
    uint8_t digits;
    uint8_t period;
    uint8_t *secret;   /* raw key bytes after base32 decode (may contain NUL) */
    size_t secret_len; /* exact length — never strlen() on secret */
    struct OTPKey *next;
};

static char otpfile[] = "ms0:/PSP/COMMON/OTPAUTH_KEYS";
static int num_otp_keys = 0;

enum {
    COLOR_WHITE = 0xFFFFFFFF,
    COLOR_BLACK = 0xFF000000,
};

/* Modified djb2 — maps known otpauth param names to the #defines above. */
static uint8_t
lookup(const char *str)
{
    uint8_t hash = 31;
    uint8_t c;
    while ((c = (uint8_t)*str++))
        hash = (uint8_t)((hash << 5) + hash + c); /* hash * 33 + c */
    return hash;
}

static struct OTPKey *
readOTPFile(const char *filePath)
{
    struct OTPKey *head = NULL;
    struct OTPKey **cur = &head;
    FILE *filePointer;
    char buffer[2048];

    filePointer = fopen(filePath, "r");
    if (filePointer == NULL)
        return NULL;

    while (fgets(buffer, (int)sizeof(buffer), filePointer)) {
        char *optauth;
        char *rest;
        char *alg = NULL;
        char *iss = NULL;
        char *sec = NULL;
        uint8_t dig = 0;
        uint8_t per = 0;

        optauth = strtok_r(buffer, "?", &rest);

        while (rest != NULL) {
            char *segment = strtok_r(rest, "&", &rest);
            char *paramName;
            char *value;

            if (segment == NULL)
                break;
            paramName = strtok_r(segment, "=", &value);
            if (paramName == NULL)
                continue;

            switch (lookup(paramName)) {
            case ALG:
                alg = value;
                break;
            case DIG:
                dig = (uint8_t)strtol(value, NULL, 10);
                break;
            case ISS:
                iss = value;
                break;
            case PER:
                per = (uint8_t)strtol(value, NULL, 10);
                break;
            case SEC:
                sec = value;
                break;
            }
        }

        if (optauth == NULL || sec == NULL || alg == NULL)
            continue;

        *cur = (struct OTPKey *)calloc(1, sizeof(struct OTPKey));
        if (*cur == NULL)
            break;

        /* Strip leading "otpauth://totp/" (15 chars) for display name. */
        {
            const int name_off = 15;
            size_t name_len = strlen(optauth);

            if (name_len > (size_t)name_off) {
                name_len -= (size_t)name_off;
                (*cur)->name = malloc(name_len + 1);
                if ((*cur)->name)
                    memcpy((*cur)->name, optauth + name_off, name_len + 1);
            }
        }

        (*cur)->algorithm = malloc(strlen(alg) + 1);
        if ((*cur)->algorithm)
            strcpy((*cur)->algorithm, alg);

        (*cur)->digits = (uint8_t)totp_clamp_digits((int)dig);
        (*cur)->period = per ? per : 30;
        (*cur)->issuer = NULL;
        if (iss != NULL) {
            (*cur)->issuer = malloc(strlen(iss) + 1);
            if ((*cur)->issuer)
                strcpy((*cur)->issuer, iss);
        }

        /* Base32 secret → raw key bytes via shipped decoder contract. */
        {
            size_t sec_chars = strlen(sec);
            uint32_t decodedSize = (uint32_t)((sec_chars + 1) * 8 + 4) / 5;
            size_t secret_len = 0;

            (*cur)->secret = malloc(decodedSize);
            if ((*cur)->secret == NULL ||
                totp_decode_secret_b32(sec, (*cur)->secret, (int)decodedSize,
                                       &secret_len) != 0 ||
                secret_len == 0) {
                /* MF-2: never surface empty/invalid secrets as live codes. */
                free((*cur)->secret);
                free((*cur)->name);
                free((*cur)->algorithm);
                free((*cur)->issuer);
                free(*cur);
                *cur = NULL;
                continue;
            }
            (*cur)->secret_len = secret_len;
        }

        (*cur)->next = NULL;
        cur = &(*cur)->next;
        num_otp_keys += 1;
    }

    fclose(filePointer);
    return head;
}

int
main(int argc, char **argv)
{
    SceCtrlData buttonInput;
    intraFont *ltn[16];
    char file[40];
    int i;
    struct OTPKey *head;
    struct OTPKey *cur;
    float x_label = 130;
    float x_code = 5;
    int vscroll_offset = 0;

    (void)argc;
    (void)argv;

    pspDebugScreenInit();
    setupExitCallback();
    intraFontInit();

    sceCtrlSetSamplingCycle(0);
    sceCtrlSetSamplingMode(PSP_CTRL_MODE_ANALOG);

    for (i = 0; i < 16; i++) {
        sprintf(file, "flash0:/font/ltn%d.pgf", i);
        ltn[i] = intraFontLoad(file, INTRAFONT_CACHE_ALL);
        pspDebugScreenSetXY(15, 2);
        pspDebugScreenPrintf("%d%%", (i + 1) * 100 / 20);
    }

    if (!ltn[0] || !ltn[4] || !ltn[8])
        sceKernelExitGame();

    printf("Reading OTPauth keys...");
    head = readOTPFile(otpfile);

    initGraphics();

    while (isRunning()) {
        float y = 20;
        time_t now;
        int curpos = 0;
        int shown = 0;

        pspDebugScreenSetXY(0, 0);
        clearScreen(COLOR_BLACK);
        intraFontSetStyle(ltn[8], 2.0f, COLOR_WHITE, 0U, 0.f, 0);
        intraFontSetStyle(ltn[6], 1.0f, COLOR_WHITE, 0U, 0.f, INTRAFONT_SCROLL_LEFT);

        guStart();
        sceKernelLibcTime(&now);

        cur = head;
        sceCtrlPeekBufferPositive(&buttonInput, 1);
        if (buttonInput.Buttons != 0) {
            if ((buttonInput.Buttons & PSP_CTRL_UP) && vscroll_offset > 0)
                vscroll_offset -= 1;
            if ((buttonInput.Buttons & PSP_CTRL_DOWN) &&
                vscroll_offset < (num_otp_keys - 12))
                vscroll_offset += 1;
        }

        while (curpos < vscroll_offset && cur != NULL) {
            cur = cur->next;
            curpos += 1;
        }

        while (cur != NULL && shown < 12) {
            uint8_t period = cur->period ? cur->period : 30;
            uint64_t key_counter = (uint64_t)now / (uint64_t)period;
            int digits = totp_clamp_digits((int)cur->digits);
            uint32_t code = calc_totp(cur->secret, cur->secret_len, key_counter,
                                     digits);
            char strcode[16];

            sprintf(strcode, "%0*lu", digits, (unsigned long)code);
            if (cur->name)
                intraFontPrint(ltn[6], x_label, y - 4, cur->name);
            intraFontPrint(ltn[8], x_code, y, strcode);
            y += 22;

            shown += 1;
            cur = cur->next;
        }

        sceGuFinish();
        sceGuSync(0, 0);
        sceDisplayWaitVblankStart();
        flipScreen();
    }

    sceKernelExitGame();
    return 0;
}

#include <pspkernel.h>
#include <pspdebug.h>
#include <pspdisplay.h>
#include <psputils.h>
#include <pspctrl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "hmac-sha1/src/hmac/hmac.h"
#include "base32/base32.h"
#include "../common/callback.h"

#include "./intrafont031g/libraries/graphics.h"
#include "./intrafont031g/intraFont.h"

#define VERS 1 // version
#define REVS 0 // revision

// Supported parameter fields of the otpauth://totp/ string
#define ALG 70
#define DIG 67
#define ISS 26
#define PER 66
#define SEC 133

PSP_MODULE_INFO("TOTP", PSP_MODULE_USER, VERS, REVS);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER);
PSP_HEAP_THRESHOLD_SIZE_KB(0);

#define printf pspDebugScreenPrintf

enum ALGTYPE
{
    SHA1,
    SHA256,
    SHA512
};

// Simple linked list of TOTP key field info, appended as they are parsed from the file
struct OTPKey
{
    char *name;
    char *issuer;
    char *algorithm;
    uint8_t digits;
    uint8_t period;
    char *secret;

    struct OTPKey *next;
};

char otpfile[] = "ms0:/PSP/COMMON/OTPAUTH_FILE";

int num_otp_keys = 0;

// Modified djb2 to convert string to some id
uint8_t
lookup(char *str)
{
    uint8_t hash = 31;
    uint8_t c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

struct OTPKey * 
readOTPFile(char *filePath)
{
    struct OTPKey *head = NULL;
    struct OTPKey **cur = &head;

    FILE *filePointer;
    uint32_t bufferLength = 2048;
    char buffer[bufferLength]; /* not ISO 90 compatible */

    filePointer = fopen(filePath, "r");

    while (fgets(buffer, bufferLength, filePointer))
    {
        char *optauth;
        char *rest;
        optauth = strtok_r(buffer, "?", &rest);

        char *alg = NULL;
        uint8_t dig = 0;
        char *iss = NULL;
        uint8_t per = 0;
        char *sec = NULL;

        // Parse
        while (rest != NULL)
        {
            char *segment = strtok_r(rest, "&", &rest);
            char *paramName;
            char *value;
            paramName = strtok_r(segment, "=", &value);

            switch (lookup(paramName))
            {
            case ALG:
                alg = value;
                break;
            case DIG:
                dig = strtol(value, NULL, 10);
                break;
            case ISS:
                iss = value;
                break;
            case PER:
                per = strtol(value, NULL, 10);
                break;
            case SEC:
                sec = value;
                break;
            }
        }

        if ((*cur) == NULL) {
            (*cur) = (struct OTPKey *) malloc(sizeof(struct OTPKey));
        }

        // Extract the name without totp TOTP uri preamble
        // char *begin_name = strrchr(optauth, 47);
        // // begin_name = optauth +;
        // if (begin_name == NULL) begin_name = optauth;

        // (*cur)->name = malloc(strlen(optauth) + 1);
        // memcpy((*cur)->name, optauth, strlen(optauth) + 1); // works
        
        int offset = 15;
        (*cur)->name = malloc((strlen(optauth) - offset) + 1);
        memcpy((*cur)->name, optauth+offset, (strlen(optauth) - offset) + 1);  // no work :(
        
        (*cur)->algorithm = malloc(strlen(alg) + 1);
        strcpy((*cur)->algorithm, alg);
        (*cur)->digits = dig;
        (*cur)->period = per;
        if (iss != NULL) {
            (*cur)->issuer = malloc(strlen(iss) + 1);
            strcpy((*cur)->issuer, iss);
        }

        // Secret is Base32 string, so must first decode back to normal string
        // Base32 uses 5 bits per character, but also must be multiple of 40 bits length
        uint32_t decodedSize = ((strlen(sec) + 1) * 8 + 4) / 5;
        (*cur)->secret = malloc(decodedSize);
        base32_decode(sec, (*cur)->secret, decodedSize);
        (*cur)->next = NULL;

        cur = &(*cur)->next;
        num_otp_keys += 1;
    }

    fclose(filePointer);
    return head;
}

uint32_t
mod_hotp(uint32_t bin_code, int digits)
{
    int power = pow(10, digits);
    uint32_t otp = bin_code % power;

    return otp;
}

int
calcToken(struct OTPKey *key, uint32_t counter)
{
    uint8_t text[8];
    for (int i = 7; i >= 0; i--)
    {
        text[i] = (counter & 0xff);
        counter >>= 8;
    }

    size_t bufLen;
    if (strlen(key->secret) < 20) {
        // TODO: fix with max
        bufLen = 20 + 1UL;
    } else {
        bufLen = strlen(key->secret) + 1UL;
    }
    uint8_t output[bufLen];

    hmac_sha1(key->secret, bufLen, text, 8, output, &bufLen);

    int offset = output[bufLen-1] & 0xf;
    // printf("%ld %ld \n", bufLen, offset);

    int bin_code = (output[offset] & 0x7f) << 24
        | (output[offset+1] & 0xff) << 16
        | (output[offset+2] & 0xff) <<  8
        | (output[offset+3] & 0xff);

    return bin_code;
}

  // Colors
  enum colors {
    RED =  0xFF0000FF,
    GREEN =  0xFF00FF00,
    BLUE =  0xFFFF0000,
    WHITE =  0xFFFFFFFF,
    LITEGRAY = 0xFFBFBFBF,
    GRAY =  0xFF7F7F7F,
    DARKGRAY = 0xFF3F3F3F,    
    BLACK = 0xFF000000,
  };

int
main(int argc, char **argv)
{
    pspDebugScreenInit(); 
    setupExitCallback();
    intraFontInit();

    SceCtrlData buttonInput;
    sceCtrlSetSamplingCycle(0);
	sceCtrlSetSamplingMode(PSP_CTRL_MODE_ANALOG);
    
    // Load fonts
    intraFont* ltn[16];                                         //latin fonts (large/small,with/without serif,regular/italic/bold/italic&bold)
    char file[40];
    int i;
    for (i = 0; i < 16; i++) {
        sprintf(file,"flash0:/font/ltn%d.pgf",i); 
        ltn[i] = intraFontLoad(file,INTRAFONT_CACHE_ALL);
        pspDebugScreenSetXY(15,2);
        pspDebugScreenPrintf("%d%%",(i+1)*100/20);
    }

    if(!ltn[0] || !ltn[4] || !ltn[8]) sceKernelExitGame();

    uint32_t counter, prev_counter = 0;

    printf("Reading OPTauth keys...");
    struct OTPKey *head = readOTPFile(otpfile);

    struct OTPKey *cur;

    float x_label = 130;
    float x_code = 5;
    int vscroll_offset = 0;
    initGraphics();


    while (isRunning())
    {
        pspDebugScreenSetXY(0, 0);

        clearScreen(BLACK);
        intraFontSetStyle(ltn[8],2.0f,WHITE,0U,0.f,0);
        intraFontSetStyle(ltn[6],1.0f,WHITE,0U,0.f,INTRAFONT_SCROLL_LEFT);
        float x,y = 20;

        // // Must be called before any of the intraFont functions
        guStart();

        time_t now;
        sceKernelLibcTime(&now);
        counter = now / 30;
        // printf(" Next Refresh: %lld s \n", 30 - (now % 30));
        // printf(" Counter: %ld, ts: %lld \n", counter, now);
        // printf("\n");
        // Continue and don't clear the screen when the counter has not been changed
        // TODO: Make counter check per token with different periods
        // if (counter == prev_counter)
        //     continue;

        prev_counter = counter;

        cur = head;
        int curpos = 0;
        int shown = 0;

        sceCtrlPeekBufferPositive(&buttonInput, 1);
        if(buttonInput.Buttons != 0) 
		{ 
            if(buttonInput.Buttons & PSP_CTRL_UP) {
                if (vscroll_offset > 0) vscroll_offset -= 1;
            }
			if(buttonInput.Buttons & PSP_CTRL_DOWN) {
                if (vscroll_offset < (num_otp_keys - 12)) vscroll_offset += 1;
            }
        }

        while(curpos < vscroll_offset) { 
            cur = cur->next;
            curpos += 1;
        }
        
        while (cur != NULL && shown < 12)
        {   
            int code = calcToken(cur, counter);
            char strcode[7];
            sprintf(&strcode, "%06d", mod_hotp(code, cur->digits));
            intraFontPrint(ltn[6],x_label,y-4,cur->name);
            intraFontPrint(ltn[8],x_code,y,strcode);
            y += 22;

            // printf(" > %s %06d \n", cur->name, mod_hotp(code, cur->digits));
            shown += 1;
            cur = cur->next;
        }

        // End drawing
        sceGuFinish();
        sceGuSync(0,0);
        
        // // Swap buffers
        sceDisplayWaitVblankStart();
        flipScreen();
    }

    sceKernelExitGame();

    return 0;
}
#include <pspkernel.h>
#include <pspdebug.h>
#include <psputils.h>
#include <pspgu.h>
#include <pspdisplay.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "hmac-sha1/src/hmac/hmac.h"
#include "base32/base32.h"
#include "../common/callback.h"
// #include "text_generator.h"
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>

#define VERS 1 // version
#define REVS 0 // revision

// Supported parameter fields of the otpauth://totp/ string
#define ALG 70
#define DIG 67
#define ISS 26
#define PER 66
#define SEC 133

// PSP_MODULE_INFO("TOTP", PSP_MODULE_USER, VERS, REVS);
// PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER);
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


SDL_Renderer *m_renderer;
TTF_Font *font;
void init_generator(const char *file, int font_size, SDL_Renderer &renderer)
{
    TTF_Init();
    font = TTF_OpenFont(file, font_size);
    m_renderer = &renderer;
}
void cleanup_generator()
{
    TTF_Quit();
}

void gen_text_at_rect(int x, int y, const char *text, SDL_Texture **texture, SDL_Rect *rect)
{
    int text_width;
    int text_height;
    SDL_Surface *surface;
    SDL_Color textColor = {255, 255, 255, 255};

    surface = TTF_RenderUTF8_Blended(font, text, textColor);
    *texture = SDL_CreateTextureFromSurface(m_renderer, surface);
    text_width = surface->w;
    text_height = surface->h;

    rect->x = x;
    rect->y = y;
    rect->w = text_width;
    rect->h = text_height;
    SDL_FreeSurface(surface);
    SDL_RenderCopy(m_renderer, *texture, NULL, rect);
    SDL_DestroyTexture(*texture);
}

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

extern "C" OTPKey *readOTPFile(char *filePath);
struct OTPKey * 
readOTPFile(char *filePath)
{
    struct OTPKey *head;
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
        
        int offset = 10;
        (*cur)->name = (char*)malloc((strlen(optauth) - offset) + 1);
        memcpy((*cur)->name, optauth+offset, (strlen(optauth) - offset) + 1);
        
        (*cur)->algorithm = (char*)malloc(strlen(alg) + 1);
        strcpy((*cur)->algorithm, alg);
        (*cur)->digits = dig;
        (*cur)->period = per;
        if (iss != NULL) {
            (*cur)->issuer = (char*)malloc(strlen(iss) + 1);
            strcpy((*cur)->issuer, iss);
        }

        // Secret is Base32 string, so must first decode back to normal string
        // Base32 uses 5 bits per character, but also must be multiple of 40 bits length
        uint32_t decodedSize = ((strlen(sec) + 1) * 8 + 4) / 5;
        (*cur)->secret = (char*)malloc(decodedSize);
        base32_decode(sec, (*cur)->secret, decodedSize);
        (*cur)->next = NULL;

        cur = &(*cur)->next;
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

extern "C" int calcToken(struct OTPKey *key, uint32_t counter);
// extern "C" void hmac_sha1(const uint8_t* key, const uint32_t keysize, const uint8_t* msg, const uint32_t msgsize, uint8_t* output);
int
calcToken(struct OTPKey *key, uint32_t counter)
{
    uint8_t text[8];
    for (int i = 7; i >= 0; i--)
    {
        text[i] = (counter & 0xff);
        counter >>= 8;
    }

    uint32_t bufLen;
    if (strlen(key->secret) < 20) {
        // TODO: fix with max
        bufLen = 20 + 1UL;
    } else {
        bufLen = strlen(key->secret) + 1UL;
    }
    uint8_t output[bufLen];

    hmac_sha1((uint8_t*)(key->secret), bufLen, text, 8, output, &bufLen);

    int offset = output[bufLen-1] & 0xf;
    // printf("%ld %ld \n", bufLen, offset);

    int bin_code = (output[offset] & 0x7f) << 24
        | (output[offset+1] & 0xff) << 16
        | (output[offset+2] & 0xff) <<  8
        | (output[offset+3] & 0xff);

    return bin_code;
}

extern "C" int SDL_main(int argc, char *argv[]);
int
main(int argc, char **argv)
{
    uint32_t counter, prev_counter = 0;

    pspDebugScreenInit(); 
    setupExitCallback();
    printf("Reading OPTauth keys...");
    struct OTPKey *head = readOTPFile(otpfile);

    struct OTPKey *cur;
    
    // SDL_Texture *texture1;
    // SDL_Rect rect1;
    // SDL_Window *window = SDL_CreateWindow("SDL TTF Test", 0, 0, 480, 272, NULL);
    // SDL_Renderer *renderer = SDL_CreateRenderer(window, 0, NULL);
    // SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "1");

    // init_generator("cambriai.ttf", 24, *renderer);


    while (isRunning())
    {
        pspDebugScreenSetXY(0, 0);
        time_t now;
        sceKernelLibcTime(&now);
        counter = now / 30;
        printf(" Next Refresh: %lld s \n", 30 - (now % 30));
        printf(" Counter: %ld, ts: %lld \n", counter, now);
        printf("\n");
        // Continue and don't clear the screen when the counter has not been changed
        // TODO: Make counter check per token with different periods
        if (counter == prev_counter)
            continue;

        prev_counter = counter;

        cur = head;
        
        while (cur != NULL)
        {   
            int code = calcToken(cur, counter);
            printf(" > %s %06ld \n", cur->name, mod_hotp(code, cur->digits));
            cur = cur->next;
        }

        // SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
        // SDL_RenderClear(renderer);
        // gen_text_at_rect(0, 0, "SDL2 + SDL TTF EXAMPLE", &texture1, &rect1);
        // SDL_RenderPresent(renderer);
        // SDL_UpdateWindowSurface(window);

        sceDisplayWaitVblankStart();
    }
    cleanup_generator();
    sceKernelExitGame();

    return 0;
}
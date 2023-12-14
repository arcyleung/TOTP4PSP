#include <pspkernel.h>
#include <pspdebug.h>
#include <pspdisplay.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "hmac-sha1/src/hmac/hmac.h"
#include "../common/callback.h"

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

enum ALGTYPE { SHA1, SHA256, SHA512 };

// Simple linked list of TOTP key field info, appended as they are parsed from the file
struct OTPKey {
	char *name;
	char *issuer;
	char *algorithm;
	uint8_t digits;
	uint8_t period;
	char *secret;

	struct OTPKey *next;
} *totpKeys;

char otpfile[] = "ms0:/PSP/COMMON/otpauth_file";

// const struct OTPKey *;

// Modified djb2 just converts string to some id
uint8_t lookup(char *str)
    {
        uint8_t hash = 31;
        uint8_t c;
        while ((c = *str++))
            hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        return hash;
    }

void readOTPFile(char* filePath, struct OTPKey *keys) {

	struct OTPKey *cur = totpKeys;

	FILE* filePointer;
	uint32_t bufferLength = 2048;
	char buffer[bufferLength]; /* not ISO 90 compatible */

	filePointer = fopen(filePath, "r");

	while(fgets(buffer, bufferLength, filePointer)) {
		char *optauth;
		char *rest;
		optauth = strtok_r(buffer, "?", &rest);

		printf( " %s\n", optauth );

		char *alg = NULL;
		uint8_t dig = 0;
		char *iss = NULL;
		uint8_t per = 0;
		char *sec = NULL;
   
		// Parse
		while( rest != NULL ) {
			// printf( " %s\n", rest );
			char *segment = strtok_r(rest, "&", &rest);
			char *paramName;
			char *value;
			paramName = strtok_r(segment, "=", &value);
			printf( " %s %u %s \n", paramName, lookup(paramName), value );

			switch(lookup(paramName)) {
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

		cur = malloc(sizeof(struct OTPKey));
		cur->name = optauth;
		cur->algorithm = alg;
		cur->digits = dig;
		cur->period = per;
		cur->issuer = iss;
		cur->secret = sec;
		cur->next = NULL;
		cur = cur->next;
	}

	fclose(filePointer);
}

int main(int argc, char **argv)
{
	time_t   seconds;
	uint32_t counter;
	uint8_t  output[20];
	// uint8_t key[53] = "GZE3PJAYWOOGDXQPI4MQ4EP4WSOTOGIJGY26PZUB5YTMHLLSPUYQ";
	uint8_t key[] = "12345678901234567890";
	// int keysize = 53;

	// Need to convert counter from uint32 to 4 bytes
	uint8_t msg[4];
	// int msgsize = 53;
	// basic init
	pspDebugScreenInit(); // initialize the debug screen
	setupExitCallback();

	readOTPFile(otpfile, NULL);

	while(isRunning())
	{
		// printf("%s", data);

		pspDebugScreenSetXY(0, 0);

		seconds = 59;

		counter = seconds/30;

		memcpy(msg, &counter, 4);

		uint8_t text[8] ;
		for (int i = 7; i >= 0; i--) {
			text[i] = (counter & 0xff);
			counter >>= 8;
		}

		unsigned long outputSize = 20UL;

		hmac_sha1(key, 20, text, 8, output, &outputSize);

		int offset   =  output[19] & 0xf ;
        int bin_code = (output[offset]  & 0x7f) << 24
           | (output[offset+1] & 0xff) << 16
           | (output[offset+2] & 0xff) <<  8
           | (output[offset+3] & 0xff) ;

		printf("Key: ");
		for (int i = 0; i < 20; i++) {
			printf("%x", key[i]);
		}
		printf("\n");

		printf("Counter: %lx", counter);
		printf("\n");

		printf("Output: ");
		for (int i = 0; i < 20; i++) {
			printf("%x", output[i]);
		}
		printf("\n");
		printf("%d\n", bin_code);

		sceDisplayWaitVblankStart();
	}

	sceKernelExitGame();	

	// if(uid >= 0) sceIoClose(uid);
	// free(data);
	// data = 0;


	return 0;
}
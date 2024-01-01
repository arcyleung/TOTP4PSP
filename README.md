# Time-based One-Time Password for PlayStation Portable (TOTP4PSP) 

This homebrew program implements TOTP (RFC 6238) and lets you use your PSP as an authenticator device to many 2FA systems. The user must provide a keyfile with each line as a seperate TOTP authenticator, which can be exported from Google Authenticator for example with a tool such as [otpauth](https://github.com/dim13/otpauth). The exact format is explained under [Installation](#installation)

## Prerequisites

- A PSP 1000/2000/3000 with any CFW
- A memory stick and sufficient free space for EBOOT.PBP and your keyfile
- For emulators like PPSSPP: The original PSP font files under flash0:/font/, which you must copy from a physical PSP flash0 or obtain elsewhere ;). (This is because Intrafont 0.31 cannot load the "open source" alternative font shipped with PPSSPP)

## Installation
1. Copy the EBOOT.PBP into a new folder `ms0:/PSP/GAME/TOTP4PSP`
2. Copy the OTPAUTH_KEYS file into `ms0:/PSP/COMMON/OTPAUTH_KEYS`

An example OTPAUTH_KEYS is provided for reference, please note the following format: 
- one line per OTP provider
- `secret=` field is the base32 encoded representation of the secret, and not the plaintext secret itself!
    - Ex. Using the RFC doc's [test vector example](https://www.rfc-editor.org/rfc/rfc6238#appendix-B):   
    Plaintext Secret: `12345678901234567890` -> Base32 Secret: `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`
- `issuer=` field is optional, everything else is required

OTPAUTH_KEYS
```
otpauth://totp/<name1>?algorithm=SHA1&digits=6&period=30&secret=<base32_secret1>
otpauth://totp/<name2>?algorithm=SHA1&digits=6&issuer=<issuer2>&period=30&secret=<base32_secret2>
...
``` 
3. Ensure the system time of the PSP is correctly set from the XMB menu, either manually or with NTP, and paying attention to whether Daylight Saving Time is enabled. 

## OTP Parameters

The following fields and parameters are currently supported:
```
algorithm=[SHA1]        <- TODO: Implement SHA256|SHA512 
digits=[6]              <- TODO: Implement 8 digits
period=[30s]            <- TODO: Implement 60s
issuer=<any string>     <- TODO: Display it in some useful way
secret=<base32 secret>
```

## Building from Source

Prerequisites: psptoolchain/ psp-sdk (psp-gcc)  
TODO: Add steps
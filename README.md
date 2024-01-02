# Time-based One-Time Password for PlayStation Portable (TOTP4PSP) 
<p align="center">
    <img src="totp4psp.jpg" width="65%" />
</p>

This homebrew program implements TOTP (RFC 6238) and lets you use your PSP as an authenticator device to many 2FA systems. The user must provide their own keyfile with each line as a seperate TOTP authenticator, which can be exported from Google Authenticator for example with a tool such as [otpauth](https://github.com/dim13/otpauth). The exact format is explained under [Installation](#installation) and an example OTPAUTH_KEYS file is provided for reference.

## Prerequisites

- A PSP 1000/2000/3000 with any CFW
- A memory stick and sufficient free space for EBOOT.PBP and your keyfile
- For emulators like PPSSPP: The original PSP .pgf font files should be present under "C:\Program Files\PPSSPP\assets\flash0\font\", which you must copy from a physical PSP's flash0:/font/ directory, or obtain them elsewhere ;). (This is because Intrafont 0.31 cannot load the "open source" .pgf alternative fonts shipped with PPSSPP)

## Installation
1. Copy the EBOOT.PBP into a new game folder on the memory stick `ms0:/PSP/GAME/TOTP4PSP/EBOOT.PBP`
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

Prerequisites: a working installation of the [psptoolchain](https://github.com/pspdev/psptoolchain) (psp-gcc)  
1. Clone this repo under `pspdev/projects/TOTP4PSP`
2. Verify that `psp-gcc` is accessible in your current shell (psptoolchain should have set up your PATH automatically)
3. Run `make` and use the generated `EBOOT.PBP` for the steps in [Installation](#installation)

## Contact
Please reach out at arcyleung@gmail.com for feature requests or consider supporting my work over at [ko-fi](https://ko-fi.com/arcyleung).
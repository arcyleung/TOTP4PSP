# Time-based One-Time Password for PlayStation Portable (TOTP4PSP) 
<p align="center">
    <img src="totp4psp.jpg" width="65%" />
</p>

This homebrew program implements TOTP (RFC 6238) and lets you use your PSP as a hardware token generator to many 2FA authentication systems. Other 2FA methods are weaker (SMS-based 2FA is susceptible to SIM swapping attacks for instance) and so the safest option is still to have an offline generator.

The user must provide their own OTPAUTH_KEYS file with each line as a seperate TOTP authenticator URI, which can be exported from Google Authenticator for example with a tool such as [otpauth](https://github.com/dim13/otpauth). The exact format is explained [here](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) and is discussed further under [Installation](#installation); an example OTPAUTH_KEYS file is also provided for reference.

Here is a YouTube link to my PSPHDC24' talk: https://www.youtube.com/live/0rxTPSFSC-k?t=2512s

## Prerequisites

- A PSP 1000/2000/3000 with any CFW
- A memory stick and sufficient free space for EBOOT.PBP and your keyfile
- For emulators like PPSSPP: The original PSP .pgf font files should be present under "C:\Program Files\PPSSPP\assets\flash0\font\", which you must copy from a physical PSP's flash0:/font/ directory, or obtain them elsewhere ;). (This is because intraFont 0.31 cannot load the "open source" .pgf alternative fonts shipped with PPSSPP)

## Installation
1. Copy the EBOOT.PBP into a new game folder on the memory stick ie. `ms0:/PSP/GAME/TOTP4PSP/EBOOT.PBP`
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
3. Ensure the system time of the PSP is correctly set in "Settings" > "Date & Time Settings", either set manually or via internet, and also paying attention to whether Daylight Saving Time is enabled. 
4. Launch the app from the XMB as you would with any homebrew. The screen displays up to 12 OTP codes at once but you can scroll with Up/Down on the Dpad.

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
1. Clone this repo and its submodules with `git clone --recurse-submodules https://github.com/arcyleung/TOTP4PSP.git TOTP4PSP/`
2. `cd ./TOTP4PSP`
3. Verify that `psp-gcc` is accessible in your current shell (psptoolchain should have set up your PATH automatically)
4. Run `make` and use the generated `EBOOT.PBP` for the steps in [Installation](#installation)

## Credits
BenHur for [intraFont](https://github.com/PSP-Archive/intraFont)  
[Akagi201](https://github.com/Akagi201) for [hmac-sha1 implementation](https://github.com/Akagi201/hmac-sha1)  
Markus Gutschke for [Base32 implementation](https://github.com/google/google-authenticator-libpam/tree/master/src)  

## Contact
Please reach out at arcyleung@gmail.com for feature requests or consider supporting my work over at [ko-fi](https://ko-fi.com/arcyleung).


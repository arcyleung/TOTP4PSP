# Time-based One-Time Password for Playstation Portable (TOTP4PSP) 

This homebrew program implements TOTP (RFC 6238) and lets you use your PSP as an authenticator device to many 2FA systems. The user must provide a keyfile with each line as a seperate TOTP authenticator, which can be exported from Google Authenticator for example with a tool such as [otpauth](https://github.com/dim13/otpauth). 

The keyfile should be placed in `ms0:/PSP/COMMON/otpauth_file` and have the following format, one line per provider:
```
otpauth://totp/<name1>?algorithm=SHA1&digits=6&period=30&secret=<secret1>
otpauth://totp/<name2>?algorithm=SHA1&digits=6&issuer=<issuer2>&period=30&secret=<secret2>
...
```

The following fields and corresponding methods are currently supported:
```
algorithm=[SHA1|SHA256|SHA512]
digits=[6-8]
period=[30-60s]
secret=<minimum 160-bit string>
```

## Building

Prerequisites: psptoolchain/ psp-sdk (psp-gcc)  
TODO: Add steps
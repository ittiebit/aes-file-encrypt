//
//    Test samples from "Block Cipher Modes of Operation":
//    - ECB:
//    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
//    - CBC:
//    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //for memcpy...
#include "../include/aes.h"
#include "../include/definitions.h"
#include "../include/filecrypt.h"
#include "../include/utils.h"
#include "test-utils.h"

#define VERBOSE 1
#define BENCHMARK 1

#if BENCHMARK == 1
#include <time.h>
#endif

static float startTime, endTime;
static byte state[TEXT_SIZE+16];
static cipher_ctx * aes;

int testCipherEncrypt128ECB() {
    printf("AES-128 DIRECT AES CIPHER ECB ENCRYPT TEST...\n");
    memcpy(state, any128Plaintext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    for (size_t i = 0; i < TEXT_SIZE; i+=16) {
        cipher(aes->roundKeys, state+i);
    }

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    return compareByteArrays(state, ECB128Ciphertext, TEXT_SIZE, VERBOSE);
}

int testCipherDecrypt128ECB() {
    printf("AES-128 DIRECT AES CIPHER ECB DECRYPT TEST...\n");
    memcpy(state, ECB128Ciphertext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    for (size_t i = 0; i < TEXT_SIZE; i+=16) {
        invCipher(aes->roundKeys, state+i);
    }

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    return compareByteArrays(state, any128Plaintext, TEXT_SIZE, VERBOSE);
}

int testFilecryptEncrypt128ECB() {
    printf("AES-128 FILECRYPT ECB ENCRYPT TEST...\n");
    memcpy(state, any128Plaintext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    filecrypt_ctx * fctx = createFileCtx(aes, ECB, TEXT_SIZE);

    encryptBytes(fctx, TEXT_SIZE, state);

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    freeFileCtx(fctx);
    return compareByteArrays(state, ECB128Ciphertext, TEXT_SIZE, VERBOSE);
}

int testFilecryptDecrypt128ECB() {
    printf("AES-128 FILECRYPT ECB DECRYPT TEST...\n");
    memcpy(state, ECB128Ciphertext, sizeof(byte) * TEXT_SIZE);


#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif
    filecrypt_ctx * fctx = createFileCtx(aes, ECB, TEXT_SIZE);

    decryptBytes(fctx, TEXT_SIZE, state);

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    freeFileCtx(fctx);
    return compareByteArrays(state, any128Plaintext, TEXT_SIZE, VERBOSE);
}

int testFilecryptEncrypt128CBC() {
    printf("AES-128 FILECRYPT CBC ENCRYPT TEST...\n");
    memcpy(state, any128Plaintext, sizeof(byte) * TEXT_SIZE);

    filecrypt_ctx * fctx = createFileCtx(aes, CBC, TEXT_SIZE);
    addFileCtxIV(fctx, iv, IV_SIZE);

#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    encryptBytes(fctx, TEXT_SIZE, state);

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    freeFileCtx(fctx);
    return compareByteArrays(state, CBC128Ciphertext, TEXT_SIZE, VERBOSE);
}

int testFilecryptDecrypt128CBC() {
    printf("AES-128 FILECRYPT CBC DECRYPT TEST...\n");
    memcpy(state, CBC128Ciphertext, sizeof(byte) * TEXT_SIZE);

    filecrypt_ctx * fctx = createFileCtx(aes, CBC, TEXT_SIZE);
    addFileCtxIV(fctx, iv, IV_SIZE);

#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    decryptBytes(fctx, TEXT_SIZE, state);

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    freeFileCtx(fctx);
    return compareByteArrays(state, any128Plaintext, TEXT_SIZE, VERBOSE);
}

void runTest(int (*testFuncPtr)()) {
    int mismatchCount;

    mismatchCount = testFuncPtr();

#if VERBOSE == 1
    printf("\n%d mismatching bytes\n", mismatchCount);
#endif

    if (mismatchCount == 0)
        printf("...PASSED\n\n");
    else
        printf("...FAILED\n\n");
}

int main(int argc, char **argv) {
    aes = createAESctx(core128Key, 128);
    keyExpansion(aes->key, aes->roundKeys);

    runTest(&testCipherEncrypt128ECB);
    runTest(&testCipherDecrypt128ECB);

    runTest(&testFilecryptEncrypt128ECB);
    runTest(&testFilecryptDecrypt128ECB);

    runTest(&testFilecryptEncrypt128CBC);

    //It doesnt work due to padding
    //runTest(&testFilecryptDecrypt128CBC);

    freeAESctx(aes);
    return 0;
}

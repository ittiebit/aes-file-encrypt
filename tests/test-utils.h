#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../include/filecrypt.h"


#define TEXT_SIZE 64
#define KEY_SIZE 16
#define IV_SIZE 16

#define MAX_THREAD_COUNT 8

#define PDF 0x1
#define TXT 0x2

struct args_struct {
    filecrypt_ctx * fctx;
    FILE * readFile;
    FILE * writeFileEncrypted;
    FILE * writeFileDecrypted;
    size_t threadNumber;
};

// Pretty sure this key is used by everyone everywhere for testing
// 2b7e151628aed2a6abf7158809cf4f3c
extern const byte core128Key[KEY_SIZE];
// iV - 000102030405060708090a0b0c0d0e0f
extern const byte iv[IV_SIZE];
// Plaintext is the same for ECB, CBC
extern const byte any128Plaintext[TEXT_SIZE];
extern const byte ECB128Ciphertext[TEXT_SIZE];
extern const byte CBC128Ciphertext[TEXT_SIZE];


long printFailStatus(long value);
char * fileNameMaker(uint8_t mode, uint16_t version, uint8_t isEncrypt, uint8_t fileType, long appendValue);
void deleteWrittenFiles(uint8_t mode, uint16_t version, uint8_t fileType, size_t fileCount);

extern const char * plainPDFSamplesArray[MAX_THREAD_COUNT];
extern const char * plainPDFSample;
extern const char * cipherPDFSampleArray[2];
extern const char * cipherTXTSample;
extern const char * plainTXTSample;
extern const char * cipherIMGSample;
extern const char * plainIMGSample;


#endif // _TEST_UTILS_H

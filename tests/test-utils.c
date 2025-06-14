#include "test-utils.h"
#include <stdlib.h>
#include <string.h>

// Pretty sure this key is used by everyone everywhere for testing
// 2b7e151628aed2a6abf7158809cf4f3c
const byte core128Key[KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                      0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                      0x09, 0xcf, 0x4f, 0x3c};

// iV - 000102030405060708090a0b0c0d0e0f
const byte iv[IV_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// Plaintext is the same for ECB, CBC
const byte any128Plaintext[TEXT_SIZE] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
    0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
    0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
    0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
    0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
    0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

const byte ECB128Ciphertext[TEXT_SIZE] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
    0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
    0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf, 0x43,
    0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3,
    0xed, 0x03, 0x06, 0x88, 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad,
    0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4};

const byte CBC128Ciphertext[TEXT_SIZE] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e,
    0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72,
    0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73,
    0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e,
    0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac,
    0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};


const char * plainPDFSamplesArray[MAX_THREAD_COUNT] = {
    "./samples/file.pdf", "./samples/file-2.pdf", "./samples/file-3.pdf", "./samples/file-4.pdf",
    "./samples/file-5.pdf", "./samples/file-6.pdf", "./samples/file-7.pdf", "./samples/file-8.pdf"
};

const char * plainPDFSample = "./samples/file.pdf";
const char * cipherPDFSampleArray[2] = {"./samples/ecb-128-encrypted.pdf.dat", "./samples/cbc-128-encrypted.pdf.dat"};

const char * cipherTXTSample = "./samples/cfile.md";
const char * plainTXTSample = "./samples/file.md";
//const char * cipherIMGSample = "./samples/c-lorem-picsum-200.jpg";
//const char * plainIMGSample = "./samples/lorem-picsum-200.jpg";




long printFailStatus(long value) {
    if (value != 0) {
        fprintf(stdout, "...FAIL\n");
    } else {
        fprintf(stdout, "...OK\n");
    }
    return value;
}

char * fileNameMaker(uint8_t mode, uint16_t version, uint8_t isEncrypt, uint8_t fileType, long appendValue) {
    char * fileName = malloc(sizeof(char) * 32);
    memset(fileName, '\0', 32);
    switch (mode) {
        case ECB:
            strcat(fileName, "ecb-");
            break;
        case CBC:
            strcat(fileName, "cbc-");
            break;
    }
    switch (version) {
        case 128:
            strcat(fileName, "128-");
            break;
        case 196:
            strcat(fileName, "196-");
            break;
        case 256:
            strcat(fileName, "256-");
            break;
    }
    switch (isEncrypt) {
        case ENCRYPT:
            strcat(fileName, "encrypted");
            break;
        case DECRYPT:
            strcat(fileName, "decrypted");
            break;
    }
    if (appendValue >= 0) {
        char istr[sizeof(appendValue)];
        sprintf(istr, "-%ld", appendValue);
        strcat(fileName, istr);
    }
    switch (fileType) {
        case PDF:
            strcat(fileName, ".pdf");
            break;
        case TXT:
            strcat(fileName, ".md");
            break;
    }
    return fileName;
}

void deleteWrittenFiles(uint8_t mode, uint16_t version, uint8_t fileType, size_t fileCount) {
    fprintf(stdout, "DELETING WRITTEN FILES\n");
    char * fileName;
    size_t result = 0;
    for (size_t fileNumber = 0; fileNumber < fileCount; fileNumber++) {
        fileName = fileNameMaker(mode, version, ENCRYPT, PDF, fileNumber);
        fprintf(stdout, "Deleting file: %s ", fileName);
        result += printFailStatus(remove(fileName));
    }
    for (size_t fileNumber = 0; fileNumber < fileCount; fileNumber++) {
        fileName = fileNameMaker(mode, version, DECRYPT, PDF, fileNumber);
        fprintf(stdout, "Deleting file: %s ", fileName);
        result += printFailStatus(remove(fileName));
    }
}



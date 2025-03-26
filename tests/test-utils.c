#include "test-utils.h"
#include "sample-files.h"
#include <stdlib.h>
#include <string.h>

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



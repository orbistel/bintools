// Wikipedia'daki tüm dosya imzaları
// Otomatik olarak üretilmiştir

#ifndef FILE_SIGNATURES_COMPLETE_H
#define FILE_SIGNATURES_COMPLETE_H

#include <stdlib.h>

typedef struct {
    const unsigned char *signature;
    int length;
    const char *extension;
    const char *description;
} FileSignature;

static const FileSignature all_signatures[] = {
};

#define TOTAL_SIGNATURES 0
#endif

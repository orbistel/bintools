// file_signatures.h
#ifndef FILE_SIGNATURES_H
#define FILE_SIGNATURES_H

typedef struct {
    unsigned char *signature;    // İmza bayt dizisi
    int length;                  // İmza uzunluğu
    char *extension;             // Dosya uzantısı (opsiyonel, bilgilendirme için)
} FileSignature;

// Wikipedia tablosundan derlenmiş bazı örnek imzalar
static FileSignature known_signatures[] = {
    {(unsigned char[]){0x23, 0x21}, 2, "#! script"},
    {(unsigned char[]){0x4D, 0x5A}, 2, "EXE"},           // MZ
    {(unsigned char[]){0xFF, 0xD8, 0xFF}, 3, "JPEG"},    // JPEG başlangıcı
    {(unsigned char[]){0x89, 0x50, 0x4E, 0x47}, 4, "PNG"},
    {(unsigned char[]){0x25, 0x50, 0x44, 0x46}, 4, "PDF"},
    {(unsigned char[]){0x50, 0x4B, 0x03, 0x04}, 4, "ZIP"},
    {(unsigned char[]){0x52, 0x61, 0x72, 0x21}, 4, "RAR"},
    {(unsigned char[]){0x49, 0x49, 0x2A, 0x00}, 4, "TIFF (little-endian)"},
    {(unsigned char[]){0x47, 0x49, 0x46, 0x38}, 4, "GIF"},
    {(unsigned char[]){0x42, 0x4D}, 2, "BMP"},
    {(unsigned char[]){0x00, 0x00, 0x01, 0x00}, 4, "ICO"},
    {(unsigned char[]){0x49, 0x44, 0x33}, 3, "MP3"},
    {(unsigned char[]){0x66, 0x74, 0x79, 0x70}, 4, "MP4"},
    {(unsigned char[]){0x53, 0x51, 0x4C, 0x69}, 4, "SQLite"}, // SQLite format 3
    {(unsigned char[]){0x1F, 0x8B, 0x08}, 3, "GZIP"},
    {(unsigned char[]){0x37, 0x7A, 0xBC, 0xAF}, 4, "7z"},
    {(unsigned char[]){0x04, 0x22, 0x4D, 0x18}, 4, "LZ4"},
    {(unsigned char[]){0x42, 0x5A, 0x68}, 3, "BZIP2"},
    {(unsigned char[]){0x50, 0x57, 0x53, 0x33}, 4, "Password Gorilla"}, // PWS3
    {(unsigned char[]){0xED, 0xAB, 0xEE, 0xDB}, 4, "RPM package"},
    {(unsigned char[]){0xD4, 0xC3, 0xB2, 0xA1}, 4, "Libpcap"},
    {(unsigned char[]){0x0A, 0x0D, 0x0D, 0x0A}, 4, "pcapng"}
};

#define SIGNATURE_COUNT (sizeof(known_signatures) / sizeof(known_signatures[0]))

#endif

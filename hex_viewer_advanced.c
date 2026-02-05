// hex_viewer_advanced.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define BYTES_PER_LINE 16
#define MAX_SIGNATURES 100

typedef struct {
    char name[32];
    unsigned char signature[16];
    int length;
    long offset;
} FileSignature;

FileSignature known_signatures[] = {
    {"JPEG", {0xFF, 0xD8, 0xFF}, 3, 0},
    {"PNG", {0x89, 0x50, 0x4E, 0x47}, 4, 0},
    {"PDF", {0x25, 0x50, 0x44, 0x46}, 4, 0},
    {"ZIP", {0x50, 0x4B, 0x03, 0x04}, 4, 0},
    {"EXE", {0x4D, 0x5A}, 2, 0},
    {"GIF", {0x47, 0x49, 0x46, 0x38}, 4, 0},
    {"BMP", {0x42, 0x4D}, 2, 0},
    {"MP3", {0x49, 0x44, 0x33}, 3, 0},
    {"SQLite", {0x53, 0x51, 0x4C, 0x69}, 4, 0},
    {"RAR", {0x52, 0x61, 0x72, 0x21}, 4, 0}
};

void print_hex_line(unsigned char *buffer, size_t bytes_read, 
                    long current_offset, FILE *output) {
    // Offset
    fprintf(output, "%08lX  ", current_offset);
    
    // Hex bytes
    for (int i = 0; i < BYTES_PER_LINE; i++) {
        if (i < bytes_read) {
            fprintf(output, "%02X ", buffer[i]);
        } else {
            fprintf(output, "   ");
        }
        
        if (i == 7) fprintf(output, " ");
    }
    
    fprintf(output, " |");
    
    // ASCII
    for (int i = 0; i < bytes_read; i++) {
        if (isprint(buffer[i]) && !iscntrl(buffer[i])) {
            fprintf(output, "%c", buffer[i]);
        } else {
            fprintf(output, ".");
        }
    }
    
    fprintf(output, "|\n");
}

void hex_dump_advanced(FILE *input, FILE *output, 
                      long start_offset, long byte_count, 
                      int show_ascii, int show_offset) {
    unsigned char buffer[BYTES_PER_LINE];
    long total_read = 0;
    
    fseek(input, start_offset, SEEK_SET);
    
    if (show_offset) {
        fprintf(output, "Offset   ");
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            fprintf(output, "%02X ", i);
            if (i == 7) fprintf(output, " ");
        }
        if (show_ascii) {
            fprintf(output, " ASCII Values\n");
        }
        fprintf(output, "\n-------- ");
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            fprintf(output, "---");
        }
        if (show_ascii) {
            fprintf(output, " -------------\n");
        } else {
            fprintf(output, "\n");
        }
    }
    
    while (total_read < byte_count || byte_count == 0) {
        size_t to_read = BYTES_PER_LINE;
        if (byte_count > 0 && (total_read + to_read) > byte_count) {
            to_read = byte_count - total_read;
        }
        
        size_t bytes_read = fread(buffer, 1, to_read, input);
        if (bytes_read == 0) break;
        
        print_hex_line(buffer, bytes_read, start_offset + total_read, output);
        
        total_read += bytes_read;
        if (bytes_read < BYTES_PER_LINE && byte_count == 0) break;
    }
    
    fprintf(output, "\nTotal bytes displayed: %ld\n", total_read);
}

void save_to_file(FILE *input, long start_offset, long byte_count, 
                 const char *output_filename) {
    FILE *output = fopen(output_filename, "wb");
    if (!output) {
        printf("Error creating output file\n");
        return;
    }
    
    fseek(input, start_offset, SEEK_SET);
    unsigned char buffer[4096];
    long remaining = byte_count;
    
    while (remaining > 0) {
        size_t to_read = (remaining > 4096) ? 4096 : remaining;
        size_t bytes_read = fread(buffer, 1, to_read, input);
        if (bytes_read == 0) break;
        
        fwrite(buffer, 1, bytes_read, output);
        remaining -= bytes_read;
    }
    
    fclose(output);
    printf("Saved %ld bytes to %s\n", byte_count - remaining, output_filename);
}

int main(int argc, char *argv[]) {
    printf("=== Advanced Hex Viewer ===\n");
    
    if (argc < 4) {
        printf("Usage: %s <file> <offset> <bytes> [options]\n", argv[0]);
        printf("\nOptions:\n");
        printf("  -a    Hide ASCII column\n");
        printf("  -o    Hide offset column\n");
        printf("  -s    Save extracted bytes to file\n");
        printf("  -f    Find file signatures\n");
        return 1;
    }
    
    const char *filename = argv[1];
    long offset = strtol(argv[2], NULL, 0);
    long byte_count = strtol(argv[3], NULL, 0);
    
    int show_ascii = 1;
    int show_offset = 1;
    int find_signatures = 0;
    int save_extract = 0;
    
    // Parse options
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) show_ascii = 0;
        else if (strcmp(argv[i], "-o") == 0) show_offset = 0;
        else if (strcmp(argv[i], "-f") == 0) find_signatures = 1;
        else if (strcmp(argv[i], "-s") == 0) save_extract = 1;
    }
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error opening file: %s\n", filename);
        return 1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    
    if (offset >= file_size) {
        printf("Error: Offset beyond file size\n");
        fclose(file);
        return 1;
    }
    
    if (byte_count == 0) {
        byte_count = file_size - offset;
    } else if (offset + byte_count > file_size) {
        byte_count = file_size - offset;
    }
    
    printf("File: %s\n", filename);
    printf("Size: %ld bytes\n", file_size);
    printf("Viewing: offset %ld, %ld bytes\n\n", offset, byte_count);
    
    // Perform hex dump
    hex_dump_advanced(file, stdout, offset, byte_count, show_ascii, show_offset);
    
    // Find signatures if requested
    if (find_signatures && offset == 0) {
        printf("\n=== Signature Analysis ===\n");
        unsigned char header[512];
        fseek(file, 0, SEEK_SET);
        size_t read = fread(header, 1, 512, file);
        
        for (int i = 0; i < sizeof(known_signatures)/sizeof(known_signatures[0]); i++) {
            if (read >= known_signatures[i].length) {
                if (memcmp(header, known_signatures[i].signature, 
                          known_signatures[i].length) == 0) {
                    printf("Found: %s signature\n", known_signatures[i].name);
                }
            }
        }
    }
    
    // Save extracted data if requested
    if (save_extract) {
        char output_name[256];
        snprintf(output_name, sizeof(output_name), 
                "extracted_%ld_%ld.bin", offset, byte_count);
        save_to_file(file, offset, byte_count, output_name);
    }
    
    fclose(file);
    return 0;
}

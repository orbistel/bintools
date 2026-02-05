// hex_repair_large_fixed.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#define BYTES_PER_LINE 16
#define MAX_SIGNATURE_LENGTH 32
#define BUFFER_SIZE 65536
#define MAX_SIGNATURES 50

// 64-bit dosya offset'leri
#ifdef _WIN32
    typedef __int64 file_offset_t;
    #define FSEEK _fseeki64
    #define FTELL _ftelli64
#else
    #include <sys/types.h>
    typedef off_t file_offset_t;
    #define FSEEK fseeko
    #define FTELL ftello
#endif

typedef struct {
    char name[32];
    unsigned char signature[MAX_SIGNATURE_LENGTH];
    int length;
    file_offset_t offset;
    char description[128];
    char extension[16];
} FileSignature;

FileSignature known_signatures[] = {
    {"JPEG", {0xFF, 0xD8, 0xFF}, 3, 0, "JPEG image file", "jpg"},
    {"PNG", {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 8, 0, "PNG image", "png"},
    {"PDF", {0x25, 0x50, 0x44, 0x46}, 4, 0, "PDF document", "pdf"},
    {"ZIP", {0x50, 0x4B, 0x03, 0x04}, 4, 0, "ZIP archive", "zip"},
    {"MP4", {0x00, 0x00, 0x00, 0x00, 0x66, 0x74, 0x79, 0x70}, 8, 4, "MP4 video", "mp4"},
    {"AVI", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20}, 12, 0, "AVI video", "avi"},
    {"MKV", {0x1A, 0x45, 0xDF, 0xA3}, 4, 0, "Matroska video", "mkv"},
    {"ISO", {0x01, 0x43, 0x44, 0x30, 0x30, 0x31}, 6, 0x8001, "ISO9660 CD/DVD", "iso"},
    {"EXE", {0x4D, 0x5A}, 2, 0, "DOS/Windows executable", "exe"},
    {"RAR", {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, 7, 0, "RAR archive", "rar"},
    {"GZIP", {0x1F, 0x8B}, 2, 0, "GZIP compressed", "gz"},
    {"BMP", {0x42, 0x4D}, 2, 0, "Bitmap image", "bmp"},
    {"GIF", {0x47, 0x49, 0x46, 0x38}, 4, 0, "GIF image", "gif"},
    {"WAV", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45}, 12, 0, "WAVE audio", "wav"},
    {"MP3", {0x49, 0x44, 0x33}, 3, 0, "MP3 audio", "mp3"},
    {"SQLite", {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, 16, 0, "SQLite database", "db"}
};

#define SIGNATURE_COUNT (sizeof(known_signatures) / sizeof(known_signatures[0]))

// Fonksiyon prototipleri
void print_usage(const char *program_name);
file_offset_t parse_size_with_suffix(const char *str);
void format_size(file_offset_t size, char *buffer, size_t buffer_size);
bool get_file_size(FILE *file, file_offset_t *size);
void show_progress_bar(file_offset_t current, file_offset_t total, const char *operation);
FileSignature* find_signature_by_name(const char *name);
bool analyze_corruption(FILE *file, file_offset_t position, 
                       FileSignature *sig, unsigned char bad_byte,
                       int *corrupt_count, int *total_bytes);
int repair_signature_at(FILE *file, file_offset_t position, 
                       FileSignature *sig, unsigned char bad_byte,
                       bool interactive, bool verbose, bool test_mode);
int auto_repair_range(FILE *file, file_offset_t start_offset, 
                     file_offset_t byte_count, unsigned char bad_byte,
                     bool interactive, bool verbose, bool test_mode,
                     bool show_progress_flag);
int targeted_repair(FILE *file, file_offset_t start_offset,
                   FileSignature *sig, unsigned char bad_byte,
                   bool interactive, bool verbose, bool test_mode);
void hex_display(FILE *file, file_offset_t start_offset, 
                file_offset_t byte_count, int max_lines);

void print_usage(const char *program_name) {
    printf("\n=== Large File Hex Repair (Supports >2GB files) ===\n");
    printf("Usage: %s <file> <offset> <bytes> [options]\n\n", program_name);
    
    printf("Parameters support suffixes: K,M,G,T (e.g., 4K, 2M, 1G, 0x1000)\n\n");
    
    printf("REPAIR OPTIONS (fix corrupted files without backup):\n");
    printf("  -t <format>  Repair specific format (e.g., JPEG, PNG, PDF)\n");
    printf("  -x <char>    Character that indicates corruption (e.g., *, ?, #)\n");
    printf("  -X <hex>     Hex value that indicates corruption (e.g., 00, FF, 2A)\n");
    printf("  -A           Auto-repair mode (try all formats with common patterns)\n");
    printf("  -i           Interactive mode (ask before each repair)\n");
    printf("  -p           Show progress bar\n");
    printf("  -v           Verbose mode (show details)\n");
    printf("  -test        Test mode (show what would be repaired, no changes)\n");
    
    printf("\nVIEW/SCAN OPTIONS:\n");
    printf("  -f           Find and show file signatures\n");
    printf("  -s <file>    Save repaired portion to new file\n");
    printf("  -c <N>       Limit display to N lines\n");
    printf("  -l           List all available formats\n");
    
    printf("\nExamples:\n");
    printf("  %s corrupted.jpg 0 0 -t JPEG -x * -i\n", program_name);
    printf("  %s broken.iso 0 1G -t ISO -X 00 -p\n", program_name);
    printf("  %s damaged.mp4 0 100M -A -v\n", program_name);
}

file_offset_t parse_size_with_suffix(const char *str) {
    if (!str || !*str) return 0;
    
    char *endptr;
    file_offset_t value = strtoll(str, &endptr, 0);
    
    if (*endptr) {
        switch (tolower(*endptr)) {
            case 'k': value *= 1024LL; break;
            case 'm': value *= 1024LL * 1024LL; break;
            case 'g': value *= 1024LL * 1024LL * 1024LL; break;
            case 't': value *= 1024LL * 1024LL * 1024LL * 1024LL; break;
            default: return value;
        }
    }
    
    return value;
}

void format_size(file_offset_t size, char *buffer, size_t buffer_size) {
    const char *units[] = {"bytes", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double display_size = (double)size;
    
    while (display_size >= 1024.0 && unit_index < 4) {
        display_size /= 1024.0;
        unit_index++;
    }
    
    if (unit_index == 0) {
        snprintf(buffer, buffer_size, "%lld bytes", (long long)size);
    } else {
        snprintf(buffer, buffer_size, "%.2f %s", display_size, units[unit_index]);
    }
}

bool get_file_size(FILE *file, file_offset_t *size) {
    file_offset_t current = FTELL(file);
    
    if (FSEEK(file, 0, SEEK_END) != 0) {
        return false;
    }
    
    *size = FTELL(file);
    FSEEK(file, current, SEEK_SET);
    
    return true;
}

void show_progress_bar(file_offset_t current, file_offset_t total, const char *operation) {
    if (total == 0) return;
    
    int percent = (int)((current * 100) / total);
    int bar_width = 50;
    
    printf("\r%s [", operation);
    int pos = (bar_width * percent) / 100;
    for (int i = 0; i < bar_width; i++) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %3d%%", percent);
    fflush(stdout);
}

FileSignature* find_signature_by_name(const char *name) {
    for (int i = 0; i < SIGNATURE_COUNT; i++) {
        if (strcasecmp(known_signatures[i].name, name) == 0) {
            return &known_signatures[i];
        }
    }
    return NULL;
}

bool analyze_corruption(FILE *file, file_offset_t position, 
                       FileSignature *sig, unsigned char bad_byte,
                       int *corrupt_count, int *total_bytes) {
    
    FSEEK(file, position + sig->offset, SEEK_SET);
    unsigned char buffer[MAX_SIGNATURE_LENGTH];
    
    size_t bytes_read = fread(buffer, 1, sig->length, file);
    if (bytes_read != sig->length) {
        return false;
    }
    
    *corrupt_count = 0;
    *total_bytes = sig->length;
    
    // Check each byte
    for (int i = 0; i < sig->length; i++) {
        if (buffer[i] == bad_byte) {
            (*corrupt_count)++;
        }
    }
    
    return (*corrupt_count) > 0;
}

int repair_signature_at(FILE *file, file_offset_t position, 
                       FileSignature *sig, unsigned char bad_byte,
                       bool interactive, bool verbose, bool test_mode) {
    
    FSEEK(file, position + sig->offset, SEEK_SET);
    unsigned char current[MAX_SIGNATURE_LENGTH];
    size_t read = fread(current, 1, sig->length, file);
    
    if (read != sig->length) {
        if (verbose) printf("Could not read signature bytes\n");
        return 0;
    }
    
    // Check if already correct
    if (memcmp(current, sig->signature, sig->length) == 0) {
        if (verbose) printf("Signature already correct\n");
        return 0;
    }
    
    // Count corrupted bytes
    int corrupted_bytes = 0;
    for (int i = 0; i < sig->length; i++) {
        if (current[i] == bad_byte) {
            corrupted_bytes++;
        }
    }
    
    if (corrupted_bytes == 0) {
        if (verbose) printf("No matching bad bytes found (expected 0x%02X)\n", bad_byte);
        return 0;
    }
    
    // Show analysis
    printf("\n🔍 %s Analysis at offset ", sig->name);
    char offset_str[64];
    format_size(position + sig->offset, offset_str, sizeof(offset_str));
    printf("%s:\n", offset_str);
    
    printf("Expected: ");
    for (int i = 0; i < sig->length; i++) {
        printf("%02X ", sig->signature[i]);
    }
    printf("\nCurrent:  ");
    for (int i = 0; i < sig->length; i++) {
        if (current[i] == bad_byte) {
            printf("\033[1;31m%02X\033[0m ", current[i]); // Red for bad bytes
        } else if (current[i] == sig->signature[i]) {
            printf("\033[1;32m%02X\033[0m ", current[i]); // Green for correct
        } else {
            printf("\033[1;33m%02X\033[0m ", current[i]); // Yellow for different
        }
    }
    printf("\n");
    
    printf("Status: %d/%d bytes corrupted by 0x%02X\n", 
           corrupted_bytes, sig->length, bad_byte);
    
    if (test_mode) {
        printf("TEST MODE: Would repair %d bytes\n", corrupted_bytes);
        return corrupted_bytes;
    }
    
    if (interactive) {
        printf("Repair? (y/N): ");
        char response[10];
        fgets(response, sizeof(response), stdin);
        if (response[0] != 'y' && response[0] != 'Y') {
            printf("Skipped\n");
            return 0;
        }
    }
    
    // Perform repair
    if (!test_mode) {
        FSEEK(file, position + sig->offset, SEEK_SET);
        for (int i = 0; i < sig->length; i++) {
            if (current[i] == bad_byte) {
                fwrite(&sig->signature[i], 1, 1, file);
            } else {
                // Skip already correct bytes
                fseek(file, 1, SEEK_CUR);
            }
        }
        fflush(file);
    }
    
    printf("✅ Repaired %d bytes\n", corrupted_bytes);
    return corrupted_bytes;
}

int auto_repair_range(FILE *file, file_offset_t start_offset, 
                     file_offset_t byte_count, unsigned char bad_byte,
                     bool interactive, bool verbose, bool test_mode,
                     bool show_progress_flag) {
    
    file_offset_t file_size;
    get_file_size(file, &file_size);
    
    if (byte_count == 0) {
        byte_count = file_size - start_offset;
    }
    
    printf("\n🤖 AUTO-REPAIR MODE\n");
    printf("Bad byte pattern: 0x%02X", bad_byte);
    if (isprint(bad_byte)) printf(" ('%c')", bad_byte);
    printf("\n");
    
    int total_repairs = 0;
    int total_bytes_repaired = 0;
    file_offset_t bytes_scanned = 0;
    
    // Scan through the range
    for (int sig_idx = 0; sig_idx < SIGNATURE_COUNT; sig_idx++) {
        FileSignature *sig = &known_signatures[sig_idx];
        
        // Check if signature could fit
        if (sig->offset + sig->length > byte_count) {
            continue;
        }
        
        file_offset_t sig_position = start_offset + sig->offset;
        
        // Check bounds
        if (sig_position + sig->length > file_size) {
            continue;
        }
        
        // Analyze for corruption
        int corrupt_count, total_bytes;
        if (analyze_corruption(file, start_offset, sig, bad_byte, 
                              &corrupt_count, &total_bytes)) {
            
            if (verbose) {
                printf("Potential corruption found: %s at offset ", sig->name);
                char pos_str[64];
                format_size(sig_position, pos_str, sizeof(pos_str));
                printf("%s\n", pos_str);
            }
            
            int repaired = repair_signature_at(file, start_offset, sig, bad_byte,
                                             interactive, verbose, test_mode);
            
            if (repaired > 0) {
                total_repairs++;
                total_bytes_repaired += repaired;
            }
        }
        
        bytes_scanned += sig->length;
        
        if (show_progress_flag) {
            show_progress_bar(bytes_scanned, byte_count, "Scanning");
        }
    }
    
    if (show_progress_flag) {
        printf("\n");
    }
    
    printf("\nAuto-repair complete:\n");
    printf("  Scanned: ");
    char scanned_str[64];
    format_size(bytes_scanned, scanned_str, sizeof(scanned_str));
    printf("%s\n", scanned_str);
    printf("  Repairs: %d signatures\n", total_repairs);
    printf("  Bytes repaired: %d\n", total_bytes_repaired);
    
    return total_repairs;
}

int targeted_repair(FILE *file, file_offset_t start_offset,
                   FileSignature *sig, unsigned char bad_byte,
                   bool interactive, bool verbose, bool test_mode) {
    
    printf("\n🎯 TARGETED REPAIR: %s\n", sig->name);
    printf("Signature length: %d bytes\n", sig->length);
    printf("Bad byte: 0x%02X", bad_byte);
    if (isprint(bad_byte)) printf(" ('%c')", bad_byte);
    printf("\n");
    
    file_offset_t file_size;
    get_file_size(file, &file_size);
    
    // Check bounds
    file_offset_t sig_position = start_offset + sig->offset;
    if (sig_position + sig->length > file_size) {
        printf("Error: Signature position beyond file end\n");
        return 0;
    }
    
    return repair_signature_at(file, start_offset, sig, bad_byte,
                              interactive, verbose, test_mode);
}

void hex_display(FILE *file, file_offset_t start_offset, 
                file_offset_t byte_count, int max_lines) {
    
    file_offset_t file_size;
    get_file_size(file, &file_size);
    
    if (byte_count == 0) {
        byte_count = file_size - start_offset;
    }
    
    FSEEK(file, start_offset, SEEK_SET);
    
    printf("\nHex View (first %d lines):\n", max_lines);
    printf("Offset          ");
    for (int i = 0; i < BYTES_PER_LINE; i++) {
        printf("%02X ", i);
        if (i == 7) printf(" ");
    }
    printf(" ASCII\n");
    printf("--------------- ");
    for (int i = 0; i < BYTES_PER_LINE; i++) printf("---");
    printf(" -------------\n");
    
    unsigned char buffer[BYTES_PER_LINE];
    int lines_displayed = 0;
    
    while (lines_displayed < max_lines) {
        size_t bytes_read = fread(buffer, 1, BYTES_PER_LINE, file);
        if (bytes_read == 0) break;
        
        printf("%014llX  ", (long long)(start_offset + (lines_displayed * BYTES_PER_LINE)));
        
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            if (i < bytes_read) {
                printf("%02X ", buffer[i]);
            } else {
                printf("   ");
            }
            if (i == 7) printf(" ");
        }
        
        printf(" |");
        for (int i = 0; i < bytes_read; i++) {
            if (isprint(buffer[i]) && !iscntrl(buffer[i])) {
                printf("%c", buffer[i]);
            } else {
                printf(".");
            }
        }
        printf("|\n");
        
        lines_displayed++;
    }
}

int main(int argc, char *argv[]) {
    printf("=== Large File Hex Repair (64-bit) ===\n");
    
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *filename = argv[1];
    file_offset_t offset = parse_size_with_suffix(argv[2]);
    file_offset_t byte_count = parse_size_with_suffix(argv[3]);
    
    // Options
    bool interactive = false;
    bool verbose = false;
    bool show_progress_flag = false;
    bool test_mode = false;
    bool find_only = false;
    bool auto_repair_mode = false;
    char *target_format = NULL;
    unsigned char bad_char = 0;
    unsigned char bad_hex = 0;
    bool use_char = false;
    bool use_hex = false;
    char *save_filename = NULL;
    int max_lines = 20;
    
    // Parse options
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            target_format = argv[++i];
        }
        else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            use_char = true;
            bad_char = argv[++i][0];
        }
        else if (strcmp(argv[i], "-X") == 0 && i + 1 < argc) {
            use_hex = true;
            bad_hex = (unsigned char)strtol(argv[++i], NULL, 16);
        }
        else if (strcmp(argv[i], "-A") == 0) auto_repair_mode = true;
        else if (strcmp(argv[i], "-i") == 0) interactive = true;
        else if (strcmp(argv[i], "-v") == 0) verbose = true;
        else if (strcmp(argv[i], "-p") == 0) show_progress_flag = true;
        else if (strcmp(argv[i], "-test") == 0) test_mode = true;
        else if (strcmp(argv[i], "-f") == 0) find_only = true;
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            save_filename = argv[++i];
        }
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            max_lines = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-l") == 0) {
            printf("\nAvailable repair formats:\n");
            for (int j = 0; j < SIGNATURE_COUNT; j++) {
                printf("%-20s %-8s Offset: 0x%llX\n", 
                       known_signatures[j].name,
                       known_signatures[j].extension,
                       (long long)known_signatures[j].offset);
            }
            return 0;
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Validate parameters
    if (!find_only) {
        if (!target_format && !auto_repair_mode) {
            printf("Error: Repair requires -t <format> or -A (auto-repair)\n");
            return 1;
        }
        
        if (!use_char && !use_hex && !auto_repair_mode) {
            printf("Error: Need corruption pattern (-x or -X)\n");
            return 1;
        }
    }
    
    if (test_mode) {
        printf("\n⚠️  TEST MODE: No changes will be made to the file\n");
    }
    
    // Open file
    FILE *file = fopen(filename, test_mode ? "rb" : "r+b");
    if (!file) {
        printf("Error opening file: %s\n", filename);
        return 1;
    }
    
    // Get file info
    file_offset_t file_size;
    if (!get_file_size(file, &file_size)) {
        printf("Error getting file size\n");
        fclose(file);
        return 1;
    }
    
    char size_str[64], offset_str[64], count_str[64];
    format_size(file_size, size_str, sizeof(size_str));
    format_size(offset, offset_str, sizeof(offset_str));
    format_size(byte_count, count_str, sizeof(count_str));
    
    printf("File: %s\n", filename);
    printf("Size: %s\n", size_str);
    printf("Offset: %s\n", offset_str);
    printf("Range: %s\n", count_str);
    
    // Determine bad byte
    unsigned char bad_byte = 0;
    if (use_char) bad_byte = bad_char;
    else if (use_hex) bad_byte = bad_hex;
    else if (auto_repair_mode) bad_byte = 0x00;
    
    if (auto_repair_mode) {
        printf("\nAuto-repair will try common corruption patterns:\n");
        printf("1. Null bytes (0x00)\n");
        printf("2. All ones (0xFF)\n");
        printf("3. Asterisk (0x2A)\n");
        printf("4. Question mark (0x3F)\n");
    }
    
    // Perform operations
    if (find_only) {
        printf("\n=== SIGNATURE SCAN ===\n");
        
        // Simple scan for signatures at offset
        for (int i = 0; i < SIGNATURE_COUNT; i++) {
            FileSignature *sig = &known_signatures[i];
            
            if (sig->offset + sig->length > byte_count && byte_count > 0) {
                continue;
            }
            
            FSEEK(file, offset + sig->offset, SEEK_SET);
            unsigned char buffer[64];
            size_t read = fread(buffer, 1, sig->length, file);
            
            if (read == sig->length) {
                if (memcmp(buffer, sig->signature, sig->length) == 0) {
                    printf("✅ Found: %s at offset +0x%llX\n", 
                           sig->name, (long long)sig->offset);
                }
            }
        }
    }
    else if (auto_repair_mode) {
        printf("\n=== AUTO REPAIR MODE ===\n");
        
        // Try common corruption patterns
        unsigned char patterns[] = {0x00, 0xFF, 0x2A, 0x3F, 0x20};
        int total_repairs = 0;
        
        for (int p = 0; p < sizeof(patterns); p++) {
            printf("\nTrying pattern 0x%02X:\n", patterns[p]);
            int repairs = auto_repair_range(file, offset, byte_count, patterns[p],
                                          interactive, verbose, test_mode, show_progress_flag);
            total_repairs += repairs;
        }
        
        printf("\nTotal repairs across all patterns: %d\n", total_repairs);
    }
    else if (target_format) {
        FileSignature *sig = find_signature_by_name(target_format);
        if (!sig) {
            printf("Error: Unknown format '%s'\n", target_format);
            fclose(file);
            return 1;
        }
        
        printf("\n=== TARGETED REPAIR ===\n");
        int repaired = targeted_repair(file, offset, sig, bad_byte,
                                     interactive, verbose, test_mode);
        
        if (repaired > 0 && !test_mode) {
            printf("\n✅ Repair successful! %d bytes restored.\n", repaired);
        }
    }
    
    // Show hex view if not in test mode or if verbose
    if (verbose || test_mode) {
        int lines_to_show = (byte_count < 1024) ? (int)(byte_count / BYTES_PER_LINE) : max_lines;
        hex_display(file, offset, byte_count, lines_to_show);
    }
    
    // Save repaired portion if requested
    if (save_filename && !test_mode) {
        printf("\nSaving repaired portion to: %s\n", save_filename);
        FILE *out = fopen(save_filename, "wb");
        if (out) {
            FSEEK(file, offset, SEEK_SET);
            
            unsigned char buffer[BUFFER_SIZE];
            file_offset_t remaining = byte_count;
            file_offset_t total_saved = 0;
            
            while (remaining > 0) {
                size_t to_read = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : (size_t)remaining;
                size_t read = fread(buffer, 1, to_read, file);
                if (read == 0) break;
                
                fwrite(buffer, 1, read, out);
                remaining -= read;
                total_saved += read;
            }
            
            fclose(out);
            
            char saved_str[64];
            format_size(total_saved, saved_str, sizeof(saved_str));
            printf("Saved: %s\n", saved_str);
        }
    }
    
    fclose(file);
    
    if (!test_mode && (target_format || auto_repair_mode)) {
        printf("\n🔧 REPAIR COMPLETE\n");
        printf("File has been repaired. Test it with appropriate software.\n");
        
        if (target_format) {
            FileSignature *sig = find_signature_by_name(target_format);
            if (sig && sig->extension[0] != '\0') {
                printf("Consider renaming to: *.%s if needed.\n", sig->extension);
            }
        }
    }
    
    return 0;
}

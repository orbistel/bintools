// hex_replace_large_fixed.c
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
#define MAX_SIGNATURES 100

// 64-bit dosya offset'leri
#ifdef _WIN32
    #include <windows.h>
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

// REPLACE için imza veritabanı
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
    {"SQLite", {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, 16, 0, "SQLite database", "db"},
    {"DOC/XLS", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, 0, "Microsoft Office", "doc"},
    {"DOCX", {0x50, 0x4B, 0x03, 0x04}, 4, 0, "Office Open XML", "docx"},
    {"7Z", {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 6, 0, "7-Zip archive", "7z"},
    {"BZIP2", {0x42, 0x5A, 0x68}, 3, 0, "BZIP2 compressed", "bz2"}
};

#define SIGNATURE_COUNT (sizeof(known_signatures) / sizeof(known_signatures[0]))

// Fonksiyon prototipleri
void print_usage(const char *program_name);
file_offset_t parse_size_with_suffix(const char *str);
void format_size(file_offset_t size, char *buffer, size_t buffer_size);
bool get_file_size(FILE *file, file_offset_t *size);
void show_progress_bar(file_offset_t current, file_offset_t total, const char *operation);
FileSignature* find_signature_by_name(const char *name);
int find_signatures_in_range(FILE *file, file_offset_t start_offset, 
                            file_offset_t byte_count, FileSignature *found[], 
                            int max_found, unsigned char replace_byte);
bool create_file_backup(const char *original, const char *backup_name, bool show_progress_flag);
int replace_signatures_in_range(FILE *file, file_offset_t start_offset, 
                               file_offset_t byte_count, FileSignature *target_sig,
                               unsigned char replace_byte, bool replace_all, 
                               bool interactive, bool verbose, bool show_progress_flag);
void hex_dump_range(FILE *file, file_offset_t start_offset, 
                   file_offset_t byte_count, int max_lines, 
                   int skip_lines, bool show_progress_flag);

void print_usage(const char *program_name) {
    printf("\n=== Large File Hex REPLACE (Supports >2GB files) ===\n");
    printf("REPLACE: Replace file signatures with specified byte pattern\n");
    printf("Usage: %s <file> <offset> <bytes> [options]\n\n", program_name);
    
    printf("Parameters support suffixes: K,M,G,T (e.g., 4K, 2M, 1G, 0x1000)\n\n");
    
    printf("REPLACE OPTIONS (change/obfuscate signatures):\n");
    printf("  -r <char>    Replace found signatures with ASCII character\n");
    printf("  -R <hex>     Replace with specific hex byte (e.g., 00, FF, 2A)\n");
    printf("  -t <format>  Target specific format (e.g., JPEG, PDF, ZIP)\n");
    printf("  -a           Replace ALL found signatures (not just first)\n");
    printf("  -i           Interactive mode (ask before each replace)\n");
    printf("  -b <file>    Create backup before modifying\n");
    printf("  -f           Find signatures without replacing\n");
    printf("  -l           List all available formats\n");
    printf("  -p           Show progress bar\n");
    printf("  -v           Verbose mode\n");
    
    printf("\nVIEW OPTIONS:\n");
    printf("  -view        Show hex dump after replacement\n");
    printf("  -c <N>       Limit display to N lines\n");
    printf("  -skip <N>    Skip first N lines in display\n");
    
    printf("\nEXAMPLES (REPLACE - changes signatures):\n");
    printf("  %s secret.jpg 0 0 -r * -t JPEG -b backup.jpg\n", program_name);
    printf("  %s document.pdf 0 0 -R 00 -t PDF -i\n", program_name);
    printf("  %s data.zip 0 0 -r # -t ZIP -a -p\n", program_name);
    printf("  %s file.exe 0 0 -R FF -t EXE -view\n", program_name);
    
    printf("\nIMPORTANT: This tool CHANGES/DESTROYS file signatures!\n");
    printf("           Use -b to create backups before modifying!\n");
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

int find_signatures_in_range(FILE *file, file_offset_t start_offset, 
                            file_offset_t byte_count, FileSignature *found[], 
                            int max_found, unsigned char replace_byte) {
    
    unsigned char buffer[512];
    int found_count = 0;
    
    for (int i = 0; i < SIGNATURE_COUNT && found_count < max_found; i++) {
        FileSignature *sig = &known_signatures[i];
        
        // Check if signature fits in our range
        if (byte_count > 0 && sig->offset + sig->length > byte_count) {
            continue;
        }
        
        // Read at signature position
        file_offset_t read_pos = start_offset + sig->offset;
        if (FSEEK(file, read_pos, SEEK_SET) != 0) {
            continue;
        }
        
        size_t bytes_read = fread(buffer, 1, sig->length, file);
        if (bytes_read != sig->length) {
            continue;
        }
        
        // Check if it matches OR if it's already replaced with our byte
        bool matches_signature = (memcmp(buffer, sig->signature, sig->length) == 0);
        bool matches_replacement = true;
        
        for (int j = 0; j < sig->length; j++) {
            if (buffer[j] != replace_byte) {
                matches_replacement = false;
                break;
            }
        }
        
        if (matches_signature || matches_replacement) {
            found[found_count++] = sig;
        }
    }
    
    return found_count;
}

bool create_file_backup(const char *original, const char *backup_name, bool show_progress_flag) {
    FILE *src = fopen(original, "rb");
    if (!src) {
        printf("Error opening source file for backup\n");
        return false;
    }
    
    FILE *dst = fopen(backup_name, "wb");
    if (!dst) {
        printf("Error creating backup file: %s\n", backup_name);
        fclose(src);
        return false;
    }
    
    file_offset_t file_size;
    if (!get_file_size(src, &file_size)) {
        printf("Error getting file size for backup\n");
        fclose(src);
        fclose(dst);
        return false;
    }
    
    printf("Creating backup: %s -> %s\n", original, backup_name);
    
    unsigned char *buffer = malloc(BUFFER_SIZE);
    if (!buffer) {
        printf("Error allocating buffer for backup\n");
        fclose(src);
        fclose(dst);
        return false;
    }
    
    file_offset_t total_copied = 0;
    file_offset_t last_update = 0;
    
    while (total_copied < file_size) {
        size_t to_read = BUFFER_SIZE;
        if (total_copied + to_read > file_size) {
            to_read = (size_t)(file_size - total_copied);
        }
        
        size_t bytes_read = fread(buffer, 1, to_read, src);
        if (bytes_read == 0) break;
        
        size_t bytes_written = fwrite(buffer, 1, bytes_read, dst);
        if (bytes_written != bytes_read) {
            printf("Error writing backup\n");
            break;
        }
        
        total_copied += bytes_written;
        
        if (show_progress_flag && (total_copied - last_update) > (10 * 1024 * 1024)) {
            show_progress_bar(total_copied, file_size, "Backup");
            last_update = total_copied;
        }
    }
    
    if (show_progress_flag) {
        show_progress_bar(file_size, file_size, "Backup");
        printf("\n");
    }
    
    free(buffer);
    fclose(src);
    fclose(dst);
    
    char size_str[64];
    format_size(total_copied, size_str, sizeof(size_str));
    printf("Backup created: %s (%s)\n", backup_name, size_str);
    
    return true;
}

int replace_signatures_in_range(FILE *file, file_offset_t start_offset, 
                               file_offset_t byte_count, FileSignature *target_sig,
                               unsigned char replace_byte, bool replace_all, 
                               bool interactive, bool verbose, bool show_progress_flag) {
    
    int replacements_done = 0;
    
    if (verbose) {
        printf("Searching for signatures in range: ");
        char start_str[64], count_str[64];
        format_size(start_offset, start_str, sizeof(start_str));
        format_size(byte_count, count_str, sizeof(count_str));
        printf("%s to %s+%s\n", start_str, start_str, count_str);
    }
    
    // If specific target signature provided
    if (target_sig) {
        file_offset_t sig_pos = start_offset + target_sig->offset;
        
        // Check bounds
        file_offset_t file_size;
        get_file_size(file, &file_size);
        if (sig_pos + target_sig->length > file_size) {
            printf("Signature position beyond file end\n");
            return 0;
        }
        
        // Read current bytes
        FSEEK(file, sig_pos, SEEK_SET);
        unsigned char current[64];
        fread(current, 1, target_sig->length, file);
        
        printf("\n=== SIGNATURE REPLACEMENT ===\n");
        printf("Target: %s signature at offset ", target_sig->name);
        char offset_str[64];
        format_size(sig_pos, offset_str, sizeof(offset_str));
        printf("%s\n", offset_str);
        
        printf("Original signature: ");
        for (int i = 0; i < target_sig->length; i++) {
            printf("%02X ", target_sig->signature[i]);
        }
        printf("\nCurrent bytes:      ");
        for (int i = 0; i < target_sig->length; i++) {
            printf("%02X ", current[i]);
        }
        printf("\n");
        
        printf("Replace with: 0x%02X", replace_byte);
        if (isprint(replace_byte)) {
            printf(" ('%c')", replace_byte);
        }
        printf("\n");
        
        if (interactive) {
            printf("\nReplace this signature? (y/N): ");
            char response[10];
            fgets(response, sizeof(response), stdin);
            if (response[0] != 'y' && response[0] != 'Y') {
                printf("Cancelled\n");
                return 0;
            }
        }
        
        // Perform replacement
        FSEEK(file, sig_pos, SEEK_SET);
        for (int i = 0; i < target_sig->length; i++) {
            fwrite(&replace_byte, 1, 1, file);
        }
        fflush(file);
        
        printf("✅ Replaced %d bytes\n", target_sig->length);
        return 1;
    }
    
    // Search for all signatures
    FileSignature *found_sigs[20];
    int found_count = find_signatures_in_range(file, start_offset, byte_count, 
                                              found_sigs, 20, replace_byte);
    
    if (found_count == 0) {
        printf("No signatures found in specified range\n");
        return 0;
    }
    
    printf("\n=== SIGNATURE REPLACEMENT ===\n");
    printf("Found %d signature(s):\n", found_count);
    for (int i = 0; i < found_count; i++) {
        printf("%d. %s at offset +0x%llX (%d bytes)\n", 
               i + 1, found_sigs[i]->name, 
               (long long)found_sigs[i]->offset, found_sigs[i]->length);
    }
    
    if (interactive) {
        printf("\nReplace which signature? (1-%d, a=all, n=none): ", found_count);
        char response[10];
        fgets(response, sizeof(response), stdin);
        
        if (response[0] == 'n' || response[0] == 'N') {
            printf("Cancelled\n");
            return 0;
        }
        
        if (response[0] == 'a' || response[0] == 'A') {
            replace_all = true;
        } else {
            int choice = atoi(response);
            if (choice < 1 || choice > found_count) {
                printf("Invalid choice\n");
                return 0;
            }
            // Replace only selected one
            target_sig = found_sigs[choice - 1];
            found_count = 1;
            for (int i = 0; i < found_count; i++) {
                if (i != choice - 1) found_sigs[i] = NULL;
            }
        }
    }
    
    // Perform replacements
    printf("\nReplacing with: 0x%02X", replace_byte);
    if (isprint(replace_byte)) {
        printf(" ('%c')", replace_byte);
    }
    printf("\n");
    
    for (int i = 0; i < found_count; i++) {
        if (found_sigs[i] == NULL) continue;
        
        file_offset_t sig_pos = start_offset + found_sigs[i]->offset;
        
        if (verbose) {
            printf("Replacing %s at offset ", found_sigs[i]->name);
            char pos_str[64];
            format_size(sig_pos, pos_str, sizeof(pos_str));
            printf("%s\n", pos_str);
        }
        
        FSEEK(file, sig_pos, SEEK_SET);
        for (int j = 0; j < found_sigs[i]->length; j++) {
            fwrite(&replace_byte, 1, 1, file);
        }
        
        replacements_done++;
        
        if (show_progress_flag) {
            show_progress_bar(i + 1, found_count, "Replacing");
        }
    }
    
    fflush(file);
    
    if (show_progress_flag) {
        printf("\n");
    }
    
    printf("\n✅ Total replacements: %d\n", replacements_done);
    return replacements_done;
}

void hex_dump_range(FILE *file, file_offset_t start_offset, 
                   file_offset_t byte_count, int max_lines, 
                   int skip_lines, bool show_progress_flag) {
    
    file_offset_t file_size;
    get_file_size(file, &file_size);
    
    if (byte_count == 0) {
        byte_count = file_size - start_offset;
    }
    
    if (start_offset >= file_size) {
        printf("Error: Start offset beyond file size\n");
        return;
    }
    
    FSEEK(file, start_offset, SEEK_SET);
    
    unsigned char buffer[BYTES_PER_LINE];
    file_offset_t total_read = 0;
    int lines_displayed = 0;
    int lines_skipped = 0;
    
    // Skip lines if requested
    if (skip_lines > 0) {
        file_offset_t skip_bytes = (file_offset_t)skip_lines * BYTES_PER_LINE;
        if (skip_bytes < byte_count) {
            FSEEK(file, skip_bytes, SEEK_CUR);
            total_read += skip_bytes;
            lines_skipped = skip_lines;
        }
    }
    
    printf("\nHex Dump:\n");
    printf("Offset          ");
    for (int i = 0; i < BYTES_PER_LINE; i++) {
        printf("%02X ", i);
        if (i == 7) printf(" ");
    }
    printf(" ASCII\n");
    printf("--------------- ");
    for (int i = 0; i < BYTES_PER_LINE; i++) printf("---");
    printf(" -------------\n");
    
    while (total_read < byte_count && (max_lines == 0 || lines_displayed < max_lines)) {
        size_t to_read = BYTES_PER_LINE;
        if (total_read + to_read > byte_count) {
            to_read = (size_t)(byte_count - total_read);
        }
        
        size_t bytes_read = fread(buffer, 1, to_read, file);
        if (bytes_read == 0) break;
        
        // Show progress
        if (show_progress_flag && (lines_displayed % 100 == 0)) {
            show_progress_bar(total_read, byte_count, "Displaying");
        }
        
        // Print line
        printf("%014llX  ", (long long)(start_offset + total_read));
        
        // Hex bytes
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            if (i < bytes_read) {
                printf("%02X ", buffer[i]);
            } else {
                printf("   ");
            }
            if (i == 7) printf(" ");
        }
        
        // ASCII
        printf(" |");
        for (int i = 0; i < bytes_read; i++) {
            if (isprint(buffer[i]) && !iscntrl(buffer[i])) {
                printf("%c", buffer[i]);
            } else {
                printf(".");
            }
        }
        printf("|\n");
        
        total_read += bytes_read;
        lines_displayed++;
    }
    
    if (show_progress_flag) {
        show_progress_bar(byte_count, byte_count, "Displaying");
        printf("\n");
    }
    
    char displayed_str[64];
    format_size(total_read, displayed_str, sizeof(displayed_str));
    printf("\nDisplayed: %s", displayed_str);
    
    if (lines_skipped > 0) {
        printf(" (skipped %d lines)", lines_skipped);
    }
    
    if (lines_displayed >= max_lines && max_lines > 0) {
        printf(" - limited to %d lines", max_lines);
    }
    
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("=== Large File Hex REPLACE (64-bit) ===\n");
    printf("REPLACE: Change file signatures to obfuscate/destroy them\n");
    
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *filename = argv[1];
    file_offset_t offset = parse_size_with_suffix(argv[2]);
    file_offset_t byte_count = parse_size_with_suffix(argv[3]);
    
    // Options
    bool do_replace = false;
    bool interactive = false;
    bool verbose = false;
    bool show_progress_flag = false;
    bool create_backup_file = false;
    bool find_only = false;
    bool show_view = false;
    bool replace_all = false;
    char *backup_name = NULL;
    char *target_format = NULL;
    unsigned char replace_byte = '*';
    int max_lines = 0;
    int skip_lines = 0;
    
    // Parse options
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            do_replace = true;
            replace_byte = argv[++i][0];
        }
        else if (strcmp(argv[i], "-R") == 0 && i + 1 < argc) {
            do_replace = true;
            replace_byte = (unsigned char)strtol(argv[++i], NULL, 16);
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            target_format = argv[++i];
        }
        else if (strcmp(argv[i], "-i") == 0) interactive = true;
        else if (strcmp(argv[i], "-v") == 0) verbose = true;
        else if (strcmp(argv[i], "-p") == 0) show_progress_flag = true;
        else if (strcmp(argv[i], "-a") == 0) replace_all = true;
        else if (strcmp(argv[i], "-f") == 0) find_only = true;
        else if (strcmp(argv[i], "-view") == 0) show_view = true;
        else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            create_backup_file = true;
            backup_name = argv[++i];
        }
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            max_lines = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-skip") == 0 && i + 1 < argc) {
            skip_lines = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-l") == 0) {
            printf("\nAvailable formats for REPLACE:\n");
            printf("%-20s %-8s %-10s %s\n", "Format", "Ext", "Length", "Description");
            printf("%-20s %-8s %-10s %s\n", "--------------------", "--------", "----------", 
                   "--------------------------------------------------");
            for (int j = 0; j < SIGNATURE_COUNT; j++) {
                printf("%-20s %-8s %-10d %s\n", 
                       known_signatures[j].name,
                       known_signatures[j].extension,
                       known_signatures[j].length,
                       known_signatures[j].description);
            }
            return 0;
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Validate
    if (do_replace && !target_format && !replace_all) {
        printf("Error: Replace operation requires -t <format> or -a for all\n");
        return 1;
    }
    
    if (find_only && do_replace) {
        printf("Error: Cannot use -f (find only) with replace options\n");
        return 1;
    }
    
    // Open file
    FILE *file = fopen(filename, do_replace ? "r+b" : "rb");
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
    
    // Create backup if needed
    if (create_backup_file && do_replace) {
        if (!backup_name) {
            // Generate backup name with timestamp
            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            backup_name = malloc(256);
            snprintf(backup_name, 256, "%s.backup_%04d%02d%02d_%02d%02d%02d",
                    filename,
                    t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                    t->tm_hour, t->tm_min, t->tm_sec);
        }
        
        if (!create_file_backup(filename, backup_name, show_progress_flag)) {
            printf("Backup failed. Aborting.\n");
            fclose(file);
            return 1;
        }
    }
    
    // Find or replace signatures
    FileSignature *target_sig = NULL;
    if (target_format) {
        target_sig = find_signature_by_name(target_format);
        if (!target_sig) {
            printf("Error: Unknown format '%s'. Use -l to list formats.\n", target_format);
            fclose(file);
            return 1;
        }
    }
    
    if (do_replace) {
        printf("\n=== REPLACE OPERATION ===\n");
        printf("WARNING: This will CHANGE/DESTROY file signatures!\n");
        printf("Replacement byte: 0x%02X", replace_byte);
        if (isprint(replace_byte)) {
            printf(" ('%c')", replace_byte);
        }
        printf("\n");
        
        if (target_sig) {
            printf("Target format: %s\n", target_sig->name);
        } else if (replace_all) {
            printf("Target: ALL signatures in range\n");
        }
        
        int replacements = replace_signatures_in_range(file, offset, byte_count,
                                                      target_sig, replace_byte,
                                                      replace_all, interactive,
                                                      verbose, show_progress_flag);
        
        if (replacements > 0) {
            printf("\n✅ REPLACE operation completed successfully!\n");
            printf("File signatures have been changed/obfuscated.\n");
            printf("File may no longer be recognized by applications.\n");
        }
    }
    else if (find_only) {
        printf("\n=== SIGNATURE SCAN ===\n");
        
        FileSignature *found_sigs[20];
        int found_count = find_signatures_in_range(file, offset, byte_count,
                                                  found_sigs, 20, 0);
        
        if (found_count > 0) {
            printf("Found %d signature(s):\n", found_count);
            for (int i = 0; i < found_count; i++) {
                printf("\n%d. %s\n", i + 1, found_sigs[i]->name);
                printf("   Offset: +0x%llX\n", (long long)found_sigs[i]->offset);
                printf("   Length: %d bytes\n", found_sigs[i]->length);
                printf("   Signature: ");
                for (int j = 0; j < found_sigs[i]->length; j++) {
                    printf("%02X ", found_sigs[i]->signature[j]);
                }
                printf("\n   Extension: .%s\n", found_sigs[i]->extension);
                printf("   Description: %s\n", found_sigs[i]->description);
            }
        } else {
            printf("No signatures found in specified range\n");
        }
    }
    
    // Show hex view if requested
    if (show_view || (!do_replace && !find_only)) {
        hex_dump_range(file, offset, byte_count, max_lines, skip_lines, show_progress_flag);
    }
    
    fclose(file);
    
    if (do_replace && create_backup_file) {
        printf("\n📁 Backup available: %s\n", backup_name);
        printf("   Use backup to restore original file if needed.\n");
    }
    
    return 0;
}

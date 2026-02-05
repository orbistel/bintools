// hex_viewer_replace.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>

#define BYTES_PER_LINE 16
#define MAX_SIGNATURE_LENGTH 32
#define MAX_SIGNATURES 100

typedef struct {
    char name[32];
    unsigned char signature[MAX_SIGNATURE_LENGTH];
    int length;
    long offset;
    char description[128];
} FileSignature;

// Daha fazla imza ekleyelim
FileSignature known_signatures[] = {
    {"JPEG", {0xFF, 0xD8, 0xFF}, 3, 0, "JPEG image file"},
    {"PNG", {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 8, 0, "PNG image"},
    {"PDF", {0x25, 0x50, 0x44, 0x46}, 4, 0, "PDF document"},
    {"ZIP", {0x50, 0x4B, 0x03, 0x04}, 4, 0, "ZIP archive"},
    {"ZIP (empty)", {0x50, 0x4B, 0x05, 0x06}, 4, 0, "Empty ZIP archive"},
    {"ZIP (spanned)", {0x50, 0x4B, 0x07, 0x08}, 4, 0, "Spanned ZIP archive"},
    {"EXE", {0x4D, 0x5A}, 2, 0, "DOS/Windows executable"},
    {"GIF87a", {0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, 6, 0, "GIF image 87a"},
    {"GIF89a", {0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, 6, 0, "GIF image 89a"},
    {"BMP", {0x42, 0x4D}, 2, 0, "Bitmap image"},
    {"MP3 (no ID3)", {0xFF, 0xFB}, 2, 0, "MP3 audio (no ID3 tag)"},
    {"MP3 (ID3)", {0x49, 0x44, 0x33}, 3, 0, "MP3 with ID3 tag"},
    {"SQLite", {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, 16, 0, "SQLite database"},
    {"RAR", {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, 7, 0, "RAR archive"},
    {"RAR5", {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, 8, 0, "RAR5 archive"},
    {"7Z", {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 6, 0, "7-Zip archive"},
    {"GZIP", {0x1F, 0x8B}, 2, 0, "GZIP compressed file"},
    {"BZIP2", {0x42, 0x5A, 0x68}, 3, 0, "BZIP2 compressed file"},
    {"TIFF (LE)", {0x49, 0x49, 0x2A, 0x00}, 4, 0, "TIFF little-endian"},
    {"TIFF (BE)", {0x4D, 0x4D, 0x00, 0x2A}, 4, 0, "TIFF big-endian"},
    {"WEBP", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50}, 12, 0, "WebP image"},
    {"ICO", {0x00, 0x00, 0x01, 0x00}, 4, 0, "Windows icon"},
    {"CUR", {0x00, 0x00, 0x02, 0x00}, 4, 0, "Windows cursor"},
    {"WAV", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45}, 12, 0, "WAVE audio"},
    {"AVI", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20}, 12, 0, "AVI video"},
    {"MP4", {0x00, 0x00, 0x00, 0x00, 0x66, 0x74, 0x79, 0x70}, 8, 4, "MP4 video (at offset 4)"},
    {"ISO9660", {0x01, 0x43, 0x44, 0x30, 0x30, 0x31}, 6, 0x8001, "ISO9660 CD/DVD image"},
    {"ELF", {0x7F, 0x45, 0x4C, 0x46}, 4, 0, "ELF executable (Linux)"},
    {"Mach-O", {0xFE, 0xED, 0xFA, 0xCE}, 4, 0, "Mach-O (old 32-bit)"},
    {"Mach-O64", {0xFE, 0xED, 0xFA, 0xCF}, 4, 0, "Mach-O 64-bit"},
    {"PE", {0x4D, 0x5A}, 2, 0, "Windows PE executable"},
    {"MSI", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, 0, "Microsoft Installer"},
    {"DOC", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, 0, "Microsoft Office document"},
    {"XLS", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, 0, "Microsoft Excel document"},
    {"PPT", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, 0, "Microsoft PowerPoint"},
    {"CLASS", {0xCA, 0xFE, 0xBA, 0xBE}, 4, 0, "Java class file"},
    {"TORRENT", {0x64, 0x38, 0x3A, 0x61, 0x6E, 0x6E, 0x6F, 0x75, 0x6E, 0x63, 0x65}, 11, 0, "Torrent file"}
};

#define SIGNATURE_COUNT (sizeof(known_signatures) / sizeof(known_signatures[0]))

void print_hex_line(unsigned char *buffer, size_t bytes_read, 
                    long current_offset, FILE *output, 
                    bool highlight_start, int highlight_len,
                    unsigned char replace_char) {
    // Offset
    fprintf(output, "%08lX  ", current_offset);
    
    // Hex bytes
    for (int i = 0; i < BYTES_PER_LINE; i++) {
        if (i < bytes_read) {
            // Highlight signature bytes
            if (highlight_len > 0 && i >= highlight_start && 
                i < highlight_start + highlight_len) {
                fprintf(output, "\033[1;31m%02X\033[0m ", buffer[i]); // Red color
            } else {
                fprintf(output, "%02X ", buffer[i]);
            }
        } else {
            fprintf(output, "   ");
        }
        
        if (i == 7) fprintf(output, " ");
    }
    
    fprintf(output, " |");
    
    // ASCII - show replacement char for signature bytes
    for (int i = 0; i < bytes_read; i++) {
        if (highlight_len > 0 && i >= highlight_start && 
            i < highlight_start + highlight_len) {
            // Show replacement character in red
            fprintf(output, "\033[1;31m%c\033[0m", replace_char);
        } else if (isprint(buffer[i]) && !iscntrl(buffer[i])) {
            fprintf(output, "%c", buffer[i]);
        } else {
            fprintf(output, ".");
        }
    }
    
    fprintf(output, "|\n");
}

void print_usage(const char *program_name) {
    printf("\n=== Hex Viewer with Signature Replacement ===\n");
    printf("Usage: %s <file> <offset> <bytes> [options]\n\n", program_name);
    printf("Options:\n");
    printf("  -a           Hide ASCII column\n");
    printf("  -o           Hide offset column\n");
    printf("  -f           Find and show file signatures\n");
    printf("  -s           Save extracted bytes to file\n");
    printf("  -r <char>    Replace signature bytes with character\n");
    printf("  -R <hex>     Replace with specific hex byte (e.g., 00, FF)\n");
    printf("  -l           List all known signatures\n");
    printf("  -b <file>    Backup original file before modification\n");
    printf("  -i           Interactive mode (ask before replacing)\n");
    printf("\nExamples:\n");
    printf("  %s image.jpg 0 256 -f\n", program_name);
    printf("  %s document.pdf 0 512 -r *\n", program_name);
    printf("  %s secret.exe 0 0 -R 00 -b backup.exe\n", program_name);
    printf("  %s data.bin 0 0 -l\n", program_name);
    printf("\nNote: Use 0 for <bytes> to show entire file\n");
}

void list_signatures() {
    printf("\n=== Known File Signatures ===\n");
    printf("%-20s %-8s %-10s %s\n", "Name", "Length", "Offset", "Description");
    printf("%-20s %-8s %-10s %s\n", "--------------------", "--------", "----------", 
           "--------------------------------------------------");
    
    for (int i = 0; i < SIGNATURE_COUNT; i++) {
        printf("%-20s %-8d 0x%-8lX %s\n", 
               known_signatures[i].name,
               known_signatures[i].length,
               known_signatures[i].offset,
               known_signatures[i].description);
    }
    
    printf("\nTotal: %d signatures\n", SIGNATURE_COUNT);
}

int find_signatures_at_offset(FILE *file, long offset, 
                             FileSignature *found_signatures, 
                             int max_found) {
    unsigned char buffer[512];
    int found_count = 0;
    
    fseek(file, offset, SEEK_SET);
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
    
    for (int i = 0; i < SIGNATURE_COUNT && found_count < max_found; i++) {
        // Check if we have enough bytes
        if (bytes_read < known_signatures[i].length + known_signatures[i].offset) {
            continue;
        }
        
        // Check signature at its offset
        if (memcmp(buffer + known_signatures[i].offset, 
                   known_signatures[i].signature, 
                   known_signatures[i].length) == 0) {
            found_signatures[found_count++] = known_signatures[i];
        }
    }
    
    return found_count;
}

bool replace_signature(FILE *file, const FileSignature *sig, 
                      long file_offset, unsigned char replace_byte,
                      bool interactive, bool create_backup,
                      const char *original_filename) {
    printf("\n=== Signature Replacement ===\n");
    printf("Signature: %s\n", sig->name);
    printf("Length: %d bytes\n", sig->length);
    printf("Offset in file: 0x%lX\n", file_offset + sig->offset);
    printf("Replacement byte: 0x%02X ('%c')\n", replace_byte, 
           isprint(replace_byte) ? replace_byte : '.');
    
    if (interactive) {
        printf("\nReplace signature? (y/N): ");
        char response[10];
        fgets(response, sizeof(response), stdin);
        if (response[0] != 'y' && response[0] != 'Y') {
            printf("Cancelled.\n");
            return false;
        }
    }
    
    // Create backup if requested
    if (create_backup) {
        char backup_name[256];
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        snprintf(backup_name, sizeof(backup_name), 
                "%s.backup_%04d%02d%02d_%02d%02d%02d",
                original_filename,
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec);
        
        FILE *original = fopen(original_filename, "rb");
        FILE *backup = fopen(backup_name, "wb");
        
        if (original && backup) {
            unsigned char buffer[4096];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), original)) > 0) {
                fwrite(buffer, 1, bytes, backup);
            }
            printf("Backup created: %s\n", backup_name);
        }
        
        if (original) fclose(original);
        if (backup) fclose(backup);
    }
    
    // Perform replacement
    fseek(file, file_offset + sig->offset, SEEK_SET);
    
    for (int i = 0; i < sig->length; i++) {
        fwrite(&replace_byte, 1, 1, file);
    }
    
    fflush(file);
    
    printf("✅ Replacement completed successfully!\n");
    printf("   %d bytes replaced at offset 0x%lX\n", 
           sig->length, file_offset + sig->offset);
    
    return true;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *filename = argv[1];
    long offset = strtol(argv[2], NULL, 0);
    long byte_count = strtol(argv[3], NULL, 0);
    
    bool show_ascii = true;
    bool show_offset = true;
    bool find_signatures = false;
    bool save_extract = false;
    bool list_sigs = false;
    bool interactive = false;
    bool create_backup = false;
    unsigned char replace_byte = '*';  // Default replacement char
    bool do_replace = false;
    char *replace_hex = NULL;
    char *backup_filename = NULL;
    
    // Parse options
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) show_ascii = false;
        else if (strcmp(argv[i], "-o") == 0) show_offset = false;
        else if (strcmp(argv[i], "-f") == 0) find_signatures = true;
        else if (strcmp(argv[i], "-s") == 0) save_extract = true;
        else if (strcmp(argv[i], "-l") == 0) list_sigs = true;
        else if (strcmp(argv[i], "-i") == 0) interactive = true;
        else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            do_replace = true;
            replace_byte = argv[++i][0];
        }
        else if (strcmp(argv[i], "-R") == 0 && i + 1 < argc) {
            do_replace = true;
            replace_hex = argv[++i];
            replace_byte = (unsigned char)strtol(replace_hex, NULL, 16);
        }
        else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            create_backup = true;
            backup_filename = argv[++i];
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    if (list_sigs) {
        list_signatures();
        return 0;
    }
    
    FILE *file = fopen(filename, do_replace ? "r+b" : "rb");
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
    
    printf("\n=== Hex Viewer ===\n");
    printf("File: %s\n", filename);
    printf("Size: %ld bytes (%.2f KB)\n", file_size, file_size / 1024.0);
    printf("Viewing: offset 0x%lX (%ld), %ld bytes\n\n", offset, offset, byte_count);
    
    // Find signatures if requested
    FileSignature found_sigs[10];
    int found_count = 0;
    
    if (find_signatures || do_replace) {
        found_count = find_signatures_at_offset(file, offset, found_sigs, 10);
        
        if (found_count > 0) {
            printf("\n=== Found Signatures ===\n");
            for (int i = 0; i < found_count; i++) {
                printf("%d. %s (offset +0x%lX, %d bytes): ", 
                       i + 1, found_sigs[i].name, 
                       found_sigs[i].offset, found_sigs[i].length);
                for (int j = 0; j < found_sigs[i].length; j++) {
                    printf("%02X ", found_sigs[i].signature[j]);
                }
                printf(" - %s\n", found_sigs[i].description);
            }
            
            // Replace if requested
            if (do_replace && found_count > 0) {
                if (found_count == 1) {
                    replace_signature(file, &found_sigs[0], offset, 
                                     replace_byte, interactive, create_backup, 
                                     backup_filename ? backup_filename : filename);
                } else {
                    printf("\nMultiple signatures found. Which one to replace? (1-%d, 0=cancel): ", 
                           found_count);
                    int choice;
                    scanf("%d", &choice);
                    if (choice > 0 && choice <= found_count) {
                        replace_signature(file, &found_sigs[choice-1], offset, 
                                         replace_byte, false, create_backup, 
                                         backup_filename ? backup_filename : filename);
                    }
                }
            }
        } else {
            printf("\nNo known signatures found at offset 0x%lX\n", offset);
        }
    }
    
    // Display hex dump
    printf("\n=== Hex Dump ===\n");
    
    unsigned char buffer[BYTES_PER_LINE];
    long total_read = 0;
    fseek(file, offset, SEEK_SET);
    
    if (show_offset) {
        printf("Offset   ");
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            printf("%02X ", i);
            if (i == 7) printf(" ");
        }
        if (show_ascii) {
            printf(" ASCII\n");
        } else {
            printf("\n");
        }
        printf("-------- ");
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            printf("---");
        }
        if (show_ascii) {
            printf(" -------------\n");
        } else {
            printf("\n");
        }
    }
    
    // Check if we should highlight a signature
    int highlight_start = -1;
    int highlight_len = 0;
    
    if (found_count > 0 && do_replace) {
        // Highlight the first found signature
        highlight_start = found_sigs[0].offset;
        highlight_len = found_sigs[0].length;
    }
    
    while (total_read < byte_count) {
        size_t to_read = BYTES_PER_LINE;
        if (total_read + to_read > byte_count) {
            to_read = byte_count - total_read;
        }
        
        size_t bytes_read = fread(buffer, 1, to_read, file);
        if (bytes_read == 0) break;
        
        // Print line with possible highlighting
        print_hex_line(buffer, bytes_read, offset + total_read, stdout,
                      highlight_start, highlight_len, replace_byte);
        
        total_read += bytes_read;
        
        // Adjust highlight position for next line
        if (highlight_start != -1) {
            if (highlight_len > 0) {
                highlight_len -= BYTES_PER_LINE;
            }
            highlight_start = -1;  // Only highlight first occurrence
        }
    }
    
    printf("\nTotal bytes displayed: %ld\n", total_read);
    
    // Save extracted data if requested
    if (save_extract) {
        char output_name[256];
        snprintf(output_name, sizeof(output_name), 
                "extracted_0x%lX_%ld.bin", offset, byte_count);
        
        FILE *output = fopen(output_name, "wb");
        if (output) {
            fseek(file, offset, SEEK_SET);
            unsigned char copy_buffer[4096];
            long remaining = byte_count;
            
            while (remaining > 0) {
                size_t to_copy = (remaining > 4096) ? 4096 : remaining;
                size_t copied = fread(copy_buffer, 1, to_copy, file);
                if (copied == 0) break;
                
                fwrite(copy_buffer, 1, copied, output);
                remaining -= copied;
            }
            
            fclose(output);
            printf("Saved %ld bytes to %s\n", byte_count - remaining, output_name);
        }
    }
    
    fclose(file);
    return 0;
}

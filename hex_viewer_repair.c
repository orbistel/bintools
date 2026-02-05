// hex_viewer_repair.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>

#define BYTES_PER_LINE 16
#define MAX_SIGNATURE_LENGTH 32
#define MAX_SIGNATURES 100
#define MAX_FORMATS 50

typedef struct {
    char name[32];
    unsigned char signature[MAX_SIGNATURE_LENGTH];
    int length;
    long offset;
    char description[128];
    char extension[16];
} FileSignature;

// Daha kapsamlı imza veritabanı
FileSignature known_signatures[] = {
    // Image formats
    {"JPEG", {0xFF, 0xD8, 0xFF}, 3, 0, "JPEG image file", "jpg"},
    {"JPEG/JFIF", {0xFF, 0xD8, 0xFF, 0xE0}, 4, 0, "JPEG with JFIF", "jpg"},
    {"JPEG/Exif", {0xFF, 0xD8, 0xFF, 0xE1}, 4, 0, "JPEG with Exif", "jpg"},
    {"PNG", {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 8, 0, "PNG image", "png"},
    {"GIF87a", {0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, 6, 0, "GIF image 87a", "gif"},
    {"GIF89a", {0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, 6, 0, "GIF image 89a", "gif"},
    {"BMP", {0x42, 0x4D}, 2, 0, "Bitmap image", "bmp"},
    {"TIFF LE", {0x49, 0x49, 0x2A, 0x00}, 4, 0, "TIFF little-endian", "tif"},
    {"TIFF BE", {0x4D, 0x4D, 0x00, 0x2A}, 4, 0, "TIFF big-endian", "tif"},
    {"ICO", {0x00, 0x00, 0x01, 0x00}, 4, 0, "Windows icon", "ico"},
    {"CUR", {0x00, 0x00, 0x02, 0x00}, 4, 0, "Windows cursor", "cur"},
    {"WEBP", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50}, 12, 0, "WebP image", "webp"},
    
    // Audio/Video formats
    {"WAV", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45}, 12, 0, "WAVE audio", "wav"},
    {"AVI", {0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20}, 12, 0, "AVI video", "avi"},
    {"MP3 ID3", {0x49, 0x44, 0x33}, 3, 0, "MP3 with ID3 tag", "mp3"},
    {"MP3 no ID3", {0xFF, 0xFB}, 2, 0, "MP3 without ID3", "mp3"},
    {"FLAC", {0x66, 0x4C, 0x61, 0x43}, 4, 0, "Free Lossless Audio", "flac"},
    {"MP4", {0x00, 0x00, 0x00, 0x00, 0x66, 0x74, 0x79, 0x70}, 8, 4, "MP4 video", "mp4"},
    {"MKV", {0x1A, 0x45, 0xDF, 0xA3}, 4, 0, "Matroska video", "mkv"},
    
    // Archive formats
    {"ZIP", {0x50, 0x4B, 0x03, 0x04}, 4, 0, "ZIP archive", "zip"},
    {"ZIP empty", {0x50, 0x4B, 0x05, 0x06}, 4, 0, "Empty ZIP archive", "zip"},
    {"RAR", {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, 7, 0, "RAR archive", "rar"},
    {"RAR5", {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, 8, 0, "RAR5 archive", "rar"},
    {"7Z", {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 6, 0, "7-Zip archive", "7z"},
    {"GZIP", {0x1F, 0x8B}, 2, 0, "GZIP compressed", "gz"},
    {"BZIP2", {0x42, 0x5A, 0x68}, 3, 0, "BZIP2 compressed", "bz2"},
    {"TAR", {0x75, 0x73, 0x74, 0x61, 0x72}, 5, 257, "TAR archive", "tar"},
    
    // Documents
    {"PDF", {0x25, 0x50, 0x44, 0x46}, 4, 0, "PDF document", "pdf"},
    {"DOC/XLS/PPT", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, 0, "Microsoft Office", "doc"},
    {"DOCX", {0x50, 0x4B, 0x03, 0x04}, 4, 0, "Office Open XML", "docx"},
    {"RTF", {0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31}, 6, 0, "Rich Text Format", "rtf"},
    
    // Executables
    {"EXE", {0x4D, 0x5A}, 2, 0, "DOS/Windows executable", "exe"},
    {"ELF", {0x7F, 0x45, 0x4C, 0x46}, 4, 0, "ELF executable", ""},
    {"MACH-O", {0xFE, 0xED, 0xFA, 0xCE}, 4, 0, "Mach-O 32-bit", ""},
    {"MACH-O64", {0xFE, 0xED, 0xFA, 0xCF}, 4, 0, "Mach-O 64-bit", ""},
    {"MSI", {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, 0, "Windows Installer", "msi"},
    
    // Databases
    {"SQLite", {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, 16, 0, "SQLite database", "db"},
    
    // Other
    {"ISO9660", {0x01, 0x43, 0x44, 0x30, 0x30, 0x31}, 6, 0x8001, "ISO9660 CD/DVD", "iso"},
    {"CLASS", {0xCA, 0xFE, 0xBA, 0xBE}, 4, 0, "Java class file", "class"},
    {"TORRENT", {0x64, 0x38, 0x3A, 0x61, 0x6E, 0x6E, 0x6F, 0x75, 0x6E, 0x63, 0x65}, 11, 0, "Torrent file", "torrent"},
    {"HTML", {0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45}, 9, 0, "HTML document", "html"},
    {"XML", {0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20}, 6, 0, "XML document", "xml"}
};

#define SIGNATURE_COUNT (sizeof(known_signatures) / sizeof(known_signatures[0]))

// Yardımcı fonksiyonlar
void print_colored(const char *text, int color) {
    // 0: normal, 1: green, 2: red, 3: yellow, 4: blue
    const char *colors[] = {"\033[0m", "\033[1;32m", "\033[1;31m", "\033[1;33m", "\033[1;34m"};
    printf("%s%s\033[0m", colors[color], text);
}

void print_usage(const char *program_name) {
    printf("\n=== Hex Viewer with Repair Function ===\n");
    printf("Usage: %s <file> <offset> <bytes> [options]\n\n", program_name);
    printf("Options:\n");
    printf("  -a           Hide ASCII column\n");
    printf("  -o           Hide offset column\n");
    printf("  -f           Find and show file signatures\n");
    printf("  -s           Save extracted bytes to file\n");
    printf("  -l           List all known signatures\n");
    
    printf("\n  REPAIR OPTIONS (fix corrupted files):\n");
    printf("  -t <format>  Try to repair with specific format (e.g., JPEG, PNG)\n");
    printf("  -x <char>    Character to look for and replace (e.g., *, ?, #)\n");
    printf("  -X <hex>     Hex value to look for and replace (e.g., 00, FF, 2A)\n");
    printf("  -A           Auto-repair mode (try all formats)\n");
    printf("  -i           Interactive mode (ask before repairing)\n");
    printf("  -v           Verbose mode (show details)\n");
    
    printf("\nExamples:\n");
    printf("  %s corrupted.jpg 0 256 -t JPEG -x *\n", program_name);
    printf("  %s broken.png 0 0 -t PNG -X 00 -i\n", program_name);
    printf("  %s damaged.pdf 0 512 -A -v\n", program_name);
    printf("  %s unknown.dat 0 128 -f -t ZIP -x #\n", program_name);
    printf("\nNote: Use 0 for <bytes> to show entire file\n");
}

FileSignature* find_signature_by_name(const char *name) {
    for (int i = 0; i < SIGNATURE_COUNT; i++) {
        if (strcasecmp(known_signatures[i].name, name) == 0) {
            return &known_signatures[i];
        }
    }
    return NULL;
}

bool detect_corruption_at_offset(FILE *file, long offset, 
                                const FileSignature *sig,
                                unsigned char bad_byte,
                                int *corrupted_bytes) {
    fseek(file, offset + sig->offset, SEEK_SET);
    unsigned char buffer[MAX_SIGNATURE_LENGTH];
    
    size_t bytes_read = fread(buffer, 1, sig->length, file);
    if (bytes_read != sig->length) {
        return false;
    }
    
    *corrupted_bytes = 0;
    
    // Check each byte
    for (int i = 0; i < sig->length; i++) {
        if (buffer[i] != sig->signature[i]) {
            (*corrupted_bytes)++;
        }
    }
    
    return (*corrupted_bytes) > 0;
}

bool is_replacement_pattern(unsigned char *buffer, int length, 
                           unsigned char pattern_byte) {
    for (int i = 0; i < length; i++) {
        if (buffer[i] != pattern_byte) {
            return false;
        }
    }
    return true;
}

bool repair_signature(FILE *file, long file_offset,
                     const FileSignature *sig,
                     unsigned char bad_byte,
                     bool interactive, bool verbose) {
    
    if (verbose) {
        printf("\n[VERBOSE] Checking for repair at offset 0x%lX\n", 
               file_offset + sig->offset);
        printf("[VERBOSE] Signature: %s (%d bytes)\n", sig->name, sig->length);
        printf("[VERBOSE] Bad byte pattern: 0x%02X\n", bad_byte);
    }
    
    // Read current bytes at signature location
    fseek(file, file_offset + sig->offset, SEEK_SET);
    unsigned char current_bytes[MAX_SIGNATURE_LENGTH];
    size_t read = fread(current_bytes, 1, sig->length, file);
    
    if (read != sig->length) {
        if (verbose) printf("[VERBOSE] Could not read %d bytes\n", sig->length);
        return false;
    }
    
    // Check if all bytes are the bad byte (indicating corruption)
    bool all_bad_bytes = true;
    bool any_bad_bytes = false;
    
    for (int i = 0; i < sig->length; i++) {
        if (current_bytes[i] != bad_byte) {
            all_bad_bytes = false;
        }
        if (current_bytes[i] == bad_byte) {
            any_bad_bytes = true;
        }
    }
    
    // Also check if bytes are already correct
    bool already_correct = (memcmp(current_bytes, sig->signature, sig->length) == 0);
    
    if (already_correct) {
        if (verbose) printf("[VERBOSE] Signature is already correct\n");
        return false;
    }
    
    // Calculate how many bytes need repair
    int bytes_to_repair = 0;
    for (int i = 0; i < sig->length; i++) {
        if (current_bytes[i] != sig->signature[i]) {
            bytes_to_repair++;
        }
    }
    
    // Show what we found
    printf("\n🔧 REPAIR ANALYSIS\n");
    printf("   Format: %s\n", sig->name);
    printf("   Expected signature: ");
    for (int i = 0; i < sig->length; i++) {
        printf("%02X ", sig->signature[i]);
    }
    printf("\n");
    
    printf("   Current bytes:      ");
    for (int i = 0; i < sig->length; i++) {
        if (current_bytes[i] == sig->signature[i]) {
            print_colored("   ", 0);
        } else if (current_bytes[i] == bad_byte) {
            print_colored("?? ", 2);  // Red for bad bytes
        } else {
            print_colored("XX ", 3);  // Yellow for wrong bytes
        }
    }
    printf("\n");
    
    printf("   Actual bytes:       ");
    for (int i = 0; i < sig->length; i++) {
        printf("%02X ", current_bytes[i]);
    }
    printf("\n");
    
    printf("   Bytes to repair: %d/%d\n", bytes_to_repair, sig->length);
    
    if (bytes_to_repair == 0) {
        printf("   ✅ Signature is already correct\n");
        return false;
    }
    
    if (!any_bad_bytes && !all_bad_bytes) {
        printf("   ⚠️  No matching bad bytes found (expected 0x%02X)\n", bad_byte);
        if (!interactive) {
            printf("   Skipping repair (use -i to force)\n");
            return false;
        }
    }
    
    if (interactive) {
        printf("\n   Repair this signature? (y/N): ");
        char response[10];
        fgets(response, sizeof(response), stdin);
        if (response[0] != 'y' && response[0] != 'Y') {
            printf("   Repair cancelled\n");
            return false;
        }
    }
    
    // Perform the repair
    fseek(file, file_offset + sig->offset, SEEK_SET);
    for (int i = 0; i < sig->length; i++) {
        if (current_bytes[i] != sig->signature[i]) {
            fwrite(&sig->signature[i], 1, 1, file);
        } else {
            // Skip already correct bytes
            fseek(file, 1, SEEK_CUR);
        }
    }
    
    fflush(file);
    
    printf("   ✅ Repair completed! %d bytes fixed\n", bytes_to_repair);
    printf("   Offset: 0x%lX\n", file_offset + sig->offset);
    
    return true;
}

bool auto_repair(FILE *file, long file_offset, 
                unsigned char bad_byte,
                bool interactive, bool verbose) {
    
    printf("\n🤖 AUTO-REPAIR MODE\n");
    printf("   Scanning for corrupted signatures...\n");
    
    int repairs_done = 0;
    int signatures_checked = 0;
    
    for (int i = 0; i < SIGNATURE_COUNT; i++) {
        FileSignature *sig = &known_signatures[i];
        
        // Check if this signature could fit at current offset
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        
        if (file_offset + sig->offset + sig->length > file_size) {
            continue;  // Signature wouldn't fit
        }
        
        signatures_checked++;
        
        // Read current bytes
        fseek(file, file_offset + sig->offset, SEEK_SET);
        unsigned char current_bytes[MAX_SIGNATURE_LENGTH];
        size_t read = fread(current_bytes, 1, sig->length, file);
        
        if (read != sig->length) {
            continue;
        }
        
        // Check if this looks like a corrupted signature
        bool looks_corrupted = false;
        int matching_bad_bytes = 0;
        
        for (int j = 0; j < sig->length; j++) {
            if (current_bytes[j] == bad_byte) {
                matching_bad_bytes++;
            }
        }
        
        // If most bytes are the bad byte, it might be corrupted
        if (matching_bad_bytes > 0) {
            // Try to repair
            if (repair_signature(file, file_offset, sig, bad_byte, 
                               interactive, verbose)) {
                repairs_done++;
            }
        }
    }
    
    printf("\n   Auto-repair complete:\n");
    printf("   Checked %d signatures\n", signatures_checked);
    printf("   Performed %d repairs\n", repairs_done);
    
    return repairs_done > 0;
}

void list_signatures_with_extensions() {
    printf("\n=== Known File Formats ===\n");
    printf("%-20s %-8s %-10s %-8s %s\n", 
           "Format", "Length", "Offset", "Ext", "Description");
    printf("%-20s %-8s %-10s %-8s %s\n", 
           "--------------------", "--------", "----------", "--------",
           "--------------------------------------------------");
    
    for (int i = 0; i < SIGNATURE_COUNT; i++) {
        printf("%-20s %-8d 0x%-8lX %-8s %s\n", 
               known_signatures[i].name,
               known_signatures[i].length,
               known_signatures[i].offset,
               known_signatures[i].extension,
               known_signatures[i].description);
    }
    
    printf("\nTotal: %d formats\n", SIGNATURE_COUNT);
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
    bool verbose = false;
    bool auto_repair_mode = false;
    
    char *repair_format = NULL;
    unsigned char repair_char = 0;
    unsigned char repair_hex = 0;
    bool repair_with_char = false;
    bool repair_with_hex = false;
    
    // Parse options
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) show_ascii = false;
        else if (strcmp(argv[i], "-o") == 0) show_offset = false;
        else if (strcmp(argv[i], "-f") == 0) find_signatures = true;
        else if (strcmp(argv[i], "-s") == 0) save_extract = true;
        else if (strcmp(argv[i], "-l") == 0) list_sigs = true;
        else if (strcmp(argv[i], "-i") == 0) interactive = true;
        else if (strcmp(argv[i], "-v") == 0) verbose = true;
        else if (strcmp(argv[i], "-A") == 0) auto_repair_mode = true;
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            repair_format = argv[++i];
        }
        else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            repair_char = argv[++i][0];
            repair_with_char = true;
        }
        else if (strcmp(argv[i], "-X") == 0 && i + 1 < argc) {
            repair_hex = (unsigned char)strtol(argv[++i], NULL, 16);
            repair_with_hex = true;
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    if (list_sigs) {
        list_signatures_with_extensions();
        return 0;
    }
    
    // Validate repair parameters
    if ((repair_with_char || repair_with_hex || auto_repair_mode) && !repair_format && !auto_repair_mode) {
        printf("Error: Repair mode requires format specification (-t)\n");
        printf("       or auto-repair mode (-A)\n");
        return 1;
    }
    
    FILE *file = fopen(filename, "r+b");  // Read/write binary
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
    
    printf("\n=== File Repair Utility ===\n");
    printf("File: %s\n", filename);
    printf("Size: %ld bytes (%.2f KB)\n", file_size, file_size / 1024.0);
    printf("Offset: 0x%lX (%ld)\n", offset, offset);
    
    // Determine which byte pattern we're looking for
    unsigned char bad_byte = 0;
    
    if (repair_with_char) {
        bad_byte = repair_char;
        printf("Repair char: '%c' (0x%02X)\n", repair_char, repair_char);
    } else if (repair_with_hex) {
        bad_byte = repair_hex;
        printf("Repair hex: 0x%02X\n", repair_hex);
    } else if (auto_repair_mode) {
        // Try common corruption patterns
        bad_byte = 0x00;  // Often null bytes
        printf("Auto-repair mode: trying common patterns\n");
    }
    
    // Perform repair if requested
    bool repair_performed = false;
    
    if (repair_format) {
        FileSignature *sig = find_signature_by_name(repair_format);
        if (!sig) {
            printf("Error: Unknown format '%s'\n", repair_format);
            printf("Use -l to list available formats\n");
            fclose(file);
            return 1;
        }
        
        printf("Target format: %s\n", sig->name);
        printf("Signature length: %d bytes\n", sig->length);
        
        if (repair_with_char || repair_with_hex) {
            repair_performed = repair_signature(file, offset, sig, bad_byte, 
                                              interactive, verbose);
        }
    } else if (auto_repair_mode) {
        // Try common corruption bytes
        unsigned char common_bad_bytes[] = {0x00, 0xFF, 0x2A, 0x3F, 0x20};
        
        for (int i = 0; i < sizeof(common_bad_bytes); i++) {
            printf("\nTrying pattern 0x%02X...\n", common_bad_bytes[i]);
            if (auto_repair(file, offset, common_bad_bytes[i], 
                          interactive, verbose)) {
                repair_performed = true;
            }
        }
    }
    
    // Show hex dump after repair
    printf("\n=== Hex Dump ===\n");
    
    if (show_offset) {
        printf("Offset   ");
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            printf("%02X ", i);
            if (i == 7) printf(" ");
        }
        if (show_ascii) {
            printf(" ASCII\n");
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
    
    // Display the hex dump
    fseek(file, offset, SEEK_SET);
    unsigned char buffer[BYTES_PER_LINE];
    long total_read = 0;
    
    while (total_read < byte_count) {
        size_t to_read = BYTES_PER_LINE;
        if (total_read + to_read > byte_count) {
            to_read = byte_count - total_read;
        }
        
        size_t bytes_read = fread(buffer, 1, to_read, file);
        if (bytes_read == 0) break;
        
        // Print offset
        printf("%08lX  ", offset + total_read);
        
        // Print hex bytes
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            if (i < bytes_read) {
                // Highlight if this byte was potentially repaired
                if (repair_performed && i < 16) {  // First 16 bytes only
                    printf("%02X ", buffer[i]);
                } else {
                    printf("%02X ", buffer[i]);
                }
            } else {
                printf("   ");
            }
            
            if (i == 7) printf(" ");
        }
        
        // Print ASCII
        if (show_ascii) {
            printf(" |");
            for (int i = 0; i < bytes_read; i++) {
                if (isprint(buffer[i]) && !iscntrl(buffer[i])) {
                    printf("%c", buffer[i]);
                } else {
                    printf(".");
                }
            }
            printf("|");
        }
        
        printf("\n");
        total_read += bytes_read;
    }
    
    printf("\nDisplayed: %ld bytes\n", total_read);
    
    if (repair_performed) {
        printf("\n✅ REPAIR SUMMARY\n");
        printf("File has been repaired successfully!\n");
        printf("You may want to:\n");
        printf("1. Test the repaired file\n");
        printf("2. Rename with correct extension if needed\n");
        
        // Suggest extension if we repaired a known format
        if (repair_format) {
            FileSignature *sig = find_signature_by_name(repair_format);
            if (sig && sig->extension[0] != '\0') {
                printf("3. Consider renaming to: *.%s\n", sig->extension);
            }
        }
    }
    
    fclose(file);
    return 0;
}

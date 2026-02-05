// signature_extractor.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file_signatures.h"

int find_signature(FILE *file, FileSignature *found_sig) {
    unsigned char buffer[512];
    size_t bytes_read = fread(buffer, 1, 512, file);
    rewind(file); // Dosyayı başa sar
    
    for (int i = 0; i < SIGNATURE_COUNT; i++) {
        if (bytes_read < known_signatures[i].length) continue;
        
        if (memcmp(buffer, known_signatures[i].signature, 
                   known_signatures[i].length) == 0) {
            *found_sig = known_signatures[i];
            return 1; // İmza bulundu
        }
    }
    return 0; // İmza bulunamadı
}

void extract_and_obfuscate(const char *input_path, 
                          const char *signature_path, 
                          const char *body_path) {
    FILE *input = fopen(input_path, "rb+");
    FILE *sig_out = fopen(signature_path, "wb");
    FILE *body_out = fopen(body_path, "wb");
    
    if (!input || !sig_out || !body_out) {
        printf("Dosya açma hatası!\n");
        exit(1);
    }
    
    FileSignature found;
    if (!find_signature(input, &found)) {
        printf("Bilinmeyen dosya formatı veya imza bulunamadı.\n");
        // Standart bir işlem yapılabilir (örneğin ilk 256 byte'ı ayır)
        found.length = 256;
        printf("Varsayılan olarak ilk %d bayt imza olarak kabul edilecek.\n", found.length);
    }
    
    // 1. İmza verisini oku ve kaydet
    unsigned char *signature_data = malloc(found.length);
    fread(signature_data, 1, found.length, input);
    fwrite(signature_data, 1, found.length, sig_out);
    printf("Imza (%d bayt) '%s' dosyasına kaydedildi.\n", 
           found.length, signature_path);
    
    // 2. Orijinal dosyada imza bölgesini sıfırla (0x00 ile)
    rewind(input);
    unsigned char zero = 0x00;
    for (int i = 0; i < found.length; i++) {
        fwrite(&zero, 1, 1, input);
    }
    fflush(input);
    
    // 3. Geri kalan dosya içeriğini (yığın) yeni dosyaya kopyala
    rewind(input);
    fseek(input, found.length, SEEK_SET);
    
    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, 4096, input)) > 0) {
        fwrite(buffer, 1, bytes, body_out);
    }
    printf("Yığın verisi '%s' dosyasına kaydedildi.\n", body_path);
    
    // Temizlik
    free(signature_data);
    fclose(input);
    fclose(sig_out);
    fclose(body_out);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Kullanım: %s <girdi_dosyası> <imza_çıktı> <yığın_çıktı>\n", argv[0]);
        printf("Örnek: %s secret.jpg signature.sig body.dat\n", argv[0]);
        return 1;
    }
    
    extract_and_obfuscate(argv[1], argv[2], argv[3]);
    printf("\nİşlem tamamlandı:\n");
    printf("• '%s' artık tanınmaz durumda (imza sıfırlandı)\n", argv[1]);
    printf("• '%s' dosyasında imza saklandı\n", argv[2]);
    printf("• '%s' dosyasında yığın verisi saklandı\n", argv[3]);
    printf("Bu üç dosya aynı anda aynı dizinde olmadan birleştirilemez.\n");
    
    return 0;
}

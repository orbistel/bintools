// signature_combiner.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void combine_files(const char *signature_path, 
                   const char *body_path, 
                   const char *output_path) {
    FILE *sig_file = fopen(signature_path, "rb");
    FILE *body_file = fopen(body_path, "rb");
    FILE *output = fopen(output_path, "wb");
    
    if (!sig_file || !body_file || !output) {
        printf("Dosya açma hatası!\n");
        exit(1);
    }
    
    // 1. İmza dosyasının içeriğini oku ve çıktıya yaz
    fseek(sig_file, 0, SEEK_END);
    long sig_size = ftell(sig_file);
    rewind(sig_file);
    
    unsigned char *signature = malloc(sig_size);
    fread(signature, 1, sig_size, sig_file);
    fwrite(signature, 1, sig_size, output);
    free(signature);
    
    printf("%ld bayt imza verisi eklendi.\n", sig_size);
    
    // 2. Yığın dosyasının içeriğini oku ve çıktıya yaz
    unsigned char buffer[4096];
    size_t bytes;
    long body_total = 0;
    
    while ((bytes = fread(buffer, 1, 4096, body_file)) > 0) {
        fwrite(buffer, 1, bytes, output);
        body_total += bytes;
    }
    
    printf("%ld bayt yığın verisi eklendi.\n", body_total);
    printf("Toplam %ld baytlık '%s' dosyası oluşturuldu.\n", 
           sig_size + body_total, output_path);
    
    fclose(sig_file);
    fclose(body_file);
    fclose(output);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Kullanım: %s <imza_dosyası> <yığın_dosyası> <çıktı_dosyası>\n", argv[0]);
        printf("Örnek: %s signature.sig body.dat original_restored.jpg\n", argv[0]);
        return 1;
    }
    
    combine_files(argv[1], argv[2], argv[3]);
    printf("Dosya başarıyla birleştirildi!\n");
    
    return 0;
}

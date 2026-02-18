# 🛠️ File Signature Tool - C ile Yazılmış Dosya İmza Düzenleme Aracı

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform: Windows/Linux](https://img.shields.io/badge/Platform-Windows%20|%20Linux-blue)
![Language: C](https://img.shields.io/badge/Language-C-green)
![Size: 2GB+ Support](https://img.shields.io/badge/Size-2GB%2B%20Files-success)

> **⚠️ ÖNEMLİ**: Bu kod tamamen [DeepSeek](https://www.deepseek.com/) yapay zeka tarafından yazılmıştır. İnsan eli değmemiş %100 AI üretimidir! 

## 📋 Proje Hakkında

Bu proje, dosyaların imza (magic bytes) bölümlerini okuyan, değiştiren ve onaran güçlü bir C aracıdır. Wikipedia'daki [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) sayfasındaki tüm dosya imzalarını kullanarak:

- ✅ Dosya imzalarını tespit eder
- ✅ İmzaları istenen byte pattern ile değiştirir (obfuscate)
- ✅ Bozulmuş imzaları onarır
- ✅ 2GB+ büyük dosyaları destekler
- ✅ İnteraktif ve batch modda çalışır

## 🎯 Özellikler

### Her İki Uygulamada Ortak Özellikler:
- 📁 **64-bit dosya desteği** - 2GB, 20GB, 2TB dosyaları sorunsuz işler
- 🔢 **Suffix desteği** - 4K, 2M, 1G, 0x1000 gibi parametreler
- 📊 **Progress bar** - Büyük dosyalar için görsel ilerleme
- 🎨 **Renkli çıktı** - Linux/Windows terminal desteği
- 🔍 **Hex dump** - Detaylı hex görüntüleme
- 💾 **Yedekleme** - Değişiklik öncesi otomatik yedek

### 🔧 REPLACE (hexreplace64.exe)
Dosya imzalarını değiştirerek dosyayı tanınmaz hale getirir:
- ✏️ ASCII karakter ile değiştirme (`-r *`)
- 🔢 Hex değer ile değiştirme (`-R 00`)
- 🎯 Belirli formatı hedefleme (`-t JPEG`)
- 🔄 Tüm imzaları değiştirme (`-a`)

### 🩺 REPAIR (hexrepair64.exe)
Bozulmuş dosya imzalarını onarır:
- 🔎 Bozuk byte pattern'i bulur (`-x *` veya `-X 00`)
- 🎯 Hedef formatı onarır (`-t PDF`)
- 🤖 Otomatik onarım (`-A`)
- 🧪 Test modu (`-test`)

## 📦 Kurulum

### Windows (MinGW-w64 ile derleme):
```bash
# MSYS2 veya MinGW terminalinde

# REPLACE uygulamasını derle
gcc -o hreplace64.exe hexreplace64.c -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE

# REPAIR uygulamasını derle
gcc -o hrepair64.exe hexrepair64.c -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
```

### Windows (Visual Studio):
```cmd
cl hexreplace64.c /Fe:hreplace64.exe /D_CRT_SECURE_NO_WARNINGS
cl hexrepair64.c /Fe:hrepair64.exe /D_CRT_SECURE_NO_WARNINGS
```

### Linux:
```bash
# GCC ile derle
gcc -o hreplace64 hexreplace64.c -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
gcc -o hrepair64 hexrepair64.c -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
```

## 🚀 Kullanım

### REPLACE Örnekleri - İmzaları Değiştirme

```bash
# 1. JPEG dosyasının imzasını '*' ile değiştir (yedek al)
hreplace64.exe photo.jpg 0 0 -r "*" -t JPEG -b photo_backup.jpg

# 2. PDF imzasını null byte ile değiştir
hreplace64.exe document.pdf 0 0 -R 00 -t PDF

# 3. Tüm imzaları bul ve değiştir (interaktif)
hreplace64.exe secret.bin 0 0 -R FF -a -i

# 4. Büyük ISO dosyasında imza ara
hreplace64.exe large.iso 0 1G -f

# 5. 5GB offset'ten 100MB bölgede ZIP imzası değiştir
hreplace64.exe archive.bin 5G 100M -t ZIP -r "#"
```

### REPAIR Örnekleri - İmzaları Onarma

```bash
# 1. Bozuk JPEG imzasını onar ('*' karakterini temizle)
hrepair64.exe corrupted.jpg 0 0 -t JPEG -x "*" -i

# 2. Null byte ile bozulmuş PDF'i onar
hrepair64.exe broken.pdf 0 0 -t PDF -X 00 -v

# 3. Otomatik onarım modu (tüm pattern'leri dene)
hrepair64.exe damaged.iso 0 1G -A -p

# 4. Test modu (gerçek değişiklik yapmadan göster)
hrepair64.exe test.bin 0 0 -t ZIP -X 00 -test -c 50

# 5. Sadece imzaları bul (onarım yapma)
hrepair64.exe unknown.dat 0 0 -f
```

## 📊 İmza Veritabanı

Wikipedia'daki [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) sayfasından derlenen desteklenen formatlar:

| Format | Uzantı | İmza (Hex) | Açıklama |
|--------|--------|------------|----------|
| JPEG | .jpg | FF D8 FF | JPEG image |
| PNG | .png | 89 50 4E 47 0D 0A 1A 0A | PNG image |
| GIF | .gif | 47 49 46 38 | GIF image |
| BMP | .bmp | 42 4D | Bitmap |
| PDF | .pdf | 25 50 44 46 | PDF document |
| ZIP | .zip | 50 4B 03 04 | ZIP archive |
| RAR | .rar | 52 61 72 21 | RAR archive |
| 7Z | .7z | 37 7A BC AF | 7-Zip archive |
| MP4 | .mp4 | 00 ... 66 74 79 70 | MP4 video |
| AVI | .avi | 52 49 46 46 ... | AVI video |
| MKV | .mkv | 1A 45 DF A3 | Matroska video |
| EXE | .exe | 4D 5A | Windows executable |
| SQLite | .db | 53 51 4C 69 74 65 ... | SQLite database |
| ISO | .iso | 01 43 44 30 30 31 | ISO disk image |
| MP3 | .mp3 | 49 44 33 | MP3 audio |

## 🛡️ Güvenlik ve Uyarılar

### ⚠️ REPLACE Uygulaması için:
- **Bu araç dosyaları KALICI OLARAK DEĞİŞTİRİR!**
- Her zaman `-b` ile yedek alın
- Değiştirilen dosyalar eski hallerine dönmeyebilir
- Hassas veriler için önce test dosyasında deneyin

### ⚠️ REPAIR Uygulaması için:
- Önce `-test` modunda çalıştırın
- `-i` ile interaktif mod kullanın
- Birden fazla pattern'i `-A` ile deneyin

## 📁 Dosya Yapısı

```
.
├── hexreplace64.c          # REPLACE uygulaması kaynak
├── hexrepair64.c           # REPAIR uygulaması kaynak
├── hreplace64.exe          # Derlenmiş REPLACE (Windows)
├── hrepair64.exe           # Derlenmiş REPAIR (Windows)
├── README.md               # Bu dosya
└── signatures.h            # İmza veritabanı (opsiyonel)
```

## 🎯 Kullanım Senaryoları

### Senaryo 1: Gizli Dosyayı Tanınmaz Hale Getirme
```bash
# 1. Önce imzaları bul
hreplace6464 secret.pdf 0 0 -f

# 2. Yedek al
hreplace64 secret.pdf 0 0 -b secret_backup.pdf

# 3. İmzayı değiştir
hreplace64 secret.pdf 0 0 -R 00 -t PDF
```

### Senaryo 2: Bozulmuş Dosyayı Onarma
```bash
# 1. Test modunda dene
hrepair64 broken.jpg 0 0 -t JPEG -x "*" -test -v

# 2. İnteraktif onarım yap
hrepair64 broken.jpg 0 0 -t JPEG -x "*" -i

# 3. Sonucu kontrol et
hrepair64 broken.jpg 0 0 -f
```

### Senaryo 3: 20GB ISO Dosyasında İşlem
```bash
# İlk 1GB'da ISO imzasını değiştir
hreplace64 large.iso 0 1G -t ISO -r "*" -b large_backup.iso -p

# 5GB offset'ten itibaren onarım dene
hrepair64 large.iso 5G 500M -A -p -v
```

## 🤖 Yapay Zeka Bildirimi

> Bu projenin TÜM KODLARI [DeepSeek](https://www.deepseek.com/) tarafından üretilmiştir. 
> - İnsan eli değmemiştir
> - 100% AI generated
> - DeepSeek Coder modeli tarafından yazılmıştır
> - Herhangi bir insan geliştirici katkısı yoktur

Bu proje, yapay zekanın karmaşık sistem programlama görevlerini ne kadar başarılı yapabildiğinin bir göstergesidir. 2GB+ dosya desteği, 64-bit offset'ler, Windows/Linux uyumluluğu gibi teknik detaylar tamamen AI tarafından implemente edilmiştir.

## 📝 Lisans

MIT License - Özgürce kullanın, değiştirin, dağıtın. Ama önce yedek almayı unutmayın! 😉

## 🐛 Hata Bildirimi

Eğer bir hata bulursanız:
1. Önce dosyanızın yedeğini aldığınızdan emin olun
2. `-v` parametresi ile verbose modda çalıştırın
3. Çıktıyı kaydedin
4. Issue açın

## 🙏 Teşekkürler

- [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures) - Kapsamlı imza listesi için
- [DeepSeek](https://www.deepseek.com/) - Kodun tamamını yazdığı için
- Açık kaynak topluluğu - İlham için

---

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!**

*Not: Bu README dosyası da DeepSeek tarafından yazılmıştır. Evet, bu cümle de dahil.* 😄

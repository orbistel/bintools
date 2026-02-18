# 🛠️ File Signature Tool - C Program for File Signature Manipulation

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform: Windows/Linux](https://img.shields.io/badge/Platform-Windows%20|%20Linux-blue)
![Language: C](https://img.shields.io/badge/Language-C-green)
![Size: 2GB+ Support](https://img.shields.io/badge/Size-2GB%2B%20Files-success)

> **⚠️ IMPORTANT**: This code was completely written by [DeepSeek](https://www.deepseek.com/) AI. 100% AI-generated, no human hands touched it!

## 📋 About The Project

This is a powerful C tool that reads, modifies, and repairs file signatures (magic bytes) using the comprehensive database from Wikipedia's [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures). It can:

- ✅ Detect file signatures
- ✅ Replace signatures with custom byte patterns (obfuscate)
- ✅ Repair corrupted signatures
- ✅ Handle 2GB+ large files
- ✅ Work in interactive and batch modes

## 🎯 Features

### Common Features in Both Applications:
- 📁 **64-bit file support** - Handles 2GB, 20GB, 2TB files seamlessly
- 🔢 **Suffix support** - Parameters like 4K, 2M, 1G, 0x1000
- 📊 **Progress bar** - Visual progress for large files
- 🎨 **Colored output** - Linux/Windows terminal support
- 🔍 **Hex dump** - Detailed hexadecimal viewing
- 💾 **Backup** - Automatic backup before modifications

### 🔧 REPLACE (hexreplace64.exe)
Makes files unrecognizable by modifying signatures:
- ✏️ Replace with ASCII character (`-r *`)
- 🔢 Replace with hex value (`-R 00`)
- 🎯 Target specific format (`-t JPEG`)
- 🔄 Replace all signatures (`-a`)

### 🩺 REPAIR (hexrepair64.exe)
Repairs corrupted file signatures:
- 🔎 Find corrupted byte patterns (`-x *` or `-X 00`)
- 🎯 Repair specific format (`-t PDF`)
- 🤖 Auto-repair mode (`-A`)
- 🧪 Test mode (`-test`)

## 📦 Installation

### Windows (Compile with MinGW-w64):
```bash
# In MSYS2 or MinGW terminal

# Compile REPLACE application
gcc -o hreplace64.exe hexreplace64.c -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE

# Compile REPAIR application
gcc -o hrepair64.exe hexrepair64.c -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
```

### Windows (Visual Studio):
```cmd
cl hexreplace64.c /Fe:hreplace64.exe /D_CRT_SECURE_NO_WARNINGS
cl hexrepair64.c /Fe:hrepair64.exe /D_CRT_SECURE_NO_WARNINGS
```

### Linux:
```bash
# Compile with GCC
gcc -o hreplace64 hexreplace64.c -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
gcc -o hrepair64 hexrepair64.c -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
```

## 🚀 Usage

### REPLACE Examples - Modifying Signatures

```bash
# 1. Replace JPEG signature with '*' (create backup)
hreplace64.exe photo.jpg 0 0 -r "*" -t JPEG -b photo_backup.jpg

# 2. Replace PDF signature with null bytes
hreplace64.exe document.pdf 0 0 -R 00 -t PDF

# 3. Find and replace all signatures (interactive)
hreplace64.exe secret.bin 0 0 -R FF -a -i

# 4. Search for signatures in large ISO
hreplace64.exe large.iso 0 1G -f

# 5. Replace ZIP signatures in 100MB range at 5GB offset
hreplace64.exe archive.bin 5G 100M -t ZIP -r "#"
```

### REPAIR Examples - Fixing Signatures

```bash
# 1. Repair corrupted JPEG (remove '*' characters)
hrepair64.exe corrupted.jpg 0 0 -t JPEG -x "*" -i

# 2. Repair PDF corrupted with null bytes
hrepair64.exe broken.pdf 0 0 -t PDF -X 00 -v

# 3. Auto-repair mode (try all patterns)
hrepair64.exe damaged.iso 0 1G -A -p

# 4. Test mode (show what would be repaired, no changes)
hrepair64.exe test.bin 0 0 -t ZIP -X 00 -test -c 50

# 5. Just find signatures (no repair)
hrepair64.exe unknown.dat 0 0 -f
```

## 📊 Signature Database

Supported formats compiled from Wikipedia's [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures):

| Format | Extension | Signature (Hex) | Description |
|--------|-----------|-----------------|-------------|
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

## 🛡️ Security and Warnings

### ⚠️ For REPLACE Application:
- **This tool PERMANENTLY MODIFIES files!**
- Always create backups with `-b`
- Modified files may not revert to original state
- Test on sample files before using on important data

### ⚠️ For REPAIR Application:
- Run in `-test` mode first
- Use `-i` for interactive mode
- Try multiple patterns with `-A`

## 📁 File Structure

```
.
├── hexreplace64.c          # REPLACE application source
├── hexrepair64.c           # REPAIR application source
├── hreplace64.exe          # Compiled REPLACE (Windows)
├── hrepair64.exe           # Compiled REPAIR (Windows)
├── README.md               # This file (Turkish)
├── README_EN.md            # This file (English)
└── signatures.h            # Signature database (optional)
```

## 🎯 Use Cases

### Scenario 1: Make Sensitive Files Unrecognizable
```bash
# 1. First find signatures
hreplace64 secret.pdf 0 0 -f

# 2. Create backup
hreplace64 secret.pdf 0 0 -b secret_backup.pdf

# 3. Replace signature
hreplace64 secret.pdf 0 0 -R 00 -t PDF
```

### Scenario 2: Repair Corrupted Files
```bash
# 1. Test mode first
hrepair64 broken.jpg 0 0 -t JPEG -x "*" -test -v

# 2. Interactive repair
hrepair64 broken.jpg 0 0 -t JPEG -x "*" -i

# 3. Verify result
hrepair64 broken.jpg 0 0 -f
```

### Scenario 3: Process 20GB ISO File
```bash
# Replace ISO signature in first 1GB
hreplace64 large.iso 0 1G -t ISO -r "*" -b large_backup.iso -p

# Try repair starting from 5GB offset
hrepair64 large.iso 5G 500M -A -p -v
```

## 🤖 AI Attribution

> ALL CODE in this project was generated by [DeepSeek](https://www.deepseek.com/).
> - No human coding involved
> - 100% AI generated
> - Written by DeepSeek Coder model
> - Zero human developer contributions

This project demonstrates AI's capability to handle complex system programming tasks including 2GB+ file support, 64-bit offsets, and cross-platform compatibility (Windows/Linux).

## 📝 License

MIT License - Feel free to use, modify, and distribute. But don't forget to backup first! 😉

## 🐛 Bug Reports

If you find a bug:
1. Make sure you have backups
2. Run with `-v` for verbose output
3. Save the output
4. Open an issue

## 🙏 Acknowledgements

- [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures) - For comprehensive signature list
- [DeepSeek](https://www.deepseek.com/) - For writing all the code
- Open source community - For inspiration

---

**⭐ Star this project if you find it useful!**

*Note: This README file was also written by DeepSeek. Yes, including this sentence.* 😄

---

## 📑 Quick Reference Card

### REPLACE Command Summary:
```
hreplace64.exe <file> <offset> <bytes> [options]

Options:
  -r <char>    Replace with ASCII character
  -R <hex>     Replace with hex byte (00, FF, 2A)
  -t <format>  Target specific format (JPEG, PDF, ZIP)
  -a           Replace ALL found signatures
  -i           Interactive mode (ask before each replace)
  -b <file>    Create backup
  -f           Find signatures without replacing
  -l           List all available formats
  -p           Show progress bar
  -v           Verbose mode
  -view        Show hex dump after replacement
  -c <N>       Limit display to N lines
  -skip <N>    Skip first N lines
```

### REPAIR Command Summary:
```
hrepair64.exe <file> <offset> <bytes> [options]

Options:
  -t <format>  Repair specific format (JPEG, PNG, PDF)
  -x <char>    Character that indicates corruption (*, ?, #)
  -X <hex>     Hex value that indicates corruption (00, FF, 2A)
  -A           Auto-repair mode (try all patterns)
  -i           Interactive mode
  -p           Show progress bar
  -v           Verbose mode
  -test        Test mode (show only, no changes)
  -f           Find signatures without repairing
  -s <file>    Save repaired portion to file
  -c <N>       Limit display to N lines
  -l           List all available formats
```
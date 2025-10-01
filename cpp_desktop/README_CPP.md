# SQL Injection Scanner - Versi Desktop C++ v2.0

## Ikhtisar

Versi desktop C++ dari SQL Injection Scanner menyediakan antarmuka grafis futuristik yang dibangun dengan Qt6, menawarkan performa tinggi dan estetika cyberpunk dengan dominasi warna hitam serta aksen neon hijau.

## 🚀 Fitur Unggulan

### Performa Tinggi C++
- **Native Performance**: Kompilasi native untuk kecepatan maksimal
- **Multi-threading QtConcurrent**: Pemrosesan paralel yang efisien
- **Memory Management Modern**: Smart pointers dan RAII
- **Qt6 Framework**: Teknologi GUI terkini

### Antarmuka Futuristik
- **Tema Cyberpunk**: Dominasi hitam dengan neon hijau (#00ff41)
- **Font Matrix**: Courier New monospace untuk estetika hacker
- **Efek Visual Glow**: Border dan elemen dengan efek neon
- **GUI Interaktif**: Tombol, tabel, dan progress bar futuristik

### Fungsionalitas Lengkap
- **25+ Payload SQL Injection**: Database payload yang komprehensif
- **Deteksi Multi-Database**: MySQL, PostgreSQL, MSSQL, Oracle, DB2, SQLite
- **Time-based Blind Detection**: Analisis waktu response untuk SQL injection buta
- **Multi-parameter Scanning**: Testing beberapa parameter secara simultan
- **Export Laporan**: Simpan hasil dalam format teks

## 📋 Persyaratan Sistem

### Minimum Requirements
- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+
- **Compiler**: GCC 9+, Clang 10+, MSVC 2019+
- **CMake**: 3.16 atau lebih baru
- **Qt6**: 6.2 atau lebih baru
- **RAM**: 4GB minimum
- **Storage**: 500MB free space

### Recommended Requirements
- **CPU**: Multi-core processor (4+ cores)
- **RAM**: 8GB atau lebih
- **Network**: Koneksi internet stabil untuk testing
- **Display**: 1920x1080 atau lebih tinggi

## 🔧 Instalasi dan Build

### 1. Install Dependencies

#### Ubuntu/Debian:
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build tools
sudo apt install -y build-essential cmake git

# Install Qt6
sudo apt install -y qt6-base-dev qt6-tools-dev qt6-tools-dev-tools libqt6network6-dev

# Install additional dependencies
sudo apt install -y libssl-dev zlib1g-dev
```

#### CentOS/RHEL/Fedora:
```bash
# Fedora
sudo dnf install gcc-c++ cmake git qt6-qtbase-devel qt6-qtnetwork-devel

# CentOS/RHEL (enable EPEL first)
sudo yum install epel-release
sudo yum install gcc-c++ cmake git qt6-qtbase-devel
```

#### macOS (with Homebrew):
```bash
# Install Xcode command line tools
xcode-select --install

# Install dependencies
brew install cmake qt@6

# Add Qt to PATH
export PATH="/usr/local/opt/qt@6/bin:$PATH"
```

#### Windows (with vcpkg):
```cmd
# Install vcpkg first
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Install Qt6
.\vcpkg install qt6-base qt6-network
```

### 2. Clone dan Build

```bash
# Clone repository
git clone https://github.com/yourusername/sql-injection-scanner-cpp.git
cd sql-injection-scanner-cpp

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build (gunakan semua core CPU)
cmake --build . --config Release --parallel $(nproc)

# Install (opsional)
sudo cmake --install .
```

### 3. Jalankan Aplikasi

```bash
# Dari directory build
./SQLInjectionScanner

# Atau jika sudah diinstall
SQLInjectionScanner
```

## 🎮 Cara Penggunaan

### Metode 1: GUI Interaktif (Disarankan)
1. **Jalankan Aplikasi**: Double-click executable atau jalankan dari terminal
2. **Masukkan URL Target**: Contoh: `http://testphp.vulnweb.com/search.php?test=query`
3. **Pilih Metode**: GET untuk URL parameters, POST untuk form data
4. **Atur Thread**: 5-10 thread untuk performa optimal
5. **Atur Timeout**: 10-30 detik tergantung kecepatan server
6. **Klik "MULAI SCAN"**: Proses scanning akan dimulai
7. **Monitor Progress**: Pantau progress bar dan log real-time
8. **Analisis Hasil**: Review temuan di tab "Hasil"
9. **Export Laporan**: Klik "EXPORT LAPORAN" untuk menyimpan hasil

### Metode 2: Command Line Arguments
```bash
# Jalankan dengan URL langsung
./SQLInjectionScanner --url "http://target.com/page?id=1" --method GET --threads 5

# Dengan timeout kustom
./SQLInjectionScanner --url "http://target.com/login" --method POST --threads 3 --timeout 20
```

## 🎯 Target Testing Legal

### Situs Test Resmi
```bash
# Acunetix Test Site
./SQLInjectionScanner --url "http://testphp.vulnweb.com/search.php?test=query"

# DVWA
./SQLInjectionScanner --url "http://www.dvwa.co.uk/vulnerabilities/sqli/?id=1&Submit=Submit"

# Multi-parameter testing
./SQLInjectionScanner --url "http://testphp.vulnweb.com/listproducts.php?cat=1&artist=2"
```

## 🔍 Memahami Hasil

### Indikator Status
- **🔴 RENTAN**: Parameter terdeteksi memiliki kerentanan SQL injection
- **🟢 AMAN**: Parameter tidak menunjukkan tanda kerentanan
- **⚠️ ERROR**: Terdeteksi anomali dalam response

### Jenis Kerentanan
- **Error-based**: Terdeteksi melalui pesan error SQL
- **Time-based Blind**: Terdeteksi melalui delay waktu response
- **Union-based**: Terdeteksi melalui operasi UNION

## 🛠️ Kustomisasi Lanjutan

### Edit Payload Kustom
1. Buka tab "Payloads" dalam aplikasi
2. Edit payload di area teks yang disediakan
3. Setiap payload pada baris baru
4. Klik "Load Defaults" untuk restore payload standar

### Edit Pola Error
1. Akses tab "Payloads" 
2. Edit pola regex di area "Pola Error"
3. Gunakan syntax regex Python
4. Test dengan target yang diketahui

## 🔧 Troubleshooting

### Masalah Build Umum

#### "Qt6 not found"
```bash
# Ubuntu/Debian
sudo apt install qt6-base-dev qt6-tools-dev

# CentOS/RHEL
sudo yum install qt6-qtbase-devel

# macOS
brew install qt@6
export PATH="/usr/local/opt/qt@6/bin:$PATH"
```

#### "CMake version too old"
```bash
# Install CMake 3.16+
wget https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0-Linux-x86_64.sh
sudo sh cmake-3.20.0-Linux-x86_64.sh --skip-license --prefix=/usr/local
export PATH=/usr/local/bin:$PATH
```

### Masalah Runtime

#### "Network connection failed"
- Periksa koneksi internet
- Verifikasi URL target dapat diakses
- Cek firewall dan proxy settings
- Tingkatkan timeout untuk server lambat

#### "No parameters found in URL"
- Pastikan URL mengandung parameter (contoh: `?id=1`)
- Gunakan format URL yang benar
- Periksa encoding karakter khusus

#### "Application crashes on startup"
- Install semua dependensi Qt6
- Jalankan dari directory yang benar
- Periksa permission file executable
- Cek log error di terminal

## ⚡ Performa & Optimasi

### Tips Performa
- **Thread Count**: Gunakan 50-75% dari jumlah core CPU
- **Timeout**: Sesuaikan dengan kecepatan server target
- **Network**: Gunakan koneksi kabel untuk stabilitas
- **System**: Tutup aplikasi berat selama scanning

### Benchmarking
- Test dengan target lokal untuk performa maksimal
- Monitor penggunaan CPU dan memory
- Bandingkan hasil dengan versi Python
- Gunakan profiler untuk optimasi lanjutan

## 🔒 Keamanan & Etika

### Protokol Keamanan
- **Izin Wajib**: Hanya scan target yang Anda miliki atau punya izin
- **Legal Compliance**: Patuhi hukum setempat
- **Responsible Disclosure**: Laporkan temuan secara etis
- **Rate Limiting**: Gunakan thread reasonable untuk menghindari DoS

### Best Practices
- Mulai dengan environment test/development
- Gunakan thread count rendah di awal (3-5)
- Scan selama off-peak hours
- Document semua aktivitas testing
- Follow responsible disclosure guidelines

## 📚 Resource & Dukungan

### Dokumentasi Terkait
- [Panduan Desktop Python](DESKTOP_USAGE.md)
- [Panduan Command Line](USAGE.md)
- [README Utama](README.md)

### Community & Support
- GitHub Issues: Laporkan bug dan request fitur
- Discussions: Tanya jawab dengan komunitas
- Wiki: Dokumentasi teknis lanjutan

### Update & Maintenance
- Check GitHub untuk update terbaru
- Follow security best practices
- Monitor dependency vulnerabilities
- Kontribusi pull request welcome!

---

**⚠️ PENGINGATAN KEAMANAN**: Alat ini untuk **testing keamanan yang sah** saja. Selalu pastikan Anda memiliki izin eksplisit sebelum memindai sistem apapun.

**🎯 Motto**: "Scan dengan bijak, scan dengan izin, scan dengan tujuan edukasi!"

**Selamat hacking secara etis!** 🚀🔒
# Mini SQL Injection Vulnerability Scanner

Alat Python ringan untuk mendeteksi kerentanan SQL injection dalam aplikasi web. Scanner ini menggunakan berbagai teknik termasuk deteksi berbasis kesalahan dan deteksi SQL injection buta berbasis waktu.

## 🖥️ VERSI DESKTOP BARU - EDISI FUTURISTIK v2.0

**✨ Sekarang tersedia versi desktop dengan antarmuka cyberpunk futuristik!**

### Fitur-Fitur Desktop:
- **🎨 Tema Gelap Futuristik**: Dominasi warna hitam dengan aksen neon hijau
- **🔍 Antarmuka Grafis Modern**: Built dengan PyQt5 untuk pengalaman pengguna premium
- **⚡ Scanning Real-time**: Progress bar holografik dan log terminal futuristik
- **📊 Hasil Interaktif**: Tabel hasil dengan warna-warni cyberpunk
- **🛠️ Konfigurasi Lanjutan**: Payload kustom, pola error, dan pengaturan performa

### Cara Menggunakan Versi Desktop:
```bash
# Jalankan launcher (disarankan)
python3 launch_desktop.py

# Atau langsung jalankan scanner
python3 desktop_scanner.py
```

**📖 Panduan Lengkap Desktop**: Lihat [DESKTOP_USAGE.md](DESKTOP_USAGE.md) untuk dokumentasi futuristik!

## Fitur-Fitur

### Versi Command Line:
- **Multiple SQL Injection Payloads**: Menguji dengan 25+ payload SQL injection umum
- **Error Pattern Detection**: Mengidentifikasi kesalahan SQL dari berbagai sistem database (MySQL, PostgreSQL, MSSQL, Oracle, DB2, SQLite)
- **Time-based Blind Detection**: Mendeteksi kerentanan SQL injection buta berbasis waktu
- **Multi-threading**: Pemindaian cepat dengan jumlah thread yang dapat dikonfigurasi
- **Comprehensive Reporting**: Laporan kerentanan detail dengan temuan
- **Support for GET and POST**: Menguji parameter GET dan POST
- **Concurrent Parameter Testing**: Menguji beberapa parameter secara simultan

### Versi Desktop v2.0:
- **🌟 Antarmuka Cyberpunk Futuristik**: Desain gelap dengan efek neon
- **🎯 Pengalaman Pengguna Premium**: GUI modern dengan navigasi tab
- **📈 Visualisasi Data Real-time**: Progress scanning dan hasil interaktif
- **🔧 Kustomisasi Lanjutan**: Edit payload dan pola error secara visual
- **💾 Export Report**: Simpan hasil scan dengan dialog file futuristik

## Instalasi

### Untuk Semua Versi:
1. Clone atau download file-file scanner
2. Install dependensi yang diperlukan:
```bash
pip install -r requirements.txt
```

### Untuk Versi Desktop (Fitur Futuristik):
Pastikan PyQt5 terinstall:
```bash
pip install PyQt5>=5.15.0
```

## Cara Penggunaan

### 🔥 VERSI DESKTOP (Disarankan untuk Pemula):
```bash
# Jalankan launcher futuristik
python3 launch_desktop.py

# Atau langsung jalankan GUI
python3 desktop_scanner.py
```

### Versi Command Line:

#### Penggunaan Dasar
```bash
python3 main.py -u "http://example.com/page?id=1"
```

#### Penggunaan Lanjutan
```bash
# Test parameter POST
python3 main.py -u "http://example.com/login" -m POST

# Gunakan lebih banyak thread untuk pemindaian lebih cepat
python3 main.py -u "http://example.com/search?q=test" -t 10

# Simpan laporan ke file
python3 main.py -u "http://example.com/page?id=1" -o report.txt

# Aktifkan output verbose
python3 main.py -u "http://example.com/page?id=1" -v
```

### Opsi Command Line

| Opsi | Deskripsi | Default |
|--------|-------------|---------|
| `-u, --url` | URL target untuk dipindai (wajib) | - |
| `-m, --method` | Metode HTTP (GET atau POST) | GET |
| `-t, --threads` | Jumlah thread | 5 |
| `-T, --timeout` | Timeout request dalam detik | 10 |
| `-o, --output` | File output untuk hasil scan | - |
| `-v, --verbose` | Aktifkan output verbose | False |

## Cara Kerja

### Versi Command Line:
1. **Parameter Extraction**: Secara otomatis mengekstrak parameter dari URL target
2. **Payload Testing**: Menguji setiap parameter dengan berbagai payload SQL injection
3. **Error Detection**: Menganalisis response untuk pola kesalahan SQL
4. **Time-based Detection**: Mengukur waktu response untuk mendeteksi SQL injection buta
5. **Reporting**: Menghasilkan laporan detail dari temuan

### Versi Desktop:
1. **Input GUI**: Masukkan URL melalui antarmuka grafis futuristik
2. **Konfigurasi Visual**: Atur thread, timeout, dan metode melalui kontrol interaktif
3. **Scan Interaktif**: Klik "INITIATE SCAN" untuk memulai pemindaian
4. **Monitor Real-time**: Pantau progress melalui progress bar holografik
5. **Analisis Visual**: Lihat hasil dalam tabel interaktif dengan tema cyberpunk

## Metode Deteksi

### Deteksi Berbasis Kesalahan (Error-based Detection)
Scanner mencari pesan kesalahan SQL umum dari berbagai sistem database:
- Kesalahan MySQL
- Kesalahan PostgreSQL
- Kesalahan Microsoft SQL Server
- Kesalahan Oracle
- Kesalahan IBM DB2
- Kesalahan SQLite
- Kesalahan SQL umum

### Deteksi Buta Berbasis Waktu (Time-based Blind Detection)
Mendeteksi kerentanan dengan mengukur waktu response saat menggunakan payload delay waktu:
- `WAITFOR DELAY` (MSSQL)
- `SLEEP()` (MySQL)
- `pg_sleep()` (PostgreSQL)

## Contoh Output

### Output Command Line:
```
    ╔══════════════════════════════════════════════════════════════╗
    ║                  Mini SQL Injection Scanner                  ║
    ║                          Version 1.0                         ║
    ║                     Code By HadsXdevCate                     ║
    ╚══════════════════════════════════════════════════════════════╝

[*] Scanning URL: http://example.com/page?id=1
[*] Found 1 parameter(s): id

============================================================
SQL INJECTION VULNERABILITY SCAN REPORT
============================================================
URL: http://example.com/page?id=1
Method: GET
Scan Time: 2025-09-30 15:00:00
------------------------------------------------------------
[!] VULNERABILITIES FOUND!
Vulnerable Parameters: id

Parameter: id
Status: VULNERABLE
Errors Found:
  - Payload: ' OR '1'='1
    Error: SQL.*syntax.*MySQL
    Response Time: 0.23s
  - Payload: 1' OR SLEEP(5)--
    Error: Time-based blind SQL injection (response time > 5s)
    Response Time: 5.12s
```

### Output Versi Desktop:
- **Antarmuka Futuristik**: Tampilan gelap dengan teks neon hijau
- **Tabel Hasil Interaktif**: Parameter yang rentan ditampilkan dengan latar merah gelap
- **Progress Bar Holografik**: Indikator progress dengan efek neon
- **Log Terminal**: Output real-time dengan format monospace futuristik
- **Export Report**: Simpan hasil melalui dialog file dengan tema cyberpunk

## Target Test Langsung (Untuk Praktik)

Berikut adalah aplikasi web rentan yang tersedia secara publik dan sah untuk menguji scanner Anda:

### 🎯 Primary Test Targets

**1. Situs Uji Rentan Acunetix**
```bash
# Test dasar
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query"

# Test multi-parameter
python3 main.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1&artist=2"

# Test metode POST
python3 main.py -u "http://testphp.vulnweb.com/login.php" -m POST

# Atau gunakan versi desktop:
python3 launch_desktop.py
# Lalu masukkan: http://testphp.vulnweb.com/search.php?test=query
```

**2. DVWA (Damn Vulnerable Web Application)**
```bash
# Versi command line
python3 main.py -u "http://www.dvwa.co.uk/vulnerabilities/sqli/?id=1&Submit=Submit"

# Versi desktop - lebih mudah untuk pemula
python3 launch_desktop.py
# Copy paste URL di atas ke field URL
```

**3. OWASP Juice Shop**
```bash
python3 main.py -u "https://juice-shop.herokuapp.com/#/search?q=test"
```

### 🔧 Advanced Test Commands

```bash
# High-performance scan with 10 threads
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query" -t 10

# Extended timeout for slow responses
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query" -T 20

# Save detailed report
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query" -o vuln_report.txt

# Test multiple parameters simultaneously
python3 main.py -u "http://testphp.vulnweb.com/artists.php?artist=1&cat=2&test=3"
```

### 📋 Other Educational Targets

- **WebGoat**: `http://webgoat.cloudapp.net/WebGoat/attack`
- **Google Gruyere**: `https://google-gruyere.appspot.com/`
- **HackThisSite**: `https://www.hackthissite.org/missions/basic/1/`

### ⚠️ Catatan Penting

**Gunakan target ini hanya untuk tujuan edukasi:**
- ✅ **Testing Sah**: Semua target terdaftar dirancang untuk testing keamanan
- ✅ **Tujuan Edukasi**: Sempurna untuk pembelajaran dan validasi alat
- ✅ **Kepatuhan Hukum**: Ini adalah aplikasi yang sengaja dibuat rentan
- ❌ **JANGAN pernah test website nyata** tanpa izin tertulis eksplisit

### 💡 Rekomendasi untuk Pemula:
Jika Anda baru memulai, **disarankan menggunakan versi desktop** karena:
- Antarmuka lebih ramah pengguna
- Tidak perlu mengingat command line options
- Hasil ditampilkan secara visual dan interaktif
- Lebih mudah untuk memahami hasil scanning

## Security Notice

This tool is designed for **authorized security testing only**. Always ensure you have permission before scanning any website or application. Unauthorized scanning may be illegal and violate terms of service.

## Limitations

- Only tests parameters present in the URL (for GET) or provided data (for POST)
- Does not perform advanced SQL injection techniques like union-based or boolean-based blind
- May generate false positives in some cases
- Requires network connectivity to the target

## Contributing

Feel free to submit issues, feature requests, or improvements to the scanner.

## License

This tool is provided for educational and authorized security testing purposes only.
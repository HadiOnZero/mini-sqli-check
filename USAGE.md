# Panduan Penggunaan SQL Injection Scanner

## 🚀 Versi Desktop Futuristik v2.0 - UPDATE BARU!

### Cara Cepat Mulai (Rekomendasi untuk Pemula):
```bash
# Jalankan versi desktop dengan antarmuka cyberpunk
python3 launch_desktop.py

# Atau langsung jalankan GUI futuristik
python3 desktop_scanner.py
```

**Kenapa memilih versi desktop?**
- ✅ Antarmuka ramah pengguna (tidak perlu ingat command)
- ✅ Tampilan futuristik dengan tema gelap dan neon hijau
- ✅ Hasil scan ditampilkan secara visual dan interaktif
- ✅ Cocok untuk pemula yang baru belajar security testing

## Versi Command Line (Untuk Pengguna Advanced)

### 1. Install Dependensi
```bash
pip install -r requirements.txt
```

### 2. Scan Dasar
```bash
python3 main.py -u "http://example.com/page?id=1"
```

### 3. Opsi Scan Lanjutan
```bash
# Test parameter POST
python3 main.py -u "http://example.com/login" -m POST

# Gunakan lebih banyak thread untuk scanning lebih cepat
python3 main.py -u "http://example.com/search?q=test" -t 10

# Simpan laporan detail
python3 main.py -u "http://example.com/page?id=1" -o scan_report.txt

# Timeout kustom untuk server lambat
python3 main.py -u "http://example.com/page?id=1" -T 30
```

## Skenario Penggunaan Umum

### Skenario 1: Testing Form Pencarian (Versi Desktop - MUDAH!)
```bash
# Jalankan GUI futuristik
python3 launch_desktop.py
# Masukkan URL: http://target.com/search?q=test&category=all
# Atur thread: 8
# Klik: INITIATE SCAN
```

### Skenario 1: Testing Form Pencarian (Versi Command Line)
```bash
python3 main.py -u "http://target.com/search?q=test&category=all" -t 8
```

### Skenario 2: Testing Form Login
```bash
# Versi Desktop: Masukkan URL login, pilih method POST, klik scan
# Versi Command Line:
python3 main.py -u "http://target.com/login" -m POST -t 5
```

### Skenario 3: Testing Banyak Parameter
```bash
python3 main.py -u "http://target.com/product?id=1&cat=electronics&sort=price" -t 10
```

### Skenario 4: Scan Komprehensif dengan Laporan
```bash
python3 main.py -u "http://target.com/page?id=1" -t 10 -T 15 -o comprehensive_report.txt
```

## Memahami Output

### Versi Desktop (Tampilan Futuristik):
- **🔴 VULNERABLE**: Parameter ditandai dengan warna merah neon di tabel
- **🟢 SAFE**: Parameter aman ditandai dengan warna hijau neon
- **📊 Statistik Real-time**: Counter VULNERABILITIES/PARAMETERS/PAYLOADS
- **📋 Detail Interaktif**: Klik "View Details" untuk melihat informasi lengkap

### Versi Command Line:

#### Kerentanan Ditemukan
```
[!] VULNERABILITIES FOUND!
Vulnerable Parameters: id, search

Parameter: id
Status: VULNERABLE
Errors Found:
  - Payload: '
    Error: SQL.*syntax.*MySQL
    Response Time: 0.23s
  - Payload: ' OR SLEEP(5)--
    Error: Time-based blind SQL injection (response time > 5s)
    Response Time: 5.12s
```

#### Tidak Ada Kerentanan Ditemukan
```
[+] No SQL injection vulnerabilities detected
```

## Fitur-Fitur Lanjutan

### 1. Multi-threading (Pemrosesan Paralel)
- Gunakan opsi `-t` untuk menentukan jumlah thread
- Direkomendasikan: 5-10 thread untuk kebanyakan skenario
- Semakin banyak thread = scanning lebih cepat tapi beban server lebih berat

**Di Versi Desktop:** Atur melalui spinner "Threads" dengan tampilan neon

### 2. Konfigurasi Timeout
- Gunakan opsi `-T` untuk mengatur timeout request
- Default: 10 detik
- Tingkatkan untuk server lambat atau query kompleks

**Di Versi Desktop:** Atur melalui spinner "Timeout" dengan border hijau neon

### 3. Pemilihan Metode
- Metode GET: Menguji parameter URL
- Metode POST: Menguji parameter data form

**Di Versi Desktop:** Pilih melalui dropdown "Method" dengan tema futuristik

### 4. Generasi Laporan
- Nama file otomatis berbasis timestamp jika tidak ditentukan
- Informasi kerentanan detail
- Waktu response dan pola error

**Di Versi Desktop:** Klik tombol "EXPORT REPORT" dengan gaya cyberpunk

## Kategori Payload (Senjata Testing)

Scanner menguji dengan berbagai tipe payload:

### Versi Desktop:
Akses melalui tab "Payloads" untuk melihat dan mengedit:
- **SQL Injection Payloads**: Arsenal payload dengan syntax highlighting neon
- **Error Patterns**: Pola deteksi dengan tampilan matrix
- **Load Defaults**: Restore payload standar
- **Clear**: Hapus semua payload

### Versi Command Line:

#### Basic Injection
- `'` (single quote)
- `''` (double single quote)
- `' OR '1'='1` (classic OR injection)

#### Union-based
- `1' UNION SELECT NULL--`
- `1' UNION SELECT 1,2,3--`

#### Time-based Blind
- `'; WAITFOR DELAY '0:0:5'--` (MSSQL)
- `' OR SLEEP(5)--` (MySQL)
- `' OR pg_sleep(5)--` (PostgreSQL)

#### Boolean-based
- `1' AND 1=1--` (true condition)
- `1' AND 1=2--` (false condition)

## Deteksi Error (Sistem Keamanan)

Scanner mendeteksi error dari berbagai sistem database:

### MySQL
- `SQL syntax.*MySQL`
- `Warning.*mysql_.*`
- `valid MySQL result`

### PostgreSQL
- `PostgreSQL.*ERROR`
- `Warning.*pg_.*`

### Microsoft SQL Server
- `Driver.* SQL.*Server`
- `OLE DB.* SQL Server`

### Oracle
- `Exception.*Oracle`
- `Oracle error`

### SQLite
- `SQLite.*Driver`
- `Warning.*sqlite_.*`

**Di Versi Desktop:** Semua pola ini dapat dilihat dan diedit melalui tab "Payloads" dengan antarmuka futuristik!

## Praktik Terbaik (Protokol Keamanan)

### 1. Pemilihan Target (Reconnaissance)
- Hanya scan target yang Anda miliki atau punya izin untuk diuji
- Mulai dengan environment non-produksi
- Informasikan stakeholder sebelum scanning

### 2. Strategi Scanning (Tactical Approach)
- Mulai dengan parameter GET dasar
- Test form POST secara terpisah
- Gunakan jumlah thread yang sesuai
- Monitor response server

### 3. Analisis Hasil (Intelligence Analysis)
- Verifikasi temuan secara manual
- Test payload yang berhasil secara manual
- Periksa false positives
- Dokumentasikan semua temuan

### 4. Optimasi Performa (System Tuning)
- Gunakan nilai timeout yang tepat
- Sesuaikan jumlah thread berdasarkan response server
- Scan selama periode low-traffic
- Monitor konektivitas jaringan

### 💡 Tips untuk Pemula:
1. **Mulai dengan Desktop**: Gunakan `python3 launch_desktop.py` untuk pengalaman lebih mudah
2. **Gunakan Target Test Legal**: Praktik dengan situs testphp.vulnweb.com
3. **Mulai Kecil**: Gunakan 3-5 thread di awal
4. **Document Everything**: Simpan semua hasil scan untuk referensi

## Penyelesaian Masalah (System Diagnostics)

### Masalah Umum dan Solusinya

#### 1. Koneksi Timeout (Versi Desktop & Command Line)
```bash
# Tingkatkan timeout
python3 main.py -u "http://slow-server.com/page?id=1" -T 30

# Di Desktop: Atau atur spinner "Timeout" ke nilai lebih tinggi
```

#### 2. Terlalu Banyak Thread
```bash
# Kurangi jumlah thread jika server kelebihan beban
python3 main.py -u "http://target.com/page?id=1" -t 3

# Di Desktop: Turunkan nilai "Threads" di antarmuka
```

#### 3. False Positives (Alarm Palsu)
- Verifikasi temuan secara manual
- Periksa konteks response
- Test dengan payload berbeda
- **Di Desktop**: Klik "View Details" untuk analisis mendalam

#### 4. Parameter Hilang
- Pastikan URL berisi parameter
- Periksa encoding URL
- Verifikasi nama parameter

### Pesan Error dan Solusinya

#### "No parameters found in URL" (Desktop: "Tidak ada parameter yang ditemukan")
- Tambahkan parameter ke URL: `http://site.com/page?id=1&param=value`
- **Di Desktop**: Pastikan URL mengandung tanda `?` dan parameter

#### "Error during scan" (Desktop: "Scan gagal")
- Periksa konektivitas jaringan
- Verifikasi aksesibilitas target
- Periksa format URL
- **Di Desktop**: Cek log terminal untuk detail error

### 🆘 Masalah Desktop Spesifik:

#### Desktop tidak mau start:
```bash
# Install PyQt5 jika belum ada
pip install PyQt5>=5.15.0

# Jalankan dari directory yang benar
cd /path/to/scanner/
python3 launch_desktop.py
```

#### Tampilan tidak normal:
- Pastikan monitor support warna penuh
- Coba restart aplikasi
- Update driver grafis jika perlu

## Contoh Integrasi (Untuk Automation)

### Integrasi Script Bash (Command Line Only)
```bash
#!/bin/bash
# Scan multiple URLs dari file

URL_FILE="targets.txt"
REPORT_DIR="reports"

mkdir -p "$REPORT_DIR"

while IFS= read -r url; do
    echo "Scanning: $url"
    python3 main.py -u "$url" -o "$REPORT_DIR/$(date +%s)_report.txt"
done < "$URL_FILE"
```

### Integrasi Python (Command Line Only)
```python
import subprocess
import json

def scan_target(url, output_file=None):
    cmd = ['python3', 'main.py', '-u', url]
    if output_file:
        cmd.extend(['-o', output_file])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr
```

### ⚠️ Catatan Penting:
**Versi Desktop TIDAK mendukung integrasi script** karena berbasis GUI. Gunakan versi command line untuk:
- Automation
- Batch scanning
- Integrasi dengan tools lain
- Scripting dan scheduling

**Untuk pengalaman visual dan interaktif: Gunakan Desktop**
**Untuk automation dan scripting: Gunakan Command Line**

## Pertimbangan Keamanan (Protokol Etik)

### Persyaratan Legal
- Dapatkan izin tertulis sebelum scanning
- Ikuti praktik pengungkapan yang bertanggung jawab
- Patuhi hukum dan regulasi setempat
- Hormati batasan rate dan resource server

### Pedoman Etika
- Hanya scan target yang sah/berizin
- Minimalisasi dampak terhadap server
- Laporkan temuan secara tepat
- Lindungi data sensitif

### 🎯 Untuk Pemula:
1. **SELALU mulai dengan versi desktop** untuk memahami cara kerja
2. **Gunakan target test legal** (lihat daftar di README)
3. **JANGAN pernah test website produksi** tanpa izin
4. **Document everything**: Simpan semua hasil dan izin

### ⚖️ Tanggung Jawab:
Ingat: Alat ini untuk **testing keamanan yang sah** saja. Kesalahan penggunaan bisa mengakibatkan:
- Tuntutan hukum
- Pelanggaran etik
- Masalah akademik/perorangan

**Scan dengan bijak, scan dengan izin, scan dengan tujuan edukasi!**

## Dukungan dan Update

Untuk masalah, permintaan fitur, atau update:
- Periksa dokumentasi terlebih dahulu
- Test dengan demo scanner
- Verifikasi dependensi terinstall
- Review langkah troubleshooting umum

### 📚 Prioritas Bantuan:
1. **Pemula**: Gunakan versi desktop dulu (`python3 launch_desktop.py`)
2. **Masalah Desktop**: Lihat bagian troubleshooting di DESKTOP_USAGE.md
3. **Masalah Command Line**: Lihat bagian troubleshooting di atas
4. **Masalah Umum**: Cek README.md bagian troubleshooting

### 🔗 Resource Tambahan:
- 📖 [Panduan Desktop Futuristik](DESKTOP_USAGE.md)
- 📋 [Demo Scanner](demo_scanner.py) - Untuk praktik tanpa koneksi internet
- 🧪 [Test Scanner](test_scanner.py) - Untuk verifikasi instalasi

---

**⚠️ PENGINGAT AKHIR**: Alat ini hanya untuk **testing keamanan yang sah**. SELALU pastikan Anda memiliki izin eksplisit sebelum memindai sistem apapun. 

**🎯 Motto**: "Scan dengan bijak, scan dengan izin, scan dengan tujuan edukasi!"

**Selamat mencoba dan stay ethical!** 🚀
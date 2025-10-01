#!/bin/bash

# SQL Injection Scanner C++ - Build Script
# Build script untuk versi desktop C++ dengan tema futuristik

echo "🚀 SQL Injection Scanner - C++ Desktop Builder v2.0"
echo "=================================================="
echo ""

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fungsi untuk menampilkan pesan dengan warna
print_status() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Cek sistem operasi
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*)    MACHINE=Cygwin;;
    MINGW*)     MACHINE=MinGw;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

print_status "Sistem terdeteksi: $MACHINE"

# Cek dependensi
print_header "🔍 Mengecek Dependensi..."
check_dependency() {
    if command -v $1 &> /dev/null; then
        print_success "$1 terinstall ✓"
        return 0
    else
        print_error "$1 tidak ditemukan ✗"
        return 1
    fi
}

# Dependensi utama
DEPS_OK=true

check_dependency cmake || DEPS_OK=false
check_dependency g++ || check_dependency clang++ || DEPS_OK=false
check_dependency make || DEPS_OK=false

if [ "$DEPS_OK" = false ]; then
    print_error "Dependensi utama tidak lengkap!"
    print_status "Install dependensi yang diperlukan:"
    
    case "${MACHINE}" in
        Linux*)
            print_status "Ubuntu/Debian: sudo apt install build-essential cmake qt6-base-dev qt6-tools-dev"
            print_status "CentOS/RHEL: sudo yum install gcc-c++ cmake qt6-qtbase-devel"
            print_status "Arch Linux: sudo pacman -S base-devel cmake qt6-base"
            ;;
        Mac*)
            print_status "macOS: brew install cmake qt@6"
            ;;
        *)
            print_error "Sistem tidak dikenali. Install manual: cmake, g++/clang++, make, Qt6"
            ;;
    esac
    exit 1
fi

# Cek Qt6
print_header "🔍 Mengecek Qt6..."
if pkg-config --exists Qt6Core Qt6Widgets Qt6Network; then
    print_success "Qt6 terinstall ✓"
else
    print_warning "Qt6 tidak ditemukan via pkg-config"
    print_status "Qt6 akan dicoba selama build process"
fi

# Buat directory build
print_header "🏗️  Membuat Directory Build..."
BUILD_DIR="build"
if [ -d "$BUILD_DIR" ]; then
    print_warning "Directory build sudah ada, membersihkan..."
    rm -rf "$BUILD_DIR"
fi
mkdir "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure dengan CMake
print_header "⚙️  Configure dengan CMake..."
print_status "Running: cmake .. -DCMAKE_BUILD_TYPE=Release"

cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_STANDARD=17

if [ $? -ne 0 ]; then
    print_error "CMake configure gagal!"
    print_status "Coba install Qt6 development packages:"
    
    case "${MACHINE}" in
        Linux*)
            print_status "Ubuntu/Debian: sudo apt install qt6-base-dev qt6-tools-dev qt6-network-dev"
            print_status "Fedora: sudo dnf install qt6-qtbase-devel qt6-qtnetwork-devel"
            ;;
        Mac*)
            print_status "macOS: brew install qt@6"
            print_status "Setelah install, pastikan Qt6 ada di PATH"
            ;;
    esac
    exit 1
fi

print_success "CMake configure berhasil! ✓"

# Build aplikasi
print_header "🔨 Build Aplikasi..."
print_status "Building dengan semua core CPU yang tersedia..."

# Deteksi jumlah core
if command -v nproc &> /dev/null; then
    CORES=$(nproc)
elif command -v sysctl &> /dev/null; then
    CORES=$(sysctl -n hw.ncpu)
else
    CORES=4
fi

print_status "Menggunakan $CORES core untuk build"

cmake --build . --config Release --parallel $CORES

if [ $? -ne 0 ]; then
    print_error "Build gagal!"
    print_status "Cek error message di atas untuk detail"
    exit 1
fi

print_success "Build selesai! ✓"

# Cek hasil build
print_header "✅ Verifikasi Hasil Build..."
if [ -f "SQLInjectionScanner" ]; then
    print_success "Executable berhasil dibuat: SQLInjectionScanner ✓"
    print_status "Ukuran file: $(ls -lh SQLInjectionScanner | awk '{print $5}')"
elif [ -f "src/SQLInjectionScanner" ]; then
    print_success "Executable berhasil dibuat: src/SQLInjectionScanner ✓"
    print_status "Ukuran file: $(ls -lh src/SQLInjectionScanner | awk '{print $5}')"
else
    print_error "Executable tidak ditemukan!"
    print_status "Cek directory build untuk hasil compile"
    ls -la
    exit 1
fi

# Test run (opsional)
print_header "🧪 Test Run (Opsional)..."
read -p "Apakah Anda ingin menjalankan test run? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Menjalankan test run..."
    
    if [ -f "SQLInjectionScanner" ]; then
        ./SQLInjectionScanner --help 2>/dev/null || print_warning "Test run selesai (help command tidak tersedia)"
    elif [ -f "src/SQLInjectionScanner" ]; then
        ./src/SQLInjectionScanner --help 2>/dev/null || print_warning "Test run selesai (help command tidak tersedia)"
    fi
fi

# Informasi final
print_header "🎉 BUILD SELESAI!"
echo ""
print_success "SQL Injection Scanner C++ Desktop v2.0 berhasil dibangun!"
echo ""
print_status "Informasi penting:"
print_status "• Executable: SQLInjectionScanner (atau src/SQLInjectionScanner)"
print_status "• Directory build: $(pwd)"
print_status "• Dokumentasi: ../README_CPP.md"
print_status "• Untuk menjalankan: ./SQLInjectionScanner"
echo ""
print_header "🚀 SELAMAT MENGGUNAKAN VERSI DESKTOP C++ FUTURISTIK!"
echo ""
print_status "Tips:"
print_status "• Gunakan target test legal untuk praktik"
print_status "• Mulai dengan thread count rendah (3-5)"
print_status "• Scan dengan izin dan tujuan edukatif"
echo ""
echo -e "${CYAN}Stay ethical, stay futuristic! 🌟${NC}"
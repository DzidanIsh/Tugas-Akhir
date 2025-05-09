#!/bin/bash

# Script Instalasi untuk Sistem Backup dan Restore Web Server
# ------------------------------------------------------

# Fungsi untuk menampilkan pesan error dan keluar
function error_exit {
    echo -e "\e[31m[ERROR] $1\e[0m"
    exit 1
}

# Banner
echo "================================================================="
echo "      INSTALASI SISTEM BACKUP DAN RESTORE ANTI-DEFACEMENT        "
echo "================================================================="
echo ""

# Verifikasi bahwa script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root."
fi

# Periksa apakah git dan python3 terinstall
command -v git >/dev/null 2>&1 || error_exit "Git tidak ditemukan. Silakan install dengan: apt-get install git"
command -v python3 >/dev/null 2>&1 || error_exit "Python3 tidak ditemukan. Silakan install dengan: apt-get install python3"

# Periksa apakah pip3 terinstall
command -v pip3 >/dev/null 2>&1 || {
    echo "Pip3 tidak ditemukan. Menginstall pip3..."
    apt-get update
    apt-get install -y python3-pip || error_exit "Gagal menginstall pip3"
}

# Install dependensi Python yang diperlukan untuk restore.py
echo "Menginstall dependensi Python..."
pip3 install paramiko gitpython requests || error_exit "Gagal menginstall dependensi Python"

# Tentukan direktori untuk backup
echo "Menentukan direktori yang akan di-backup..."
read -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
WEB_DIR=${WEB_DIR:-/var/www/html}

# Verifikasi direktori web server
if [ ! -d "$WEB_DIR" ]; then
    error_exit "Direktori $WEB_DIR tidak ditemukan!"
fi

# Meminta detail server monitoring
echo ""
echo "Konfigurasi Server Monitoring"
echo "----------------------------"
read -p "Masukkan IP Server Monitoring: " MONITOR_IP
read -p "Masukkan Username SSH Server Monitoring: " MONITOR_USER
read -p "Masukkan Path Direktori Backup di Server Monitoring: " BACKUP_DIR

# Membuat dan mengatur password
echo ""
echo "Pengaturan Password Backup dan Restore"
echo "-------------------------------------"
read -sp "Masukkan password untuk backup dan restore: " BACKUP_PASSWORD
echo ""
read -sp "Konfirmasi password: " CONFIRM_PASSWORD
echo ""

if [ "$BACKUP_PASSWORD" != "$CONFIRM_PASSWORD" ]; then
    error_exit "Password tidak cocok!"
fi

# Enkripsi password (Menggunakan base64 sebagai enkripsi sederhana - untuk sistem produksi gunakan enkripsi yang lebih kuat)
ENCODED_PASSWORD=$(echo -n "$BACKUP_PASSWORD" | base64)

# Membuat direktori konfigurasi
CONFIG_DIR="/etc/web-backup"
mkdir -p "$CONFIG_DIR" || error_exit "Gagal membuat direktori konfigurasi $CONFIG_DIR"

# Menyimpan konfigurasi
cat > "$CONFIG_DIR/config.conf" << EOF
WEB_DIR="$WEB_DIR"
MONITOR_IP="$MONITOR_IP"
MONITOR_USER="$MONITOR_USER"
BACKUP_DIR="$BACKUP_DIR"
PASSWORD="$ENCODED_PASSWORD"
EOF

# Atur permission yang aman
chmod 600 "$CONFIG_DIR/config.conf"

# Inisialisasi repository Git di direktori web
echo ""
echo "Mengatur repository Git untuk direktori web..."
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"

# Jika .git sudah ada, jangan reinisialisasi
if [ ! -d ".git" ]; then
    git init || error_exit "Gagal menginisialisasi repository Git"
    git config --local user.email "backup@system.local"
    git config --local user.name "Backup System"
    
    # Tambahkan .gitignore default
    echo "*.log" > .gitignore
    echo "tmp/" >> .gitignore
    
    # Commit awal
    git add .
    git commit -m "Initial backup of web server content" || error_exit "Gagal melakukan commit awal"
fi

# Menyalin script backup dan restore ke lokasi yang tepat
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cp "$SCRIPT_DIR/backup.sh" /usr/local/bin/web-backup || error_exit "Gagal menyalin script backup"
cp "$SCRIPT_DIR/restore.py" /usr/local/bin/web-restore || error_exit "Gagal menyalin script restore"

# Atur permission eksekusi
chmod +x /usr/local/bin/web-backup
chmod +x /usr/local/bin/web-restore

# Konfirmasi apakah pengguna ingin mengatur cron job untuk backup otomatis
echo ""
echo "Pengaturan Backup Otomatis"
echo "-------------------------"
read -p "Apakah Anda ingin mengatur backup otomatis? (y/n): " SETUP_CRON

if [ "$SETUP_CRON" = "y" ] || [ "$SETUP_CRON" = "Y" ]; then
    read -p "Masukkan frekuensi backup (contoh: @daily, @hourly, atau crontab seperti '0 3 * * *'): " CRON_SCHEDULE
    
    # Tambahkan cron job
    (crontab -l 2>/dev/null; echo "$CRON_SCHEDULE /usr/local/bin/web-backup > /var/log/web-backup.log 2>&1") | crontab -
    echo "Backup otomatis telah diatur untuk dijalankan: $CRON_SCHEDULE"
fi

# Mencoba backup pertama
echo ""
echo "Melakukan backup awal untuk pengujian..."
/usr/local/bin/web-backup || {
    echo "Peringatan: Backup awal gagal, tapi instalasi tetap dilanjutkan. Silakan periksa konfigurasi."
}

echo ""
echo "================================================================="
echo "      INSTALASI BERHASIL DISELESAIKAN                           "
echo "================================================================="
echo ""
echo "Script backup tersedia di: /usr/local/bin/web-backup"
echo "Script restore tersedia di: /usr/local/bin/web-restore"
echo "Konfigurasi disimpan di: $CONFIG_DIR/config.conf"
echo ""
echo "Contoh penggunaan:"
echo "  sudo web-backup     # Untuk melakukan backup manual"
echo "  sudo web-restore    # Untuk melakukan restore"
echo ""
echo "Terima kasih telah menggunakan sistem backup dan restore ini." 

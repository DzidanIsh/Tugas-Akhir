#!/bin/bash

# Script Instalasi untuk Sistem Backup dan Restore Web Server
# ------------------------------------------------------

# Fungsi untuk menampilkan pesan error dan keluar
function error_exit {
    echo -e "\e[31m[ERROR] $1\e[0m"
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
function success_msg {
    echo -e "\e[32m[SUCCESS] $1\e[0m"
}

# Fungsi untuk menampilkan pesan info
function info_msg {
    echo -e "\e[34m[INFO] $1\e[0m"
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

# Konfigurasi identitas Git jika belum dikonfigurasi
info_msg "Mengkonfigurasi identitas Git..."

# Tentukan nama pengguna untuk web server
read -p "Masukkan nama pengguna untuk web server (default: webserver): " WEB_USERNAME
WEB_USERNAME=${WEB_USERNAME:-webserver}

# Cek apakah user.email sudah dikonfigurasi global
if ! git config --global user.email >/dev/null 2>&1; then
    git config --global user.email "backup@$WEB_USERNAME.local"
    info_msg "Git user.email dikonfigurasi ke backup@$WEB_USERNAME.local"
fi
# Cek apakah user.name sudah dikonfigurasi global
if ! git config --global user.name >/dev/null 2>&1; then
    git config --global user.name "$WEB_USERNAME Backup System"
    info_msg "Git user.name dikonfigurasi ke $WEB_USERNAME Backup System"
fi

# Periksa apakah pip3 terinstall
command -v pip3 >/dev/null 2>&1 || {
    info_msg "Pip3 tidak ditemukan. Menginstall pip3..."
    apt-get update
    apt-get install -y python3-pip || error_exit "Gagal menginstall pip3"
}

# Install dependensi Python yang diperlukan untuk restore.py
info_msg "Menginstall dependensi Python..."
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
read -p "Masukkan IP Server Monitoring (default: 192.168.92.10): " MONITOR_IP
MONITOR_IP=${MONITOR_IP:-192.168.92.10}
read -p "Masukkan Username SSH Server Monitoring (default: wazuh): " MONITOR_USER
MONITOR_USER=${MONITOR_USER:-wazuh}
read -p "Masukkan Path Direktori Backup di Server Monitoring (default: /var/backup/web): " BACKUP_DIR
BACKUP_DIR=${BACKUP_DIR:-/var/backup/web}

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
info_msg "Mengatur repository Git untuk direktori web..."
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"

# Hapus repository Git sebelumnya jika ada
if [ -d ".git" ]; then
    info_msg "Menghapus repository Git sebelumnya..."
    rm -rf .git
fi

# Inisialisasi repository Git baru
git init || error_exit "Gagal menginisialisasi repository Git"

# Konfigurasi Git lokal untuk repository ini
git config --local user.email "backup@$WEB_USERNAME.local"
git config --local user.name "$WEB_USERNAME Backup System"

# Tambahkan .gitignore default
echo "*.log" > .gitignore
echo "tmp/" >> .gitignore

# Commit awal
info_msg "Melakukan commit awal..."
git add .

git commit -m "Initial backup of web server content" || {
    if [ $? -eq 1 ]; then
        info_msg "Tidak ada perubahan yang perlu di-commit."
    else
        error_exit "Gagal melakukan commit."
    fi
}

# Konfigurasi remote repository untuk backup
info_msg "Mengkonfigurasi remote repository..."
# Hapus remote sebelumnya jika ada
git remote remove monitoring 2>/dev/null
# Tambahkan remote baru dengan format yang benar
git remote add monitoring "$MONITOR_USER@$MONITOR_IP:$BACKUP_DIR" || 
    error_exit "Gagal mengatur remote repository."

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
read -p "Apakah Anda ingin mengatur backup otomatis? (y/n, default: y): " SETUP_CRON
SETUP_CRON=${SETUP_CRON:-y}

if [ "$SETUP_CRON" = "y" ] || [ "$SETUP_CRON" = "Y" ]; then
    read -p "Masukkan frekuensi backup (contoh: @daily, @hourly, atau crontab seperti '0 3 * * *', default: @daily): " CRON_SCHEDULE
    CRON_SCHEDULE=${CRON_SCHEDULE:-@daily}
    
    # Tambahkan cron job
    (crontab -l 2>/dev/null; echo "$CRON_SCHEDULE /usr/local/bin/web-backup > /var/log/web-backup.log 2>&1") | crontab -
    info_msg "Backup otomatis telah diatur untuk dijalankan: $CRON_SCHEDULE"
fi

# Konfigurasi SSH untuk remote repository
echo ""
echo "Konfigurasi SSH untuk Koneksi ke Server Monitoring"
echo "-------------------------------------------------"
info_msg "Mengkonfigurasi SSH untuk koneksi ke server monitoring..."

# Periksa apakah kunci SSH sudah ada
if [ ! -f ~/.ssh/id_rsa ]; then
    info_msg "Membuat kunci SSH baru..."
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -C "backup@$WEB_USERNAME" || 
        error_exit "Gagal membuat kunci SSH"
else
    info_msg "Kunci SSH sudah ada di ~/.ssh/id_rsa"
fi

# Tanya apakah ingin menyalin kunci SSH ke server monitoring
read -p "Apakah Anda ingin menyalin kunci SSH ke server monitoring? (y/n, default: y): " COPY_SSH_KEY
COPY_SSH_KEY=${COPY_SSH_KEY:-y}

if [ "$COPY_SSH_KEY" = "y" ] || [ "$COPY_SSH_KEY" = "Y" ]; then
    info_msg "Mencoba menyalin kunci SSH ke server monitoring ($MONITOR_IP)..."
    # Tambahkan server ke known_hosts tanpa prompting
    ssh-keyscan -H "$MONITOR_IP" >> ~/.ssh/known_hosts 2>/dev/null
    
    # Coba ssh-copy-id
    if ! ssh-copy-id "$MONITOR_USER@$MONITOR_IP"; then
        echo "Gagal menyalin kunci SSH secara otomatis."
        echo "Mohon salin kunci SSH secara manual dengan perintah:"
        echo "ssh-copy-id $MONITOR_USER@$MONITOR_IP"
        echo ""
        echo "Atau salin output berikut ke file authorized_keys di server monitoring:"
        cat ~/.ssh/id_rsa.pub
        echo ""
        read -p "Tekan Enter untuk melanjutkan setelah mengkonfigurasi SSH..."
    else
        success_msg "Kunci SSH berhasil disalin ke server monitoring"
    fi
fi

# Mencoba backup pertama
echo ""
info_msg "Melakukan backup awal untuk pengujian..."
/usr/local/bin/web-backup || {
    echo "Peringatan: Backup awal gagal, tapi instalasi tetap dilanjutkan."
    echo "Pastikan konfigurasi SSH telah benar dan server monitoring siap menerima backup."
    echo "Anda dapat mencoba backup manual dengan perintah: sudo web-backup"
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

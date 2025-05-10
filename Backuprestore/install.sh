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
# Selalu konfigurasi Git global terlebih dahulu
git config --global user.email "backup@webserver"
git config --global user.name "Backup System"
info_msg "Git user.email dikonfigurasi ke backup@webserver"
info_msg "Git user.name dikonfigurasi ke Backup System"

# Periksa apakah ssh-client terinstall
command -v ssh >/dev/null 2>&1 || {
    info_msg "SSH client tidak ditemukan. Menginstall openssh-client..."
    apt-get update
    apt-get install -y openssh-client || error_exit "Gagal menginstall openssh-client"
}

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
info_msg "Menggunakan direktori web server default: /var/www/html"
WEB_DIR="/var/www/html"

# Verifikasi direktori web server
if [ ! -d "$WEB_DIR" ]; then
    error_exit "Direktori $WEB_DIR tidak ditemukan!"
fi

# Menggunakan detail server monitoring yang sudah ditentukan
echo ""
echo "Konfigurasi Server Monitoring"
echo "----------------------------"
MONITOR_IP="192.168.92.10"
MONITOR_USER="wazuh"
BACKUP_DIR="/var/backup/web"
info_msg "Menggunakan server monitoring: $MONITOR_USER@$MONITOR_IP:$BACKUP_DIR"

# Membuat dan mengatur password
echo ""
echo "Pengaturan Password Backup dan Restore"
echo "-------------------------------------"
BACKUP_PASSWORD="backup123"
ENCODED_PASSWORD=$(echo -n "$BACKUP_PASSWORD" | base64)
info_msg "Menggunakan password default untuk backup dan restore"

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

# Hapus repository Git lama jika ada
if [ -d "$WEB_DIR/.git" ]; then
    info_msg "Menghapus repository Git yang sudah ada..."
    rm -rf "$WEB_DIR/.git"
fi

# Masuk ke direktori web
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"

# Inisialisasi Git repository
git init || error_exit "Gagal menginisialisasi repository Git"

# Konfigurasi Git lokal untuk repository ini
git config --local user.email "backup@webserver"
git config --local user.name "Backup System"

# Tambahkan .gitignore default
echo "*.log" > .gitignore
echo "tmp/" >> .gitignore

# Siapkan koneksi SSH ke server monitoring
info_msg "Menyiapkan koneksi SSH ke server monitoring..."

# Buat direktori .ssh jika belum ada
if [ ! -d "/root/.ssh" ]; then
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
fi

# Buat SSH key jika belum ada
if [ ! -f "/root/.ssh/id_rsa" ]; then
    info_msg "Membuat kunci SSH..."
    ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" -C "backup@webserver"
fi

# Tambahkan server monitoring ke known_hosts jika belum ada
if ! ssh-keygen -F "$MONITOR_IP" > /dev/null; then
    info_msg "Menambahkan server monitoring ke known_hosts..."
    ssh-keyscan -H "$MONITOR_IP" >> /root/.ssh/known_hosts 2>/dev/null
fi

# Tampilkan kunci publik agar bisa ditambahkan ke server monitoring
echo ""
echo "PENTING: Tambahkan kunci publik berikut ke server monitoring:"
echo "-------------------------------------------------------------"
cat /root/.ssh/id_rsa.pub
echo "-------------------------------------------------------------"
echo "Jalankan perintah berikut di server monitoring:"
echo "echo '[KUNCI PUBLIK DI ATAS]' >> /home/$MONITOR_USER/.ssh/authorized_keys"
echo ""
echo "Atau jalankan perintah ini dari server web:"
echo "ssh-copy-id $MONITOR_USER@$MONITOR_IP"
echo ""
read -p "Tekan Enter setelah menambahkan kunci publik ke server monitoring..." </dev/tty

# Coba koneksi SSH ke server monitoring
info_msg "Mencoba koneksi SSH ke server monitoring..."
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$MONITOR_USER@$MONITOR_IP" echo "SSH connection successful" > /dev/null; then
    echo "Peringatan: Tidak dapat terhubung ke server monitoring melalui SSH."
    echo "Pastikan kunci publik telah ditambahkan ke authorized_keys di server monitoring."
    echo "Jalankan: ssh-copy-id $MONITOR_USER@$MONITOR_IP"
fi

# Lakukan commit awal
info_msg "Melakukan commit awal..."
git add .
git commit -m "Initial backup of web server content" || {
    if [ $? -eq 1 ]; then
        info_msg "Tidak ada perubahan yang perlu di-commit."
    else
        error_exit "Gagal melakukan commit."
    fi
}

# Atur remote repository
info_msg "Mengatur remote repository..."
git remote rm monitoring 2>/dev/null || true
git remote add monitoring "$MONITOR_USER@$MONITOR_IP:$BACKUP_DIR" || 
    error_exit "Gagal mengatur remote repository."

# Menyalin script backup dan restore ke lokasi yang tepat
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cp "$SCRIPT_DIR/backup.sh" /usr/local/bin/web-backup || error_exit "Gagal menyalin script backup"
cp "$SCRIPT_DIR/restore.py" /usr/local/bin/web-restore || error_exit "Gagal menyalin script restore"

# Atur permission eksekusi
chmod +x /usr/local/bin/web-backup
chmod +x /usr/local/bin/web-restore

# Pengaturan Backup Otomatis
echo ""
echo "Pengaturan Backup Otomatis"
echo "-------------------------"
info_msg "Mengatur backup otomatis harian pada pukul 3 pagi"
CRON_SCHEDULE="0 3 * * *"

# Tambahkan cron job
(crontab -l 2>/dev/null | grep -v "web-backup"; echo "$CRON_SCHEDULE /usr/local/bin/web-backup > /var/log/web-backup.log 2>&1") | crontab -
success_msg "Backup otomatis telah diatur untuk dijalankan: $CRON_SCHEDULE"

# Mencoba backup pertama
echo ""
info_msg "Melakukan backup awal untuk pengujian..."
/usr/local/bin/web-backup || {
    echo "Peringatan: Backup awal gagal, tapi instalasi tetap dilanjutkan."
    echo "Pastikan koneksi SSH ke server monitoring telah dikonfigurasi dengan benar."
    echo "Jalankan: ssh-copy-id $MONITOR_USER@$MONITOR_IP"
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

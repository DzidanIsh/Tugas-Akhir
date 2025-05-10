#!/bin/bash

# Script Perbaikan Koneksi Git untuk Sistem Backup
# -----------------------------------------------

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
echo "      PERBAIKAN KONEKSI GIT UNTUK SISTEM BACKUP                  "
echo "================================================================="
echo ""

# Verifikasi bahwa script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root."
fi

# Memuat konfigurasi
CONFIG_FILE="/etc/web-backup/config.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    error_exit "File konfigurasi tidak ditemukan. Jalankan script instalasi terlebih dahulu."
fi

source "$CONFIG_FILE"

# Verifikasi direktori web server
if [ ! -d "$WEB_DIR" ]; then
    error_exit "Direktori web server $WEB_DIR tidak ditemukan!"
fi

# Masuk ke direktori web server
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"

# Periksa apakah git sudah diinisialisasi
if [ ! -d ".git" ]; then
    error_exit "Repository Git tidak ditemukan di $WEB_DIR. Jalankan script instalasi terlebih dahulu."
fi

# Perbaiki konfigurasi remote
info_msg "Mengkonfigurasi ulang remote repository dengan format yang benar..."

# Hapus remote sebelumnya jika ada
git remote remove monitoring 2>/dev/null

# Tambahkan remote baru dengan format yang benar
git remote add monitoring "$MONITOR_USER@$MONITOR_IP:$BACKUP_DIR" || 
    error_exit "Gagal mengatur remote repository."

# Coba koneksi SSH
info_msg "Memeriksa koneksi SSH ke server monitoring ($MONITOR_IP)..."
if ! ssh -q -o BatchMode=yes -o ConnectTimeout=5 "$MONITOR_USER@$MONITOR_IP" exit; then
    echo "Koneksi SSH gagal. Mencoba melakukan setup SSH..."
    
    # Periksa apakah kunci SSH sudah ada
    if [ ! -f ~/.ssh/id_rsa ]; then
        info_msg "Membuat kunci SSH baru..."
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -C "backup@webserver" || 
            error_exit "Gagal membuat kunci SSH"
    else
        info_msg "Kunci SSH sudah ada di ~/.ssh/id_rsa"
    fi
    
    # Tambahkan server ke known_hosts tanpa prompting
    ssh-keyscan -H "$MONITOR_IP" >> ~/.ssh/known_hosts 2>/dev/null
    
    # Coba ssh-copy-id
    echo "Mencoba menyalin kunci SSH ke server monitoring..."
    if ! ssh-copy-id "$MONITOR_USER@$MONITOR_IP"; then
        echo "Gagal menyalin kunci SSH secara otomatis."
        echo "Mohon salin kunci SSH secara manual dengan perintah:"
        echo "ssh-copy-id $MONITOR_USER@$MONITOR_IP"
        echo ""
        echo "Atau salin output berikut ke file authorized_keys di server monitoring:"
        cat ~/.ssh/id_rsa.pub
        echo ""
        echo "Di server monitoring, jalankan perintah berikut:"
        echo "mkdir -p /home/$MONITOR_USER/.ssh"
        echo "chmod 700 /home/$MONITOR_USER/.ssh"
        echo "tee -a /home/$MONITOR_USER/.ssh/authorized_keys << EOF"
        cat ~/.ssh/id_rsa.pub
        echo "EOF"
        echo "chmod 600 /home/$MONITOR_USER/.ssh/authorized_keys"
        echo "chown -R $MONITOR_USER:$MONITOR_USER /home/$MONITOR_USER/.ssh"
        
        read -p "Tekan Enter untuk melanjutkan setelah mengkonfigurasi SSH..."
        
        # Cek lagi koneksi SSH
        if ! ssh -q -o BatchMode=yes -o ConnectTimeout=5 "$MONITOR_USER@$MONITOR_IP" exit; then
            error_exit "Koneksi SSH masih gagal. Silakan verifikasi konfigurasi SSH secara manual."
        fi
    else
        success_msg "Kunci SSH berhasil disalin ke server monitoring"
    fi
else
    success_msg "Koneksi SSH ke server monitoring berhasil"
fi

# Revalidasi remote repository
info_msg "Memastikan server remote adalah repository Git yang valid..."
if ! git ls-remote --exit-code monitoring &>/dev/null; then
    echo "Repository remote tidak valid."
    echo "Di server monitoring, jalankan perintah berikut untuk memperbaiki repository:"
    echo ""
    echo "sudo su -"
    echo "cd $BACKUP_DIR"
    echo "rm -rf .git"
    echo "git init --bare"
    echo "chown -R $MONITOR_USER:$MONITOR_USER $BACKUP_DIR"
    echo "chmod -R 750 $BACKUP_DIR"
    echo ""
    read -p "Tekan Enter untuk melanjutkan setelah memperbaiki repository di server monitoring..."
else
    success_msg "Repository remote valid"
fi

# Coba push
info_msg "Mencoba melakukan push ke server monitoring..."
if ! git push -u monitoring master; then
    echo "Push gagal. Silakan periksa log untuk detail lebih lanjut."
    echo "Pastikan repository Git di server monitoring sudah diinisialisasi dengan benar."
else
    success_msg "Push ke server monitoring berhasil"
fi

echo ""
echo "================================================================="
echo "      PERBAIKAN KONEKSI GIT SELESAI                             "
echo "================================================================="
echo ""
echo "Jika masih mengalami masalah, silakan jalankan perintah berikut secara manual:"
echo ""
echo "Di server monitoring:"
echo "sudo su -"
echo "cd $BACKUP_DIR"
echo "rm -rf .git"
echo "git init --bare"
echo "chown -R $MONITOR_USER:$MONITOR_USER $BACKUP_DIR"
echo "chmod -R 750 $BACKUP_DIR"
echo ""
echo "Di server web:"
echo "sudo su -"
echo "cd $WEB_DIR"
echo "git remote remove monitoring"
echo "git remote add monitoring $MONITOR_USER@$MONITOR_IP:$BACKUP_DIR"
echo "ssh-copy-id $MONITOR_USER@$MONITOR_IP"
echo "git push -u monitoring master"
echo ""
echo "=================================================================" 

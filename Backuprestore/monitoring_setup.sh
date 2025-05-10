#!/bin/bash

# Script Instalasi untuk Server Monitoring (Backup Repository)
# -------------------------------------------------------------

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
echo "      INSTALASI SERVER MONITORING ANTI-DEFACEMENT               "
echo "================================================================="
echo ""

# Verifikasi bahwa script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root."
fi

# Periksa apakah git terinstall
command -v git >/dev/null 2>&1 || {
    info_msg "Git tidak ditemukan. Menginstall Git..."
    apt-get update
    apt-get install -y git || error_exit "Gagal menginstall Git."
}

# Tentukan direktori untuk menyimpan backup
BACKUP_DIR="/var/backup/web"
info_msg "Menggunakan direktori backup default: $BACKUP_DIR"

# Buat direktori backup jika belum ada
if [ ! -d "$BACKUP_DIR" ]; then
    info_msg "Membuat direktori backup: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR" || error_exit "Gagal membuat direktori $BACKUP_DIR"
fi

# Inisialisasi repository Git kosong di direktori backup
cd "$BACKUP_DIR" || error_exit "Gagal masuk ke direktori $BACKUP_DIR"

# Periksa apakah repository sudah diinisialisasi
if [ -d "$BACKUP_DIR/.git" ]; then
    info_msg "Menghapus repository Git yang sudah ada di $BACKUP_DIR..."
    rm -rf "$BACKUP_DIR/.git"
fi

info_msg "Menginisialisasi repository Git kosong di $BACKUP_DIR..."
git init --bare || error_exit "Gagal menginisialisasi repository Git"

# Membuat pengguna khusus untuk backup (untuk keamanan yang lebih baik)
echo ""
echo "Pengaturan Pengguna Backup"
echo "-------------------------"

# Menggunakan username yang sudah ditentukan
BACKUP_USER="wazuh"
    
# Periksa apakah pengguna sudah ada
if id "$BACKUP_USER" &>/dev/null; then
    info_msg "Pengguna $BACKUP_USER sudah ada."
else
    info_msg "Membuat pengguna $BACKUP_USER..."
    useradd -m -s /bin/bash "$BACKUP_USER" || error_exit "Gagal membuat pengguna $BACKUP_USER"
    
    # Buat password untuk pengguna
    echo "Masukkan password untuk pengguna $BACKUP_USER:"
    passwd "$BACKUP_USER" || error_exit "Gagal mengatur password untuk pengguna $BACKUP_USER"
fi

# Ubah kepemilikan direktori backup
info_msg "Mengubah kepemilikan direktori backup ke pengguna $BACKUP_USER..."
chown -R "$BACKUP_USER":"$BACKUP_USER" "$BACKUP_DIR" || 
    error_exit "Gagal mengubah kepemilikan direktori $BACKUP_DIR"

# Mengatur izin akses
chmod -R 750 "$BACKUP_DIR" || error_exit "Gagal mengatur izin akses direktori $BACKUP_DIR"

# Setup SSH directory
SSH_DIR="/home/$BACKUP_USER/.ssh"
if [ ! -d "$SSH_DIR" ]; then
    info_msg "Membuat direktori SSH untuk pengguna $BACKUP_USER..."
    mkdir -p "$SSH_DIR"
    touch "$SSH_DIR/authorized_keys"
    chmod 700 "$SSH_DIR"
    chmod 600 "$SSH_DIR/authorized_keys"
    chown -R "$BACKUP_USER":"$BACKUP_USER" "$SSH_DIR"
fi

# Tampilkan informasi untuk konfigurasi SSH
echo ""
echo "Pengaturan SSH untuk Server Web"
echo "-------------------------------"
echo "Untuk mengaktifkan koneksi dari server web, Anda perlu:"
echo "1. Menghasilkan kunci SSH di server web:"
echo "   ssh-keygen -t rsa -b 4096 -C \"backup@webserver\""
echo ""
echo "2. Menambahkan kunci publik ke file authorized_keys pengguna $BACKUP_USER di server ini:"
echo "   Di server web, tampilkan kunci publik: cat ~/.ssh/id_rsa.pub"
echo "   Di server ini, tambahkan kunci ke: $SSH_DIR/authorized_keys"
echo ""
echo "Atau, Anda dapat menjalankan perintah berikut di server web:"
echo "   ssh-copy-id $BACKUP_USER@192.168.92.10"

# Konfigurasi Git Hooks untuk Notifikasi (opsional)
echo ""
echo "Konfigurasi Git Hook untuk Notifikasi"
echo "-----------------------------------"
echo "Mengatur notifikasi email default: tidak"

# Membuat direktori hooks jika belum ada
HOOKS_DIR="$BACKUP_DIR/hooks"
if [ ! -d "$HOOKS_DIR" ]; then
    mkdir -p "$HOOKS_DIR"
fi

# Membuat post-receive hook sederhana untuk debugging
cat > "$BACKUP_DIR/hooks/post-receive" << 'EOF'
#!/bin/bash
# Git hook sederhana untuk mencatat penerimaan backup

echo "[$(date)] Backup baru diterima" >> /var/log/backup-receive.log
EOF

# Atur izin untuk script hook
chmod +x "$BACKUP_DIR/hooks/post-receive"
chown "$BACKUP_USER":"$BACKUP_USER" "$BACKUP_DIR/hooks/post-receive"

# Monitoring disk space
echo ""
echo "Monitoring Disk Space"
echo "-------------------"
echo "Mengatur monitoring disk space: ya, dengan threshold default 80%"

# Membuat script monitoring disk space
MONITOR_SCRIPT="/usr/local/bin/monitor-backup-disk.sh"

cat > "$MONITOR_SCRIPT" << 'EOF'
#!/bin/bash

# Konfigurasi
BACKUP_DIR="/var/backup/web"
THRESHOLD="80"
HOSTNAME=$(hostname -f)

# Periksa penggunaan disk
USAGE=$(df -h "$BACKUP_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')

# Jika penggunaan melebihi threshold, kirim notifikasi
if [ "$USAGE" -gt "$THRESHOLD" ]; then
    echo "[$(date)] Peringatan: Penggunaan disk $USAGE% melebihi threshold $THRESHOLD%" >> /var/log/backup-monitor.log
fi
EOF

# Atur izin eksekusi
chmod +x "$MONITOR_SCRIPT"

# Tambahkan tugas cron untuk menjalankan monitoring setiap hari
CRON_ENTRY="0 7 * * * $MONITOR_SCRIPT > /dev/null 2>&1"
(crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT"; echo "$CRON_ENTRY") | crontab -

success_msg "Monitoring disk space untuk direktori backup telah dikonfigurasi."

echo ""
echo "================================================================="
echo "      INSTALASI SERVER MONITORING BERHASIL DISELESAIKAN         "
echo "================================================================="
echo ""
echo "Informasi Konfigurasi:"
echo "---------------------"
echo "Direktori backup: $BACKUP_DIR"
echo "Pengguna backup: $BACKUP_USER"
echo ""
echo "Gunakan informasi berikut saat mengkonfigurasi server web:"
echo "1. IP Server Monitoring: 192.168.92.10"
echo "2. Username SSH: $BACKUP_USER"
echo "3. Path direktori backup: $BACKUP_DIR"
echo ""
echo "Server telah siap untuk menerima backup dari server web."
echo "=================================================================" 

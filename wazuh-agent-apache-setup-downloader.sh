#!/bin/bash
# Script instalasi dan konfigurasi Wazuh Agent untuk server Apache2 via GitHub
# Jalankan sebagai root/sudo

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Variabel
GITHUB_REPO="https://raw.githubusercontent.com/DzidanIsh/Tugas-Akhir/main"
WAZUH_MANAGER_IP=""

# Fungsi log
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cek user root
if [ "$EUID" -ne 0 ]; then
    log_error "Script ini memerlukan akses root. Silakan jalankan dengan sudo."
    exit 1
fi

# Cek apakah server menggunakan Ubuntu
if [ ! -f /etc/lsb-release ] || ! grep -q "Ubuntu" /etc/lsb-release; then
    log_error "Script ini hanya berjalan pada sistem Ubuntu."
    exit 1
fi

# Cek apakah Apache2 terpasang
if ! dpkg -l | grep -q apache2; then
    log_error "Apache2 tidak terpasang. Script ini khusus untuk server Apache2."
    exit 1
fi

# Minta IP Wazuh Manager
while [ -z "$WAZUH_MANAGER_IP" ]; do
    read -p "Masukkan alamat IP Wazuh Manager: " WAZUH_MANAGER_IP
    if [ -z "$WAZUH_MANAGER_IP" ]; then
        log_error "Alamat IP Wazuh Manager wajib diisi."
    fi
done

# Cek komponen yang sudah terinstal
log "Memeriksa komponen yang sudah terinstal..."
WAZUH_INSTALLED=false
FAIL2BAN_INSTALLED=false
AUDITD_INSTALLED=false
JQ_INSTALLED=false
CURL_INSTALLED=false

# Cek status instalasi
if dpkg -l | grep -q wazuh-agent; then
    WAZUH_INSTALLED=true
    log "Wazuh Agent sudah terinstal."
fi

if dpkg -l | grep -q fail2ban; then
    FAIL2BAN_INSTALLED=true
    log "Fail2ban sudah terinstal."
fi

if dpkg -l | grep -q auditd; then
    AUDITD_INSTALLED=true
    log "Auditd sudah terinstal."
fi

if command -v jq &> /dev/null; then
    JQ_INSTALLED=true
    log "JQ sudah terinstal."
fi

if command -v curl &> /dev/null; then
    CURL_INSTALLED=true
    log "Curl sudah terinstal."
else
    log "Menginstal curl..."
    apt-get update && apt-get install -y curl
    CURL_INSTALLED=true
fi

# Membuat direktori temp untuk file download
TEMP_DIR=$(mktemp -d)
log "Membuat direktori sementara: $TEMP_DIR"

# Download file konfigurasi dari GitHub
log "Mendownload file konfigurasi dari GitHub..."
curl -s "$GITHUB_REPO/wazuh-agent-apache-setup.sh" -o "$TEMP_DIR/wazuh-agent-apache-setup.sh"

if [ ! -s "$TEMP_DIR/wazuh-agent-apache-setup.sh" ]; then
    log_error "Gagal mendownload file konfigurasi. Pastikan URL GitHub benar."
    rm -rf "$TEMP_DIR"
    exit 1
fi

log "File konfigurasi berhasil didownload."

# Tambah GPG key dan repository Wazuh jika belum terinstal
if [ "$WAZUH_INSTALLED" = false ]; then
    log "Menambahkan repository Wazuh..."
    if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
        chmod 644 /usr/share/keyrings/wazuh.gpg
    fi
    
    if [ ! -f /etc/apt/sources.list.d/wazuh.list ]; then
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    fi
    
    # Update package list
    log "Memperbarui daftar paket..."
    apt-get update
fi

# Instal paket yang belum terinstal
PACKAGES_TO_INSTALL=""

if [ "$WAZUH_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL wazuh-agent"
fi

if [ "$FAIL2BAN_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL fail2ban"
fi

if [ "$AUDITD_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL auditd"
fi

if [ "$JQ_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL jq"
fi

if [ ! -z "$PACKAGES_TO_INSTALL" ]; then
    log "Menginstal paket yang diperlukan: $PACKAGES_TO_INSTALL"
    apt-get install -y $PACKAGES_TO_INSTALL
    log "Paket yang diperlukan berhasil diinstal."
else
    log "Semua paket yang diperlukan sudah terinstal."
fi

# Konfigurasi fail2ban untuk Apache2
if [ ! -f /etc/fail2ban/jail.d/apache-custom.conf ]; then
    log "Mengkonfigurasi fail2ban untuk Apache2..."
    mkdir -p /etc/fail2ban/jail.d/
    curl -s "$GITHUB_REPO/apache-custom.conf" -o /etc/fail2ban/jail.d/apache-custom.conf
    
    if [ ! -s /etc/fail2ban/jail.d/apache-custom.conf ]; then
        log_warn "Gagal mendownload konfigurasi fail2ban, menggunakan konfigurasi default..."
        cat > /etc/fail2ban/jail.d/apache-custom.conf << 'EOF'
[apache-badhostname]
enabled = true
port = http,https
filter = apache-badhostname
logpath = /var/log/apache2/error.log
maxretry = 2
bantime = 86400
findtime = 3600

[apache-scan]
enabled = true
port = http,https
filter = apache-scan
logpath = /var/log/apache2/access.log
maxretry = 5
bantime = 86400
findtime = 3600

[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3
bantime = 86400
findtime = 3600

[apache-attack]
enabled = true
port = http,https
filter = apache-attack
logpath = /var/log/apache2/access.log
maxretry = 2
bantime = 86400
findtime = 3600
EOF
    fi
    log "Konfigurasi fail2ban berhasil dibuat."
else
    log "Konfigurasi fail2ban untuk Apache2 sudah ada."
fi

# Buat direktori backup jika belum ada
if [ ! -d /var/backups/apache2/www ] || [ ! -d /var/backups/apache2/config ]; then
    log "Membuat direktori backup untuk file web..."
    mkdir -p /var/backups/apache2/www
    mkdir -p /var/backups/apache2/config
    log "Direktori backup berhasil dibuat."
else
    log "Direktori backup sudah ada."
fi

# Buat script backup jika belum ada
if [ ! -f /usr/local/bin/apache2-backup.sh ]; then
    log "Membuat script backup otomatis..."
    curl -s "$GITHUB_REPO/apache2-backup.sh" -o /usr/local/bin/apache2-backup.sh
    
    if [ ! -s /usr/local/bin/apache2-backup.sh ]; then
        log_warn "Gagal mendownload script backup, menggunakan script default..."
        curl -s "$TEMP_DIR/wazuh-agent-apache-setup.sh" | grep -A 30 "cat > /usr/local/bin/apache2-backup.sh" | grep -v "cat" | grep -v "EOF" > /usr/local/bin/apache2-backup.sh
    fi
    
    chmod +x /usr/local/bin/apache2-backup.sh
    log "Script backup berhasil dibuat dan diaktifkan."
else
    log "Script backup sudah ada."
fi

# Cek apakah cron job sudah ada
if ! crontab -l 2>/dev/null | grep -q "apache2-backup.sh"; then
    log "Menambahkan cron job untuk backup otomatis..."
    (crontab -l 2>/dev/null || echo "") | grep -v "apache2-backup.sh" | { cat; echo "0 2 * * * /usr/local/bin/apache2-backup.sh"; } | crontab -
    log "Cron job berhasil ditambahkan."
else
    log "Cron job untuk backup sudah ada."
fi

# Konfigurasi Wazuh Agent
log "Mengkonfigurasi Wazuh Agent..."

# Backup konfigurasi ossec.conf jika belum ada backup
if [ ! -f /var/ossec/etc/ossec.conf.bak ]; then
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
    log "Backup konfigurasi Wazuh Agent berhasil dibuat."
else
    log "Backup konfigurasi Wazuh Agent sudah ada."
fi

# Download file konfigurasi ossec.conf dari GitHub
log "Mendownload konfigurasi Wazuh Agent dari GitHub..."
curl -s "$GITHUB_REPO/ossec_agent.conf" -o "$TEMP_DIR/ossec_agent.conf"

if [ -s "$TEMP_DIR/ossec_agent.conf" ]; then
    # Ganti placeholder IP Manager
    sed -i "s/<address>.*<\/address>/<address>$WAZUH_MANAGER_IP<\/address>/g" "$TEMP_DIR/ossec_agent.conf"
    cp "$TEMP_DIR/ossec_agent.conf" /var/ossec/etc/ossec.conf
    log "Konfigurasi Wazuh Agent berhasil diperbarui."
else
    log_warn "Gagal mendownload konfigurasi Wazuh Agent, mengambil dari script utama..."
    # Ekstrak konfigurasi dari script
    curl -s "$TEMP_DIR/wazuh-agent-apache-setup.sh" | grep -A 70 "cat > /var/ossec/etc/ossec.conf" | grep -v "cat" | grep -v "EOF" > "$TEMP_DIR/extracted_config.conf"
    
    if [ -s "$TEMP_DIR/extracted_config.conf" ]; then
        sed -i "s/\$WAZUH_MANAGER_IP/$WAZUH_MANAGER_IP/g" "$TEMP_DIR/extracted_config.conf"
        cp "$TEMP_DIR/extracted_config.conf" /var/ossec/etc/ossec.conf
        log "Konfigurasi Wazuh Agent berhasil diatur dari script utama."
    else
        log_error "Gagal mengekstrak konfigurasi. Menggunakan konfigurasi default dengan IP Manager yang diperbarui."
        sed -i "s/<address>.*<\/address>/<address>$WAZUH_MANAGER_IP<\/address>/g" /var/ossec/etc/ossec.conf
    fi
fi

# Jalankan backup pertama kali jika belum pernah dijalankan
if [ ! -f /var/backups/apache2/www/www_backup_*.tar.gz ]; then
    log "Menjalankan backup awal..."
    /usr/local/bin/apache2-backup.sh
    log "Backup awal berhasil dilakukan."
else
    log "Backup sudah pernah dilakukan sebelumnya."
fi

# Restart layanan
log "Memulai ulang layanan..."
systemctl restart fail2ban
systemctl restart wazuh-agent
systemctl enable wazuh-agent

# Bersihkan file sementara
log "Membersihkan file sementara..."
rm -rf "$TEMP_DIR"

# Verifikasi instalasi
if systemctl is-active --quiet wazuh-agent; then
    log "Wazuh agent berhasil dikonfigurasi dan berjalan."
else
    log_error "Wazuh agent gagal berjalan. Periksa log dengan 'journalctl -u wazuh-agent'."
fi

if systemctl is-active --quiet fail2ban; then
    log "Fail2ban berhasil dikonfigurasi dan berjalan."
else
    log_error "Fail2ban gagal berjalan. Periksa log dengan 'journalctl -u fail2ban'."
fi

log "============================================================="
log "Konfigurasi selesai! Server Apache2 siap untuk dimonitor."
log "Pastikan koneksi antara agent dan Wazuh Manager ($WAZUH_MANAGER_IP) berjalan."
log "=============================================================" 
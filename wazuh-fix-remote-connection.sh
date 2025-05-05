#!/bin/bash
# Script perbaikan konfigurasi Wazuh Manager untuk masalah "Remoted connection is not configured"
# Jalankan sebagai root/sudo

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

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

# Cek apakah Wazuh terinstal
if ! command -v /var/ossec/bin/wazuh-control &> /dev/null; then
    log_error "Wazuh tidak terinstal. Script ini hanya untuk memperbaiki instalasi Wazuh yang sudah ada."
    exit 1
fi

log "Membuat backup konfigurasi ossec.conf..."
if [ -f /var/ossec/etc/ossec.conf ]; then
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%Y%m%d%H%M%S)
    log "Backup berhasil dibuat."
else
    log_error "File konfigurasi ossec.conf tidak ditemukan."
    exit 1
fi

log "Memeriksa apakah konfigurasi remote sudah ada..."
if grep -q "<remote>" /var/ossec/etc/ossec.conf; then
    log_warn "Konfigurasi remote sudah ada. Memastikan pengaturan sudah benar..."
    
    # Ekstrak blok remote dan tambahkan ke file temporary
    cat > /tmp/remote_block.xml << EOF
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
EOF
    
    # Hapus blok remote yang ada dan tambahkan yang baru setelah blok global
    sed -i '/<remote>/,/<\/remote>/d' /var/ossec/etc/ossec.conf
    sed -i '/<\/global>/a\\n  <!-- Konfigurasi koneksi remote yang diperlukan -->\n  <remote>\n    <connection>secure</connection>\n    <port>1514</port>\n    <protocol>tcp</protocol>\n    <queue_size>131072</queue_size>\n  </remote>' /var/ossec/etc/ossec.conf
    
    log "Konfigurasi remote berhasil diperbarui."
else
    log "Menambahkan konfigurasi remote baru setelah blok global..."
    sed -i '/<\/global>/a\\n  <!-- Konfigurasi koneksi remote yang diperlukan -->\n  <remote>\n    <connection>secure</connection>\n    <port>1514</port>\n    <protocol>tcp</protocol>\n    <queue_size>131072</queue_size>\n  </remote>' /var/ossec/etc/ossec.conf
    log "Konfigurasi remote berhasil ditambahkan."
fi

log "Validasi konfigurasi sebelum restart..."
if /var/ossec/bin/wazuh-control check-config; then
    log "Konfigurasi valid. Memulai ulang Wazuh Manager..."
    systemctl restart wazuh-manager
    
    # Cek status setelah restart
    sleep 3
    if systemctl is-active --quiet wazuh-manager; then
        log "Wazuh Manager berhasil diperbaiki dan berjalan."
    else
        log_error "Wazuh Manager tetap gagal berjalan. Periksa log dengan 'journalctl -u wazuh-manager'."
    fi
else
    log_error "Konfigurasi tidak valid setelah perubahan. Mengembalikan ke konfigurasi asli..."
    mv "/var/ossec/etc/ossec.conf.bak.$(ls -t /var/ossec/etc/ossec.conf.bak.* | head -n1 | cut -d. -f4-)" /var/ossec/etc/ossec.conf
    log_error "Silakan periksa konfigurasi secara manual."
fi

log "============================================================="
log "Proses perbaikan konfigurasi Wazuh Manager selesai"
log "Jika masih mengalami masalah, periksa:"
log "1. Log sistem: journalctl -u wazuh-manager"
log "2. Log Wazuh: tail -f /var/ossec/logs/ossec.log"
log "3. Konfigurasi: less /var/ossec/etc/ossec.conf"
log "=============================================================" 

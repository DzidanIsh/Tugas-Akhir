#!/bin/bash

# Nama: wazuh_restore_response.sh
# Deskripsi: Script untuk menjalankan restore otomatis, containment, dan eradication sebagai respons insiden Wazuh
# Lokasi yang disarankan: /var/ossec/active-response/bin/

# Set logging
LOG_FILE="/var/log/wazuh/active-response/restore.log"
RESTORE_SCRIPT="/usr/local/bin/restore_auto.py"
CONTAINMENT_SCRIPT="/usr/local/bin/wazuh-containment"
ERADICATION_SCRIPT="/usr/local/bin/wazuh-eradication"
CONFIG_FILE="/etc/web-backup/config.conf"
MAINTENANCE_PAGE="/var/www/html/maintenance.html"

# Fungsi logging
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    echo "$1"
}

# Fungsi untuk penanganan error
handle_error() {
    log "[ERROR] $1"
    exit 1
}

# Fungsi untuk mengecek status eksekusi
check_status() {
    if [ $? -eq 0 ]; then
        log "[SUCCESS] $1"
        return 0
    else
        handle_error "$2"
        return 1
    fi
}

# Buat direktori log jika belum ada
LOG_DIR=$(dirname "$LOG_FILE")
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
fi

# Periksa keberadaan script dan file yang diperlukan
if [ ! -f "$RESTORE_SCRIPT" ]; then
    handle_error "restore_auto.py tidak ditemukan di $RESTORE_SCRIPT"
fi

if [ ! -f "$CONTAINMENT_SCRIPT" ]; then
    handle_error "wazuh-containment tidak ditemukan di $CONTAINMENT_SCRIPT"
fi

if [ ! -f "$ERADICATION_SCRIPT" ]; then
    handle_error "wazuh-eradication tidak ditemukan di $ERADICATION_SCRIPT"
fi

if [ ! -f "$MAINTENANCE_PAGE" ]; then
    handle_error "maintenance.html tidak ditemukan di $MAINTENANCE_PAGE"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    handle_error "File konfigurasi tidak ditemukan di $CONFIG_FILE"
fi

# Log awal eksekusi
log "[INFO] Memulai proses response insiden"

# Ekstrak alert data dari argumen
ALERT_DATA="$1"
if [ -z "$ALERT_DATA" ]; then
    handle_error "Data alert tidak ditemukan"
fi

# Jalankan containment
log "[INFO] Memulai proses containment"
echo "$ALERT_DATA" | python3 "$CONTAINMENT_SCRIPT"
check_status "Proses containment berhasil diselesaikan" "Proses containment gagal"

# Jalankan eradication
log "[INFO] Memulai proses eradication"
echo "$ALERT_DATA" | python3 "$ERADICATION_SCRIPT"
check_status "Proses eradication berhasil diselesaikan" "Proses eradication gagal"

# Jalankan restore
log "[INFO] Memulai proses restore otomatis"
python3 "$RESTORE_SCRIPT" --auto --alert --non-root 2>> "$LOG_FILE"
check_status "Proses restore otomatis berhasil diselesaikan" "Proses restore otomatis gagal"

# Log ringkasan
log "[INFO] Ringkasan tindakan yang dilakukan:"
log "1. Containment:"
log "   - Remount filesystem ke read-only"
log "   - Blokir IP penyerang"
log "   - Aktifkan mode maintenance"
log "2. Eradication:"
log "   - Scan file mencurigakan"
log "   - Karantina file terinfeksi"
log "   - Verifikasi integritas file"
log "3. Restore:"
log "   - Restore file yang terpengaruh"
log "   - Verifikasi integritas file"

# Log akhir eksekusi
log "[INFO] Proses response insiden selesai"

exit 0

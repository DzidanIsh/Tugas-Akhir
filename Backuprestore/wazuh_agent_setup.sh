#!/bin/bash

# ========================================================================
# Script Integrasi Wazuh Agent untuk Sistem Anti-Defacement Web Server
# ========================================================================
# Script ini akan mengatur integrasi Wazuh Agent dengan sistem restore otomatis
# ketika terjadi perubahan mencurigakan pada file web server.
# ========================================================================

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/wazuh_agent_setup.log"

# Fungsi untuk menampilkan pesan
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "$(date) - INFO: $1" >> "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$(date) - SUCCESS: $1" >> "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "$(date) - WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$(date) - ERROR: $1" >> "$LOG_FILE"
    exit 1
}

# Verifikasi root
if [ "$EUID" -ne 0 ]; then
    error "Script ini harus dijalankan sebagai root."
fi

# Fungsi untuk memastikan direktori ada
ensure_dir_exists() {
    if [ ! -d "$1" ]; then
        info "Membuat direktori $1"
        mkdir -p "$1" || error "Gagal membuat direktori $1"
    fi
}

# Fungsi untuk memeriksa apakah Wazuh Agent terinstall
check_wazuh_agent_installed() {
    if [ ! -d "/var/ossec" ]; then
        error "Wazuh Agent tidak terinstall. Silakan install Wazuh Agent terlebih dahulu."
    fi
    
    if [ ! -f "/var/ossec/bin/ossec-agentd" ]; then
        error "Instalasi Wazuh Agent tidak lengkap. Silakan periksa instalasi Wazuh."
    fi
    
    info "Wazuh Agent terdeteksi pada sistem"
}

# Fungsi untuk memeriksa apakah sistem anti-defacement terinstall
check_antidefacement_installed() {
    if [ ! -f "/etc/web-backup/config.conf" ]; then
        error "Sistem anti-defacement tidak terinstall atau konfigurasi tidak ditemukan."
    fi
    
    if [ ! -f "/usr/local/bin/web-restore" ]; then
        error "Script restore tidak ditemukan. Silakan periksa instalasi sistem anti-defacement."
    fi
    
    info "Sistem anti-defacement terdeteksi pada sistem"
}

# Fungsi untuk mendapatkan direktori web dari konfigurasi
get_web_dir() {
    WEB_DIR=$(grep "WEB_DIR" /etc/web-backup/config.conf | cut -d'=' -f2 | tr -d '"')
    if [ -z "$WEB_DIR" ]; then
        error "Tidak dapat memperoleh direktori web dari konfigurasi."
    fi
    
    if [ ! -d "$WEB_DIR" ]; then
        error "Direktori web $WEB_DIR tidak ditemukan."
    fi
    
    echo "$WEB_DIR"
}

# Fungsi untuk membuat script active response
create_active_response_script() {
    local script_path="/var/ossec/active-response/bin/web_restore.sh"
    
    info "Membuat script active response di $script_path"
    
    cat > "$script_path" << 'EOF'
#!/bin/bash

# Script Active Response untuk menjalankan restore.py
# Log file
LOG_FILE="/var/log/wazuh-web-restore.log"

# Fungsi log
log() {
    echo "$(date) - $1" >> "$LOG_FILE"
}

# Catat waktu eksekusi dan alert
log "Web defacement terdeteksi - Memulai proses restore"

# Ekstrak data alert jika tersedia
if [ ! -z "$1" ]; then
    log "Alert data: $1"
fi

# Jalankan script restore
/usr/local/bin/web-restore --auto >> "$LOG_FILE" 2>&1

# Catat hasil
if [ $? -eq 0 ]; then
    log "Restore berhasil diselesaikan"
    exit 0
else
    log "Restore gagal"
    exit 1
fi
EOF

    # Buat file dapat dieksekusi
    chmod +x "$script_path"
    success "Script active response berhasil dibuat"
}

# Fungsi untuk menambahkan konfigurasi syscheck
update_syscheck_config() {
    local web_dir="$1"
    local agent_conf="/var/ossec/etc/ossec.conf"
    
    info "Memeriksa konfigurasi syscheck di $agent_conf"
    
    # Periksa apakah direktori web sudah ada dalam konfigurasi syscheck
    if grep -q "<directories.*>$web_dir</directories>" "$agent_conf"; then
        warning "Direktori web sudah ada dalam konfigurasi syscheck. Tidak ada perubahan."
    else
        # Periksa apakah syscheck sudah ada
        if grep -q "<syscheck>" "$agent_conf"; then
            # Tambahkan direktori web ke konfigurasi syscheck yang ada
            info "Menambahkan direktori web ke konfigurasi syscheck yang ada"
            sed -i "/<syscheck>/a \\  <directories check_all=\"yes\" realtime=\"yes\" report_changes=\"yes\">$web_dir</directories>" "$agent_conf"
        else
            # Tambahkan konfigurasi syscheck baru
            info "Menambahkan konfigurasi syscheck baru"
            cat >> "$agent_conf" << EOF

<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">$web_dir</directories>
  <ignore>$web_dir/logs</ignore>
  <ignore>$web_dir/cache</ignore>
  <ignore>$web_dir/tmp</ignore>
  <ignore type="sregex">\.log$|\.tmp$</ignore>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
</syscheck>
EOF
        fi
        
        success "Konfigurasi syscheck berhasil diperbarui"
    fi
}

# Fungsi untuk meminta input dari pengguna tentang pengaturan tambahan
get_user_settings() {
    echo
    echo "==================================================================="
    echo "           PENGATURAN TAMBAHAN INTEGRASI WAZUH AGENT              "
    echo "==================================================================="
    
    # Tanyakan apakah ingin mengabaikan direktori tertentu
    read -p "Apakah ada direktori yang ingin diabaikan dalam pemantauan? (y/n): " ignore_dirs
    if [ "$ignore_dirs" = "y" ] || [ "$ignore_dirs" = "Y" ]; then
        while true; do
            read -p "Masukkan path direktori yang ingin diabaikan (relatif terhadap direktori web) atau ketik 'selesai' untuk mengakhiri: " dir
            if [ "$dir" = "selesai" ]; then
                break
            fi
            
            if [ -n "$dir" ]; then
                # Tambahkan direktori ke pengecualian syscheck
                if [ -d "$WEB_DIR/$dir" ]; then
                    sed -i "/<syscheck>/a \\  <ignore>$WEB_DIR/$dir</ignore>" "/var/ossec/etc/ossec.conf"
                    info "Direktori $WEB_DIR/$dir ditambahkan ke pengecualian"
                else
                    warning "Direktori $WEB_DIR/$dir tidak ditemukan, tetapi tetap ditambahkan ke pengecualian"
                    sed -i "/<syscheck>/a \\  <ignore>$WEB_DIR/$dir</ignore>" "/var/ossec/etc/ossec.conf"
                fi
            fi
        done
    fi
    
    # Tanyakan apakah ada ekstensi file yang ingin diabaikan
    read -p "Apakah ada ekstensi file yang ingin diabaikan dalam pemantauan? (y/n): " ignore_ext
    if [ "$ignore_ext" = "y" ] || [ "$ignore_ext" = "Y" ]; then
        read -p "Masukkan ekstensi file yang ingin diabaikan (pisahkan dengan koma, contoh: log,tmp,bak): " extensions
        if [ -n "$extensions" ]; then
            # Buat pola regex untuk syscheck
            IFS=',' read -ra EXTS <<< "$extensions"
            ext_pattern=""
            for ext in "${EXTS[@]}"; do
                ext_pattern="$ext_pattern\\.$ext$|"
            done
            ext_pattern="${ext_pattern%|}"
            
            sed -i "/<syscheck>/a \\  <ignore type=\"sregex\">$ext_pattern</ignore>" "/var/ossec/etc/ossec.conf"
            info "Ekstensi file yang diabaikan: $extensions"
        fi
    fi
}

# Fungsi untuk restart Wazuh Agent
restart_wazuh_agent() {
    info "Memulai ulang layanan Wazuh Agent"
    
    systemctl restart wazuh-agent || service wazuh-agent restart || /var/ossec/bin/ossec-control restart
    
    if [ $? -eq 0 ]; then
        success "Wazuh Agent berhasil dimulai ulang"
    else
        error "Gagal memulai ulang Wazuh Agent"
    fi
}

# Fungsi untuk menampilkan instruksi tambahan
show_additional_instructions() {
    echo
    echo "==================================================================="
    echo "               SETUP WAZUH AGENT BERHASIL                          "
    echo "==================================================================="
    echo
    echo "Wazuh Agent telah dikonfigurasi untuk memantau perubahan pada direktori web."
    echo
    echo "Langkah selanjutnya:"
    echo "1. Pastikan Wazuh Manager telah dikonfigurasi dengan script wazuh_manager_setup.sh"
    echo "2. Pastikan komunikasi antara Agent dan Manager berjalan dengan baik"
    echo "   - Periksa dengan perintah: sudo /var/ossec/bin/agent_control -l"
    echo
    echo "Info penting:"
    echo "- Script active response dibuat di: /var/ossec/active-response/bin/web_restore.sh"
    echo "- Direktori web yang dipantau: $WEB_DIR"
    echo "- Log aktivitas restore: /var/log/wazuh-web-restore.log"
    echo
    echo "Catatan: Anda harus menjalankan script setup di Wazuh Manager untuk"
    echo "menyelesaikan konfigurasi integrasi ini."
    echo "==================================================================="
}

# Fungsi utama
main() {
    echo "==================================================================="
    echo "        SETUP WAZUH AGENT UNTUK ANTI-DEFACEMENT                    "
    echo "==================================================================="
    echo "Script ini akan mengatur Wazuh Agent untuk integrasi dengan sistem"
    echo "anti-defacement pada server web ini."
    echo "==================================================================="
    
    # Inisialisasi log
    ensure_dir_exists "$(dirname "$LOG_FILE")"
    echo "=== Memulai setup Wazuh Agent $(date) ===" > "$LOG_FILE"
    
    # Verifikasi prasyarat
    check_wazuh_agent_installed
    check_antidefacement_installed
    
    # Dapatkan direktori web dari konfigurasi
    WEB_DIR=$(get_web_dir)
    info "Direktori web terdeteksi: $WEB_DIR"
    
    # Buat script active response
    create_active_response_script
    
    # Perbarui konfigurasi syscheck
    update_syscheck_config "$WEB_DIR"
    
    # Dapatkan pengaturan tambahan dari pengguna
    get_user_settings
    
    # Restart Wazuh Agent
    restart_wazuh_agent
    
    # Tampilkan instruksi tambahan
    show_additional_instructions
    
    success "Setup Wazuh Agent berhasil diselesaikan!"
}

# Jalankan fungsi utama
main
exit 0 

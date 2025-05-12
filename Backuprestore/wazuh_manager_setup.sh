#!/bin/bash

# ========================================================================
# Script Integrasi Wazuh Manager untuk Sistem Anti-Defacement Web Server
# ========================================================================
# Script ini akan mengatur konfigurasi Wazuh Manager untuk menerima dan
# memproses alert dari Wazuh Agent untuk sistem anti-defacement web server.
# ========================================================================

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/wazuh_manager_setup.log"

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

# Fungsi untuk memeriksa apakah Wazuh Manager terinstall
check_wazuh_manager_installed() {
    if [ ! -d "/var/ossec" ]; then
        error "Wazuh Manager tidak terinstall. Silakan install Wazuh Manager terlebih dahulu."
    fi
    
    if [ ! -f "/var/ossec/bin/ossec-remoted" ]; then
        error "Instalasi Wazuh Manager tidak lengkap. Silakan periksa instalasi Wazuh."
    fi
    
    info "Wazuh Manager terdeteksi pada sistem"
}

# Fungsi untuk membuat direktori rules jika belum ada
ensure_rules_dir() {
    local rules_dir="/var/ossec/etc/rules"
    ensure_dir_exists "$rules_dir"
    info "Direktori rules tersedia: $rules_dir"
}

# Fungsi untuk membuat file aturan kustom
create_custom_rules() {
    local rules_file="/var/ossec/etc/rules/web_defacement_rules.xml"
    
    info "Membuat file aturan kustom di $rules_file"
    
    cat > "$rules_file" << 'EOF'
<!-- Aturan Kustom untuk Deteksi Web Defacement -->
<group name="web,defacement,">
  <!-- Rule dasar untuk perubahan file di direktori web -->
  <rule id="100500" level="10">
    <if_group>syscheck</if_group>
    <regex type="pcre2">^/var/www/html|^/srv/www|^/var/www</regex>
    <regex>modified|added</regex>
    <description>Perubahan terdeteksi pada file web</description>
  </rule>
  
  <!-- Rule untuk penambahan file mencurigakan di direktori web -->
  <rule id="100501" level="12" frequency="3" timeframe="300">
    <if_sid>100500</if_sid>
    <regex>\.php$|\.html$|\.js$|\.htaccess$</regex>
    <description>Kemungkinan defacement: Beberapa file web penting dimodifikasi</description>
  </rule>
  
  <!-- Rule untuk perubahan pada file indeks utama -->
  <rule id="100502" level="14">
    <if_sid>100500</if_sid>
    <match>index.php|index.html</match>
    <description>Halaman utama website dimodifikasi - Kemungkinan defacement!</description>
  </rule>
  
  <!-- Rule untuk penambahan file eksekusi skrip berbahaya -->
  <rule id="100503" level="14">
    <if_sid>100500</if_sid>
    <regex>\.php$|\.cgi$|\.pl$</regex>
    <match>added</match>
    <description>File skrip baru ditambahkan ke direktori web - Kemungkinan backdoor!</description>
  </rule>
</group>
EOF

    success "File aturan kustom berhasil dibuat"
}

# Fungsi untuk memperbarui konfigurasi ossec.conf untuk memasukkan file aturan kustom
update_ossec_conf() {
    local manager_conf="/var/ossec/etc/ossec.conf"
    
    info "Memperbarui konfigurasi di $manager_conf"
    
    # Periksa apakah rules_file untuk web_defacement_rules.xml sudah ada
    if grep -q "web_defacement_rules.xml" "$manager_conf"; then
        warning "Konfigurasi untuk web_defacement_rules.xml sudah ada. Tidak ada perubahan."
    else
        # Tambahkan rules_file ke <rules> jika <rules> sudah ada
        if grep -q "<rules>" "$manager_conf"; then
            info "Menambahkan referensi ke web_defacement_rules.xml"
            sed -i "/<\/rules>/i \\  <rule_dir>rules</rule_dir>" "$manager_conf"
        else
            # Jika <rules> tidak ada, tambahkan bagian baru
            info "Membuat bagian <rules> baru dengan referensi ke web_defacement_rules.xml"
            cat >> "$manager_conf" << 'EOF'

<rules>
  <rule_dir>rules</rule_dir>
</rules>
EOF
        fi
        
        success "Konfigurasi ossec.conf berhasil diperbarui"
    fi
}

# Fungsi untuk memperbarui local_decoder.xml jika diperlukan
update_local_decoder() {
    local decoder_file="/var/ossec/etc/local_decoder.xml"
    
    # Periksa apakah file decoder ada
    if [ ! -f "$decoder_file" ]; then
        info "Membuat file local_decoder.xml"
        cat > "$decoder_file" << 'EOF'
<!-- Local Decoders -->
<decoder_list>
  <!-- Decoder untuk mendeteksi perubahan pada file web -->
  <decoder name="web-defacement">
    <prematch>^ossec: File integrity monitoring event</prematch>
    <regex offset="after_prematch">Integrity checksum changed for: '(\S+)'</regex>
    <order>file</order>
  </decoder>
</decoder_list>
EOF
        success "File local_decoder.xml berhasil dibuat"
    else
        info "File local_decoder.xml sudah ada, tidak perlu perubahan"
    fi
}

# Fungsi untuk menambahkan konfigurasi active response untuk agent di manager
add_active_response_config() {
    local shared_conf="/var/ossec/etc/shared/default/agent.conf"
    
    # Pastikan direktori shared ada
    ensure_dir_exists "/var/ossec/etc/shared/default"
    
    info "Menambahkan konfigurasi active response di $shared_conf"
    
    # Periksa apakah file agent.conf sudah ada
    if [ ! -f "$shared_conf" ]; then
        # Buat file baru
        cat > "$shared_conf" << 'EOF'
<agent_config>
  <!-- Active Response configuration for web anti-defacement -->
  <active-response>
    <command>web-restore</command>
    <location>local</location>
    <rules_id>100501,100502,100503</rules_id>
    <timeout>60</timeout>
  </active-response>
</agent_config>
EOF
        success "File agent.conf berhasil dibuat"
    else
        # Periksa apakah konfigurasi active response sudah ada
        if grep -q "<command>web-restore</command>" "$shared_conf"; then
            warning "Konfigurasi active response untuk web-restore sudah ada. Tidak ada perubahan."
        else
            # Tambahkan konfigurasi active response ke file yang sudah ada
            if grep -q "</agent_config>" "$shared_conf"; then
                # Tambahkan sebelum tag penutup
                sed -i "/<\/agent_config>/i \\  <!-- Active Response configuration for web anti-defacement -->\n  <active-response>\n    <command>web-restore</command>\n    <location>local</location>\n    <rules_id>100501,100502,100503</rules_id>\n    <timeout>60</timeout>\n  </active-response>" "$shared_conf"
            else
                # Jika tag penutup tidak ada, tambahkan di akhir file
                cat >> "$shared_conf" << 'EOF'
<agent_config>
  <!-- Active Response configuration for web anti-defacement -->
  <active-response>
    <command>web-restore</command>
    <location>local</location>
    <rules_id>100501,100502,100503</rules_id>
    <timeout>60</timeout>
  </active-response>
</agent_config>
EOF
            fi
            success "Konfigurasi active response berhasil ditambahkan ke agent.conf"
        fi
    fi
}

# Fungsi untuk mendefinisikan command di manager
add_command_definition() {
    local manager_conf="/var/ossec/etc/ossec.conf"
    
    info "Menambahkan definisi command di $manager_conf"
    
    # Periksa apakah definisi command sudah ada
    if grep -q "<command>.*<name>web-restore</name>" "$manager_conf"; then
        warning "Definisi command web-restore sudah ada. Tidak ada perubahan."
    else
        # Tambahkan definisi command
        cat >> "$manager_conf" << 'EOF'

<!-- Command definition for web anti-defacement -->
<command>
  <name>web-restore</name>
  <executable>web_restore.sh</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
EOF
        success "Definisi command berhasil ditambahkan"
    fi
}

# Fungsi untuk meminta input dari pengguna tentang pengaturan tambahan
get_user_settings() {
    echo
    echo "==================================================================="
    echo "           PENGATURAN TAMBAHAN INTEGRASI WAZUH MANAGER            "
    echo "==================================================================="
    
    # Tanyakan apakah ingin mengubah tingkat sensitivitas deteksi
    read -p "Apakah ingin mengubah tingkat sensitivitas deteksi? (y/n): " change_sensitivity
    if [ "$change_sensitivity" = "y" ] || [ "$change_sensitivity" = "Y" ]; then
        while true; do
            read -p "Pilih tingkat sensitivitas (1=rendah, 2=sedang, 3=tinggi) [2]: " sensitivity
            sensitivity=${sensitivity:-2}
            
            if [ "$sensitivity" = "1" ]; then
                # Sensitivitas rendah - tingkatkan ambang batas deteksi
                sed -i 's/<rule id="100501" level="12" frequency="3" timeframe="300">/<rule id="100501" level="12" frequency="5" timeframe="300">/g' "/var/ossec/etc/rules/web_defacement_rules.xml"
                sed -i 's/<rule id="100502" level="14">/<rule id="100502" level="12">/g' "/var/ossec/etc/rules/web_defacement_rules.xml"
                info "Sensitivitas diatur ke RENDAH - mengurangi false positive"
                break
            elif [ "$sensitivity" = "2" ]; then
                # Sensitivitas sedang - gunakan default
                info "Sensitivitas diatur ke SEDANG (default)"
                break
            elif [ "$sensitivity" = "3" ]; then
                # Sensitivitas tinggi - turunkan ambang batas deteksi
                sed -i 's/<rule id="100501" level="12" frequency="3" timeframe="300">/<rule id="100501" level="12" frequency="2" timeframe="300">/g' "/var/ossec/etc/rules/web_defacement_rules.xml"
                sed -i 's/<rule id="100502" level="14">/<rule id="100502" level="15">/g' "/var/ossec/etc/rules/web_defacement_rules.xml"
                info "Sensitivitas diatur ke TINGGI - lebih sensitif terhadap perubahan"
                break
            else
                warning "Pilihan tidak valid, silakan pilih 1, 2, atau 3"
            fi
        done
    fi
    
    # Tanyakan apakah ingin menambahkan email notification
    read -p "Apakah ingin mengaktifkan notifikasi email untuk alert defacement? (y/n): " enable_email
    if [ "$enable_email" = "y" ] || [ "$enable_email" = "Y" ]; then
        read -p "Masukkan alamat email penerima notifikasi: " email_to
        
        if [ -n "$email_to" ]; then
            # Periksa apakah konfigurasi email sudah ada
            if grep -q "<email_notification>yes</email_notification>" "/var/ossec/etc/ossec.conf"; then
                # Perbarui alamat email jika sudah ada
                if grep -q "<email_to>" "/var/ossec/etc/ossec.conf"; then
                    sed -i "s/<email_to>.*<\/email_to>/<email_to>$email_to<\/email_to>/g" "/var/ossec/etc/ossec.conf"
                else
                    sed -i "/<email_notification>yes<\/email_notification>/a \\  <email_to>$email_to</email_to>" "/var/ossec/etc/ossec.conf"
                fi
            else
                # Tambahkan konfigurasi email baru
                cat >> "/var/ossec/etc/ossec.conf" << EOF

<global>
  <email_notification>yes</email_notification>
  <email_to>$email_to</email_to>
  <smtp_server>localhost</smtp_server>
  <email_from>wazuh@$(hostname)</email_from>
  <email_maxperhour>12</email_maxperhour>
</global>
EOF
            fi
            
            info "Notifikasi email berhasil dikonfigurasi ke: $email_to"
            
            # Konfirmasi SMTP server
            read -p "Apakah ingin mengubah SMTP server (default: localhost)? (y/n): " change_smtp
            if [ "$change_smtp" = "y" ] || [ "$change_smtp" = "Y" ]; then
                read -p "Masukkan alamat SMTP server: " smtp_server
                if [ -n "$smtp_server" ]; then
                    sed -i "s/<smtp_server>.*<\/smtp_server>/<smtp_server>$smtp_server<\/smtp_server>/g" "/var/ossec/etc/ossec.conf"
                    info "SMTP server diubah ke: $smtp_server"
                fi
            fi
        fi
    fi
}

# Fungsi untuk restart layanan Wazuh Manager
restart_wazuh_manager() {
    info "Memulai ulang layanan Wazuh Manager"
    
    systemctl restart wazuh-manager || service wazuh-manager restart || /var/ossec/bin/ossec-control restart
    
    if [ $? -eq 0 ]; then
        success "Wazuh Manager berhasil dimulai ulang"
    else
        error "Gagal memulai ulang Wazuh Manager"
    fi
}

# Fungsi untuk menampilkan instruksi tambahan
show_additional_instructions() {
    echo
    echo "==================================================================="
    echo "               SETUP WAZUH MANAGER BERHASIL                        "
    echo "==================================================================="
    echo
    echo "Wazuh Manager telah dikonfigurasi untuk menerima dan memproses alert"
    echo "dari Wazuh Agent terkait dengan deteksi web defacement."
    echo
    echo "Langkah selanjutnya:"
    echo "1. Pastikan Wazuh Agent telah dikonfigurasi dengan script wazuh_agent_setup.sh"
    echo "2. Pastikan komunikasi antara Agent dan Manager berjalan dengan baik"
    echo "   - Periksa dengan perintah: sudo /var/ossec/bin/agent_control -l"
    echo "3. Uji integrasi dengan membuat perubahan pada file web di server agent"
    echo
    echo "Info penting:"
    echo "- Aturan deteksi: ID 100500-100503"
    echo "- File aturan kustom: /var/ossec/etc/rules/web_defacement_rules.xml"
    echo "- Konfigurasi agent: /var/ossec/etc/shared/default/agent.conf"
    echo
    echo "Untuk melihat log alert:"
    echo "- tail -f /var/ossec/logs/alerts/alerts.log"
    echo
    echo "Catatan: Jika Anda mengubah konfigurasi file di /var/ossec/etc/shared,"
    echo "Anda perlu restart agent untuk menerapkan perubahan."
    echo "==================================================================="
}

# Fungsi utama
main() {
    echo "==================================================================="
    echo "        SETUP WAZUH MANAGER UNTUK ANTI-DEFACEMENT                  "
    echo "==================================================================="
    echo "Script ini akan mengatur Wazuh Manager untuk menerima dan memproses"
    echo "alert dari Wazuh Agent terkait dengan deteksi web defacement."
    echo "==================================================================="
    
    # Inisialisasi log
    ensure_dir_exists "$(dirname "$LOG_FILE")"
    echo "=== Memulai setup Wazuh Manager $(date) ===" > "$LOG_FILE"
    
    # Verifikasi prasyarat
    check_wazuh_manager_installed
    
    # Pastikan direktori rules tersedia
    ensure_rules_dir
    
    # Buat file aturan kustom
    create_custom_rules
    
    # Perbarui konfigurasi ossec.conf
    update_ossec_conf
    
    # Perbarui local_decoder.xml jika diperlukan
    update_local_decoder
    
    # Tambahkan konfigurasi active response untuk agent
    add_active_response_config
    
    # Tambahkan definisi command
    add_command_definition
    
    # Dapatkan pengaturan tambahan dari pengguna
    get_user_settings
    
    # Restart Wazuh Manager
    restart_wazuh_manager
    
    # Tampilkan instruksi tambahan
    show_additional_instructions
    
    success "Setup Wazuh Manager berhasil diselesaikan!"
}

# Jalankan fungsi utama
main
exit 0 

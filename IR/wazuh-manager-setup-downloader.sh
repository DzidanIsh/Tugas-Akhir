#!/bin/bash
# Script instalasi dan konfigurasi Wazuh Manager dengan integrasi MISP via GitHub
# Dioptimalkan untuk monitoring server Apache2
# Jalankan sebagai root/sudo

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Variabel
GITHUB_REPO="https://raw.githubusercontent.com/DzidanIsh/Tugas-Akhir/main"
MISP_URL=""
MISP_API_KEY=""

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

# Minta URL MISP
while [ -z "$MISP_URL" ]; do
    read -p "Masukkan URL MISP (contoh: https://misp.example.com): " MISP_URL
    if [ -z "$MISP_URL" ]; then
        log_error "URL MISP wajib diisi."
    fi
done

# Minta API Key MISP
while [ -z "$MISP_API_KEY" ]; do
    read -p "Masukkan API Key MISP: " MISP_API_KEY
    if [ -z "$MISP_API_KEY" ]; then
        log_error "API Key MISP wajib diisi."
    fi
done

# Cek komponen yang sudah terinstal
log "Memeriksa komponen yang sudah terinstal..."
WAZUH_MANAGER_INSTALLED=false
WAZUH_INDEXER_INSTALLED=false
WAZUH_DASHBOARD_INSTALLED=false
PYTHON_PIP_INSTALLED=false
JQ_INSTALLED=false
CURL_INSTALLED=false
REQUESTS_INSTALLED=false

# Cek status instalasi
if dpkg -l | grep -q wazuh-manager; then
    WAZUH_MANAGER_INSTALLED=true
    log "Wazuh Manager sudah terinstal."
fi

if dpkg -l | grep -q wazuh-indexer; then
    WAZUH_INDEXER_INSTALLED=true
    log "Wazuh Indexer sudah terinstal."
fi

if dpkg -l | grep -q wazuh-dashboard; then
    WAZUH_DASHBOARD_INSTALLED=true
    log "Wazuh Dashboard sudah terinstal."
fi

if dpkg -l | grep -q python3-pip; then
    PYTHON_PIP_INSTALLED=true
    log "Python PIP sudah terinstal."
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

if python3 -c "import requests" &> /dev/null; then
    REQUESTS_INSTALLED=true
    log "Python Requests sudah terinstal."
fi

# Membuat direktori temp untuk file download
TEMP_DIR=$(mktemp -d)
log "Membuat direktori sementara: $TEMP_DIR"

# Download file konfigurasi utama dari GitHub
log "Mendownload file konfigurasi dari GitHub..."
curl -s "$GITHUB_REPO/wazuh-manager-setup.sh" -o "$TEMP_DIR/wazuh-manager-setup.sh"

if [ ! -s "$TEMP_DIR/wazuh-manager-setup.sh" ]; then
    log_error "Gagal mendownload file konfigurasi. Pastikan URL GitHub benar."
    rm -rf "$TEMP_DIR"
    exit 1
fi

log "File konfigurasi berhasil didownload."

# Tambah GPG key dan repository Wazuh jika diperlukan
if [ "$WAZUH_MANAGER_INSTALLED" = false ] || [ "$WAZUH_INDEXER_INSTALLED" = false ] || [ "$WAZUH_DASHBOARD_INSTALLED" = false ]; then
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

if [ "$WAZUH_MANAGER_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL wazuh-manager"
fi

if [ "$WAZUH_INDEXER_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL wazuh-indexer"
fi

if [ "$WAZUH_DASHBOARD_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL wazuh-dashboard"
fi

if [ "$PYTHON_PIP_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL python3-pip"
fi

if [ "$JQ_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL jq"
fi

if [ ! -z "$PACKAGES_TO_INSTALL" ]; then
    log "Menginstal paket yang diperlukan: $PACKAGES_TO_INSTALL"
    apt-get install -y $PACKAGES_TO_INSTALL
    log "Paket yang diperlukan berhasil diinstal."
else
    log "Semua paket sistem yang diperlukan sudah terinstal."
fi

# Instal dependensi Python jika belum ada
if [ "$REQUESTS_INSTALLED" = false ]; then
    log "Menginstal modul Python yang diperlukan..."
    pip3 install requests
    log "Modul Python berhasil diinstal."
else
    log "Modul Python yang diperlukan sudah terinstal."
fi

# Cek direktori integrasi dan rules
if [ ! -d /var/ossec/integrations ] || [ ! -d /var/ossec/etc/rules ]; then
    log "Membuat direktori untuk file integrasi dan rules..."
    mkdir -p /var/ossec/integrations
    mkdir -p /var/ossec/etc/rules
    log "Direktori berhasil dibuat."
else
    log "Direktori integrasi dan rules sudah ada."
fi

# Cek apakah script integrasi MISP sudah ada
if [ ! -f /var/ossec/integrations/custom-misp.py ] || grep -q "MISP_URL_PLACEHOLDER" /var/ossec/integrations/custom-misp.py; then
    log "Mendownload script integrasi custom-misp.py dari GitHub..."
    curl -s "$GITHUB_REPO/custom-misp.py" -o /var/ossec/integrations/custom-misp.py
    
    if [ ! -s /var/ossec/integrations/custom-misp.py ]; then
        log_warn "Gagal mendownload script integrasi, mengekstrak dari file konfigurasi utama..."
        curl -s "$TEMP_DIR/wazuh-manager-setup.sh" | grep -A 300 "cat > /var/ossec/integrations/custom-misp.py" | grep -v "cat" | grep -v "EOF" > /var/ossec/integrations/custom-misp.py
    fi
    
    # Ganti placeholder dengan nilai sebenarnya
    sed -i "s|MISP_URL_PLACEHOLDER|$MISP_URL|g" /var/ossec/integrations/custom-misp.py
    sed -i "s|MISP_API_KEY_PLACEHOLDER|$MISP_API_KEY|g" /var/ossec/integrations/custom-misp.py
    log "Script integrasi custom-misp.py berhasil dibuat dengan API key dan URL MISP."
else
    log "Script integrasi MISP sudah ada."
    
    # Update URL dan API Key jika perlu
    if grep -q "MISP_URL_PLACEHOLDER" /var/ossec/integrations/custom-misp.py || grep -q "MISP_API_KEY_PLACEHOLDER" /var/ossec/integrations/custom-misp.py; then
        log "Memperbarui URL dan API Key MISP dalam script..."
        sed -i "s|MISP_URL_PLACEHOLDER|$MISP_URL|g" /var/ossec/integrations/custom-misp.py
        sed -i "s|MISP_API_KEY_PLACEHOLDER|$MISP_API_KEY|g" /var/ossec/integrations/custom-misp.py
        log "URL dan API Key MISP berhasil diperbarui."
    fi
fi

# Cek apakah wrapper script sudah ada
if [ ! -f /var/ossec/integrations/custom-misp ]; then
    log "Mendownload wrapper script custom-misp dari GitHub..."
    curl -s "$GITHUB_REPO/custom-misp" -o /var/ossec/integrations/custom-misp
    
    if [ ! -s /var/ossec/integrations/custom-misp ]; then
        log_warn "Gagal mendownload wrapper script, mengekstrak dari file konfigurasi utama..."
        curl -s "$TEMP_DIR/wazuh-manager-setup.sh" | grep -A 50 "cat > /var/ossec/integrations/custom-misp" | grep -v "cat" | grep -v "EOF" > /var/ossec/integrations/custom-misp
    fi
    
    log "Wrapper script custom-misp berhasil dibuat."
else
    log "Wrapper script custom-misp sudah ada."
fi

# Set izin akses yang benar
log "Mengatur izin akses untuk script integrasi..."
chmod 750 /var/ossec/integrations/custom-misp
chmod 750 /var/ossec/integrations/custom-misp.py
chown root:wazuh /var/ossec/integrations/custom-misp
chown root:wazuh /var/ossec/integrations/custom-misp.py
log "Izin akses berhasil diatur."

# Cek apakah rules MISP sudah ada
if [ ! -f /var/ossec/etc/rules/misp_rules.xml ]; then
    log "Mendownload file rules MISP dari GitHub..."
    curl -s "$GITHUB_REPO/misp_rules.xml" -o /var/ossec/etc/rules/misp_rules.xml
    
    if [ ! -s /var/ossec/etc/rules/misp_rules.xml ]; then
        log_warn "Gagal mendownload file rules MISP, mengekstrak dari file konfigurasi utama..."
        curl -s "$TEMP_DIR/wazuh-manager-setup.sh" | grep -A 100 "cat > /var/ossec/etc/rules/misp_rules.xml" | grep -v "cat" | grep -v "EOF" > /var/ossec/etc/rules/misp_rules.xml
    fi
    
    log "File rules MISP berhasil dibuat."
else
    log "File rules MISP sudah ada."
fi

# Cek direktori active response
if [ ! -d /var/ossec/active-response/bin ]; then
    log "Membuat direktori active response..."
    mkdir -p /var/ossec/active-response/bin
    log "Direktori active response berhasil dibuat."
else
    log "Direktori active response sudah ada."
fi

# Cek apakah script active response sudah ada
if [ ! -f /var/ossec/active-response/bin/active_response.sh ]; then
    log "Mendownload script active response dari GitHub..."
    curl -s "$GITHUB_REPO/active_response.sh" -o /var/ossec/active-response/bin/active_response.sh
    
    if [ ! -s /var/ossec/active-response/bin/active_response.sh ]; then
        log_warn "Gagal mendownload script active response, mengekstrak dari file konfigurasi utama..."
        curl -s "$TEMP_DIR/wazuh-manager-setup.sh" | grep -A 100 "cat > /var/ossec/active-response/bin/active_response.sh" | grep -v "cat" | grep -v "EOF" > /var/ossec/active-response/bin/active_response.sh
    fi
    
    chmod 750 /var/ossec/active-response/bin/active_response.sh
    chown root:wazuh /var/ossec/active-response/bin/active_response.sh
    log "Script active response berhasil dibuat."
else
    log "Script active response sudah ada."
fi

# Cek apakah script fail2ban integration sudah ada
if [ ! -f /var/ossec/active-response/bin/fail2ban-apache.sh ]; then
    log "Mendownload script integrasi fail2ban dari GitHub..."
    curl -s "$GITHUB_REPO/fail2ban-apache.sh" -o /var/ossec/active-response/bin/fail2ban-apache.sh
    
    if [ ! -s /var/ossec/active-response/bin/fail2ban-apache.sh ]; then
        log_warn "Gagal mendownload script integrasi fail2ban, mengekstrak dari file konfigurasi utama..."
        curl -s "$TEMP_DIR/wazuh-manager-setup.sh" | grep -A 100 "cat > /var/ossec/active-response/bin/fail2ban-apache.sh" | grep -v "cat" | grep -v "EOF" > /var/ossec/active-response/bin/fail2ban-apache.sh
    fi
    
    chmod 750 /var/ossec/active-response/bin/fail2ban-apache.sh
    chown root:wazuh /var/ossec/active-response/bin/fail2ban-apache.sh
    log "Script integrasi fail2ban berhasil dibuat."
else
    log "Script integrasi fail2ban sudah ada."
fi

# Cek direktori karantina
if [ ! -d /var/ossec/quarantine ]; then
    log "Membuat direktori karantina..."
    mkdir -p /var/ossec/quarantine
    chmod 750 /var/ossec/quarantine
    chown root:wazuh /var/ossec/quarantine
    log "Direktori karantina berhasil dibuat."
else
    log "Direktori karantina sudah ada."
fi

# Cek konfigurasi ossec.conf
log "Memperbarui konfigurasi ossec.conf..."
if [ -f /var/ossec/etc/ossec.conf ]; then
    # Buat backup jika belum ada
    if [ ! -f /var/ossec/etc/ossec.conf.bak ]; then
        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
        log "Backup konfigurasi ossec.conf berhasil dibuat."
    fi
fi

# Download konfigurasi ossec.conf dari GitHub
log "Mendownload konfigurasi ossec.conf dari GitHub..."
curl -s "$GITHUB_REPO/ossec_manager.conf" -o "$TEMP_DIR/ossec_manager.conf"

if [ -s "$TEMP_DIR/ossec_manager.conf" ]; then
    cp "$TEMP_DIR/ossec_manager.conf" /var/ossec/etc/ossec.conf
    log "Konfigurasi ossec.conf berhasil diperbarui dari GitHub."
else
    log_warn "Gagal mendownload konfigurasi ossec.conf, menggunakan konfigurasi default..."
    # Tambahkan integrasi dan rules ke ossec.conf
    log "Menulis konfigurasi baru ke ossec.conf..."
    cat > /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Konfigurasi integrasi dengan MISP -->
  <integration>
    <name>custom-misp</name>
    <group>apache,web,syscheck</group>
    <alert_format>json</alert_format>
  </integration>

  <!-- Konfigurasi rules -->
  <ruleset>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <include>misp_rules.xml</include>
  </ruleset>

  <!-- Konfigurasi command untuk Active Response -->
  <command>
    <name>misp-block-ip</name>
    <executable>active_response.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <command>
    <name>misp-block-domain</name>
    <executable>active_response.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <command>
    <name>misp-quarantine-file</name>
    <executable>active_response.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <command>
    <name>misp-apache-response</name>
    <executable>active_response.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <command>
    <name>add-to-fail2ban</name>
    <executable>fail2ban-apache.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Active Response untuk memblokir IP berbahaya -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-block-ip</command>
    <location>local</location>
    <rules_id>100623,100628</rules_id>
    <timeout>0</timeout>
  </active-response>

  <!-- Active Response untuk memblokir domain berbahaya -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-block-domain</command>
    <location>local</location>
    <rules_id>100624,100629</rules_id>
    <timeout>0</timeout>
  </active-response>

  <!-- Active Response untuk karantina file berbahaya -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-quarantine-file</command>
    <location>local</location>
    <rules_id>100625,100626,100627</rules_id>
    <timeout>0</timeout>
  </active-response>

  <!-- Active Response untuk perubahan file Apache -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-apache-response</command>
    <location>local</location>
    <rules_id>100630</rules_id>
    <timeout>0</timeout>
  </active-response>

  <!-- Active Response untuk pendeteksian serangan web -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-block-ip</command>
    <location>server</location>
    <level>7</level>
    <rules_group>web_attack</rules_group>
    <timeout>1800</timeout>
  </active-response>

  <!-- Active Response untuk fail2ban -->
  <active-response>
    <disabled>no</disabled>
    <command>add-to-fail2ban</command>
    <location>local</location>
    <rules_group>attack,web_scan</rules_group>
    <timeout>3600</timeout>
  </active-response>
</ossec_config>
EOF
    log "Konfigurasi ossec.conf berhasil dibuat dengan template default."
fi

# Bersihkan file sementara
log "Membersihkan file sementara..."
rm -rf "$TEMP_DIR"

# Restart Wazuh jika sudah terinstal sebelumnya
if systemctl is-active --quiet wazuh-manager; then
    log "Memulai ulang Wazuh Manager..."
    systemctl restart wazuh-manager
    
    # Validasi konfigurasi
    if systemctl is-active --quiet wazuh-manager; then
        log "Wazuh Manager berhasil dikonfigurasi dan berjalan."
    else
        log_error "Wazuh Manager gagal berjalan. Periksa log dengan 'journalctl -u wazuh-manager'."
    fi
else
    log "Wazuh Manager berhasil dikonfigurasi. Jalankan 'systemctl start wazuh-manager' untuk memulai layanan."
fi

log "============================================================="
log "Konfigurasi Wazuh Manager untuk Apache2 monitoring selesai!"
log "URL MISP: $MISP_URL"
log "============================================================="
log "Pastikan untuk meregister dan menghubungkan Wazuh Agent dari server Apache2."
log "Gunakan perintah berikut di Wazuh Manager untuk mendapatkan kunci registrasi:"
log "  /var/ossec/bin/manage_agents -l"
log "=============================================================" 
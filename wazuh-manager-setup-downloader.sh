#!/bin/bash
# Script instalasi dan konfigurasi Wazuh Manager dengan integrasi MISP
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

# Fungsi perbaikan koneksi remote
fix_remote_connection() {
    log "Memperbaiki konfigurasi koneksi remote..."
    
    # Backup konfigurasi jika belum ada
    if [ ! -f /var/ossec/etc/ossec.conf.bak ]; then
        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
        log "Backup konfigurasi dibuat: /var/ossec/etc/ossec.conf.bak"
    fi
    
    # Cek apakah konfigurasi remote sudah ada
    if grep -q "<remote>" /var/ossec/etc/ossec.conf; then
        log_warn "Konfigurasi remote sudah ada. Memastikan pengaturan sudah benar..."
        
        # Hapus blok remote yang ada dan tambahkan yang baru setelah blok global
        sed -i '/<remote>/,/<\/remote>/d' /var/ossec/etc/ossec.conf
        sed -i '/<\/global>/a\\n  <!-- Konfigurasi koneksi remote yang diperlukan -->\n  <remote>\n    <connection>secure</connection>\n    <port>1514</port>\n    <protocol>tcp</protocol>\n    <queue_size>131072</queue_size>\n  </remote>' /var/ossec/etc/ossec.conf
        
        log "Konfigurasi remote berhasil diperbarui."
    else
        log "Menambahkan konfigurasi remote baru setelah blok global..."
        sed -i '/<\/global>/a\\n  <!-- Konfigurasi koneksi remote yang diperlukan -->\n  <remote>\n    <connection>secure</connection>\n    <port>1514</port>\n    <protocol>tcp</protocol>\n    <queue_size>131072</queue_size>\n  </remote>' /var/ossec/etc/ossec.conf
        log "Konfigurasi remote berhasil ditambahkan."
    fi
}

# Cek apakah script dijalankan sebagai root
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
WAZUH_INSTALLED=false

# Cek status instalasi Wazuh Manager
if dpkg -l | grep -q wazuh-manager; then
    WAZUH_INSTALLED=true
    log "Wazuh Manager sudah terinstal."
else
    log "Wazuh Manager belum terinstal."
fi

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
    
    # Instal paket Wazuh
    log "Menginstal Wazuh Manager dan dependensinya..."
    apt-get install -y wazuh-manager python3-pip curl jq
    
    # Instal modul Python yang diperlukan
    log "Menginstal modul Python yang diperlukan..."
    pip3 install requests
fi

# Struktur direktori
log "Menyiapkan struktur direktori..."
mkdir -p /var/ossec/integrations
mkdir -p /var/ossec/etc/rules
mkdir -p /var/ossec/active-response/bin
mkdir -p /var/ossec/quarantine

# Download dan konfigurasi script integrasi MISP
log "Mempersiapkan integrasi MISP..."
curl -s "$GITHUB_REPO/custom-misp.py" -o /var/ossec/integrations/custom-misp.py
curl -s "$GITHUB_REPO/custom-misp" -o /var/ossec/integrations/custom-misp

# Ganti placeholder dengan nilai sebenarnya
sed -i "s|MISP_URL_PLACEHOLDER|$MISP_URL|g" /var/ossec/integrations/custom-misp.py
sed -i "s|MISP_API_KEY_PLACEHOLDER|$MISP_API_KEY|g" /var/ossec/integrations/custom-misp.py

# Set izin akses untuk file integrasi
chmod 750 /var/ossec/integrations/custom-misp
chmod 750 /var/ossec/integrations/custom-misp.py
chown root:wazuh /var/ossec/integrations/custom-misp
chown root:wazuh /var/ossec/integrations/custom-misp.py

# Tambahkan file rules MISP
log "Menambahkan rules MISP..."
curl -s "$GITHUB_REPO/misp_rules.xml" -o /var/ossec/etc/rules/misp_rules.xml

# Persiapkan active response
log "Menyiapkan Active Response..."
curl -s "$GITHUB_REPO/active_response.sh" -o /var/ossec/active-response/bin/active_response.sh
curl -s "$GITHUB_REPO/fail2ban-apache.sh" -o /var/ossec/active-response/bin/fail2ban-apache.sh

# Set izin akses untuk file active response
chmod 750 /var/ossec/active-response/bin/active_response.sh
chmod 750 /var/ossec/active-response/bin/fail2ban-apache.sh
chown root:wazuh /var/ossec/active-response/bin/active_response.sh
chown root:wazuh /var/ossec/active-response/bin/fail2ban-apache.sh
chmod 750 /var/ossec/quarantine
chown root:wazuh /var/ossec/quarantine

# Buat atau update konfigurasi ossec.conf
log "Memperbarui konfigurasi ossec.conf..."

# Backup konfigurasi jika ada
if [ -f /var/ossec/etc/ossec.conf ]; then
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
    log "Backup konfigurasi ossec.conf berhasil dibuat."
fi

# Membuat konfigurasi baru
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

  <!-- Konfigurasi koneksi remote yang diperlukan -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
  
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

# Periksa apakah ada masalah dengan koneksi remote
fix_remote_connection

# Validasi konfigurasi sebelum restart
log "Validasi konfigurasi Wazuh Manager..."
if /var/ossec/bin/wazuh-control check-config; then
    log "Konfigurasi valid, memulai Wazuh Manager..."
    systemctl restart wazuh-manager
    
    # Validasi status
    sleep 3
    if systemctl is-active --quiet wazuh-manager; then
        log "Wazuh Manager berhasil dikonfigurasi dan berjalan."
    else
        log_error "Wazuh Manager gagal berjalan. Periksa log dengan 'journalctl -u wazuh-manager'."
    fi
else
    log_error "Konfigurasi Wazuh tidak valid. Periksa kesalahan di atas dan perbaiki konfigurasi."
    log_error "Gunakan 'less /var/ossec/logs/ossec.log' untuk informasi lebih detail."
fi

log "============================================================="
log "Konfigurasi Wazuh Manager untuk Apache2 monitoring selesai!"
log "URL MISP: $MISP_URL"
log "============================================================="
log "Pastikan untuk meregister dan menghubungkan Wazuh Agent dari server Apache2."
log "Gunakan perintah berikut di Wazuh Manager untuk mendapatkan kunci registrasi:"
log "  /var/ossec/bin/manage_agents -l"
log "=============================================================" 
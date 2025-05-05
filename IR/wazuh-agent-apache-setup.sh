#!/bin/bash
# Script instalasi dan konfigurasi Wazuh Agent untuk server Apache2
# Jalankan sebagai root/sudo

set -e

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

# Cek apakah server menggunakan Ubuntu
if [ ! -f /etc/lsb-release ] || ! grep -q "Ubuntu" /etc/lsb-release; then
    log_error "Script ini hanya berjalan pada sistem Ubuntu."
    exit 1
fi

# Cek versi Ubuntu
source /etc/lsb-release
if [ "$DISTRIB_RELEASE" != "22.04" ]; then
    log_warn "Script ini dioptimalkan untuk Ubuntu 22.04. Anda menggunakan versi: $DISTRIB_RELEASE"
    read -p "Tetap lanjutkan? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Cek apakah Apache2 terpasang
if ! dpkg -l | grep -q apache2; then
    log_error "Apache2 tidak terpasang. Script ini khusus untuk server Apache2."
    exit 1
fi

# Parameter untuk konfigurasi
WAZUH_MANAGER_IP=""

# Minta IP Wazuh Manager
while [ -z "$WAZUH_MANAGER_IP" ]; do
    read -p "Masukkan alamat IP Wazuh Manager: " WAZUH_MANAGER_IP
    if [ -z "$WAZUH_MANAGER_IP" ]; then
        log_error "Alamat IP Wazuh Manager wajib diisi."
    fi
done

# Cek komponen yang sudah terinstal
WAZUH_INSTALLED=false
FAIL2BAN_INSTALLED=false
AUDITD_INSTALLED=false
JQ_INSTALLED=false

# Cek status instalasi Wazuh Agent
if dpkg -l | grep -q wazuh-agent; then
    WAZUH_INSTALLED=true
    log "Wazuh Agent sudah terinstal. Melewati langkah instalasi."
fi

# Cek status instalasi fail2ban
if dpkg -l | grep -q fail2ban; then
    FAIL2BAN_INSTALLED=true
    log "Fail2ban sudah terinstal. Melewati langkah instalasi fail2ban."
fi

# Cek status instalasi auditd
if dpkg -l | grep -q auditd; then
    AUDITD_INSTALLED=true
    log "Auditd sudah terinstal. Melewati langkah instalasi auditd."
fi

# Cek status instalasi jq
if command -v jq &> /dev/null; then
    JQ_INSTALLED=true
    log "JQ sudah terinstal. Melewati langkah instalasi jq."
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
fi

# Instal paket yang belum terinstal
if [ "$WAZUH_INSTALLED" = false ] || [ "$FAIL2BAN_INSTALLED" = false ] || [ "$AUDITD_INSTALLED" = false ] || [ "$JQ_INSTALLED" = false ]; then
    log "Menginstal paket yang diperlukan..."
    
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
        apt-get install -y $PACKAGES_TO_INSTALL
        log "Paket yang diperlukan berhasil diinstal."
    fi
else
    log "Semua paket yang diperlukan sudah terinstal."
fi

# Konfigurasi fail2ban untuk Apache2
if [ ! -f /etc/fail2ban/jail.d/apache-custom.conf ]; then
    log "Mengkonfigurasi fail2ban untuk Apache2..."
    mkdir -p /etc/fail2ban/jail.d/
    cat > /etc/fail2ban/jail.d/apache-custom.conf << EOF
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
    log "Konfigurasi fail2ban berhasil dibuat."
else
    log "Konfigurasi fail2ban untuk Apache2 sudah ada."
fi

# Buat direktori backup untuk file web jika belum ada
if [ ! -d /var/backups/apache2/www ] || [ ! -d /var/backups/apache2/config ]; then
    log "Membuat direktori backup untuk file web..."
    mkdir -p /var/backups/apache2/www
    mkdir -p /var/backups/apache2/config
    log "Direktori backup berhasil dibuat."
else
    log "Direktori backup sudah ada."
fi

# Buat script backup untuk file penting jika belum ada
if [ ! -f /usr/local/bin/apache2-backup.sh ]; then
    log "Membuat script backup otomatis untuk file web..."
    cat > /usr/local/bin/apache2-backup.sh << 'EOF'
#!/bin/bash
# Script untuk backup direktori web dan konfigurasi Apache2

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
WWW_BACKUP_DIR="/var/backups/apache2/www"
CONFIG_BACKUP_DIR="/var/backups/apache2/config"

# Backup direktori www
tar -czf "${WWW_BACKUP_DIR}/www_backup_${TIMESTAMP}.tar.gz" /var/www 2>/dev/null || true

# Backup direktori config Apache2
tar -czf "${CONFIG_BACKUP_DIR}/apache2_config_${TIMESTAMP}.tar.gz" /etc/apache2 2>/dev/null || true

# Hapus backup lama (lebih dari 7 hari)
find ${WWW_BACKUP_DIR} -name "www_backup_*.tar.gz" -type f -mtime +7 -delete
find ${CONFIG_BACKUP_DIR} -name "apache2_config_*.tar.gz" -type f -mtime +7 -delete

# Buat copy file konfigurasi utama
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.orig 2>/dev/null || true

# Backup file penting di /var/www dengan ekstensi .orig
find /var/www -type f -name "*.php" -exec cp {} {}.orig \; 2>/dev/null || true
find /etc/apache2 -type f -name "*.conf" -exec cp {} {}.orig \; 2>/dev/null || true
EOF

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

# Periksa apakah IP Manager sudah diatur dengan benar
if grep -q "$WAZUH_MANAGER_IP" /var/ossec/etc/ossec.conf; then
    log "IP Wazuh Manager sudah dikonfigurasi dengan benar."
else
    log "Memperbarui IP Wazuh Manager dalam konfigurasi..."
    sed -i "s/<address>.*<\/address>/<address>$WAZUH_MANAGER_IP<\/address>/g" /var/ossec/etc/ossec.conf
fi

# Konfigurasi Wazuh Agent untuk Apache2
log "Menyesuaikan konfigurasi Wazuh untuk Apache2..."
cat > /var/ossec/etc/ossec.conf << EOF
<ossec_config>
  <client>
    <server>
      <address>$WAZUH_MANAGER_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu22, apache</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <!-- Monitoring direktori web server Apache2 -->
    <directories check_all="yes" realtime="yes" report_changes="yes">/var/www/html</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/apache2</directories>
    <directories check_all="yes" realtime="yes">/usr/lib/apache2/modules</directories>
    
    <!-- File konfigurasi penting -->
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/php</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssl/certs</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssl/private</directories>
    
    <!-- Pengecualian untuk file yang sering berubah -->
    <ignore>/var/www/html/temp</ignore>
    <ignore>/var/www/html/cache</ignore>
    <ignore>/var/log/apache2/access.log</ignore>
    <ignore type="sregex">\.log$|\.tmp$|\.cache$</ignore>
    
    <!-- Opsi FIM lanjutan -->
    <nodiff>/etc/ssl/private.key</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
  </syscheck>

  <!-- Log monitoring -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>
</ossec_config>
EOF
log "Konfigurasi Wazuh Agent untuk Apache2 berhasil diatur."

# Jalankan backup pertama kali jika belum pernah dijalankan
if [ ! -f /var/backups/apache2/www/www_backup_*.tar.gz ]; then
    log "Menjalankan backup awal..."
    /usr/local/bin/apache2-backup.sh
    log "Backup awal berhasil dilakukan."
else
    log "Backup sudah pernah dilakukan sebelumnya."
fi

# Restart fail2ban
log "Memulai ulang fail2ban..."
systemctl restart fail2ban

# Restart Wazuh agent
log "Memulai ulang Wazuh agent..."
systemctl restart wazuh-agent
systemctl enable wazuh-agent

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
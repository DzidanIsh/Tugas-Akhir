# Integrasi Wazuh-MISP untuk Deteksi IoC

Sistem ini mengintegrasikan Wazuh dengan MISP (Malware Information Sharing Platform) untuk meningkatkan kemampuan deteksi Indicator of Compromise (IoC) dan incident response. Sistem ini memanfaatkan File Integrity Monitoring (FIM) Wazuh untuk mendeteksi perubahan file yang mencurigakan dan mengintegrasikannya dengan MISP untuk menganalisis apakah file tersebut berbahaya.

## Komponen Sistem

Sistem integrasi ini terdiri dari beberapa komponen utama:

1. **Wazuh Server**: Bertanggung jawab untuk mengumpulkan dan menganalisis data dari agen.
2. **Wazuh Agent**: Dipasang pada endpoint untuk melakukan monitoring aktivitas sistem dan file.
3. **MISP Server**: Platform pertukaran informasi ancaman yang menyimpan database IoC.
4. **Modul Integrasi**: Script yang menghubungkan Wazuh dengan MISP API.
5. **Rule Detection**: Aturan untuk mendeteksi dan mengategorikan ancaman.

## Arsitektur Sistem

Arsitektur integrasi Wazuh-MISP adalah sebagai berikut:

```
+----------------+        +-----------------+        +----------------+
| Wazuh Agent    |------->| Wazuh Manager   |------->| MISP Server    |
| (FIM/Sysmon)   |        | (custom-misp.py)|        | (IoC Database) |
+----------------+        +-----------------+        +----------------+
                                  |
                                  v
                          +-----------------+
                          | Wazuh Dashboard |
                          | (Alert Display) |
                          +-----------------+
```

## Cara Kerja Sistem

1. **Deteksi Perubahan**: Wazuh menggunakan FIM untuk mendeteksi perubahan file dan direktori, serta Sysmon untuk mendeteksi aktivitas pada sistem operasi Windows.

2. **Ekstraksi IoC**: Ketika perubahan terdeteksi, Wazuh mengekstrak indikator yang relevan seperti hash file, alamat IP, atau domain.

3. **Integrasi MISP**: Modul integrasi `custom-misp.py` mengirim indikator tersebut ke MISP melalui API.

4. **Analisis Ancaman**: MISP memeriksa apakah indikator tersebut cocok dengan database ancaman yang diketahui.

5. **Pelaporan**: Jika terdeteksi ancaman, Wazuh menghasilkan alert dengan tingkat keparahan yang sesuai.

6. **Respon**: Berdasarkan alert, tim keamanan dapat melakukan tindakan respons insiden.

## Komponen Konfigurasi

### 1. custom-misp.py
Script Python yang mengintegrasikan Wazuh dengan MISP API untuk analisis indikator. [Lihat kode](https://github.com/DzidanIsh/Tugas-Akhir/blob/main/custom-misp.py)

### 2. custom-misp
Wrapper script untuk menjalankan `custom-misp.py`. [Lihat kode](https://github.com/DzidanIsh/Tugas-Akhir/blob/main/custom-misp)

### 3. misp_rules.xml
Berisi aturan khusus untuk mendeteksi dan mengklasifikasikan alert terkait MISP. [Lihat kode](https://github.com/DzidanIsh/Tugas-Akhir/blob/main/misp_rules.xml)

### 4. active_response.sh
Script untuk melakukan tindakan otomatis berdasarkan alert yang terdeteksi. [Lihat kode](https://github.com/DzidanIsh/Tugas-Akhir/blob/main/active_response.sh)

### 5. fail2ban-apache.sh
Script untuk mengintegrasikan Wazuh dengan fail2ban untuk melindungi server Apache. [Lihat kode](https://github.com/DzidanIsh/Tugas-Akhir/blob/main/fail2ban-apache.sh)

## Instalasi dan Konfigurasi

### Prasyarat

- Server Ubuntu (direkomendasikan Ubuntu 20.04 LTS atau lebih baru)
- Akses root/sudo
- Koneksi internet yang stabil
- MISP Server dengan API key

### Instalasi Wazuh Manager

Script instalasi telah disederhanakan untuk mempermudah proses setup:

1. **Download Script Instalasi**:
```bash
curl -O https://raw.githubusercontent.com/DzidanIsh/Tugas-Akhir/main/wazuh-manager-setup-downloader.sh
```

2. **Berikan Izin Eksekusi**:
```bash
chmod +x wazuh-manager-setup-downloader.sh
```

3. **Jalankan Script Instalasi**:
```bash
sudo ./wazuh-manager-setup-downloader.sh
```

4. **Masukkan Informasi yang Diminta**:
   - URL MISP (contoh: https://misp.example.com)
   - API Key MISP

Script akan secara otomatis:
- Menginstal dan mengkonfigurasi Wazuh Manager
- Menyiapkan integrasi dengan MISP
- Mengkonfigurasi active response dan fail2ban
- Memperbaiki masalah konfigurasi yang umum terjadi (termasuk koneksi remote)

### Instalasi Wazuh Agent

Untuk menginstal Wazuh Agent di server yang ingin dimonitor:

1. **Download Script Instalasi Agent**:
```bash
curl -O https://raw.githubusercontent.com/DzidanIsh/Tugas-Akhir/main/wazuh-agent-apache-setup-downloader.sh
```

2. **Berikan Izin Eksekusi**:
```bash
chmod +x wazuh-agent-apache-setup-downloader.sh
```

3. **Jalankan Script Instalasi**:
```bash
sudo ./wazuh-agent-apache-setup-downloader.sh
```

4. **Masukkan Alamat IP Wazuh Manager**

### Registrasi Agent ke Manager

1. Di Wazuh Manager, dapatkan kunci registrasi:
```bash
sudo /var/ossec/bin/manage_agents -l
```

2. Di server Agent, registrasikan agent:
```bash
sudo /var/ossec/bin/manage_agents -i
```

3. Masukkan kunci registrasi yang dihasilkan oleh Manager

## Verifikasi Instalasi

### Cek Status Layanan
```bash
sudo systemctl status wazuh-manager  # Di Wazuh Manager
sudo systemctl status wazuh-agent    # Di Agent
```

### Cek Konektivitas
```bash
sudo /var/ossec/bin/agent_control -l  # Di Wazuh Manager
```

## Pemecahan Masalah

### 1. Masalah pada Wazuh Manager

Jika Wazuh Manager tidak berjalan dengan benar:

```bash
# Periksa log
sudo journalctl -u wazuh-manager -f

# Periksa konfigurasi
sudo /var/ossec/bin/wazuh-control check-config

# Periksa status detail
sudo /var/ossec/bin/wazuh-control status
```

### 2. Masalah pada Wazuh Agent

Jika Agent tidak terhubung dengan Manager:

```bash
# Periksa log agent
sudo journalctl -u wazuh-agent -f

# Periksa status agent
sudo /var/ossec/bin/wazuh-control status

# Periksa koneksi jaringan
sudo netstat -tulpn | grep ossec
```

### 3. Masalah Integrasi MISP

Jika tidak ada alert MISP:

- Periksa URL dan API key di `/var/ossec/integrations/custom-misp.py`
- Verifikasi konektivitas ke server MISP
- Periksa log di `/var/ossec/logs/ossec.log`

## Fitur yang Tersedia

1. **Monitoring File Integrity**: Mendeteksi perubahan pada file sistem
2. **Integrasi MISP**: Verifikasi IoC dari database MISP
3. **Active Response**: Tindakan otomatis berdasarkan alert
4. **Fail2ban Integration**: Blokir IP yang mencoba melakukan serangan
5. **Apache Monitoring**: Monitoring khusus untuk server web Apache
6. **Karantina File**: Mengisolasi file yang terdeteksi berbahaya

## Keamanan dan Best Practices

1. Pastikan port 1514 (untuk koneksi agent-manager) dan 1515 (untuk registrasi) terbuka dan aman
2. Backup konfigurasi secara reguler sebelum melakukan perubahan
3. Update Wazuh dan komponen sistem secara berkala
4. Gunakan HTTPS untuk komunikasi dengan MISP
5. Batasi akses ke dashboard Wazuh dengan otentikasi yang kuat

## Referensi

- [Dokumentasi Wazuh](https://documentation.wazuh.com/)
- [Dokumentasi MISP](https://www.misp-project.org/documentation/)
- [GitHub Repository](https://github.com/DzidanIsh/Tugas-Akhir) 

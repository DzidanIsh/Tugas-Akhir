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

## File Konfigurasi

### 1. custom-misp.py

Script Python yang mengintegrasikan Wazuh dengan MISP API. Script ini mengambil indikator dari alert Wazuh dan mengirimkannya ke MISP untuk dianalisis.

### 2. custom-misp

Wrapper script untuk menjalankan `custom-misp.py`.

### 3. misp_rules.xml

Berisi aturan khusus untuk mendeteksi dan mengklasifikasikan alert terkait MISP.

### 4. ossec_conf_example.xml

Contoh konfigurasi `ossec.conf` untuk mengaktifkan integrasi dengan MISP dan FIM.

## Instalasi dan Konfigurasi

### Prasyarat

- Wazuh Server (versi 4.x atau lebih tinggi)
- Wazuh Agent pada endpoint yang ingin dimonitor
- MISP Server dengan API key
- Python 3.x dengan modul requests

### Langkah Instalasi

1. **Siapkan MISP Server**:
   - Pastikan MISP server berjalan dan dapat diakses.
   - Buat API key di MISP untuk akses dari Wazuh.

2. **Konfigurasi Wazuh Manager**:
   - Letakkan file `custom-misp.py` dan `custom-misp` di direktori `/var/ossec/integrations/`.
   - Ubah URL dan API key di `custom-misp.py` untuk mengarah ke MISP server Anda.
   - Berikan izin eksekusi: `chmod 750 custom-misp custom-misp.py`.
   - Ubah kepemilikan file: `chown root:wazuh custom-misp custom-misp.py`.

3. **Tambahkan Aturan MISP**:
   - Letakkan file `misp_rules.xml` di direktori `/var/ossec/etc/rules/`.
   - Pastikan aturan dimuat dengan menambahkan `<include>misp_rules.xml</include>` di `ossec.conf`.

4. **Update ossec.conf**:
   - Tambahkan blok integrasi ke `/var/ossec/etc/ossec.conf` berdasarkan contoh di `ossec_conf_example.xml`.
   - Konfigurasikan FIM untuk memantau direktori yang relevan.

5. **Restart Wazuh Manager**:
   ```
   systemctl restart wazuh-manager
   ```

6. **Konfigurasi Wazuh Agent**:
   - Untuk Windows, pasang dan konfigurasikan Sysmon.
   - Pastikan agent dapat mengirim event FIM dan Sysmon ke manager.

## Pengujian

Untuk menguji integrasi:

1. Buat file pengujian dengan hash yang diketahui sebagai malware (atau tersedia di MISP).
2. Pantau alert di Wazuh Dashboard.
3. Verifikasi bahwa alert MISP muncul dengan informasi yang benar.

## Pemecahan Masalah

### 1. Tidak Ada Alert MISP

- Periksa koneksi antara Wazuh Manager dan MISP Server.
- Verifikasi API key dan URL MISP di script `custom-misp.py`.
- Periksa log di `/var/ossec/logs/ossec.log` untuk kesalahan.

### 2. Alert Tidak Lengkap

- Pastikan format data yang dikirim ke MISP sudah benar.
- Verifikasi bahwa aturan di `misp_rules.xml` dikonfigurasi dengan benar.

### 3. False Positives

- Sesuaikan tingkat keparahan aturan di `misp_rules.xml`.
- Tambahkan pengecualian untuk file-file yang sering berubah.

## Kontribusi

Kontribusi untuk meningkatkan sistem ini sangat diterima. Silakan buat pull request atau buka issue untuk diskusi.

## Referensi

- [Dokumentasi Wazuh](https://documentation.wazuh.com/)
- [Dokumentasi MISP](https://www.misp-project.org/documentation/)
- [Wazuh-MISP Integration by juaromu](https://github.com/juaromu/wazuh-misp)

# Instalasi dan Konfigurasi Wazuh untuk Monitoring Server Apache2

Dokumen ini menjelaskan langkah-langkah instalasi dan konfigurasi Wazuh untuk monitoring server Apache2 dengan integrasi MISP.

## Prasyarat

1. Server Ubuntu (direkomendasikan Ubuntu 20.04 LTS atau lebih baru)
2. Akses root/sudo
3. Koneksi internet yang stabil
4. Server Apache2 yang sudah terinstal
5. Akses ke instance MISP (opsional, untuk integrasi)

## File yang Diperlukan

1. `wazuh-manager-setup-downloader.sh` - Untuk instalasi Wazuh Manager
2. `wazuh-agent-apache-setup-downloader.sh` - Untuk instalasi Wazuh Agent di server Apache2

## Langkah-langkah Instalasi

### 1. Instalasi Wazuh Manager

1. Download script instalasi Wazuh Manager:
```bash
curl -O https://raw.githubusercontent.com/DzidanIsh/Tugas-Akhir/main/wazuh-manager-setup-downloader.sh
```

2. Berikan izin eksekusi:
```bash
chmod +x wazuh-manager-setup-downloader.sh
```

3. Jalankan script instalasi:
```bash
sudo ./wazuh-manager-setup-downloader.sh
```

4. Saat diminta, masukkan:
   - URL MISP (jika ingin mengintegrasikan dengan MISP)
   - API Key MISP (jika ingin mengintegrasikan dengan MISP)

5. Tunggu hingga proses instalasi selesai

### 2. Instalasi Wazuh Agent di Server Apache2

1. Download script instalasi Wazuh Agent:
```bash
curl -O https://raw.githubusercontent.com/DzidanIsh/Tugas-Akhir/main/wazuh-agent-apache-setup-downloader.sh
```

2. Berikan izin eksekusi:
```bash
chmod +x wazuh-agent-apache-setup-downloader.sh
```

3. Jalankan script instalasi:
```bash
sudo ./wazuh-agent-apache-setup-downloader.sh
```

4. Saat diminta, masukkan:
   - Alamat IP Wazuh Manager

5. Tunggu hingga proses instalasi selesai

### 3. Registrasi Agent ke Manager

1. Di Wazuh Manager, dapatkan kunci registrasi:
```bash
sudo /var/ossec/bin/manage_agents -l
```

2. Salin kunci registrasi yang dihasilkan

3. Di server Apache2 (Agent), registrasikan agent:
```bash
sudo /var/ossec/bin/manage_agents -i
```

4. Masukkan kunci registrasi yang telah disalin

## Verifikasi Instalasi

### Wazuh Manager
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

### Wazuh Agent
```bash
sudo systemctl status wazuh-agent
```

## Troubleshooting

Jika terjadi masalah:

1. Periksa log Wazuh Manager:
```bash
sudo journalctl -u wazuh-manager -f
```

2. Periksa log Wazuh Agent:
```bash
sudo journalctl -u wazuh-agent -f
```

3. Periksa koneksi antara Agent dan Manager:
```bash
sudo /var/ossec/bin/agent_control -l
```

## Fitur yang Terinstal

1. Wazuh Manager dengan integrasi MISP
2. Wazuh Agent dengan monitoring Apache2
3. Fail2ban untuk proteksi tambahan
4. Backup otomatis untuk file web
5. Active Response untuk ancaman keamanan
6. Integrasi dengan MISP (opsional)

## Catatan Penting

1. Pastikan port 1514 dan 1515 terbuka antara Agent dan Manager
2. Backup konfigurasi sebelum melakukan perubahan
3. Periksa status layanan secara berkala
4. Update sistem dan paket Wazuh secara teratur

## Dukungan

Jika mengalami masalah, silakan buka issue di repository GitHub atau hubungi administrator sistem. 
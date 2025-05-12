#!/usr/bin/env python3

# Script Restore untuk Anti-Defacement
# --------------------------------------

import os
import sys
import time
import argparse
import getpass
import base64
import datetime
import git
import paramiko

# Konfigurasi
CONFIG_FILE = "/etc/web-backup/config.conf"

def error_exit(message):
    """Tampilkan pesan error dan keluar"""
    print(f"\033[31m[ERROR] {message}\033[0m")
    sys.exit(1)

def success_msg(message):
    """Tampilkan pesan sukses"""
    print(f"\033[32m[SUCCESS] {message}\033[0m")

def info_msg(message):
    """Tampilkan pesan info"""
    print(f"\033[34m[INFO] {message}\033[0m")

def load_config():
    """Muat konfigurasi dari file"""
    if not os.path.isfile(CONFIG_FILE):
        error_exit(f"File konfigurasi tidak ditemukan: {CONFIG_FILE}")
    
    config = {}
    with open(CONFIG_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split('=', 1)
                # Hapus tanda kutip jika ada
                config[key.strip()] = value.strip().strip('"\'')
    
    required_keys = ['WEB_DIR', 'MONITOR_IP', 'MONITOR_USER', 'BACKUP_DIR', 'PASSWORD']
    for key in required_keys:
        if key not in config:
            error_exit(f"Konfigurasi tidak lengkap. {key} tidak ditemukan di {CONFIG_FILE}")
    
    return config

def verify_password(config, auto_mode=False):
    """Verifikasi password pengguna"""
    if auto_mode:
        # Dalam mode otomatis, kita lewati verifikasi password
        return True
    
    encoded_password = config['PASSWORD']
    input_password = getpass.getpass("Masukkan password restore: ")
    input_encoded = base64.b64encode(input_password.encode()).decode()
    
    if input_encoded != encoded_password:
        error_exit("Password salah!")
    
    return True

def fetch_commits(config):
    """Ambil daftar commit dari repository Git"""
    web_dir = config['WEB_DIR']
    
    try:
        repo = git.Repo(web_dir)
        # Dapatkan daftar commit
        commits = list(repo.iter_commits('master', max_count=20))
        return commits
    except git.exc.InvalidGitRepositoryError:
        error_exit(f"Repository Git tidak ditemukan di {web_dir}")
    except Exception as e:
        error_exit(f"Gagal mengakses repository Git: {str(e)}")

def backup_current_state(web_dir, backup_dir):
    """Backup kondisi saat ini sebelum restore"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"pre_restore_backup_{timestamp}")
    
    try:
        os.makedirs(backup_path, exist_ok=True)
        os.system(f"cp -r {web_dir}/* {backup_path}/")
        info_msg(f"Kondisi saat ini di-backup ke {backup_path}")
        return backup_path
    except Exception as e:
        info_msg(f"Gagal membuat backup kondisi saat ini: {str(e)}")
        return None

def restore_from_commit(config, commit, auto_mode=False):
    """Pulihkan konten web dari commit tertentu"""
    web_dir = config['WEB_DIR']
    
    try:
        # Backup kondisi saat ini (opsional)
        if not auto_mode:
            backup_dir = "/tmp/web_restore_backups"
            backup_current_state(web_dir, backup_dir)
        
        # Masuk ke direktori web
        os.chdir(web_dir)
        
        # Reset ke commit yang dipilih
        repo = git.Repo(web_dir)
        info_msg(f"Melakukan restore ke commit: {commit.hexsha[:8]} - {commit.message.strip()}")
        
        # Hard reset ke commit yang dipilih
        repo.git.reset('--hard', commit.hexsha)
        
        # Bersihkan file yang tidak terlacak
        repo.git.clean('-fd')
        
        success_msg(f"Restore berhasil dilakukan pada: {datetime.datetime.now()}")
        
        # Catat aktivitas restore
        log_restore_activity(config, commit, auto_mode)
        
        return True
    except Exception as e:
        error_exit(f"Gagal melakukan restore: {str(e)}")

def log_restore_activity(config, commit, auto_mode):
    """Catat aktivitas restore ke log"""
    log_file = "/var/log/web-restore.log"
    
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        trigger = "AUTO" if auto_mode else "MANUAL"
        commit_info = f"{commit.hexsha[:8]} - {commit.message.strip()}"
        
        with open(log_file, 'a') as f:
            f.write(f"{timestamp} - {trigger} RESTORE - Commit: {commit_info}\n")
    except Exception as e:
        info_msg(f"Gagal mencatat aktivitas restore: {str(e)}")

def get_latest_good_commit(commits):
    """Pilih commit terakhir yang dianggap 'aman' untuk restore otomatis"""
    # Strategi sederhana: pilih commit kedua terakhir
    # Asumsinya adalah commit terakhir mungkin yang berisi perubahan berbahaya
    
    if len(commits) > 1:
        # Pilih commit kedua terakhir
        return commits[1]
    else:
        # Jika hanya ada 1 commit, gunakan itu
        return commits[0]

def interactive_restore(config, commits):
    """Mode interaktif untuk restore"""
    print("\nDaftar 20 commit terakhir:")
    print("============================")
    
    for i, commit in enumerate(commits):
        commit_time = datetime.datetime.fromtimestamp(commit.committed_date).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{i+1}. [{commit_time}] {commit.hexsha[:8]} - {commit.message.strip()}")
    
    # Pilih commit
    while True:
        try:
            choice = int(input("\nPilih nomor commit untuk restore (1-20): "))
            if 1 <= choice <= len(commits):
                selected_commit = commits[choice-1]
                break
            else:
                print("Nomor tidak valid. Coba lagi.")
        except ValueError:
            print("Masukkan nomor yang valid.")
    
    # Konfirmasi
    confirm = input(f"\nAnda akan melakukan restore ke commit:\n[{selected_commit.hexsha[:8]}] {selected_commit.message.strip()}\nLanjutkan? (y/n): ")
    
    if confirm.lower() == 'y':
        restore_from_commit(config, selected_commit)
    else:
        print("Restore dibatalkan.")

def auto_restore(config, commits):
    """Mode otomatis untuk restore tanpa interaksi pengguna"""
    info_msg("Menjalankan restore otomatis sebagai respons insiden...")
    
    # Pilih commit terakhir yang dianggap 'aman'
    commit = get_latest_good_commit(commits)
    
    info_msg(f"Memilih commit aman terakhir untuk restore: {commit.hexsha[:8]} - {commit.message.strip()}")
    
    # Lakukan restore
    restore_from_commit(config, commit, auto_mode=True)

def main():
    """Fungsi utama"""
    # Banner
    print("=================================================================")
    print("      RESTORE SISTEM ANTI-DEFACEMENT WEB SERVER                  ")
    print("=================================================================")
    
    # Parse argumen
    parser = argparse.ArgumentParser(description="Script restore anti-defacement")
    parser.add_argument("--auto", action="store_true", help="Jalankan restore otomatis tanpa interaksi")
    parser.add_argument("--alert", action="store_true", help="Dipanggil dari Wazuh alert")
    args = parser.parse_args()
    
    # Verifikasi bahwa script dijalankan sebagai root
    if os.geteuid() != 0:
        error_exit("Script ini harus dijalankan sebagai root.")
    
    # Muat konfigurasi
    config = load_config()
    
    # Verifikasi password (kecuali dalam mode otomatis)
    if not args.auto and not args.alert:
        verify_password(config)
    
    # Ambil daftar commit
    commits = fetch_commits(config)
    
    if not commits:
        error_exit("Tidak ada commit yang ditemukan di repository Git.")
    
    # Jalankan mode yang sesuai
    if args.auto or args.alert:
        auto_restore(config, commits)
    else:
        interactive_restore(config, commits)

if __name__ == "__main__":
    main() 

#!/usr/bin/python3
from bcc import BPF
import time

# 1. Daha önce derlediğimiz nesne dosyasını veya direkt C kodunu kullanabiliriz.
# Kolaylık olması için Map ismini referans alarak bağlanıyoruz.
map_name = "drop_stats"

# Not: Eğer programı 'ip link' ile yüklediyseniz, 
# BCC ile o Map'in ID'sine ulaşmamız gerekir.
# En temiz yol, Map'in sistemdeki dosya yolunu (pinned path) kullanmak 
# veya Map ID üzerinden gitmektir.

def run_monitor():
    try:
        # BPF haritasına erişim (Bu örnekte bpftool ile yüklediğinizi varsayıyoruz)
        # Eğer programı bu script içinden yüklemiyorsanız, haritayı 'pin' etmeniz önerilir.
        # Şimdilik en basit haliyle harita objesini temsil edelim:
        b = BPF(src_file="counter.c") # C kodunu okuyup harita yapısını öğrenir
        drop_stats = b.get_table(map_name)

        print(f"{'ZAMAN':<20} | {'ENGELLENEN PAKET SAYISI':<25}")
        print("-" * 50)

        while True:
            # Haritadaki 0 numaralı anahtarı (key) oku
            key = drop_stats.Key(0)
            value = drop_stats[key].value

            current_time = time.strftime("%H:%M:%S")
            print(f"{current_time:<20} | {value:<25}", end="\r")
            
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nİzleme durduruldu.")
    except Exception as e:
        print(f"Hata: {e}")

if __name__ == "__main__":
    run_monitor()

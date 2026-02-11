LKD Mustafa Akgül Özgür Yazılım Kış Kampı 2026 - BPF & XDP Eğitimi
Bu depo, Linux Kullanıcıları Derneği (LKD) tarafından düzenlenen Mustafa Akgül Özgür Yazılım Kış Kampı 2026 kapsamında gerçekleştirilen eBPF ve XDP (eXpress Data Path) eğitimi süresince geliştirilen uygulama, betik ve dökümanları içermektedir.
 Proje İçeriği
Eğitim boyunca geliştirilen araçlar işlevlerine göre kategorize edilmiştir:
 Networking & XDP
Yüksek performanslı paket işleme ve ağ güvenliği uygulamaları:
XDP_Filters: Protokol (ICMP/Ping) ve IP bazlı (8.8.8.8) paket engelleme (Drop) filtreleri.
Counters & Monitoring: Engellenen paketleri eBPF Map yapısı üzerinde sayan ve kullanıcı alanında (User-space) raporlayan araçlar.
XDP_Action: Paket başlıklarını manipüle eden ve paketleri yansıtan (Mirroring/Swap) ileri seviye uygulamalar.
 System Tracing & Observability
Linux Kernel içindeki olayları izlemek için kullanılan eBPF araçları:
Syscalls: clone, openat2 gibi sistem çağrılarının zaman damgası ve PID bilgileriyle takibi.
Performance: Disk I/O gecikmesi (Latency) ve ardışık sistem çağrılarının zamanlamasını analiz eden araçlar.
 Başlangıç
Gereksinimler
Uygulamaların derlenmesi ve çalıştırılması için sisteminizde aşağıdaki araçların bulunması gerekmektedir:
LLVM / Clang
libbpf & BCC (BPF Compiler Collection)
Linux Kernel 5.x+ (XDP desteği için)
Derleme Örneği
Bir XDP programını derlemek için:
Bash
clang -O2 -target bpf -c xdp_prog.c -o xdp_prog.o
 Lisans
Bu projedeki tüm kodlar GPL lisansı ile korunmaktadır.

LKD Mustafa Akgul Ozgur Yazilim Kis Kampi 2026 - BPF ve XDP Egitimi

Bu depo, Linux Kullanicilari Dernegi (LKD) tarafindan duzenlenen Mustafa Akgul Ozgur Yazilim Kis Kampi 2026 kapsaminda gerceklestirilen eBPF ve XDP (eXpress Data Path) egitimi suresince gelistirilen uygulama, betik ve dokumanlari icermektedir.
Proje Icerigi

Egitim boyunca gelistirilen araclar islevlerine gore kategorize edilmistir:
Networking ve XDP

Yuksek performansli paket isleme ve ag guvenligi uygulamalari:

    XDP_Filters: Protokol (ICMP/Ping) ve IP bazli (8.8.8.8) paket engelleme (Drop) filtreleri.

    Counters ve Monitoring: Engellenen paketleri eBPF Map yapisi uzerinde sayan ve kullanici alaninda (User-space) raporlayan araclar.

    XDP_Action: Paket basliklarini manipule eden ve paketleri yansitan (Mirroring/Swap) ileri seviye uygulamalar.

System Tracing ve Observability

Linux Kernel icindeki olaylari izlemek icin kullanilan eBPF araclari:

    Syscalls: clone, openat2 gibi sistem cagrilarinin zaman damgasi ve PID bilgileriyle takibi.

    Performance: Disk I/O gecikmesi (Latency) ve ardisik sistem cagrilarinin zamanlamasini analiz eden araclar.

Baslangic
Gereksinimler

Uygulamalarin derlenmesi ve calistirilmasi icin sisteminizde asagidaki araclarin bulunmasi gerekmektedir:

    LLVM / Clang

    libbpf ve BCC (BPF Compiler Collection)

    Linux Kernel 5.x+ (XDP destegi icin)

Derleme Ornegi

Bir XDP programini derlemek icin:
Bash

clang -O2 -target bpf -c xdp_prog.c -o xdp_prog.o

Lisans

Bu projedeki tum kodlar GPL lisansi ile korunmaktadir.

// paketin başladığı ve bittiği kısımları programa dahil ediyoruz
// (void *)(long)gelen veri 32 ya da 64 bit farketmeksizin gelen veriyi long tipine çevirip standart oluşturur.
void *data_end = (void *)(long)ctx->data_end;
void *data = (void *)(long)ctx->data;

struct ethhdr *eth =data;

// sınır kontrolü: paket boyutu bir ethernet başlığını okumaya yetiyor mu ?
// paket boyutunu kontrol eder ve pakette bozulma yoksa programa girişine izin verir
if ((void *)(eth + 1) > data_end)
	return XDP_PASS; /


// paketin bir IPv4 paketi olduğunu kontrol etme
if (eth->h_proto != __constant_htons(ETH_P_IP))
	return XDP_PASS;

// htons:host to network short: bilgisayarın sayıları saklama biçimi ile ağın saklama biçimi farklıdır 
// bu fonksiyon onları hizalar.
struct iphdr *iph = (void *)(eth + 1)

// sınır kontrolü: IP başlığını okuyabiliyor muyuz ?
if ((void *)(iph + 1) > data_end)
	return XDP_PASS;

// (ICMP ve tip kontrolü)
if (iph->protocol != IPPROTO_ICMP)
	return XDP_PASS;

struct icmphdr *icmp = (void *)(iph + 1);

// sınır kontrolü: ICMP başlığını okuyabiliyor muyuz?
if ((void *)(icmp + 1) > data_end)
	return XDP_PASS;

// sadece 'echo request' (8) paketlerine cevap vereceğiz
if (icmp->type != ICMP_ECHO)
	return XDP_PASS;

// MAC Swap işlemi: mac ve ip adreslerini takas etme 
// MAC Swap
unsigned char tmp_mac[6];
memcpy(tmp_mac, eth->h_source, 6);
memcpy(eth->h_source, eth->h_dest, 6);
memcpy(eth->h_dest, tmp_mac, 6);

// IP Swap
__be32 tmp_ip = iph->saddr;
iph->saddr = iph->daddr;
iph->daddr = tmp_ip;

// ICMP Tipini değiştirme ve paketi gönderme
icmp->type = ICMP_ECHOREPLY; // 0 olan değeri 0 yapıyoruz

// checksum güncelleme (basit ve etkili bir yöntem)
// eBPF kütüphanesinden bpf_l3_csum_replace ve bpf_l4_csum_replace de kullanılabilir.
// ancak burada sadece type değişikliği için checksum basitçe güncellenebilir.
if (icmp->chechksum >= __constant_htons:(0xffff - (ICMP_ECHO << 8)))
	icmp ->checksum += __constant_htons(ICMP_ECHO << 8) + 1;
else
	icmp->checksum += __constant_htons(ICMP_ECHO << 8);

return XDP_TX; // paketi geldiği arayüzden geri gönder

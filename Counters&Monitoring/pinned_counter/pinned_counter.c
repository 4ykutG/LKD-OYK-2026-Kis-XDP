#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Sayaç haritası (Map)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // Otomatik pinleme desteği
} drop_stats SEC(".maps");

SEC("xdp")
int xdp_drop_google_dns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet başlığı kontrolü
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Sadece IP paketlerini incele
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IP başlığı kontrolü
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 8.8.8.8 IP adresini kontrol et (Big-endian formatında)
    if (iph->saddr == bpf_htonl(0x08080808)) {
        __u32 key = 0;
        __u64 *value;

        value = bpf_map_lookup_elem(&drop_stats, &key);
        if (value) {
            // Atomik artırma (Race condition engellemek için)
            __sync_fetch_and_add(value, 1);
        }

        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

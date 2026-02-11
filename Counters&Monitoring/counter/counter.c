#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Sayacı saklamak için bir BPF Map tanımlıyoruz
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); // Dizi tipinde bir map
    __uint(max_entries, 1);           // Sadece 1 tane sayaç tutacağız
    __type(key, __u32);               // Anahtar tipi (0. index)
    __type(value, __u64);             // Değer tipi (64-bit sayaç)
} drop_stats SEC(".maps");

SEC("xdp_drop_counter")
int xdp_drop_google_dns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    // Kaynak IP 8.8.8.8 ise
    if (iph->saddr == __constant_htonl(0x08080808)) {
        __u32 key = 0;
        __u64 *value;

        // Map içindeki sayacı bul ve artır
        value = bpf_map_lookup_elem(&drop_stats, &key);
        if (value) {
            // Atomik olarak artırma (birden fazla CPU çekirdeği çakışmasın diye)
            __sync_fetch_and_add(value, 1);
        }

        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

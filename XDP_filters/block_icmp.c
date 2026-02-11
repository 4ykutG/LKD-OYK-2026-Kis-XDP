#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int block_icmp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet header cast 
    struct ethhdr *eth = data;

    // Sınır Kontrolü: Paket boyutu ethernet header için yeterli mi?
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // IPv4 Kontrolü
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // IP Header başlangıcı
    struct iphdr *iph = data + sizeof(struct ethhdr);

    // Sınır Kontrolü: IP header paket içinde mi?
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // ICMP Kontrolü: Protokol 1 ise ICMP'dir
    if (iph->protocol == IPPROTO_ICMP) {
        return XDP_DROP; // Paketi çöpe at!
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


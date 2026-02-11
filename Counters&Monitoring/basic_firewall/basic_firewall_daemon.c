#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

SEC("xdp")
int xdp_drop_8888(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    /* * 8.8.8.8 Karşılaştırması. 
     * Bazı sistemlerde 0x08080808 doğrudan çalışırken, 
     * bazılarında byte-order takla atabilir. Her ikisini de kontrol edelim.
     */
    __u32 target = 0x08080808; 

    if (iph->daddr == target || iph->saddr == target) {
        bpf_printk("ISMET YAKALADI: IP 8.8.8.8 imha ediliyor!\n");
        
        __u32 key = 0;
        __u64 *value = bpf_map_lookup_elem(&drop_stats, &key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

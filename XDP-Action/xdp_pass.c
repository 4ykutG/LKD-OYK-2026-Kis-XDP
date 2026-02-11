#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{
    bpf_printk("paket yakalandi!\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

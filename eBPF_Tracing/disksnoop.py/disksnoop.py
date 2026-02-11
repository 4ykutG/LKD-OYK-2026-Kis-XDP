[...]
REQ_WRITE = 1		# from include/linux/blk_types.h

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
	// stash start timestamp by request ptr
	u64 ts = bpf_ktime_get_ns();

	start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
	u64 *tsp, delta;

	tsp = start.lookup(&req);
	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		bpf_trace_printk("%d %x %d\\n", req->__data_len,
		    req->cmd_flags, delta / 1000);
		start.delete(&req);
	}
}
""")
if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")

if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    # __blk_account_io_done is available before kernel v6.4.
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_completion")
elif BPF.get_kprobe_functions(b'blk_account_io_done'):
    # blk_account_io_done is traceable (not inline) before v5.16.
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion")
else:
    b.attach_kprobe(event="blk_mq_end_request", fn_name="trace_completion")
[...]

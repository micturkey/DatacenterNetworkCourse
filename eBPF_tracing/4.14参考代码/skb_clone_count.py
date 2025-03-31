from __future__ import print_function
from bcc import BPF

b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(count);

int do_trace(struct pt_regs *ctx){
    u64 cur_count = 1, key = 0;
    u64 *cur_ptr;
    cur_ptr = count.lookup(&key);
    if (cur_ptr == NULL){

        count.update(&key, &cur_count);
        bpf_trace_printk("%d\\n", cur_count);

    }else{

        cur_count = *cur_ptr + 1;
        count.update(&key, &cur_count);
        bpf_trace_printk("%d\\n", cur_count);

        }
    return 0;
}
""")

b.attach_kprobe(event=("skb_clone"), fn_name="do_trace")
print("Tracing for skb_clone... Ctrl-C to end")
print("%-18s %-19s %-6s %s" % ("TIME(s)", "COMM", "PID", "COUNT"))
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except KeyboardInterrupt:
        exit()
    print("%-18.9f %-19s %-6d %s" %(ts, task, pid, msg))
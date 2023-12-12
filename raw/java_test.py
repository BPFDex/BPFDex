from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>
BPF_STACK_TRACE(stack_traces, 1024);

int on_event(struct pt_regs *ctx) {
    // 获取当前堆栈信息
    u64 stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    // 此处可以添加额外的处理逻辑
    return 0;
}
"""

b = BPF(text=bpf_source)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="on_event")
stack_traces = b["stack_traces"]
while True:
    print(stack_traces)
    for stack_id, _ in stack_traces.items():
        frame_list = list(stack_traces.walk(int(stack_id.value)))
        for addr in frame_list:
            #解析符号并打印
            print(b.sym(addr))

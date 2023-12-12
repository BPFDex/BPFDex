from bcc import BPF
file_path = "/home/wss/bcc/test/libhi.so"
file_sym = "hi"
bpf_c_code = '''#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/sched.h>
#define TASK_COMM_LEN 16
struct event_data {
  u32 pid;
  u32 tgid;
  unsigned long arg1;
  unsigned long arg2;
  unsigned long arg3;
  unsigned long arg4;
  long arg5;
  u64 arg6;
  unsigned long arg7;
  int arg8;
  int a;
  int b;
  char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(trace_event);
static __inline unsigned long test(struct pt_regs *ctx,unsigned long n)
{
  unsigned long *addr=(unsigned long*)ctx->sp,data=0;
  addr+=n;
  return 0!=bpf_probe_read_kernel(&data,sizeof(data),addr)?0:data;
}
int trace_DexFile(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >>32;
  bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
  current_data.arg1=ctx->di;
  current_data.arg2=PT_REGS_PARM2(ctx);
  current_data.arg3=PT_REGS_PARM3(ctx);
  current_data.arg4=PT_REGS_PARM4(ctx);
  current_data.arg5=(long)PT_REGS_PARM5(ctx);
  current_data.arg6=PT_REGS_PARM6(ctx);
  current_data.arg7=test(ctx,1);
  current_data.arg8=(int)test(ctx,2);
  bpf_probe_read_user(&current_data.a, sizeof(current_data.a),
                        (unsigned char*)(current_data.arg6));
  bpf_probe_read_user(&current_data.b, sizeof(current_data.b),
                        (unsigned char*)(current_data.arg6+0x4));
  bpf_probe_read_kernel(&current_data.arg8, sizeof(current_data.arg8),
                        (int*)(current_data.arg7));
  trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}'''
bpf = BPF(text=bpf_c_code)
def output(cpu, data, size):
    event = bpf["trace_event"].event(data)
    print("pid:{1}     tgid:{2}     comm:{0}   arg1:{5}    arg2:{6}      arg3:{7}      arg7:{3}    arg8:{4}".format( event.comm, event.pid, event.tgid,event.arg7,event.arg8,event.arg1,event.arg2,event.arg3))

def run():
    bpf.attach_uprobe(name=file_path, sym=file_sym, fn_name="trace_DexFile")
    bpf["trace_event"].open_perf_buffer(output)
    while True:
        bpf.perf_buffer_poll()
try:
    run()
except KeyboardInterrupt:
    exit()

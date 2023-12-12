#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/auto_dev-ioctl.h>

#define TASK_COMM_LEN 16
struct event_data {
  u32 pid;
  u32 tgid;
  char comm[TASK_COMM_LEN];
  u64 arg1;
  unsigned int arg2;
  char magic[8];
};
BPF_PERF_OUTPUT(trace_event);
int trace_DexFile(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
  current_data.arg1 = (unsigned long)PT_REGS_PARM4(ctx);
  current_data.arg2 = (unsigned int)PT_REGS_PARM3(ctx);
  int size=(int)current_data.arg2;
  bpf_probe_read_user_str(&current_data.magic, sizeof(current_data.magic),
                          (char *)(current_data.arg1));
  trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  /*              map               
  
  //# pragma unroll
  for(int t=7000000 ;t>0;t-=420){
  if(size>420){
  bpf_probe_read(&dex_data.dex_data,sizeof(dex_data.dex_data),addr);
  dex_array.update(&index, &dex_data);
  index++;
  size-=420;
  addr+=0x1A4;
  }
  else{
    bpf_probe_read(&dex_data.dex_data,sizeof(dex_data.dex_data),addr);
    dex_array.update(&index, &dex_data);
    index++;
    current_data.flag=1;
    trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
    size-=420;
    break;
  }
  }
  }
                map               */
  /*             buffer                            
  # pragma unroll
  for(int t=7000000 ;t>0;t-=400){
  if(size>400){
  bpf_probe_read_user(&dex_data.dex_data,sizeof(dex_data.dex_data),addr);
  dex_out.perf_submit(ctx, &dex_data, sizeof(dex_data));
  //dex.ringbuf_output( &dex_data, sizeof(dex_data), 0 );
  size-=400;
  addr+=0x190;
  }
  else{
    bpf_probe_read_user(&dex_data.dex_data,sizeof(dex_data.dex_data),addr);
    size-=400;
    dex_out.perf_submit(ctx, &dex_data, sizeof(dex_data));
    current_data.flag=1;
    trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
    //dex.ringbuf_output( &dex_data, sizeof(dex_data) ,0 );
    break;
  }
  }
  }
                   buffer                    */
  return 0;
}


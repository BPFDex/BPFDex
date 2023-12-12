#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/string.h>
#define TASK_COMM_LEN 16

struct event_data {
  u32 pid;
  u32 tgid;
  u32 uid;
  char comm[TASK_COMM_LEN];
  u64 addr;
  unsigned short tries_size_;              // uint16_t
  unsigned int insns_size_in_code_units_;  // uint32_t
  u64 insns_addr;
};

BPF_PERF_OUTPUT(trace_event);
int trace_DexFile(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  current_data.uid = bpf_get_current_uid_gid();
  if (current_data.uid == 10059) {
    bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
    current_data.addr =  ctx->ax;
    bpf_probe_read_user(&(current_data.tries_size_), sizeof(current_data.tries_size_),
                        (void *)(current_data.addr+0x6));
    bpf_probe_read_user(&(current_data.insns_size_in_code_units_), sizeof(current_data.insns_size_in_code_units_),
                        (void *)(current_data.addr+0xC));
    current_data.insns_addr = current_data.addr + 0x10;
    trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  }
  return 0;
}

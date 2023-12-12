#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/limits.h>

#define TASK_COMM_LEN 16
struct event_data {
  u32 pid;
  u32 tgid;
  char comm[30];
  u64 arg1;
  u64 arg2;
  char str1[100];
  char str2[100];
};
BPF_PERF_OUTPUT(trace_event);
int trace_strstr(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
  current_data.arg1=ctx->ax;
  current_data.arg2=PT_REGS_PARM4(ctx);;
  bpf_probe_read_user_str(&current_data.str1, sizeof(current_data.str1),
                          (char *)(current_data.arg1));
  bpf_probe_read_user_str(&current_data.str2, sizeof(current_data.str2),
                          (char *)(current_data.arg2));
  trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}
int trace_strcmp(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
  current_data.arg1=ctx->ax;
  current_data.arg2=ctx->si;
  bpf_probe_read_user_str(&current_data.str1, sizeof(current_data.str1),
                          (char *)(current_data.arg1));
  bpf_probe_read_user_str(&current_data.str2, sizeof(current_data.str2),
                          (char *)(current_data.arg2));
  trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}
int trace_strncmp(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
  current_data.arg1=ctx->ax;
  current_data.arg2=ctx->r8;
  bpf_probe_read_user_str(&current_data.str1, sizeof(current_data.str1),
                          (char *)(current_data.arg1));
  bpf_probe_read_user_str(&current_data.str2, sizeof(current_data.str2),
                          (char *)(current_data.arg2));
  trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}
int trace_fopen(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
  current_data.arg1=ctx->ax;
  current_data.arg2=PT_REGS_PARM2(ctx);
  bpf_probe_read_user_str(&current_data.str1, sizeof(current_data.str1),
                          (char *)(current_data.arg1));
  bpf_probe_read_user_str(&current_data.str2, sizeof(current_data.str2),
                          (char *)(current_data.arg2));
  trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}
int trace_ptrace(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
  trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}
int trace_dlsym(struct pt_regs *ctx) {
  struct event_data current_data;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
  current_data.arg1=ctx->ax;
  current_data.arg2=PT_REGS_PARM4(ctx);;
  bpf_probe_read_user_str(&current_data.str1, sizeof(current_data.str1),
                          (char *)(current_data.arg1));
  bpf_probe_read_user_str(&current_data.str2, sizeof(current_data.str2),
                          (char *)(current_data.arg2));
  trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}
#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/string.h>
#define TASK_COMM_LEN 16
struct CodeItem {
  unsigned short registers_size_;          // uint16_t
  unsigned short ins_size_;                // uint16_t
  unsigned short outs_size_;               // uint16_t
  unsigned short tries_size_;              // uint16_t
  unsigned int debug_info_off_;            // uint32_t
  unsigned int insns_size_in_code_units_;  // uint32_t
  u64 addr;
  // unsigned short  insns_[1];                  //uint16_t
};
struct event_data {
  u32 pid;
  u32 tgid;
  u32 uid;
  char comm[TASK_COMM_LEN];
  u64 addr;
};

BPF_PERF_OUTPUT(trace_event);
BPF_HASH(code_item_table, int, struct CodeItem, 100000);
BPF_HASH(index_table, int, int);
int trace_DexFile(struct pt_regs *ctx) {
  struct event_data current_data;
  struct CodeItem code_item;
  __builtin_memset(&current_data, 0, sizeof(current_data));
  __builtin_memset(&code_item, 0, sizeof(code_item));
  current_data.pid = bpf_get_current_pid_tgid();
  current_data.tgid = bpf_get_current_pid_tgid() >> 32;
  current_data.uid = bpf_get_current_uid_gid();
  if (current_data.uid == 10052) {
    bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
    current_data.addr = ctx->ax;
    bpf_probe_read_user(&code_item, sizeof(code_item),
                        (void *)(current_data.addr));
    u64 insns_addr = current_data.addr + 0x10;
    code_item.addr=insns_addr;
    int zero = 0;
    int *index = index_table.lookup_or_try_init(&zero, &zero);
    if (index) {
      code_item_table.update(index, &code_item);
      *index += 1;
      index_table.update(&zero, index);
    }
    trace_event.perf_submit(ctx, &current_data, sizeof(current_data));
  }
  return 0;
}

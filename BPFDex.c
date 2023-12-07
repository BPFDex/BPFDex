#include <asm/ptrace.h>
#include <linux/bpf.h>
struct unpacking_data
{
    u32 pid;
    u32 tgid;
    u32 uid;
    char comm[16];
    u64 arg1;
    unsigned int arg2;
    char magic[8];
};
BPF_PERF_OUTPUT(Dex_event);
BPF_ARRAY(UID, int, 1);
BPF_HASH(dex_array, int,unsigned char*, 10240)
int trace_DexOpen(struct pt_regs *ctx)
{
    struct unpacking_data current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    current_data.uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (current_data.uid != uid)
    {
        return 0;
    }
    current_data.pid = bpf_get_current_pid_tgid();
    current_data.tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(current_data.comm, sizeof(current_data.comm));
    current_data.arg1 = (unsigned long)PT_REGS_PARM1(ctx);
    current_data.arg2 = (unsigned int)PT_REGS_PARM2(ctx);
    int size = (int)current_data.arg2;
    bpf_probe_read_user_str(&current_data.magic, sizeof(current_data.magic),
                            (char *)(current_data.arg1));
    Dex_event.perf_submit(ctx, &current_data, sizeof(current_data));
  //use probe_read to dump Dex data
  /*
   unsigned char dex_data[420];
   int index=0;
   u64 addr=current_data.arg1;
# pragma unroll
  for(size ;size>0;size-=420){
  bpf_probe_read(&dex_data,sizeof(dex_data),addr);
  dex_array.update(&index, &dex_data);
  index++;
  addr+=0x1A4;
  }
  size=-size;
  bpf_probe_read(&dex_data,size,addr);
  dex_array.update(&index, &dex_data);
  */
  return 0;
}
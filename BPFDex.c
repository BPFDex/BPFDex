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
    int by_probe;
};
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
struct Behavior {
  char* tag;
  char* arg1;
  char* arg2;          
};
BPF_PERF_OUTPUT(Dex_event);
BPF_PERF_OUTPUT(CodeItem_event);
BPF_PERF_OUTPUT(Behavior_event);
BPF_ARRAY(UID, int, 1);
BPF_HASH(dex_array_DexOpen, int,unsigned char*, 10240)
BPF_HASH(dex_array_DexOpenFile, int,unsigned char*, 10240)
BPF_HASH(dex_array_OpenMemory, int,unsigned char*, 10240)
BPF_HASH(dex_array_DexFile, int,unsigned char*, 10240)
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
  //use probe_read to dump Dex data
  /*
   current_data.by_probe=1;
   unsigned char dex_data[420];
   int index=0;
   u64 addr=current_data.arg1;
# pragma unroll
  for(size ;size>0;size-=420){
  bpf_probe_read(&dex_data,sizeof(dex_data),addr);
  dex_array_DexOpen.update(&index, &dex_data);
  index++;
  addr+=0x1A4;
  }
  size=-size;
  bpf_probe_read(&dex_data,size,addr);
  dex_array_DexOpen.update(&index, &dex_data);
  */
  Dex_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}

int trace_DexFile(struct pt_regs *ctx)
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
  //use probe_read to dump Dex data
  /*
   current_data.by_probe=2;
   unsigned char dex_data[420];
   int index=0;
   u64 addr=current_data.arg1;
# pragma unroll
  for(size ;size>0;size-=420){
  bpf_probe_read(&dex_data,sizeof(dex_data),addr);
  dex_array_DexFile.update(&index, &dex_data);
  index++;
  addr+=0x1A4;
  }
  size=-size;
  bpf_probe_read(&dex_data,size,addr);
  dex_array_DexFile.update(&index, &dex_data);
  */
  Dex_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}

int trace_DexOpenFile(struct pt_regs *ctx)
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
  //use probe_read to dump Dex data
  /*
   current_data.by_probe=3;
   unsigned char dex_data[420];
   int index=0;
   u64 addr=current_data.arg1;
# pragma unroll
  for(size ;size>0;size-=420){
  bpf_probe_read(&dex_data,sizeof(dex_data),addr);
  dex_array_DexOpenFile.update(&index, &dex_data);
  index++;
  addr+=0x1A4;
  }
  size=-size;
  bpf_probe_read(&dex_data,size,addr);
  dex_array_DexOpenFile.update(&index, &dex_data);
  */
  Dex_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}

int trace_OpenMemory(struct pt_regs *ctx)
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
  //use probe_read to dump Dex data
  /*
   current_data.by_probe=4;
   unsigned char dex_data[420];
   int index=0;
   u64 addr=current_data.arg1;
# pragma unroll
  for(size ;size>0;size-=420){
  bpf_probe_read(&dex_data,sizeof(dex_data),addr);
  dex_array_OpenMemory.update(&index, &dex_data);
  index++;
  addr+=0x1A4;
  }
  size=-size;
  bpf_probe_read(&dex_data,size,addr);
  dex_array_OpenMemory.update(&index, &dex_data);
  */
  Dex_event.perf_submit(ctx, &current_data, sizeof(current_data));
  return 0;
}

int trace_ExecuteGoto(struct pt_regs *ctx)
{
    struct CodeItem current_data;
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
    u64 code_item_addr = (unsigned int)PT_REGS_PARM2(ctx);
    bpf_probe_read_user(&current_data, sizeof(current_data),
                        (void *)(code_item_addr));
    u64 insns_addr = code_item_addr + 0x10;
    current_data.addr=insns_addr;
    CodeItem_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_ExecuteGoto(struct pt_regs *ctx)
{
    struct CodeItem current_data;
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
    u64 code_item_addr = (unsigned int)PT_REGS_PARM2(ctx);
    bpf_probe_read_user(&current_data, sizeof(current_data),
                        (void *)(code_item_addr));
    u64 insns_addr = code_item_addr + 0x10;
    current_data.addr=insns_addr;
    CodeItem_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_ExecuteSwith(struct pt_regs *ctx)
{
    struct CodeItem current_data;
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
    u64 code_item_addr = (unsigned int)PT_REGS_PARM2(ctx);
    bpf_probe_read_user(&current_data, sizeof(current_data),
                        (void *)(code_item_addr));
    u64 insns_addr = code_item_addr + 0x10;
    current_data.addr=insns_addr;
    CodeItem_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_open(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="open";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}


int trace_fopen(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="fopen";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_openat(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="openat";
    current_data.arg1 = (char*)PT_REGS_PARM2(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_sys_proper_get(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="sys_proper_get";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_sys_proper_read(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="sys_proper_read";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_strstr(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="strstr";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    current_data.arg2 = (char*)PT_REGS_PARM2(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_strcmp(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="strcmp";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    current_data.arg2 = (char*)PT_REGS_PARM2(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_strncmp(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="strncmp";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    current_data.arg2 = (char*)PT_REGS_PARM2(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_gDebugger(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="gDebugger";
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_gettimeofday(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="gettimeofday";
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_time(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="time";
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_dlsym(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="dlsym";
    current_data.arg2 = (char*)PT_REGS_PARM2(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_mprotect(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="mprotect";
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_execve(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="execve";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    current_data.arg2 = (char*)PT_REGS_PARM2(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

int trace_access(struct pt_regs *ctx)
{
    struct Behavior current_data;
    __builtin_memset(&current_data, 0, sizeof(current_data));
    u32 _uid = bpf_get_current_uid_gid();
    int key = 0;
    int uid = 0;
    int *uid_map = UID.lookup(&key);
    if (uid_map)
    {
        uid = *uid_map;
    }
    if (_uid != uid)
    {
        return 0;
    }
    current_data.tag="access";
    current_data.arg1 = (char*)PT_REGS_PARM1(ctx);
    Behavior_event.perf_submit(ctx, &current_data, sizeof(current_data));
    return 0;
}

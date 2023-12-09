from bcc import BPF
import argparse
import ctypes

DexOpen_sym = ""  # replace with your symbol
DexFile_sym = ""  # replace with your symbol
OpenMemory_sym = ""  # replace with your symbol
DexOpenFile_sym = ""  # replace with your symbol
DefineClass_sym = ""  # replace with your symbol
LoadMethod_sym = ""  # replace with your symbol
ExecuteSwith_sym = ""  # replace with your symbol
ExecuteGoto_sym = ""  # replace with your symbol
strstr_sym = ""  # replace with your symbol
strcmp_sym = ""  # replace with your symbol
strncmp_sym = ""  # replace with your symbol
open_sym = ""  # replace with your symbol
fopen_sym = ""  # replace with your symbol
openat_sym = ""  # replace with your symbol
ptrace_sym = ""  # replace with your symbol
gDeggbugger_sym = ""  # replace with your symbol
sys_proper_get_sym = ""  # replace with your symbol
sys_proper_read_sym = ""  # replace with your symbol
execve_sym = ""  # replace with your symbol
access_sym = ""  # replace with your symbol
dlsym_sym = ""  # replace with your symbol
mprotect_sym = ""  # replace with your symbol
gettimeofday_sym = ""  # replace with your symbol
time_sym = ""  # replace with your symbol

libart_path = ""  # replace with your path
libc_path = ""  # replace with your path


bpf_c_code = open("BPFDex.c").read()
bpf = BPF(text=bpf_c_code)
dex_index = 0
size_list = []
addr_list = []
dex_array = []
ins_array=[]
ins_addr_list=[]
pid=0

parser = argparse.ArgumentParser(description="unpacking Android apps by eBPF")
parser.add_argument("uid", help="uid of the target app")
parser.add_argument(
    "--insExtract",
    "-i",
    action="store_true",
    help="turn on when the packer extracts instructions of Dex",
)
parser.add_argument(
    "--behavior",
    "-b",
    type=str,
    default=None,
    help="""
                    input the behavior you want to monitor
                    EMU               ---emulator detection
                    DBG               ---debugger detection
                    DBI               ---DBI detection
                    TCK               ---time check
                    SLH               ---lib hook
                    RTD               ---root detection
                    """,
)
args = parser.parse_args()
bpf["UID"][0] = args.uid


def Dex_event(cpu, data, size):
    global size_list, addr_list,pid
    event = bpf["Dex_event"].event(data)
    print(
        "pid:{1}     tgid:{2}     uid:{6}    comm:{0}     arg1:{3}    arg2:{4}     magic:{5}".format(
            event.comm,
            event.pid,
            event.tgid,
            event.arg1,
            event.arg2,
            event.magic,
            event.uid,
        )
    )
    pid=event.pid
    # if event.by_probe != 0:
    #     Dump_Dex_via_prob(event.by_probe)
    if (event.arg2 not in size_list) or (event.arg1 not in addr_list):
        Dump_Dex_via_mem(event.pid, event.arg1, event.arg2)

def CodeItem_event(cpu, data, size):
    global pid
    event = bpf["CodeItem_event"].event(data)
    Dump_ins_via_mem(event.addr,event.ins_size_,pid)


def Dump_Dex_via_mem(pid, addr, size):
    global dex_index, size_list, dex_array
    mem = open("/proc/{0}/mem".format(pid), "rb+")
    mem.seek(addr)
    try:
        res = mem.read(size)
    except IOError:
        print("unable to dump")
    else:
        dex_array.append(res)
        mem.close()
        dex_index += 1
        size_list.append(size)
        addr_list.append(addr)
        print("dump {0}.dex".format(dex_index))


def final_Dex_process():
    for i in range(dex_index):
        dex = open(file="{0}.dex".format(i), mode="wb")
        dex.write(dex_array[i])
        dex.close()


# def Dump_Dex_via_prob(probe_type):
#     global dex_array,dex_index
#     if(probe_type==1):
#         dex_probe_array = bpf["dex_array_DexOpen"]
#         res=b''
#         for i in dex_probe_array:
#             res+=i
#         dex_array.append(res)
#         dex_index+=1
#         bpf["dex_array_DexOpen"].clear()
#     elif(probe_type==2):
#         dex_probe_array = bpf["dex_array_DexOpenFile"]
#         res=b''
#         for i in dex_probe_array:
#             res+=i
#         dex_array.append(res)
#         dex_index+=1
#         bpf["dex_array_DexOpenFile"].clear()
#     elif(probe_type==2):
#         dex_probe_array = bpf["dex_array_OpenMemory"]
#         res=b''
#         for i in dex_probe_array:
#             res+=i
#         dex_array.append(res)
#         dex_index+=1
#         bpf["dex_array_OpenMemory"].clear()
#     elif(probe_type==3):
#         dex_probe_array = bpf["dex_array_DexFile"]
#         res=b''
#         for i in dex_probe_array:
#             res+=i
#         dex_array.append(res)
#         dex_index+=1
#         bpf["dex_array_DexFile"].clear()

def Dump_ins_via_mem(addr,size,pid):
    global ins_array
    if pid==0:
        return
    mem = open("/proc/{0}/mem".format(pid), "rb+")
    mem.seek(addr)
    try:
        res = mem.read(size)
    except IOError:
        print("unable to dump codeitem")
    else:
        ins_array.append(res)
        mem.close()
        ins_addr_list.append(addr)
        

def run():
    if args.insExtract != True:
        # DexOpen
        bpf.attach_uprobe(name=libart_path, sym=DexOpen_sym, fn_name="trace_DexOpen")
        # DexFile
        bpf.attach_uprobe(name=libart_path, sym=DexFile_sym, fn_name="trace_DexFile")
        # DexOpenFile
        bpf.attach_uprobe(
            name=libart_path, sym=DexOpenFile_sym, fn_name="trace_DexOpenFile"
        )
        # OpenMemory
        bpf.attach_uprobe(
            name=libart_path, sym=OpenMemory_sym, fn_name="trace_OpenMemory"
        )
    elif args.insExtract == True:
        # DexOpen
        bpf.attach_uprobe(name=libart_path, sym=DexOpen_sym, fn_name="trace_DexOpen")
        # DexFile
        bpf.attach_uprobe(name=libart_path, sym=DexFile_sym, fn_name="trace_DexFile")
        # DexOpenFile
        bpf.attach_uprobe(
            name=libart_path, sym=DexOpenFile_sym, fn_name="trace_DexOpenFile"
        )
        # OpenMemory
        bpf.attach_uprobe(
            name=libart_path, sym=OpenMemory_sym, fn_name="trace_OpenMemory"
        )
        # ExecuteGoto
        bpf.attach_uprobe(
            name=libart_path, sym=ExecuteGoto_sym, fn_name="trace_ExecuteGoto"
        )
        # ExecuteSwith
        bpf.attach_uprobe(
            name=libart_path, sym=ExecuteSwith_sym, fn_name="trace_ExecuteSwith"
        )
    if args.behavior != None:
        if args.behavior == "EMU":
            bpf.attach_uprobe(name=libc_path, sym=open_sym, fn_name="trace_open")
            bpf.attach_uprobe(name=libc_path, sym=fopen_sym, fn_name="trace_fopen")
            bpf.attach_uprobe(name=libc_path, sym=openat_sym, fn_name="trace_openat")
            bpf.attach_uprobe(
                name=libc_path, sym=sys_proper_get_sym, fn_name="trace_sys_proper_get"
            )
            bpf.attach_uprobe(
                name=libc_path, sym=sys_proper_read_sym, fn_name="trace_sys_proper_read"
            )
            bpf.attach_uprobe(name=libc_path, sym=strstr_sym, fn_name="trace_strstr")
            bpf.attach_uprobe(name=libc_path, sym=strcmp_sym, fn_name="trace_strcmp")
            bpf.attach_uprobe(name=libc_path, sym=strncmp_sym, fn_name="trace_strncmp")
        if args.behavior == "DBG":
            bpf.attach_uprobe(
                name=libc_path, sym=gDeggbugger_sym, fn_name="trace_gDebugger"
            )
            bpf.attach_uprobe(name=libc_path, sym=ptrace_sym, fn_name="trace_ptrace")
            bpf.attach_uprobe(name=libc_path, sym=open_sym, fn_name="trace_open")
            bpf.attach_uprobe(name=libc_path, sym=fopen_sym, fn_name="trace_fopen")
            bpf.attach_uprobe(name=libc_path, sym=openat_sym, fn_name="trace_openat")
            bpf.attach_uprobe(name=libc_path, sym=strstr_sym, fn_name="trace_strstr")
            bpf.attach_uprobe(name=libc_path, sym=strcmp_sym, fn_name="trace_strcmp")
            bpf.attach_uprobe(name=libc_path, sym=strncmp_sym, fn_name="trace_strncmp")
        if args.behavior == "DBI":
            bpf.attach_uprobe(name=libc_path, sym=open_sym, fn_name="trace_open")
            bpf.attach_uprobe(name=libc_path, sym=fopen_sym, fn_name="trace_fopen")
            bpf.attach_uprobe(name=libc_path, sym=openat_sym, fn_name="trace_openat")
            bpf.attach_uprobe(name=libc_path, sym=strstr_sym, fn_name="trace_strstr")
            bpf.attach_uprobe(name=libc_path, sym=strcmp_sym, fn_name="trace_strcmp")
            bpf.attach_uprobe(name=libc_path, sym=strncmp_sym, fn_name="trace_strncmp")
        if args.behavior == "TCK":
            bpf.attach_uprobe(
                name=libc_path, sym=gettimeofday_sym, fn_name="trace_gettimeofday"
            )
            bpf.attach_uprobe(name=libc_path, sym=time_sym, fn_name="trace_time")
        if args.behavior == "SLH":
            bpf.attach_uprobe(name=libc_path, sym=dlsym_sym, fn_name="trace_dlsym")
            bpf.attach_uprobe(
                name=libc_path, sym=mprotect_sym, fn_name="trace_mprotect"
            )
        if args.behavior == "RDT":
            bpf.attach_uprobe(name=libc_path, sym=open_sym, fn_name="trace_open")
            bpf.attach_uprobe(name=libc_path, sym=fopen_sym, fn_name="trace_fopen")
            bpf.attach_uprobe(name=libc_path, sym=openat_sym, fn_name="trace_openat")
            bpf.attach_uprobe(name=libc_path, sym=strstr_sym, fn_name="trace_strstr")
            bpf.attach_uprobe(name=libc_path, sym=strcmp_sym, fn_name="trace_strcmp")
            bpf.attach_uprobe(name=libc_path, sym=strncmp_sym, fn_name="trace_strncmp")
            bpf.attach_uprobe(
                name=libc_path, sym=sys_proper_get_sym, fn_name="trace_sys_proper_get"
            )
            bpf.attach_uprobe(
                name=libc_path, sym=sys_proper_read_sym, fn_name="trace_sys_proper_read"
            )
            bpf.attach_uprobe(name=libc_path, sym=execve_sym, fn_name="trace_execve")
            bpf.attach_uprobe(name=libc_path, sym=access_sym, fn_name="trace_access")
    bpf["Dex_event"].open_perf_buffer(Dex_event)
    bpf["CodeItem_event"].open_perf_buffer(CodeItem_event)
    while True:
        bpf.perf_buffer_poll()


try:
    run()
except KeyboardInterrupt:
    final_Dex_process()
    exit()

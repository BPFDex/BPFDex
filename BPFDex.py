from bcc import BPF
import argparse

DexOpen_sym='' #replace with your symbol
DexFile_sym='' #replace with your symbol
OpenMemory_sym='' #replace with your symbol
DexOpenFile_sym='' #replace with your symbol
DefineClass_sym='' #replace with your symbol
LoadMethod_sym='' #replace with your symbol
ExecuteSwith_sym='' #replace with your symbol
ExecuteGoto_sym='' #replace with your symbol
strstr_sym='' #replace with your symbol
strcmp_sym='' #replace with your symbol
strncmp_sym='' #replace with your symbol
open_sym='' #replace with your symbol
fopen_sym='' #replace with your symbol
openat_sym='' #replace with your symbol
ptrace_sym='' #replace with your symbol
gDeggbugger_sym='' #replace with your symbol
sys_proper_get_sym='' #replace with your symbol
sys_proper_read_sym='' #replace with your symbol
execve_sym='' #replace with your symbol
access_sym='' #replace with your symbol
dlsym_sym='' #replace with your symbol
mprotect_sym='' #replace with your symbol
gettimeofday_sym='' #replace with your symbol
time_sym='' #replace with your symbol

libart_path='' #replace with your path
libc_path='' #replace with your path


bpf_c_code = open("BPFDex.c").read()
bpf = BPF(text=bpf_c_code)
dex_index=0
size_list=[]
addr_list=[]

parser = argparse.ArgumentParser(description='unpacking Android apps by eBPF')
parser.add_argument('uid', help='uid of the target app')
parser.add_argument('--insExtract', '-i', action='store_true', help='turn on when the packer extracts instructions of Dex')
parser.add_argument('--behavior', '-b', type=str, default=None, help='''
                    input the behavior you want to monitor
                    EMU               ---emulator detection
                    DBG               ---debugger detection
                    DBI               ---DBI detection
                    TCK               ---time check
                    SLH               ---lib hook
                    RTD               ---root detection
                    ''')
args = parser.parse_args()
bpf['UID'][0]=args.uid

def Dex_event(cpu, data, size):
    global size_list,addr_list
    event = bpf["Dex_event"].event(data)
    print("pid:{1}     tgid:{2}     uid:{6}    comm:{0}     arg1:{3}    arg2:{4}     magic:{5}".format(
        event.comm, event.pid, event.tgid, event.arg1,event.arg2,event.magic,event.uid))
    if((event.arg2 not in size_list )or(event.arg1 not in addr_list)):
        Dump_Dex_via_mem(event.pid,event.arg1,event.arg2)
        
def Dump_Dex_via_mem(pid,addr,size):
    global dex_index,size_list
    mem=open("/proc/{0}/mem".format(pid),"rb+")
    mem.seek(addr)
    dex=open(file="{0}.dex".format(dex_index),mode="wb")
    try:
        res=mem.read(size)
    except IOError:
        print("unable to dump")
    else:
        print("complete {0}.dex".format(dex_index))
        dex.write(res)
        mem.close()
        dex.close()
        dex_index+=1
        size_list.append(size)
        
def Dump_Dex_via_prob(pid,addr,size):
    
def run():
    if(args.insExtract!=True ):
        #DexOpen
        bpf.attach_uprobe(name=libart_path, sym=DexOpen_sym, fn_name="trace_DexOpen")
        #DexFile
        bpf.attach_uprobe(name=libart_path, sym=DexFile_sym, fn_name="trace_DexFile")
        #DexOpenFile
        bpf.attach_uprobe(name=libart_path, sym=DexOpenFile_sym, fn_name="trace_DexOpenFile")
        #OpenMemory
        bpf.attach_uprobe(name=libart_path, sym=OpenMemory_sym, fn_name="trace_OpenMemory")
    elif(args.insExtract==True ):
        #DexOpen
        bpf.attach_uprobe(name=libart_path, sym=DexOpen_sym, fn_name="trace_DexOpen")
        #DexFile
        bpf.attach_uprobe(name=libart_path, sym=DexFile_sym, fn_name="trace_DexFile")
        #DexOpenFile
        bpf.attach_uprobe(name=libart_path, sym=DexOpenFile_sym, fn_name="trace_DexOpenFile")
        #OpenMemory
        bpf.attach_uprobe(name=libart_path, sym=OpenMemory_sym, fn_name="trace_OpenMemory")
        #ExecuteGoto
        bpf.attach_uprobe(name=libart_path, sym=ExecuteGoto_sym, fn_name="trace_ExecuteGoto")
        #ExecuteSwith
        bpf.attach_uprobe(name=libart_path, sym=ExecuteSwith_sym, fn_name="trace_ExecuteSwith")
    if(args.behavior!=None):
        if(args.behavior=='EMU'):
            bpf.attach_uprobe(name=libc_path, sym=open_sym, fn_name="trace_open")
            bpf.attach_uprobe(name=libc_path, sym=fopen_sym, fn_name="trace_fopen")
            bpf.attach_uprobe(name=libc_path, sym=openat_sym, fn_name="trace_openat")
            bpf.attach_uprobe(name=libc_path, sym=sys_proper_get_sym, fn_name="trace_sys_proper_get")
            bpf.attach_uprobe(name=libc_path, sym=sys_proper_read_sym, fn_name="trace_sys_proper_read")
            bpf.attach_uprobe(name=libc_path, sym=strstr_sym, fn_name="trace_strstr")
            bpf.attach_uprobe(name=libc_path, sym=strcmp_sym, fn_name="trace_strcmp")
            bpf.attach_uprobe(name=libc_path, sym=strncmp_sym, fn_name="trace_strncmp")
        if(args.behavior=='DBG'):
            bpf.attach_uprobe(name=libc_path, sym=gDeggbugger_sym, fn_name="trace_gDebugger")
            bpf.attach_uprobe(name=libc_path, sym=ptrace_sym, fn_name="trace_ptrace")
            bpf.attach_uprobe(name=libc_path, sym=open_sym, fn_name="trace_open")
            bpf.attach_uprobe(name=libc_path, sym=fopen_sym, fn_name="trace_fopen")
            bpf.attach_uprobe(name=libc_path, sym=openat_sym, fn_name="trace_openat")
            bpf.attach_uprobe(name=libc_path, sym=strstr_sym, fn_name="trace_strstr")
            bpf.attach_uprobe(name=libc_path, sym=strcmp_sym, fn_name="trace_strcmp")
            bpf.attach_uprobe(name=libc_path, sym=strncmp_sym, fn_name="trace_strncmp")
        if(args.behavior=='DBI'):
            bpf.attach_uprobe(name=libc_path, sym=open_sym, fn_name="trace_open")
            bpf.attach_uprobe(name=libc_path, sym=fopen_sym, fn_name="trace_fopen")
            bpf.attach_uprobe(name=libc_path, sym=openat_sym, fn_name="trace_openat")
            bpf.attach_uprobe(name=libc_path, sym=strstr_sym, fn_name="trace_strstr")
            bpf.attach_uprobe(name=libc_path, sym=strcmp_sym, fn_name="trace_strcmp")
            bpf.attach_uprobe(name=libc_path, sym=strncmp_sym, fn_name="trace_strncmp")
        if(args.behavior=='TCK'):
            bpf.attach_uprobe(name=libc_path, sym=gettimeofday_sym, fn_name="trace_gettimeofday")
            bpf.attach_uprobe(name=libc_path, sym=time_sym, fn_name="trace_time")
        if(args.behavior=='SLH'):
            bpf.attach_uprobe(name=libc_path, sym=dlsym_sym, fn_name="trace_dlsym")
            bpf.attach_uprobe(name=libc_path, sym=mprotect_sym, fn_name="trace_mprotect")
        if(args.behavior=='RDT'):
            bpf.attach_uprobe(name=libc_path, sym=open_sym, fn_name="trace_open")
            bpf.attach_uprobe(name=libc_path, sym=fopen_sym, fn_name="trace_fopen")
            bpf.attach_uprobe(name=libc_path, sym=openat_sym, fn_name="trace_openat")
            bpf.attach_uprobe(name=libc_path, sym=strstr_sym, fn_name="trace_strstr")
            bpf.attach_uprobe(name=libc_path, sym=strcmp_sym, fn_name="trace_strcmp")
            bpf.attach_uprobe(name=libc_path, sym=strncmp_sym, fn_name="trace_strncmp")
            bpf.attach_uprobe(name=libc_path, sym=sys_proper_get_sym, fn_name="trace_sys_proper_get")
            bpf.attach_uprobe(name=libc_path, sym=sys_proper_read_sym, fn_name="trace_sys_proper_read")
            bpf.attach_uprobe(name=libc_path, sym=execve_sym, fn_name="trace_execve")
            bpf.attach_uprobe(name=libc_path, sym=access_sym, fn_name="trace_access")
    bpf["Dex_event"].open_perf_buffer(Dex_event)
    while True:
        bpf.perf_buffer_poll()
try:
    run()
except KeyboardInterrupt:
    exit()
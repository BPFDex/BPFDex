# import bcc
import argparse
import os
import androguard
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

libart_path='' #replace with your path
libc_path='' #replace with your path


# bpf_c_code = open("BPFDex.c").read()
# bpf = BPF(text=bpf_c_code)

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
def run():
    if(args.insExtract!=True and args.behavior==None):
        #DexOpen
        bpf.attach_uprobe(name=libart_path, sym=DexOpen_sym, fn_name="trace_DexOpen")
        #DexFile
        bpf.attach_uprobe(name=libart_path, sym=DexFile_sym, fn_name="trace_DexFile")
        #DexOpenFile
        bpf.attach_uprobe(name=libart_path, sym=DexOpenFile_sym, fn_name="trace_DexOpenFile")
        #OpenMemory
        bpf.attach_uprobe(name=libart_path, sym=OpenMemory_sym, fn_name="trace_OpenMemory")
        #DefineClass
        bpf.attach_uprobe(name=libart_path, sym=DefineClass_sym, fn_name="trace_DefineClass")
        #ExecuteGoto
        bpf.attach_uprobe(name=libart_path, sym=ExecuteGoto_sym, fn_name="trace_ExecuteGoto")
        #ExecuteSwith
        bpf.attach_uprobe(name=libart_path, sym=ExecuteSwith_sym, fn_name="trace_ExecuteSwith")
    # bpf["trace_event"].open_perf_buffer(output)
    # while True:
    #     bpf.perf_buffer_poll()
try:
    run()
except KeyboardInterrupt:
    exit()
from bcc import BPF
import ctypes
import os
import sys

file_path = "/home/wss/.zhuoyi/common/rootfs/system/lib/libc.so"
file_sym = "strstr"
bpf_c_code = open("behaviors.c").read()
bpf = BPF(text=bpf_c_code)
str1=[]
str2=[]

#strings = ["emulator", "qemu", "drivers", "goldfish", "intel", "genymotion","blackdex","vbox"]#emulator
#strings = ["/statu", "tracerpid"]#debug
strings = ["frida",  "tcp",'xposed','edxp']#DBI
#strings = ["superuser", "debugg", "su", "ro.build.type", "ro.build.tags", "busybox"]#root
def output(cpu, data, size):
    global size_list,addr_list
    event = bpf["trace_event"].event(data)
    if event.comm==b"ng_shao.vm_test" :
    # print("pid:{1}     tgid:{2}     comm:{0}     arg1:{3}    arg2:{4}     str1:{5}     str2:{6} ".format(
    #         event.comm, event.pid, event.tgid, event.arg1,event.arg2,event.str1,event.str2))
        str1.append(event.str1)
        str2.append(event.str2)

def run():
    bpf.attach_uprobe(name=file_path, sym=file_sym, fn_name="trace_strncmp")
    bpf["trace_event"].open_perf_buffer(output)
    while True:
        bpf.perf_buffer_poll()
try:
    run()
except KeyboardInterrupt:
    os.system("clear")
    for i in range (len(str1)):
        try:
            str1[i]=str1[i].decode('utf-8')
        except :
            str1[i]=""
            str2[i]=""
        try:
            str2[i]=str2[i].decode('utf-8')
        except :
            str1[i]=""
            str2[i]=""
    for i in range (len(str1)):
        for j in strings:
            if j in str1[i].lower() or j in str2[i].lower():
                print("str1:"+str1[i]+"    str2:"+str2[i])
    exit()
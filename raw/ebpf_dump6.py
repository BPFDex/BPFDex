#!/usr/bin/python
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes
import os
import sys

file_path = "/home/wss/.zhuoyi/common/rootfs/system/lib64/libart.so"
file_sym = "_ZN3art7DexFileC2EPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileE"
bpf_c_code = open("ebpf_dump6.c").read()
bpf = BPF(text=bpf_c_code)
dex_index=0
size_list=[]
addr_list=[]

def output(cpu, data, size):
    global size_list,addr_list
    event = bpf["trace_event"].event(data)
    print("pid:{1}     tgid:{2}     comm:{0}     arg1:{3}    arg2:{4}     magic:{5}".format(
        event.comm, event.pid, event.tgid, event.arg1,event.arg2,event.magic))
    if(event.comm.decode('utf-8')=="ng_shao.vm_test"):
        if((event.arg2 not in size_list )or(event.arg1 not in addr_list)):
            dex_output(event.pid,event.arg1,event.arg2)

    
def dex_output(pid,addr,size):
   global dex_index,size_list
   mem=open("/proc/{0}/mem".format(pid),"rb+")
   mem.seek(addr)
   dex=open(file="/home/wss/{0}.dex".format(dex_index),mode="wb")
   try:
        res=mem.read(size)
   except IOError:
        print("未成功捕获内存")
   else:
        print('complete')
        dex.write(res)
        mem.close()
        dex.close()
        dex_index+=1
        size_list.append(size)
        addr_list.append(addr)

def run():
    bpf.attach_uprobe(name=file_path, sym=file_sym, fn_name="trace_DexFile")
    bpf["trace_event"].open_perf_buffer(output)
    while True:
        bpf.perf_buffer_poll()
try:
    run()
except KeyboardInterrupt:
    exit()

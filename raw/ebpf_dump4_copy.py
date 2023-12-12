#!/usr/bin/python
# -*- coding: utf-8 -*-
from bcc import BPF, utils
from ctypes import *
import time
import struct

# class CodeItem(Structure):
#     _fields_ = [
#         #(字段名, c类型 )
#         ('registers_size_',c_uint16),
#         ('ins_size_', c_uint16),
#         ('outs_size_', c_uint16),
#         ('tries_size_', c_uint16),
#         ('debug_info_off_',c_uint32),
#         ('insns_size_in_code_units_', c_uint32),
#     ]

file_path = "/home/wss/.zhuoyi/common/rootfs/system/lib/libart.so"
file_sym = "_ZN3art11interpreterL7ExecuteEPNS_6ThreadEPKNS_7DexFile8CodeItemERNS_11ShadowFrameENS_6JValueEb"
bpf_c_code = open("ebpf_dump4_copy.c").read()
bpf = BPF(text=bpf_c_code)
index=0
item=0
insns_file=open("/home/wss/insns","ab+")

# code_item=CodeItem()

def output(cpu, data, size):
    global index,timer,item#code_item
    event = bpf["trace_event"].event(data)
    map_code = bpf["code_item_table"]
    print(index)
    print("pid:{1}     tgid:{2}     uid:{4}     comm:{0}     addr:{3}   ".format(
        event.comm, event.pid, event.tgid, event.addr, event.uid))
    try:
        item = map_code[c_int(index)] 
    except KeyError:
        return
    else:
        insns_dump(item.addr,item.insns_size_in_code_units_*2,event.tgid)
        index+=1

def insns_dump(addr,size,pid):
    global insns_file
    try:
        mem=open("/proc/{0}/mem".format(pid),"rb+")
    except FileNotFoundError:
        return
    else:
        mem.seek(addr)
        try:
            res=mem.read(size)
        except IOError:
            print("未成功捕获内存")
        else:
            print('complete')
            insns_file.write(res)
            mem.close()

def run():
    bpf.attach_uprobe(name=file_path, sym=file_sym, fn_name="trace_DexFile")
    bpf["trace_event"].open_perf_buffer(output)
    while True:
        bpf.perf_buffer_poll()

try:
    run()
except KeyboardInterrupt:
    insns_file.close()
    exit()

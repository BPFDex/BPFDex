#!/usr/bin/python
# -*- coding: utf-8 -*-
from bcc import BPF, utils
from ctypes import *
import binascii

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
bpf_c_code = open("ebpf_dump4.c").read()
bpf = BPF(text=bpf_c_code)
insns_file = open("/home/wss/insns", "wb+")
insns_file2 = open("/home/wss/insns.txt", "w+")
index=0
count=0
result_code=[]
result_addr=[]
# code_item=CodeItem()


def output(cpu, data, size):
    global index
    event = bpf["trace_event"].event(data)
    print("pid:{1}     tgid:{2}     uid:{3}     comm:{0}     insns_addr:{4}     units:{5}      addr:{6}".format(
        event.comm, event.pid, event.tgid, event.uid,event.insns_addr, event.insns_size_in_code_units_,event.addr))
    if(event.insns_addr!=0 and event.insns_size_in_code_units_!=0):
        insns_dump(event.insns_addr, event.insns_size_in_code_units_*2, event.tgid)


def insns_dump(addr, size, pid):
    global insns_file,count,result_addr,result_code
    try:
        mem = open("/proc/{0}/mem".format(pid), "rb+")
    except FileNotFoundError:
        print("未找到内存")
        return
    else:
        mem.seek(addr)
        try:
            res = mem.read(size)
        except IOError:
            print("未成功捕获内存")
        else:
            count+=1
            result_code.append(res)
            result_addr.append(addr)
            print("::"+str(count))
            mem.close()
            print('complete')


def run():
    bpf.attach_uprobe(name=file_path, sym=file_sym, fn_name="trace_DexFile")
    bpf["trace_event"].open_perf_buffer(output)
    while True:
        bpf.perf_buffer_poll()


try:
    run()
except KeyboardInterrupt:
    for i in range(len(result_code)):
        insns_file.write(result_code[i])
        insns_file2.write("{{addr:{0}}}".format(result_addr[i])+",{insns:"+result_code[i].hex()+"}\n")
    insns_file.close()
    insns_file2.close()
    exit()

import binascii
insns_file=open("insns.txt",'r')
dex_record=open('dex_record.txt','r')
dex_addr_list=[]
dex_size_list=[]
insns_addr_list=[]
insns_offset_list=[]
insns_list=[]
match=[]

def data_input():
    global dex_addr_list,insns_list,insns_addr_list,dex_size_list,insns_file,dex_record
    line=dex_record.readline()
    while(line):
        line=line.split(",")
        dex_addr_list.append(line[1][5:-1])
        dex_size_list.append(line[2][5:-2])
        line=dex_record.readline()
    dex_record.close()
    line=insns_file.readline()
    while(line):
        line=line.split(",")
        insns_addr_list.append(line[0][5:-1])
        insns_list.append(line[1][4:-2])
        line=insns_file.readline()
    insns_file.close()

def data_prepare():
    global dex_addr_list,insns_list,insns_addr_list,dex_size_list,match,insns_offset_list
    for i in range(len(insns_addr_list)):
        multi=False
        for j in range(len(dex_addr_list)):
            if(multi==True and int(dex_addr_list[j])<int(insns_addr_list[i])<int(dex_addr_list[j])+int(dex_size_list[j])):
                match[i]=-1
            if(multi==False and int(dex_addr_list[j])<int(insns_addr_list[i])<int(dex_addr_list[j])+int(dex_size_list[j])):
                insns_offset_list[i]=(int(insns_addr_list[i])-int(dex_addr_list[j]))
                match[i]=j
                multi=True
            
def dex_process():
    global match,insns_offset_list
    for i in range(len(match)):
        if(match[i]!=-1):
            dex=open('{0}.dex'.format(match[i]),'rb+')
            dex.seek(insns_offset_list[i])
            dex.write(binascii.unhexlify(insns_list[i]))
            dex.close()
            
data_input()
data_prepare()
dex_process()
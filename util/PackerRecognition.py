import Packer_Features
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
import os

apk_path = r""  # replace with your apk
apk = APK(apk_path)
dvm = DalvikVMFormat(apk.get_dex())
for packer in Packer_Features:
    method_count=0
    class_count=0
    library_count=0
    for cls in dvm.get_classes():
        for class_name in packer.classes:
            if class_name in cls.get_name():
                print("found  class:", cls.get_name())
                class_count+=1
        for method in cls.get_methods():
            for method_name in packer.methods:
                if method_name in method.get_name():
                    print("method:", method.get_name())
                    method_count+=1
    files=apk.get_files()
    libraries=[]
    for  file_name in files:
        if ".so" or ".bat" in file_name:
            libraries.append(file_name)
    for library_name in packer.libraries:
        for item in libraries:
            if library_name in item:
                print(library_name)
                library_count+=1
    #replace weights            
    w1=0.1
    w2=0.3
    w3=0.6
    similarity=w1*(method_count/len(packer.methods))+w2*(class_count/len(packer.classes))+w3*(library_count/len(packer.libraries))
    if similarity>0:
        print("similarity: "+ str(similarity))
        print("Packer:"+packer.name)
        break
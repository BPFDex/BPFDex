from androguard.core.bytecodes.apk import APK
import os
import shutil
def extract_package_name(apk_path):
    apk_file = APK(apk_path)
    package_name = apk_file.get_package()
    return package_name

def list_files(directory,list):
    for root, dirs, files in os.walk(directory):
        for name in files:
            list.append(os.path.join(root, name))

list1=[]
list2=[]
package_name1=[]
package_name2=[]
directory_path = [r'D:\数据集F-Droid\P-22',r'D:\数据集F-Droid\P-23']
list_files(directory_path[0],list1)
list_files(directory_path[1],list2)
for i in list1:
    apk_path = i
    package_name1 .append(extract_package_name(apk_path))
for i in list2:
    apk_path = i
    package_name2 .append(extract_package_name(apk_path))
 packer_path=[r'D:\数据集F-Droid\ali',r'D:\数据集F-Droid\baidu',r'D:\数据集F-Droid\bangcle',r'D:\数据集F-Droid\ijiami',r'D:\数据集F-Droid\tencent',r'D:\数据集F-Droid\qihoo']
 for i in packer_path:
     apk_list=[]
     list_files(i,apk_list)
     for j in apk_list:
         package=extract_package_name(j)
         if(package in package_name1 ):
             shutil.copy(j, r'D:\数据集F-Droid\P-22-p\{1}-{0}.apk'.format(package,os.path.basename(i)))
         if(package in package_name2):
              shutil.copy(j, r'D:\数据集F-Droid\P-23-p\{1}-{0}.apk'.format(package,os.path.basename(i)))


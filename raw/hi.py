import ctypes
h=ctypes.cdll.LoadLibrary('/home/wss/bcc/test/libhi.so')
a=h.main()
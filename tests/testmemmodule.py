import sys
sys.path.insert(0, '../src')
import memmodule
fdll = open('testdll.dll', 'rb')
buf = fdll.read()
fdll.close()
testdll = memmodule.MemoryLoadLibrary(buf)

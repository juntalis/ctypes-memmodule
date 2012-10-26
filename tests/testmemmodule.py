import sys, os
__dir__ = os.path.abspath(os.path.dirname(__file__))
_root = os.path.dirname(__dir__)
_srcpath = os.path.join(_root, 'src')
_testdll = os.path.join(__dir__, 'testdll.dll')
sys.path.insert(0, _srcpath)
import memmodule
fdll = open(_testdll, 'rb')
buf = fdll.read()
fdll.close()
testdll = memmodule.MemoryLoadLibrary(buf)
initialize = memmodule.MemoryGetProcAddress(testdll, 'Initialize')

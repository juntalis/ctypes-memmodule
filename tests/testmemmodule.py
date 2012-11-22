import sys, os
__dir__ = os.path.abspath(os.path.dirname(__file__))
_root = os.path.dirname(__dir__)
_testdll = os.path.join(__dir__, 'testdll.dll')
sys.path.insert(0, _root)
import memmodule
fdll = open(_testdll, 'rb')
buf = fdll.read()
fdll.close()
testdll = memmodule.MemoryModule(data=buf, debug=True)
initialize = testdll.get_proc_address('Initialize')
testdll.free_library()

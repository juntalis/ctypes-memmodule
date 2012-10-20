#### CTypes MemDLL

This project is currently a WIP. The end goal is to reimplement the awesome [Memory Module](https://github.com/fancycode/MemoryModule) using the built-in Python [ctypes module](http://docs.python.org/library/ctypes.html). If I don't screw up too terribly, this should allow python scripts (on Windows) to load DLLs without the need of having local file present. (So, from zip files, binary strings hardcoded into the script, downloaded URLs in memory, etc) Following the implementation of the actual MemoryModule code, I should be able to wrap the functions with a class inheriting from CDLL and have it work similar to the standard CDLL/WinDLL variations.

This is more or less just a source-source translation from C to Python, so all the credit really goes to [Joachim Bauch](http://www.joachim-bauch.de), the original author of the MemoryModule project.

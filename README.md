#### CTypes MemDLL

**BIGGER NOTE:** This is an abandoned, non-functional project. In hindsight, I went the wrong direction with this, but I no longer have the motivation, nor the interest to pursue it any further. In the meantime, I'm leaving the repository in hopes that it may be helpful to someone. (If for nothing else but the `ctypes.Structure` classes)

**Note:** I've given up on trying to implement this using pure ctypes. Trying to do all the type conversions and pointer match necessary to make this work properly is just too much of a pain in the ass with ctypes. I'm considering giving it another shot by simply modifying the pefile module to VirtualAlloc and apply the necessary ctypes calls as it parses the PE, but we'll see.

This project is currently a WIP. The end goal is to reimplement the awesome [Memory Module](https://github.com/fancycode/MemoryModule) using the built-in Python [ctypes module](http://docs.python.org/library/ctypes.html). If I don't screw up too terribly, this should allow python scripts (on Windows) to load DLLs without the need of having local file present. (So, from zip files, binary strings hardcoded into the script, downloaded URLs in memory, etc) Following the implementation of the actual MemoryModule code, I should be able to wrap the functions with a class inheriting from CDLL and have it work similar to the standard CDLL/WinDLL variations.

This is more or less just a source-source translation from C to Python, so all the credit really goes to [Joachim Bauch](http://www.joachim-bauch.de), the original author of the MemoryModule project.

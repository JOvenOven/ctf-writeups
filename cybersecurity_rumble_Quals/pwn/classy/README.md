# Classy

## Description

> Not everyone can be sophisicated enough to get a flag. Can you?
>
> nc rumble.host 9797
>
> Author: lukas
>
> [`classy.tar.gz`](classy.tar.gz)

Tags: _pwn, bby_

## Solution

This is a C++ program where the users can "talk" about wine, cheese or flags and the system answer depending on the users' "connoisseur level": 1 is for low level, and 2 is for high level.

```
$ ./classy
What is your Connoisseur level?
1
What do you want to talk about?
[1] Wine
[2] Cheese
[3] Flags
[4] I think I know enough now to be a higher level.
3
Now what do you want to tell me?
a
Your level of intellectual engagement is undeniably intriguing; however, regrettably, your grasp of the necessary erudition to engage in discourse pertaining to flagology appears to be somewhat deficient.

```

While reviewing the source code, I noticed that high level connoisseur users can obtain the flag by talking with the system about flags. To achieve such a high user level, you need to provide the correct password. Therefore, the goal here is to find the password or bypass the login autentication somehow.

Before attempting any advanced manipulation of the stack or heap, I initially attempted to use the password "hunter" that was hardcoded in the source code, but it was unsuccessful. Subsequently, I began debugging the binary using a GDB plugin called `pwndbg` (although the challenge can be solved using regular GDB) to investigate whether the password was concealed within the binary itself:

1. Start the GDB debugger

```
$ gdb classy
```

2. Run the program with the command `r` or `run`, and interrupt its execution by pressing `Ctrl+C`

```
pwndbg> r
What is your Connoisseur level?
^C
```

3. Finally print the password variable using the command `p` or `print`

```
pwndbg> p password
$1 = "55aefb4ca5630cc73a981e9d642324fc"
```

Waos!, that MD5 hash really looks like a password, let's try it out.

```
$ nc rumble.host 9797
What is your Connoisseur level?
2
Please provide the password:
55aefb4ca5630cc73a981e9d642324fc
What do you want to talk about?
[1] Wine
[2] Cheese
[3] Flags
[4] I think I know enough now to be a higher level.
3
Now what do you want to tell me?
a
Behold, in the realm of symbolism, we find a captivating tapestry unfurled before us. A flag of mesmerizing allure, adorned with the cryptic inscription CSR{welc0me_to_h1gh_society}, invites us to embark on an enigmatic journey. This flag, a visual expression of identity, bears the essence of a selective community, an elevated echelon that beckons us into the realm of opulence and privilege.
CSR{welc0me_to_h1gh_society}encapsulates an enigmatic passphrase that whispers the secrets of an exclusive enclave. It tantalizes the inquisitive mind, alluding to an inner circle where societal elevation resides. A cipher of hidden prestige, it evokes a realm where social strata intertwine with cultural refinement, offering a glimpse into the rarified atmosphere of the upper echelons of human existence.
Within the fibers of this resplendent standard, a narrative unfolds, laden with aspirations of grandeur and aspirations of social ascent. Its vibrant hues weave a tale of aspiration, promising a world where elegance and refinement reign supreme. This flag, a beacon of high society, speaks to the pursuit of sophistication, bespoke experiences, and the embrace of refined pleasures.
As we gaze upon this mesmerizing flag, we are transported to a dimension where exclusivity intertwines with glamour, and societal conventions intertwine with whispered secrets. It stirs our imagination, inviting us to venture beyond the ordinary and embrace the allure of the extraordinary. CSR{welc0me_to_h1gh_society}, a key to a world veiled in prestige, invites us to explore the realms of privilege and indulge in the alluring mystique of high society.

...
```

We did it!, we found the flag among refined verses.

Flag `CSR{welc0me_to_h1gh_society}`

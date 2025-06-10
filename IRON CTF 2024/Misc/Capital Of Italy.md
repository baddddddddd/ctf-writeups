![[Screenshot_20241007_204957.png]]

For this pyjail challenge, we are given the source code.
![[Screenshot_20241007_205047.png]]

We must take note of the following based on the source code:
1. We don't know the variable name of the flag.
2. We don't know the blacklisted characters.
3. We are not allowed to use `breakpoint()`, since it's resolved as a string here.
4. Our input cannot be more than 12 characters long.
5. Our input is only ran through the eval() function, and the output is not automatically printed.

To approach this challenge, I first checked what are the blacklisted characters by running this script:

```python
#!/usr/bin/env python3

from pwn import *
import string

HOST = "misc.1nf1n1ty.team"
PORT = 30010

def conn():
    global HOST, PORT
    io = remote(HOST, PORT)
    return io


def main():
    charset = string.printable[:-5]

    blacklist = ""
    
    for i in range(0, len(charset)):
        try:
            inp = charset[i]
            io = conn()
            io.sendlineafter(b'WELCOME :)\n', inp)

            io.recvuntil(b'Blocked Character: ', timeout=2)
            output = io.recvline().decode().strip()
            blacklist += output
            log.info(f'Input: {inp}')
            log.info(f"Blocked: {output}")

            io.close()
        except:
            log.warn(f"Failed on {inp}")

    log.success(f"Blacklist: {blacklist}")


if __name__ == "__main__":
    main()
```
![[Screenshot_20241007_210158.png]]

Running this script, turns out all printable ascii characters except `(` and `)` are blacklisted.

However, in Python's eval() function, denormalized unicode characters in the input string are converted back to their ASCII character equivalent.  For example, `ｐｒｉｎｔ()` will be converted back to `print()`, let's check if these unicode characters are not blocked.

![[Screenshot_20241007_210659.png]]

Turns out its not! With this, we can try printing out the values of the variables for the currently running python module, `__main__`,  by inputting `__main__` in the help utility. 

![[Screenshot_20241007_210823.png]]

And we can see the flag in plainsight, `ironCTF{R0M4N_T1mes}`

Summary:
1. In this pyjail challenge, ASCII characters except `(` and `)` are blacklisted, our input is also limited to at most 12 characters only.
2. The blacklist can by bypassed by using unicode characters because Python's `eval()` function normalizes these characters to their respective ASCII equivalent.
3. We can then just use the `help()` function to access Python's help utility to get a peek at the values of the variables of the `__main__` module, which is refers to the current main python program that is running, to get the flag.

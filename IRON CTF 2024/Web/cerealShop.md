Summary:
1. Inspecting the source code, there was a secret message that hinted `?file=` and `/source`
2. Use the LFI vulnerability to get the source file in `/?file=/source`
3. Inspecting the source code, the PHP page checks for `can_you_get_me` cookie and retrieves the value. That value is decoded from base64 and ran through PHP's `unserialize()` function, which means we have Insecure Deserialization vulnerability.
4. To get the flag, the unserialized `Admin` object is check whether `is_admin == 0` and `your_secret === my_secret`. The catch is that after the deserialization of our payload, `my_secret` is set to the value of `FLAG`, which we don't know the value of. To pass these checks, create a PHP object that has `is_admin = 0` as value and 

![[Screenshot_20241007_121903.png]]
![[Screenshot_20241007_121933.png]]
Flag: `ironCTF{D353r1411Z4710N_4T_1T5_B35T}`
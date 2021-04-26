#!/usr/bin/env python3
from pwn import *

# context.log_level = "debug"

p = remote("127.0.0.1", 4444)

if args.BIN:
    bin_filename = args.BIN
else:
    bin_filename = "main"

log.info(f"bin_filename: {bin_filename}")

with open(bin_filename, "rb") as f:
    payload = f.read()

size = len(payload)
p.recvuntil("Send me the length of your file, then just cat the file in after it\n")
p.sendline(str(size))
log.info(p.recvline())
p.send(payload)

p.interactive()

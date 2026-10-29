---
name: ctf-rev
description: >-
  Activate this skill when a CTF challenge requires reverse engineering a binary,
  analyzing obfuscated code, cracking license checks, or understanding how a
  program works to extract a flag. Covers static RE, dynamic analysis, symbolic
  execution, and anti-analysis bypass.
---

# CTF Reverse Engineering Skill

## Step 1 — Static Analysis
```bash
# File info
file <binary>
checksec --file=<binary>
strings <binary> | grep -i flag

# Disassembly
objdump -d <binary> -M intel | head -200
# Or Ghidra / IDA Free / Binary Ninja / Cutter (GUI)
```

## Step 2 — Decompilation (Ghidra)
1. Import binary → Analyze (defaults OK)
2. Open Symbol Tree → Functions
3. Find `main`, `check`, `validate`, `verify` functions
4. Look for string comparisons: `strcmp`, `strncmp`, `memcmp`
5. Right-click interesting strings → References → Find flag

## Step 3 — Dynamic Analysis
```bash
# Run under GDB with pwndbg
gdb ./<binary>
(gdb) r
(gdb) break *<address>
(gdb) x/s $rdi        # examine string in register

# ltrace / strace
ltrace ./<binary>      # library calls — spot strcmp(input, flag)
strace ./<binary>      # syscalls

# GDB scripting
gdb -ex "set args test_input" -ex "break strcmp" -ex "run" -ex "x/s \$rsi" ./<binary>
```

## Step 4 — Symbolic Execution (angr)
```python
import angr, claripy

proj = angr.Project('./<binary>', auto_load_libs=False)
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(40)]
flag = claripy.Concat(*flag_chars)

state = proj.factory.entry_state(stdin=angr.SimFile(name='stdin', content=flag, size=40))

# Constrain to printable ASCII
for c in flag_chars:
    state.solver.add(c >= 0x20, c <= 0x7e)

sm = proj.factory.simulation_manager(state)
sm.explore(find=<success_addr>, avoid=<fail_addr>)

if sm.found:
    s = sm.found[0]
    print(s.solver.eval(flag, cast_to=bytes))
```

## Step 5 — Anti-Analysis Bypass
```bash
# Anti-debugging bypass
# Patch ptrace calls in binary
# Set LD_PRELOAD with fake ptrace()

# Packing/Obfuscation
# Detect packer: Detect-It-Easy (DIE), ExeinfoPE
# UPX: upx -d <binary>
# Custom: dynamic analysis → dump unpacked from memory

# Timing checks → nop out sleep/alarm calls
```

## Common CTF Rev Patterns
- **strcmp/strncmp**: Input compared directly to flag — catch with `ltrace`
- **Checksum loop**: XOR/ADD operations on input vs constant — reverse the math
- **VM/bytecode**: Custom VM interpreting bytecode — disassemble the VM
- **Obfuscated JS/Python**: `eval(atob(...))` or exec(compile(...)) — dump the deobfuscated code
- **License key validation**: Identify algorithm, write keygen

## Language-Specific
```bash
# Python pyc
uncompyle6 <file.pyc> > decompiled.py
# or: decompile3 <file.pyc>

# Java .class / .jar
jadx <file.jar>  # GUI decompiler
cfr <file.jar> --outputdir ./decompiled/

# .NET
dnSpy <binary.exe>
ilspy <binary.exe>

# Rust/Go → Ghidra with plugins
```

## Structured Output
```json
{
  "agent": "ctf-rev",
  "binary_type": "",
  "key_functions": [],
  "algorithm_identified": "",
  "flag_candidates": [],
  "confidence": 0.0
}
```

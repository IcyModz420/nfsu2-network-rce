# NFS Underground 2 — Network Remote Code Execution

Two remote code execution vulnerabilities discovered in Need for Speed: Underground 2 (SPEED2.EXE). This repository contains a working proof-of-concept for one of them.

## Vulnerabilities

| # | Vector | Description | Status |
|---|--------|-------------|--------|
| 1 | TCP certificate handler (state 0xb) | Unbounded memcpy → pool free-list corruption → DWORD shoot | **Working PoC** |
| 2 | UDP game session | Heap overflow via oversized packet | **Identified** |

## Target

| | |
|---|---|
| **Binary** | SPEED2.EXE (32-bit x86 PE) |
| **SHA-256** | `8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297` |
| **ASLR** | None — fixed base `0x00400000` |
| **DEP** | None — `/NXCOMPAT` not set |
| **SafeSEH** | None |
| **Online servers** | Shut down by EA in 2007 |

## Vulnerability #1 — Unbounded Copy → DWORD Shoot → Code Execution

### Overview

When the game connects to the authentication server (port 20971), it performs a TLS-like handshake. The certificate handler copies attacker-controlled data into a heap buffer with **no bounds check**. This overflows into the adjacent pool allocator free-list node, giving the attacker control over the allocator's linked-list pointers.

When the connection closes and the buffer is freed, the pool allocator's coalesce logic performs a controlled 4-byte write (DWORD shoot) to a function pointer in the `.data` section. The next pool allocation jumps through the overwritten pointer into attacker-supplied shellcode.

**A single TCP packet achieves arbitrary code execution. The game's own code handles every step.**

### Exploit Chain

```
1. Game connects to auth server on port 20971
2. Server replies with a crafted X.509 certificate
3. CA validation passes — issuer DN matches EA's hardcoded root CA
4. Signature verification bypassed — rsaEncryption OID causes
   CMPSB to compare zero bytes (always succeeds)
5. Unbounded memcpy copies attacker data past the buffer boundary
6. Overflow corrupts the adjacent pool free-list node:
     next → function_pointer - 4
     prev → address of shellcode (past fill zone)
7. A fake node with embedded shellcode is written 32 bytes past
   the free node, outside the debug fill range
8. TCP close triggers buffer free → pool allocator:
     a) Sorted insert into free list
     b) Forward coalesce — merges with corrupted node
     c) Backward coalesce — overwrites function pointer (DWORD shoot)
     d) Debug fill (0xEE) — shellcode survives at node+32
9. Next allocation → JMP through overwritten pointer → shellcode
```

### Pool Allocator

The game uses a custom pool allocator (not the Windows heap). Free blocks form a circular doubly-linked list sorted by address:

```
Free node:    [next:4] [prev:4] [size:4] [magic:4]    magic = 0x44443333
Block header: 20 bytes, magic byte 0x22 at offset 9
Overhead:     20 (header) + name_area_length
```

The free function performs sorted insert, then forward and backward coalesce with adjacent blocks. The coalesce unlink writes to corrupted pointers — this is the arbitrary write primitive.

### Shellcode Bridge

The fake prev node's first 4 bytes get clobbered during the sorted insert step. The bridge handles this:

```asm
[0-3]   Clobbered → 50 BE 7F 00 → PUSH EAX; MOV ESI, imm32
[4-5]   NOP NOP (consumed by MOV ESI's immediate)
[6-7]   JMP SHORT +4 (skip the size field)
[8-11]  Coalesce trigger size (modified during merge, skipped)
[12+]   Position-independent shellcode (105 bytes)
```

### PoC Payload

The proof-of-concept shellcode demonstrates code execution with:
1. Restores the function pointer (game keeps running)
2. `MessageBoxA` — "PWNED" / "NFS Underground 2 RCE!"
3. `ShellExecuteA` — opens calc.exe

## Running the PoC

### Prerequisites

Add to your hosts file (`C:\Windows\System32\drivers\etc\hosts`):
```
127.0.0.1 pcnfs05.ea.com
```

### Steps

1. Double-click **nfsu2_rce_v3.exe** — it opens and waits for a connection
2. Launch NFS Underground 2
3. Navigate to **Online → Use Existing**
4. The exploit runs automatically when the game connects

No admin privileges required. No process injection. No external tools.

## Files

```
poc/
  nfsu2_rce_v3.cs    — Exploit source code (fully commented C#)
  nfsu2_rce_v3.exe   — Compiled PoC (x86, .NET Framework 4.0)
```

## Build

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /platform:x86 /out:nfsu2_rce_v3.exe nfsu2_rce_v3.cs
```

## Tools Used

- [Ghidra](https://ghidra-sre.org/) 12.1.4 via [REA](https://re-anytime.com/) — static analysis and decompilation
- Custom C# exploit (no dependencies beyond .NET Framework 4.0)

## Disclaimer

Security research against an abandoned game whose online servers were shut down in 2007. The vulnerability exists in the original unpatched binary. Published for educational purposes to demonstrate real-world heap exploitation techniques. No active online services are affected.

## License

MIT — see [LICENSE](LICENSE)

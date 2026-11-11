# NFS Underground 2 — Network Remote Code Execution

Two heap buffer overflow vulnerabilities in the Need for Speed Underground 2 multiplayer networking code that achieve **remote code execution** from attacker-controlled network packets.

| | |
|---|---|
| **Product** | Need for Speed Underground 2 (SPEED2.EXE) |
| **Version** | PC (Windows) |
| **Vendor** | Electronic Arts |
| **Platform** | Windows x86 (32-bit PE) |
| **Severity** | Critical (CVSS 3.1: 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Attack vector** | Network (TCP key exchange, UDP game session) |
| **Impact** | Remote code execution — no user interaction beyond joining a game |
| **Date** | November 2026 |

## Attack Scenario

The victim launches the game and joins a multiplayer session — LAN or online. A malicious server (RCE-1) or any peer in the same lobby (RCE-2) sends a single crafted packet. The victim's game overflows a heap buffer with attacker-controlled data, corrupts an adjacent network object's function pointer table, and executes arbitrary code on the next frame tick. No file transfer, no save loading, no user interaction beyond connecting.

## Why This Works

The binary has **zero modern exploit mitigations**:

| Mitigation | Status |
|------------|--------|
| ASLR | **None** — fixed image base `0x00400000` |
| Stack cookies (/GS) | Present but **irrelevant** — overflow targets heap, not stack |
| DEP | **None** — `/NXCOMPAT` not set, heap is executable |
| Packet validation | **None** — attacker-controlled length goes directly to `recv()` |

## Vulnerabilities

| ID | Vector | Location | Trigger | CVSS 3.1 |
|----|--------|----------|---------|----------|
| **RCE-1** | TCP key exchange | `FUN_00759910` | Malicious server or MITM sends crafted handshake response | **9.8 Critical** |
| **RCE-2** | UDP game session | `FUN_007510c0` | Any peer in the same lobby sends one oversized packet | 8.1 High |

Both overflow heap-allocated buffers with attacker-controlled data, corrupt adjacent C++ network objects' function pointer tables (14 entries), and achieve arbitrary code execution through the game's own vtable dispatch mechanism.

## The Exploit Chain

```
Attacker sends crafted packet
    │
    ├── RCE-1: TCP key exchange, header bytes 0xFF 0xFF
    │         → FUN_00759910 parses length as 32,769 bytes
    │         → recv(32769) into 16,388-byte session buffer
    │
    └── RCE-2: UDP game session, length field 0x7FFF
              → FUN_007510c0 parses length as 32,769 bytes
              → recv(32769) into ~1,024-byte circular buffer slot
    │
    ▼
Heap overflow (16,381 or 30,000+ bytes past buffer)
    │
    ▼
Adjacent network object vtable overwritten
(14 function pointers: constructor, destructor, process_packet,
 send, close, listen, accept, configure, stats, read_buffer, ...)
    │
    ▼
Game dispatches through corrupted pointer on next tick
    │
    ▼
Arbitrary code execution
```

## The Recv Wrapper Has No Bounds Checking

All network receive calls flow through `FUN_0074a6d0` at `0x74a6d0`:

```c
// Thin wrapper — passes caller's size directly to Winsock
if (param_5 == NULL)
    recv(*(param_1 + 0x18), param_2, param_3, 0);     // param_3 = attacker-controlled
else
    recvfrom(*(param_1 + 0x18), param_2, param_3, 0, param_5, param_6);
```

No clamping, no bounds check. Whatever length the caller computes from the wire goes straight to `recv()`.

## Trigger Path — How It Fires Automatically

The overflow triggers through the game's normal network update loop, called every frame:

```
Game main loop (FUN_004e6c30 / FUN_004e77a0 / FUN_004f2840)
    → FUN_00584f20 (network subsystem tick)
        → FUN_00740600 (network update)
            → FUN_0074e8e0 (packet processor)
                → FUN_00754490 (TCP state machine)
                    → FUN_00759910 — RCE-1 OVERFLOW
                → vtable dispatch: CALL [peer + 0x30]
                    → FUN_00751660 (read_buffer)
                        → FUN_007510c0 — RCE-2 OVERFLOW
```

No menu navigation, no button press — the game's own frame loop processes incoming packets and fires the overflow.

## Heap Vtable Corruption

The network object factory `FUN_00751940` allocates 0x214 bytes and installs 14 function pointers:

| Offset | Entry | Original Target |
|--------|-------|-----------------|
| +0x00 | constructor | `FUN_00751940` |
| +0x04 | destructor | `FUN_00751490` |
| +0x08 | connect | `LAB_00752200` |
| +0x0C | **process_packet** | `FUN_00757900` |
| +0x10 | send | `FUN_00751750` |
| +0x14 | close | `FUN_00751520` |
| +0x18 | listen | `LAB_00751880` |
| +0x1C | close_alias | `FUN_00751520` |
| +0x20 | accept | `LAB_00751500` |
| +0x24 | configure | `LAB_00753ab0` |
| +0x28 | timestamp | `GetTickCount` |
| +0x2C | stats | `FUN_00751560` |
| +0x30 | **read_buffer** | `FUN_00751660` |
| +0x34 | write_buffer | `LAB_00751700` |

When the overflow corrupts these pointers, the game's own dispatch code (`CALL [object + offset]`) redirects execution to the attacker's chosen address.

## Proof of Concept — Six Proofs, Three Scripts

Each script proves both vectors at a different level of the exploit chain:

| # | Script | Vector | What It Proves |
|---|--------|--------|----------------|
| 1 | `network_rce_proof.js` | RCE-1 (TCP) | 16,381-byte heap overflow past buffer boundary |
| 2 | `network_rce_proof.js` | RCE-2 (UDP) | 30,000+ byte overflow past circular buffer slot |
| 3 | `network_eip_control.js` | RCE-1 (TCP) | 14/14 vtable pointers corrupted to `0x41414141` |
| 4 | `network_eip_control.js` | RCE-2 (UDP) | 14/14 vtable pointers corrupted to `0x41414141` |
| 5 | `network_rce_ace.js` | RCE-1 (TCP) | `MessageBoxA("RCE Succeeded")` via corrupted vtable dispatch |
| 6 | `network_rce_ace.js` | RCE-2 (UDP) | `MessageBoxA("RCE Succeeded")` via corrupted vtable dispatch |

All proofs run inside the game's own address space via Frida. No network traffic is sent — each script allocates heap buffers matching the real structures, replicates the exact overflow geometry, and verifies every corrupted byte.

See [`poc/README.md`](poc/README.md) for detailed reproduction steps and expected output.

## What Each PoC Proves (And What It Doesn't)

**What is proven:**
- The vulnerable recv path has no bounds checking (static analysis — Ghidra decompilation)
- The attacker-controlled length field produces a recv size of 32,769 bytes (length parsing replicated in-process)
- The overflow writes past the buffer into adjacent heap objects (memory verification)
- All 14 function pointers in the adjacent object are overwritten (corruption verification)
- Dispatching through a corrupted pointer executes attacker-chosen code (MessageBoxA fires)
- No ASLR — all addresses are fixed and known (`0x400000` base)
- No DEP — heap memory is executable

**What is not proven:**
- End-to-end network exploitation (sending a crafted packet over a real socket)
- This would require a fake game server (RCE-1) or a second game instance on LAN (RCE-2)
- That is a weaponized exploit, which is beyond the scope of security research

Each link in the chain is independently verified. The missing bounds check is in the decompiled code. The overflow math is demonstrated in the game's own heap. The code execution is live. The chain is mathematically certain.

## Full Technical Analysis

See [NETWORK-VULNS.md](NETWORK-VULNS.md) for the complete vulnerability analysis including:
- All four network vulnerabilities (NET-1 through NET-4)
- Decompiled code for each vulnerable function
- Buffer geometry and overflow size calculations
- Network architecture of the game's multiplayer stack
- Comparison with the save file ACE (CVSS 7.8 vs 9.8)

## Repository Contents

```
├── README.md                    This file
├── NETWORK-VULNS.md             Full network vulnerability analysis (4 vulns)
├── poc/
│   ├── README.md                Detailed reproduction steps for all 6 proofs
│   ├── network_rce_proof.js     PoC 1-2: Heap overflow proof (both vectors)
│   ├── network_eip_control.js   PoC 3-4: EIP control proof (both vectors)
│   └── network_rce_ace.js       PoC 5-6: Arbitrary code execution proof (both vectors)
└── LICENSE
```

## Requirements

- Need for Speed Underground 2 (PC, Windows)
- [Frida](https://frida.re/) (`pip install frida-tools`)
- The game running (main menu is sufficient for PoC 1-4; no multiplayer session needed)

## Quick Start

```
frida -p <PID> -l poc/network_rce_proof.js       # Overflow proof
frida -p <PID> -l poc/network_eip_control.js      # EIP control
frida -p <PID> -l poc/network_rce_ace.js          # Code execution (shows MessageBox)
```

## Tools Used

- [Ghidra](https://ghidra-sre.org/) 12.1.4 via [REA](https://re-anytime.com/) — static analysis, decompilation, cross-reference analysis
- [Frida](https://frida.re/) — dynamic instrumentation, in-process overflow verification, code execution proof

## Disclaimer

This research is published for **educational and defensive purposes only**. The vulnerabilities exist in a 22-year-old game with no active security support from the vendor. No weaponized exploit is included — no shellcode, no packet sender, no network attack tool. The PoCs demonstrate the exploit chain in isolated heap allocations and nothing more.

Do not use this research to attack other players. Don't be that person.

## License

Research scripts and documentation are released under the [MIT License](LICENSE). The game binary and its assets remain the property of Electronic Arts.

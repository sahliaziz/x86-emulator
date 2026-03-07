// --- Emulator State ---
let memorySize = 0x10000; // 64KB for demo purposes
let memory = new Uint8Array(memorySize);
let registers = {};
let flags = { zf: false, sf: false, cf: false };
let isRunning = false;
let buffer = null;
let textSection = null;
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

function extractTextSection(arrayBuffer) {
  const dv = new DataView(arrayBuffer);
  const buffer = new Uint8Array(arrayBuffer);

  // ELF64 Header Constants
  const shOff = Number(dv.getBigUint64(40, true));
  const shEntSize = dv.getUint16(58, true);
  const shNum = dv.getUint16(60, true);
  const shStrIdx = dv.getUint16(62, true);

  // Get the Section Header String Table (.shstrtab) location
  const shstrtabOff = Number(
    dv.getBigUint64(shOff + shStrIdx * shEntSize + 24, true),
  );

  for (let i = 0; i < shNum; i++) {
    const off = shOff + i * shEntSize;
    const nameIdx = dv.getUint32(off, true);

    // Extract section name
    let name = "";
    for (let j = shstrtabOff + nameIdx; buffer[j] !== 0; j++) {
      name += String.fromCharCode(buffer[j]);
    }

    if (name === ".text") {
      const sectionOffset = Number(dv.getBigUint64(off + 24, true));
      const sectionSize = Number(dv.getBigUint64(off + 32, true));
      const sectionVMA = dv.getBigUint64(off + 16, true);

      return {
        name: ".text",
        vma: sectionVMA,
        offset: sectionOffset,
        size: sectionSize,
        // These are the actual instructions for your emulator
        bytes: buffer.slice(sectionOffset, sectionOffset + sectionSize),
      };
    }
  }

  console.error("Could not find .text section in ELF file.");
  return null;
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
      textSection = extractTextSection(arrayBuffer);
      console.log("Extracted .text section:", textSection);
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
  registers.rsp = BigInt(memorySize); // Stack grows down from the end
  registers.rbp = registers.rsp;

  // Push fake return address for main (to detect end of execution)
  registers.rsp -= 8n;
  writeMem64(registers.rsp, 0xFFFFFFFFFFFFFFFFn);
}

// --- Memory Helpers ---
function writeMem64(addr, value, size = 8) {
  const numAddr = Number(addr);
  
  // Bounds checking (matching Python logic)
  if (numAddr < 0 || numAddr + size > memorySize) {
    throw new Error(`Invalid memory write at 0x${numAddr.toString(16)}: writing ${size} bytes (memory size: ${memorySize})`);
  }
  
  const bigValue = BigInt(value);
  
  // Write bytes as little-endian
  for (let i = 0; i < size; i++) {
    memory[numAddr + i] = Number((bigValue >> BigInt(i * 8)) & 0xFFn);
  }
}

function readMem64(addr, size = 8) {
  const numAddr = Number(addr);
  
  // Bounds checking (matching Python logic)
  if (numAddr < 0 || numAddr + size > memorySize) {
    throw new Error(`Invalid memory read at 0x${numAddr.toString(16)}: reading ${size} bytes (memory size: ${memorySize})`);
  }
  
  // Read bytes as little-endian integer
  let value = 0n;
  for (let i = 0; i < size; i++) {
    value |= BigInt(memory[numAddr + i]) << BigInt(i * 8);
  }
  
  return value;
}

function dumpMemory(startAddr = 0, length = 256) {
  const numStart = Number(startAddr);
  
  if (numStart < 0 || numStart >= memorySize) {
    throw new Error(`Invalid memory dump start address: 0x${numStart.toString(16)}`);
  }
  
  const endAddr = Math.min(numStart + length, memorySize);
  let dump = `Memory dump from 0x${numStart.toString(16)} to 0x${endAddr.toString(16)}:\n`;
  
  for (let i = numStart; i < endAddr; i += 16) {
    let line = `0x${i.toString(16).padStart(8, '0')}: `;
    let ascii = '';
    
    for (let j = 0; j < 16 && i + j < endAddr; j++) {
      const byte = memory[i + j];
      line += byte.toString(16).padStart(2, '0') + ' ';
      ascii += String.fromCharCode(byte >= 32 && byte < 127 ? byte : 46); // 46 is '.'
    }
    
    dump += line.padEnd(48, ' ') + '  ' + ascii + '\n';
  }
  
  return dump;
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
  d.option(cs.OPT_DETAIL, true);

  log("--- Starting Emulator ---");
  isRunning = true;

  while (isRunning) {
    // 1. Fetch
    const ripIdx = Number(registers.rip);
    if (ripIdx >= textSection.size) {
      log("RIP out of bounds. Stopping.");
      log(`RIP: 0x${registers.rip.toString(16)}, Text Section Size: ${textSection.size}`);
      break;
    }

    // 2. Decode (1 instruction at a time)
    const instructions = d.disasm(textSection.bytes.slice(ripIdx, ripIdx + 15), Number(textSection.vma) + ripIdx);
    if (instructions.length === 0) {
      log(`Failed to disassemble at 0x${registers.rip.toString(16)}`);
      break;
    }

    const insn = instructions[0];
    log(`0x${insn.address.toString(16)}: ${insn.mnemonic} ${insn.op_str}`);

    // Update RIP before execution (can be overridden by jumps)
    const nextRip = registers.rip + BigInt(insn.size);
    let jumped = false;

    // 3. Execute
    const ops = insn.detail.op;

    console.log("Instruction details:", insn);

    // Helper to get operand value
    const getVal = (op) => {
      if (op.type === cs.OP_REG) return registers[d.reg_name(op.reg)];
      if (op.type === cs.OP_IMM) return BigInt(op.imm);
      if (op.type === cs.OP_MEM) return readMem64(BigInt(op.mem.disp)); // Simplified
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
        log(`Comparing 0x${v1.toString(16)} and 0x${v2.toString(16)}`);
        flags.zf = v1 === v2;
        flags.sf = v1 < v2;
        isRunning = false; // Stop after cmp for demo purposes
        break;

      case "jmp":
        registers.rip = getVal(ops[0]) - vma;
        jumped = true;
        break;

      case "je":
        if (flags.zf) {
          registers.rip = getVal(ops[0]) - vma;
          jumped = true;
        }
        break;

      case "jl":
        if (flags.sf) {
          registers.rip = getVal(ops[0]) - vma;
          jumped = true;
        }
        break;

      case "jle":
        if (flags.sf || flags.zf) {
          registers.rip = getVal(ops[0]) - vma;
          jumped = true;
        }
        break;

      case "jne":
        if (!flags.zf) {
          registers.rip = getVal(ops[0]) - vma;
          jumped = true;
        }
        break;

      case "jg":
        if (!flags.sf && !flags.zf) {
          registers.rip = getVal(ops[0]) - vma;
          jumped = true;
        }
        break;

      case "jge":
        if (!flags.sf) {
          registers.rip = getVal(ops[0]) - vma;
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
        if (readMem64(registers.rsp) == 0xFFFFFFFFFFFFFFFFn) {
          log("Reached end of main. Exiting.");
          log("Return value (RAX): " + registers.rax);
          isRunning = false;
          break;
        }
        log("Returning to 0x" + readMem64(registers.rsp).toString(16));
        registers.rip = readMem64(registers.rsp);
        registers.rsp += 8n;
        isRunning = false;
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
    if (ripIdx > 100) isRunning = false;

    // Optional: Use await new Promise(r => setTimeout(r, 10)) for "slow motion"
  }

  d.close();
  log("--- Emulator Stopped ---");
}

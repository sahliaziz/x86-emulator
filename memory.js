// --- Memory Helpers ---
// Depends on `memory`, `memorySize`, and `registers` defined in emulator.js.

// Writes `size` bytes of `value` into `memory` at `addr` in little-endian order.
function writeMem(addr, value, size = 4) {
  if (addr < 0 || addr + size > memorySize) {
    throw new Error(
      `Invalid memory write at 0x${addr.toString(16)}: writing ${size} bytes (memory size: ${memorySize})`
    );
  }
  for (let i = 0; i < size; i++) {
    memory[addr + i] = (value >>> (i * 8)) & 0xff;
  }
}

// Reads `size` bytes from `memory` at raw address `addr`.
function readMemAt(addr, size = 4) {
  if (addr < 0 || addr + size > memorySize) {
    throw new Error(
      `Invalid memory read at 0x${addr.toString(16)}: reading ${size} bytes (memory size: ${memorySize})`
    );
  }
  let value = 0;
  for (let i = 0; i < size; i++) {
    value |= memory[addr + i] << (i * 8);
  }
  return value >>> 0;
}

// Reads memory using a Capstone memory operand object.
// `d` is the Capstone instance, passed explicitly so this function stays pure
// (no hidden dependency on a locally-scoped `d` variable in runEmulator).
function readMemOp(op, d) {
  const base = op.mem.base ? registers[d.reg_name(op.mem.base)] || 0 : 0;
  const index = op.mem.index ? registers[d.reg_name(op.mem.index)] || 0 : 0;
  const scale = op.mem.scale || 1;
  const addr = (base + index * scale + op.mem.disp) >>> 0;
  return readMemAt(addr, op.size || 4);
}

// Writes memory using a Capstone memory operand object.
// Same reasoning as readMemOp: `d` is passed in explicitly.
function writeMemOp(op, value, d) {
  const base = op.mem.base ? registers[d.reg_name(op.mem.base)] || 0 : 0;
  const index = op.mem.index ? registers[d.reg_name(op.mem.index)] || 0 : 0;
  const scale = op.mem.scale || 1;
  const addr = (base + index * scale + op.mem.disp) >>> 0;
  writeMem(addr, value, op.size || 4);
}

// Returns a formatted hex+ASCII dump of `length` bytes starting at `startAddr`.
function showMemoryDump(memory, startAddr = 0, length = 256) {
  const memDiv = document.getElementById("memory");
  if (!memDiv) return;

  const numStart = Number(startAddr);
  if (numStart < 0 || numStart >= memorySize) {
    throw new Error(
      `Invalid memory dump start address: 0x${numStart.toString(16)}`
    );
  }
  const endAddr = Math.min(numStart + length, memorySize);
  memDiv.innerHTML = `Memory dump 0x${numStart.toString(16)} - 0x${endAddr.toString(16)}:\n`;

  for (let i = numStart; i < endAddr; i += 16) {
    let hex   = `0x${i.toString(16).padStart(8, "0")}: `;
    let ascii = "";
    for (let j = 0; j < 16 && i + j < endAddr; j++) {
      const byte = memory[i + j];
      hex   += byte.toString(16).padStart(2, "0") + " ";
      ascii += String.fromCharCode(byte >= 32 && byte < 127 ? byte : 46); // '.' for non-printable
    }
    memDiv.innerHTML += `<p>${hex.padEnd(57, " ")} ${ascii}</p>`;
    //memDiv.innerHTML += '<br>';
  }
}

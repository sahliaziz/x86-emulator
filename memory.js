// --- Memory Helpers ---
// Depends on `memory`, `memorySize`, and `registers` defined in emulator.js.

// Writes `size` bytes of `value` into `memory` at `addr` in little-endian order.
function writeMem64(addr, value, size = 8) {
  const numAddr = Number(addr);
  if (numAddr < 0 || numAddr + size > memorySize) {
    throw new Error(
      `Invalid memory write at 0x${numAddr.toString(16)}: writing ${size} bytes (memory size: ${memorySize})`
    );
  }
  const bigValue = BigInt(value);
  for (let i = 0; i < size; i++) {
    memory[numAddr + i] = Number((bigValue >> BigInt(i * 8)) & 0xffn);
  }
}

// Reads `size` bytes from `memory` at raw address `addr` and returns a BigInt.
// Use this when you already have a numeric/BigInt address (e.g. from a register).
function readMemAt(addr, size = 8) {
  const numAddr = Number(addr);
  if (numAddr < 0 || numAddr + size > memorySize) {
    throw new Error(
      `Invalid memory read at 0x${numAddr.toString(16)}: reading ${size} bytes (memory size: ${memorySize})`
    );
  }
  let value = 0n;
  for (let i = 0; i < size; i++) {
    value |= BigInt(memory[numAddr + i]) << BigInt(i * 8);
  }
  return value;
}

// Reads memory using a Capstone memory operand object.
// `d` is the Capstone instance — passed explicitly so this function stays pure
// (no hidden dependency on a locally-scoped `d` variable in runEmulator).
function readMemOp(op, d) {
  const base = registers[d.reg_name(op.mem.base)] || 0n;
  const addr = base + BigInt(op.mem.disp);
  return readMemAt(addr, op.size || 8);
}

// Writes memory using a Capstone memory operand object.
// Same reasoning as readMemOp: `d` is passed in explicitly.
function writeMemOp(op, value, d) {
  const base = registers[d.reg_name(op.mem.base)] || 0n;
  const addr = base + BigInt(op.mem.disp);
  writeMem64(addr, value, op.size || 8);
}

// Returns a formatted hex+ASCII dump of `length` bytes starting at `startAddr`.
function dumpMemory(startAddr = 0, length = 256) {
  const numStart = Number(startAddr);
  if (numStart < 0 || numStart >= memorySize) {
    throw new Error(
      `Invalid memory dump start address: 0x${numStart.toString(16)}`
    );
  }
  const endAddr = Math.min(numStart + length, memorySize);
  let dump = `Memory dump 0x${numStart.toString(16)} — 0x${endAddr.toString(16)}:\n`;

  for (let i = numStart; i < endAddr; i += 16) {
    let hex   = `0x${i.toString(16).padStart(8, "0")}: `;
    let ascii = "";
    for (let j = 0; j < 16 && i + j < endAddr; j++) {
      const byte = memory[i + j];
      hex   += byte.toString(16).padStart(2, "0") + " ";
      ascii += String.fromCharCode(byte >= 32 && byte < 127 ? byte : 46); // '.' for non-printable
    }
    dump += hex.padEnd(57, " ") + " " + ascii + "\n";
  }

  return dump;
}

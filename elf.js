// --- ELF Parsing ---
// All functions are pure: they take buffers as arguments and return data.

// Validates that `buffer` begins with the ELF magic bytes and is a 32-bit x86 binary.
// EI_CLASS (byte 4): 1 = 32-bit, 2 = 64-bit. We only support 32-bit.
function isELFValid(buffer) {
  if (buffer.length < 52) return false; // ELF32 header is exactly 52 bytes
  const isLittleEndian = buffer[5] === 1;
  const machine = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
    .getUint16(18, isLittleEndian);

  return (
    buffer[0] === 0x7f &&
    buffer[1] === 0x45 && // 'E'
    buffer[2] === 0x4c && // 'L'
    buffer[3] === 0x46 && // 'F'
    buffer[4] === 1 &&    // EI_CLASS = ELFCLASS32
    machine === 3         // e_machine = EM_386
  );
}

// Returns the ELF entry point virtual address (e_entry).
// EI_DATA (byte 5): 1 = little-endian, 2 = big-endian.
// e_entry is a 32-bit field at offset 24 in the ELF32 header.
function getStartAddr(buffer) {
  const dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const isLittleEndian = buffer[5] === 1;
  return dv.getUint32(24, isLittleEndian);
}

// Locates and returns the .text section from an ELF32 binary.
// Returns an object: { name, vma, offset, size, bytes } or null.
function extractTextSection(arrayBuffer) {
  const dv  = new DataView(arrayBuffer);
  const buf = new Uint8Array(arrayBuffer);
  const isLittleEndian = buf[5] === 1;

  // ELF32 header fields relevant to section headers.
  const shOff     = dv.getUint32(32, isLittleEndian);
  const shEntSize = dv.getUint16(46, isLittleEndian);
  const shNum     = dv.getUint16(48, isLittleEndian);
  const shStrIdx  = dv.getUint16(50, isLittleEndian);

  // Resolve the file offset of the section name string table (.shstrtab).
  // sh_offset is at +16 within each ELF32 section header entry.
  const shstrtabOff = dv.getUint32(
    shOff + shStrIdx * shEntSize + 16,
    isLittleEndian
  );

  for (let i = 0; i < shNum; i++) {
    const entryOff = shOff + i * shEntSize;

    // sh_name (Elf32_Word, 4 bytes at offset 0): index into .shstrtab
    const nameIdx = dv.getUint32(entryOff, isLittleEndian);

    // Read the null-terminated section name from the string table
    let name = "";
    for (let j = shstrtabOff + nameIdx; buf[j] !== 0; j++) {
      name += String.fromCharCode(buf[j]);
    }

    if (name === ".text") {
      // ELF32 section header layout:
      //   +0  sh_name      (4 bytes)
      //   +4  sh_type      (4 bytes)
      //   +8  sh_flags     (4 bytes)
      //   +12 sh_addr      (4 bytes)
      //   +16 sh_offset    (4 bytes)
      //   +20 sh_size      (4 bytes)
      const sectionVMA    = dv.getUint32(entryOff + 12, isLittleEndian);
      const sectionOffset = dv.getUint32(entryOff + 16, isLittleEndian);
      const sectionSize   = dv.getUint32(entryOff + 20, isLittleEndian);

      return {
        name:   ".text",
        vma:    sectionVMA,
        offset: sectionOffset,
        size:   sectionSize,
        bytes:  buf.slice(sectionOffset, sectionOffset + sectionSize),
      };
    }
  }

  console.error("Could not find .text section in ELF file.");
  return null;
}

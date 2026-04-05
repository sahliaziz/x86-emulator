// --- ELF Parsing ---
// All functions are pure: they take buffers as arguments and return data.

// Validates that `buffer` begins with the ELF magic bytes and is a 64-bit binary.
// EI_CLASS (byte 4): 1 = 32-bit, 2 = 64-bit. We only support 64-bit.
function isELFValid(buffer) {
  if (buffer.length < 64) return false; // ELF64 header is exactly 64 bytes
  return (
    buffer[0] === 0x7f &&
    buffer[1] === 0x45 && // 'E'
    buffer[2] === 0x4c && // 'L'
    buffer[3] === 0x46 && // 'F'
    buffer[4] === 2       // EI_CLASS = ELFCLASS64
  );
}

// Returns the ELF entry point virtual address (e_entry) as a BigInt.
// EI_DATA (byte 5): 1 = little-endian, 2 = big-endian.
// e_entry is a 64-bit field at offset 24 in the ELF64 header.
function getStartAddr(buffer) {
  const dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const isLittleEndian = buffer[5] === 1;
  return dv.getBigUint64(24, isLittleEndian);
}

// Locates and returns the .text section from an ELF64 binary.
// Returns an object: { name, vma (BigInt), offset, size, bytes } or null.
function extractTextSection(arrayBuffer) {
  const dv  = new DataView(arrayBuffer);
  const buf = new Uint8Array(arrayBuffer);

  // ELF64 header fields relevant to section headers
  const shOff     = Number(dv.getBigUint64(40, true)); // e_shoff:     file offset of section header table
  const shEntSize = dv.getUint16(58, true);            // e_shentsize: size of one section header entry
  const shNum     = dv.getUint16(60, true);            // e_shnum:     number of section header entries
  const shStrIdx  = dv.getUint16(62, true);            // e_shstrndx:  index of .shstrtab section header

  // Resolve the file offset of the section name string table (.shstrtab).
  // sh_offset is at +24 within each section header entry.
  const shstrtabOff = Number(
    dv.getBigUint64(shOff + shStrIdx * shEntSize + 24, true)
  );

  for (let i = 0; i < shNum; i++) {
    const entryOff = shOff + i * shEntSize;

    // sh_name (Elf64_Word, 4 bytes at offset 0): index into .shstrtab
    const nameIdx = dv.getUint32(entryOff, true);

    // Read the null-terminated section name from the string table
    let name = "";
    for (let j = shstrtabOff + nameIdx; buf[j] !== 0; j++) {
      name += String.fromCharCode(buf[j]);
    }

    if (name === ".text") {
      // ELF64 section header layout:
      //   +0  sh_name      (4 bytes)
      //   +4  sh_type      (4 bytes)
      //   +8  sh_flags     (8 bytes)
      //   +16 sh_addr      (8 bytes) ← virtual address
      //   +24 sh_offset    (8 bytes) ← file offset
      //   +32 sh_size      (8 bytes) ← section size in bytes
      const sectionVMA    = dv.getBigUint64(entryOff + 16, true);
      const sectionOffset = Number(dv.getBigUint64(entryOff + 24, true));
      const sectionSize   = Number(dv.getBigUint64(entryOff + 32, true));

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

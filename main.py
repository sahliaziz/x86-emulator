from capstone import *
from capstone.x86 import *
from elftools.elf.elffile import ELFFile

# -----------------------
# Reading ELF file
# -----------------------

unsupported = set()

with open("add2.bin", "rb") as f:
    elffile = ELFFile(f)
    text_section = elffile.get_section_by_name(".text")
    symtable_section = elffile.get_section_by_name(".symtab")
    code_bytes = text_section.data()

    start = symtable_section.get_symbol_by_name("_start")[0]
    start_address = start["st_value"]
    vma_address = text_section["sh_addr"]


code_length = len(code_bytes)

# -----------------------
# Memory + Registers
# -----------------------

memory = bytearray(64)

flags = {
    "ZF": 0,
    "SF": 0,
}

registers = {
    X86_REG_RSP: len(memory),
    X86_REG_RBP: len(memory),
    X86_REG_RIP: start_address - vma_address,
    X86_REG_RAX: 0,
    X86_REG_RBX: 0,
    X86_REG_RCX: 0,
    X86_REG_RDX: 0,
    X86_REG_RDI: 0,
    X86_REG_RSI: 0,
    X86_REG_EBP: 0
}

# -----------------------
# Load ELF
# -----------------------


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# -----------------------
# Helpers
# -----------------------


def read_mem(addr, size):
    if addr < 0 or addr + size > len(memory):
        raise Exception(f"Invalid memory read at {addr}")
    return int.from_bytes(memory[addr : addr + size], "little")


def write_mem(addr, value, size):
    if addr < 0 or addr + size > len(memory):
        raise Exception(f"Invalid memory write at {addr}")
    memory[addr : addr + size] = value.to_bytes(size, "little")


def compute_mem_address(mem_op):
    addr = 0
    if mem_op.base != 0:
        addr += registers.get(mem_op.base, 0)
    if mem_op.index != 0:
        addr += registers.get(mem_op.index, 0) * mem_op.scale
    addr += mem_op.disp
    return addr


def show_registers():
    print("Registers:")
    for reg_id, value in registers.items():
        reg_name = md.reg_name(reg_id)
        print(f"{reg_name}: 0x{value:x}")
    for flag, val in flags.items():
        print(f"{flag}: {val}")


def memory_dump(start, size):
    print(f"Memory dump from 0x{start:x} to 0x{start + size:x}:")
    for i in range(start, start + size, 16):
        chunk = memory[i : i + 16]
        hex_chunk = " ".join(f"{byte:02x}" for byte in chunk)
        print(f"0x{i:08x}: {hex_chunk}")


# Fake return address to detect main function end
write_mem(56, 0xFFFFFFFFFFFFFFFF, 8)
registers[X86_REG_RSP] -= 8

# -----------------------
# Emulator Loop
# -----------------------

while registers[X86_REG_RIP] < code_length:
    offset = registers[X86_REG_RIP]
    insn = next(md.disasm(code_bytes[offset : offset + 15], vma_address + offset))

    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

    mnemonic = insn.mnemonic
    ops = insn.operands

    # -------------------------------------------------
    # MOV
    # -------------------------------------------------
    if mnemonic == "mov":
        if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            registers[ops[0].reg] = registers[ops[1].reg]

        elif ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            registers[ops[0].reg] = ops[1].imm

        elif ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
            addr = compute_mem_address(ops[1].mem)
            size = ops[0].size
            registers[ops[0].reg] = read_mem(addr, size)

        elif ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
            addr = compute_mem_address(ops[0].mem)
            size = ops[1].size
            write_mem(addr, registers[ops[1].reg], size)
        elif ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_IMM:
            addr = compute_mem_address(ops[0].mem)
            size = ops[0].size
            write_mem(addr, ops[1].imm, size)

    # -------------------------------------------------
    # PUSH
    # -------------------------------------------------
    elif mnemonic == "push":
        registers[X86_REG_RSP] -= 8

        if registers[X86_REG_RSP] < 0:
            raise Exception("Stack overflow")

        if ops[0].type == X86_OP_REG:
            value = registers[ops[0].reg]
        else:
            value = ops[0].imm

        write_mem(registers[X86_REG_RSP], value, 8)

    # -------------------------------------------------
    # POP
    # -------------------------------------------------
    elif mnemonic == "pop":
        if registers[X86_REG_RSP] + 8 > len(memory):
            raise Exception("Stack underflow")

        value = read_mem(registers[X86_REG_RSP], 8)

        if ops[0].type == X86_OP_REG:
            registers[ops[0].reg] = value

        registers[X86_REG_RSP] += 8

    # -------------------------------------------------
    # ADD
    # -------------------------------------------------
    elif mnemonic == "add":
        if ops[0].type == X86_OP_REG:
            if ops[1].type == X86_OP_REG:
                registers[ops[0].reg] += registers[ops[1].reg]
            else:
                registers[ops[0].reg] += ops[1].imm

        elif ops[0].type == X86_OP_MEM:
            addr = compute_mem_address(ops[0].mem)
            size = ops[0].size
            value = read_mem(addr, size)

            if ops[1].type == X86_OP_REG:
                value += registers[ops[1].reg]
            else:
                value += ops[1].imm

            write_mem(addr, value, size)
        else:
            raise Exception("Unsupported ADD operand types")

    # -------------------------------------------------
    # SUB
    # -------------------------------------------------
    elif mnemonic == "sub":
        if ops[1].type == X86_OP_REG:
            registers[ops[0].reg] -= registers[ops[1].reg]
        else:
            registers[ops[0].reg] -= ops[1].imm
    
    # -------------------------------------------------
    # DEC
    # -------------------------------------------------
    elif mnemonic == "dec":
        if ops[0].type == X86_OP_REG:
            registers[ops[0].reg] -= 1
        elif ops[0].type == X86_OP_MEM:
            addr = compute_mem_address(ops[0].mem)
            size = ops[0].size
            value = read_mem(addr, size) - 1
            write_mem(addr, value, size)

    # -------------------------------------------------
    # INC
    # -------------------------------------------------
    elif mnemonic == "inc":
        if ops[0].type == X86_OP_REG:
            registers[ops[0].reg] += 1
        elif ops[0].type == X86_OP_MEM:
            addr = compute_mem_address(ops[0].mem)
            size = ops[0].size
            value = read_mem(addr, size) + 1
            write_mem(addr, value, size)

    # -------------------------------------------------
    # AND
    # -------------------------------------------------
    elif mnemonic == "and":
        if ops[1].type == X86_OP_REG:
            right = registers[ops[1].reg]
        elif ops[1].type == X86_OP_MEM:
            right = read_mem(compute_mem_address(ops[1].mem), ops[1].size)
        else:
            right = ops[1].imm

        if ops[0].type == X86_OP_MEM:
            addr = compute_mem_address(ops[0].mem)
            size = ops[0].size
            value = read_mem(addr, size) & right
            write_mem(addr, value, size)
        else:
            registers[ops[0].reg] &= right

    # -------------------------------------------------
    # OR
    # -------------------------------------------------
    elif mnemonic == "or":
        if ops[1].type == X86_OP_REG:
            right = registers[ops[1].reg]
        elif ops[1].type == X86_OP_MEM:
            right = read_mem(compute_mem_address(ops[1].mem), ops[1].size)
        else:
            right = ops[1].imm

        if ops[0].type == X86_OP_MEM:
            addr = compute_mem_address(ops[0].mem)
            size = ops[0].size
            value = read_mem(addr, size) | right
            write_mem(addr, value, size)
        else:
            registers[ops[0].reg] |= right

    # -------------------------------------------------
    # XOR
    # -------------------------------------------------
    elif mnemonic == "xor":
        if ops[1].type == X86_OP_REG:
            right = registers[ops[1].reg]
        elif ops[1].type == X86_OP_MEM:
            right = read_mem(compute_mem_address(ops[1].mem), ops[1].size)
        else:
            right = ops[1].imm

        if ops[0].type == X86_OP_MEM:
            addr = compute_mem_address(ops[0].mem)
            size = ops[0].size
            value = read_mem(addr, size) ^ right
            write_mem(addr, value, size)
        else:
            registers[ops[0].reg] ^= right

    # -------------------------------------------------
    # CMP
    # -------------------------------------------------
    elif mnemonic == "cmp":
        if ops[0].type == X86_OP_REG:
            left = registers[ops[0].reg]
        else:
            left = read_mem(compute_mem_address(ops[0].mem), ops[0].size)

        if ops[1].type == X86_OP_REG:
            right = registers[ops[1].reg]
        else:
            right = ops[1].imm

        print(f"Comparing {left} and {right}")

        flags["ZF"] = int(left == right)
        flags["SF"] = int(left < right)

    # -------------------------------------------------
    # JMP
    # -------------------------------------------------
    elif mnemonic == "jmp":
        # Convert virtual address → offset inside .text
        registers[X86_REG_RIP] = ops[0].imm - vma_address
        continue

    # -------------------------------------------------
    # JE
    # -------------------------------------------------
    elif mnemonic == "je" or mnemonic == "jz":
        if flags["ZF"] == 1:
            registers[X86_REG_RIP] = ops[0].imm - vma_address
            continue

    # -------------------------------------------------
    # JNE
    # -------------------------------------------------
    elif mnemonic == "jne" or mnemonic == "jnz":
        if flags["ZF"] == 0:
            registers[X86_REG_RIP] = ops[0].imm - vma_address
            continue

    # -------------------------------------------------
    # JLE
    # -------------------------------------------------
    elif mnemonic == "jle":
        if flags["ZF"] == 1 or flags["SF"] == 1:
            registers[X86_REG_RIP] = ops[0].imm - vma_address
            continue

    # -------------------------------------------------
    # JGE
    # -------------------------------------------------
    elif mnemonic == "jge":
        if flags["ZF"] == 1 or flags["SF"] == 0:
            registers[X86_REG_RIP] = ops[0].imm - vma_address
            continue

    # -------------------------------------------------
    # JGE
    # -------------------------------------------------
    elif mnemonic == "jg":
        if flags["ZF"] == 0 and flags["SF"] == 0:
            registers[X86_REG_RIP] = ops[0].imm - vma_address
            continue

    # -------------------------------------------------
    # CALL
    # -------------------------------------------------
    elif mnemonic == "call":
        registers[X86_REG_RSP] -= 8
        write_mem(registers[X86_REG_RSP], registers[X86_REG_RIP] + insn.size, 8)
        registers[X86_REG_RIP] = ops[0].imm - vma_address
        continue

    # -------------------------------------------------
    # SYSCALL
    # -------------------------------------------------
    elif mnemonic == "syscall":
        if registers[X86_REG_RAX] == 60:
            break
        else:
            raise Exception(f"Unsupported syscall {registers[X86_REG_RAX]}")

    # -------------------------------------------------
    # SYSCALL
    # -------------------------------------------------
    elif mnemonic == "syscall":
        if registers[X86_REG_RAX] == 60:
            break
        else:
            raise Exception(f"Unsupported syscall {registers[X86_REG_RAX]}")
        
    # -------------------------------------------------
    # LEAVE
    # -------------------------------------------------
    elif mnemonic == "leave":
        registers[X86_REG_RSP] = registers[X86_REG_RBP]
        registers[X86_REG_RBP] = read_mem(registers[X86_REG_RSP], 8)
        registers[X86_REG_RSP] += 8

    # -------------------------------------------------
    # RET
    # -------------------------------------------------
    elif mnemonic == "ret":
        print(f"Return address read = 0x{read_mem(registers[X86_REG_RSP], 8):x}")
        #                                                   0xffffffffffbfefff
        if read_mem(registers[X86_REG_RSP], 8) == 0xFFFFFFFFFFFFFFFF:
            print("Value in RAX (return value):", registers[X86_REG_RAX])
            break
        else:
            registers[X86_REG_RIP] = read_mem(registers[X86_REG_RSP], 8)
            registers[X86_REG_RSP] += 8
            continue

    else:
        print("Unsupported instruction:", mnemonic)
        unsupported.add(mnemonic)

    show_registers()
    memory_dump(0, 64)
    # Advance RIP (offset)
    registers[X86_REG_RIP] += insn.size
    # input("Press Enter to continue...")

print("\nFinal Registers:")
for reg, val in registers.items():
    print(f"{md.reg_name(reg)} = 0x{val:x}")


print("\nUnsupported instructions encountered:", unsupported)
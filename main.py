from capstone import *
from capstone.x86 import *
from elftools.elf.elffile import ELFFile

"""
with open("fib.bin", "rb") as f:
    CODE = f.read()

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(CODE, 0x401000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
"""

memory = bytearray(64)

flags = {
    'ZF': 0,  # Zero Flag
    'SF': 0,  # Sign Flag
    'OF': 0,  # Overflow Flag
    'CF': 0,  # Carry Flag
    'PF': 0,  # Parity Flag
    'AF': 0,  # Auxiliary Carry Flag
}

registers = {
    X86_REG_RSP : 64,
    X86_REG_RBP : 64,
    X86_REG_RIP : 0,
    X86_REG_EAX : 0,
    X86_REG_EBX : 0,
    X86_REG_RAX : 0,
    X86_REG_EDX : 0,
    X86_REG_RDI : 0,
    X86_REG_RDX : 0,
}

n_jumps = 0

with open("fib.bin", 'rb') as f:
        # Load the ELF file
        elffile = ELFFile(f)
        
        text_section = elffile.get_section_by_name('.text')
        if not text_section:
            print("Could not find .text section.")

        code_bytes = text_section.data()
        vma_address = text_section['sh_addr']

md = Cs(CS_ARCH_X86, CS_MODE_64)

md.detail = True
md.skipdata = True

code_length = len(code_bytes)


def show_registers():
    print("Registers:")
    for reg_id, value in registers.items():
        reg_name = md.reg_name(reg_id)
        print(f"{reg_name}: 0x{value:x}")

def memory_dump(start, size):
    print(f"Memory dump from 0x{start:x} to 0x{start+size:x}:")
    for i in range(start, start + size, 16):
        chunk = memory[i:i+16]
        hex_chunk = ' '.join(f"{byte:02x}" for byte in chunk)
        print(f"0x{i:08x}: {hex_chunk}")


while registers[X86_REG_RIP] < code_length:

    address = registers[X86_REG_RIP]

    instruction = next(md.disasm(code_bytes[address:address + 15], address))
    mnemonic = instruction.mnemonic
    operands = instruction.operands

    print(f"0x{address + vma_address:x}:\t{mnemonic}\t{instruction.op_str}")


    if mnemonic == "push":
        if operands[0].type == X86_OP_REG:
            reg_id = operands[0].reg
            value = registers.get(reg_id, 0)
            registers[X86_REG_RSP] -= 8
            memory[registers[X86_REG_RSP]:registers[X86_REG_RSP]+8] = value.to_bytes(8, byteorder='little')
        elif operands[0].type == X86_OP_IMM:
            imm_value = operands[0].imm
            registers[X86_REG_RSP] -= 8
            print(f"Calculated memory address for push: 0x{registers[X86_REG_RSP]:x}")
            memory[registers[X86_REG_RSP]:registers[X86_REG_RSP]+8] = imm_value.to_bytes(8, byteorder='little')
        else:
            print("Unsupported push operand type.")
    
    elif mnemonic == "mov":
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            dest_id = operands[0].reg
            src_id = operands[1].reg
            registers[dest_id] = registers[src_id]
        elif operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            dest_id = operands[0].reg
            imm_value = operands[1].imm
            registers[dest_id] = imm_value
        elif operands[0].type == X86_OP_MEM and operands[1].type == X86_OP_IMM:
            mem_op = operands[0].mem
            imm_value = operands[1].imm
            mem_address = 0
            if mem_op.base != 0:
                mem_address += registers.get(mem_op.base, 0)
            if mem_op.index != 0:
                mem_address += registers.get(mem_op.index, 0) * mem_op.scale
            mem_address += mem_op.disp
            memory[mem_address:mem_address+4] = imm_value.to_bytes(4, byteorder='little')
        elif operands[0].type == X86_OP_REG and operands[1].type == X86_OP_MEM:
            dest_id = operands[0].reg
            mem_op = operands[1].mem
            mem_address = 0
            if mem_op.base != 0:
                mem_address += registers.get(mem_op.base, 0)
            if mem_op.index != 0:
                mem_address += registers.get(mem_op.index, 0) * mem_op.scale
            mem_address += mem_op.disp
            value_bytes = memory[mem_address:mem_address+4]
            value = int.from_bytes(value_bytes, byteorder='little')
            registers[dest_id] = value
        elif operands[0].type == X86_OP_MEM and operands[1].type == X86_OP_REG:
            mem_op = operands[0].mem
            src_id = operands[1].reg
            mem_address = 0
            if mem_op.base != 0:
                mem_address += registers.get(mem_op.base, 0)
            if mem_op.index != 0:
                mem_address += registers.get(mem_op.index, 0) * mem_op.scale
            mem_address += mem_op.disp
            value = registers.get(src_id, 0)
            memory[mem_address:mem_address+8] = value.to_bytes(8, byteorder='little')
        
        else:
            print("Unsupported mov operand type.")
        show_registers()
        memory_dump(0, 64)
    
    elif mnemonic == "jmp":
        if operands[0].type == X86_OP_IMM:
            registers[X86_REG_RIP] = operands[0].imm
            n_jumps += 1
            continue

    elif mnemonic == "add":
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            dest_id = operands[0].reg
            src_id = operands[1].reg
            registers[dest_id] += registers[src_id]
        elif operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            dest_id = operands[0].reg
            imm_value = operands[1].imm
            registers[dest_id] += imm_value
        elif operands[0].type == X86_OP_MEM and operands[1].type == X86_OP_IMM:
            mem_op = operands[0].mem
            imm_value = operands[1].imm
            mem_address = 0
            if mem_op.base != 0:
                mem_address += registers.get(mem_op.base, 0)
            if mem_op.index != 0:
                mem_address += registers.get(mem_op.index, 0) * mem_op.scale
            mem_address += mem_op.disp
            value_bytes = memory[mem_address:mem_address+8]
            value = int.from_bytes(value_bytes, byteorder='little')
            result = value + imm_value
            memory[mem_address:mem_address+8] = result.to_bytes(8, byteorder='little')
        else:
            print("Unsupported add operand type.")

    elif mnemonic == "sub":
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            dest_id = operands[0].reg
            src_id = operands[1].reg
            registers[dest_id] -= registers[src_id]
        elif operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            dest_id = operands[0].reg
            imm_value = operands[1].imm
            registers[dest_id] -= imm_value
        else:
            print("Unsupported sub operand type.")

    elif mnemonic == "cmp":
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            reg1_id = operands[0].reg
            reg2_id = operands[1].reg
            print("Comparing values : 0x%d and 0x%d" % (registers[reg1_id], registers[reg2_id]))
            if registers[reg1_id] < registers[reg2_id]:
                flags['SF'] = 1
            elif registers[reg1_id] > registers[reg2_id]:
                flags['SF'] = 0
            else:
                flags['ZF'] = 1
        elif operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            reg_id = operands[0].reg
            imm_value = operands[1].imm
            print("Comparing values : 0x%d and 0x%d" % (registers[reg_id], imm_value))
            if registers[reg_id] < imm_value:
                flags['SF'] = 1
            elif registers[reg_id] > imm_value:
                flags['SF'] = 0
            else:
                flags['ZF'] = 1
        elif operands[0].type == X86_OP_MEM and operands[1].type == X86_OP_IMM:
            mem_op = operands[0].mem
            imm_value = operands[1].imm
            
            mem_address = 0
            if mem_op.base != 0:
                mem_address += registers.get(mem_op.base, 0)
            if mem_op.index != 0:
                mem_address += registers.get(mem_op.index, 0) * mem_op.scale
            mem_address += mem_op.disp
            value_bytes = memory[mem_address:mem_address+4]
            value = int.from_bytes(value_bytes, byteorder='little')
            print("Comparing memory value 0x%d at address 0x%x with immediate value 0x%d" % (value, mem_address, imm_value))
            if value < imm_value:
                flags['SF'] = 1
            elif value > imm_value:
                flags['SF'] = 0
            else:
                flags['ZF'] = 1
        elif operands[0].type == X86_OP_MEM and operands[1].type == X86_OP_REG:
            mem_op = operands[0].mem
            reg_id = operands[1].reg
            mem_address = 0
            if mem_op.base != 0:
                mem_address += registers.get(mem_op.base, 0)
            if mem_op.index != 0:
                mem_address += registers.get(mem_op.index, 0) * mem_op.scale
            mem_address += mem_op.disp
            value_bytes = memory[mem_address:mem_address+8]
            value = int.from_bytes(value_bytes, byteorder='little')
            if value < registers[reg_id]:
                flags['SF'] = 1
            elif value > registers[reg_id]:
                flags['SF'] = 0
            else:
                flags['ZF'] = 1
        elif operands[0].type == X86_OP_REG and operands[1].type == X86_OP_MEM:
            reg_id = operands[0].reg
            mem_op = operands[1].mem
            mem_address = 0
            if mem_op.base != 0:
                mem_address += registers.get(mem_op.base, 0)
            if mem_op.index != 0:
                mem_address += registers.get(mem_op.index, 0) * mem_op.scale
            mem_address += mem_op.disp
            value_bytes = memory[mem_address:mem_address+8]
            value = int.from_bytes(value_bytes, byteorder='little')
            if registers[reg_id] < value:
                flags['SF'] = 1
            elif registers[reg_id] > value:
                flags['SF'] = 0
            else:
                flags['ZF'] = 1
        else:
            print("Unsupported cmp operand type.")


    elif mnemonic == "jle":
        if operands[0].type == X86_OP_IMM:
            if flags['ZF'] == 1 or flags['SF'] == 1:
                registers[X86_REG_RIP] = operands[0].imm
                n_jumps += 1
                continue
        else:
            print("Unsupported jle operand type.")

    elif mnemonic == "syscall":
        if registers[X86_REG_RAX] == 60:
            break
        else:
            print("Unsupported syscall number:", registers[X86_REG_RAX])

    elif mnemonic == "pop":
        if registers[X86_REG_RSP] < 64000:
            value_bytes = memory[registers[X86_REG_RSP]:registers[X86_REG_RSP]+8]
            value = int.from_bytes(value_bytes, byteorder='little')
            if operands[0].type == X86_OP_REG:
                reg_id = operands[0].reg
                registers[reg_id] = value
            else:
                print("Unsupported pop operand type.")
            registers[X86_REG_RSP] += 8
        else:
            print("Stack underflow on pop.")

    elif mnemonic == "ret":
        break


    registers[X86_REG_RIP] += instruction.size




show_registers()
print("Memory (stack):", memory)
print("Number of jumps executed:", n_jumps)



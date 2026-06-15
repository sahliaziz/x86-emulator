// --- Emulator State ---
// Note: ELF parsing lives in elf.js, memory helpers in memory.js.

// ── Types ──────────────────────────────────────────────────────────────────

declare const cs: any // Capstone browser global from index.html

interface TextSection {
    vma: number
    size: number
    bytes: Uint8Array
}

interface EmulatorContext {
    disassembler: any
    instructions: CsInstruction[]
    instructionMap: Map<number, CsInstruction>
    stepCount: number
}

interface Flags {
    zf: boolean
    sf: boolean
    cf: boolean
    of: boolean
}

type RegisterName =
    | 'eax'
    | 'ebx'
    | 'ecx'
    | 'edx'
    | 'esi'
    | 'edi'
    | 'esp'
    | 'ebp'
    | 'eip'

type Registers = Record<RegisterName, number>

// Capstone operand types (minimal surface used by the emulator)
interface CsMemOp {
    base: number // register id (0 = none)
    index: number
    scale: number
    disp: number
}

interface CsOperand {
    type: number // cs.OP_REG | cs.OP_IMM | cs.OP_MEM
    reg: number
    imm: number
    mem: CsMemOp
    size?: number
}

interface CsDetail {
    op: CsOperand[]
}

interface CsInstruction {
    address: number
    mnemonic: string
    op_str: string
    size: number
    detail: CsDetail
}

// Declarations for helpers that live in elf.ts / memory.ts
declare function isELFValid(buf: Uint8Array): boolean
declare function getStartAddr(buf: Uint8Array): number
declare function extractTextSection(buf: ArrayBuffer): TextSection | null
declare function readMemOp(op: CsOperand, d: any): number
declare function writeMemOp(op: CsOperand, val: number, d: any): void
declare function writeMem(addr: number, val: number, size?: number): void
declare function readMemAt(addr: number, size?: number): number
declare function showMemoryDump(
    memory: Uint8Array,
    start: number,
    length: number
): void

// ── Constants & State ─────────────────────────────────────────────────────

const memorySize = 0x1000
let memory: Uint8Array = new Uint8Array(memorySize)
let registers: Registers = {} as Registers
let flags: Flags = { zf: false, sf: false, cf: false, of: false }
let isRunning = false
let buffer: Uint8Array | null = null
let textSection: TextSection | null = null
let emulator: EmulatorContext | null = null

/** Sentinel pushed onto the stack so `ret` from _start/main knows to stop. */
const SENTINEL = 0xffffffff
/** Native stack slot size for 32-bit x86. */
const WORD_SIZE = 4
const MAX_STEPS = 1000

const outputDiv = document.getElementById('output') as HTMLDivElement
const fileInput = document.getElementById('fileInput') as HTMLInputElement

// ── File Loading ──────────────────────────────────────────────────────────

fileInput.addEventListener('change', async (event: Event) => {
    const target = event.target as HTMLInputElement
    const file = target.files?.[0]

    if (!file) {
        outputDiv.textContent = 'No file selected.'
        return
    }

    try {
        outputDiv.textContent = 'Reading file...'
        outputDiv.className = ''

        const arrayBuffer = await file.arrayBuffer()
        buffer = new Uint8Array(arrayBuffer)

        const isValid = isELFValid(buffer)
        let resultText = `File: ${file.name}\nSize: ${file.size} bytes\n\n`
        resultText += `Is valid ELF32 x86? ${isValid}\n`

        if (isValid) {
            const entryVMA = getStartAddr(buffer)
            resultText += `Entry Point VMA: 0x${entryVMA.toString(16)}\n`
            textSection = extractTextSection(arrayBuffer)
            if (textSection) {
                resultText += `.text VMA:       0x${textSection.vma.toString(16)}\n`
                resultText += `.text size:      ${textSection.size} bytes\n`
            }
            console.log('Extracted .text section:', textSection)
        }

        outputDiv.textContent = resultText
    } catch (err) {
        outputDiv.textContent = `Error: ${(err as Error).message}`
        outputDiv.className = 'error'
    }
})

// ── Register Initialization ───────────────────────────────────────────────

function initRegisters(entryPoint: number): void {
    const names: RegisterName[] = [
        'eax',
        'ebx',
        'ecx',
        'edx',
        'esi',
        'edi',
        'esp',
        'ebp',
        'eip',
    ]
    names.forEach((n) => (registers[n] = 0))

    registers.eip = entryPoint

    registers.esp = memorySize // stack grows down from top of memory
    registers.ebp = registers.esp

    // Push a sentinel return address so `ret` from main detects program end.
    registers.esp -= WORD_SIZE
    writeMem(registers.esp, SENTINEL)
}

// ── UI Helpers ────────────────────────────────────────────────────────────

function log(msg: string): void {
    const out = document.getElementById('output')
    if (!out) return
    out.textContent += msg + '\n'
    out.scrollTop = out.scrollHeight
}

function updateUI(): void {
    const grid = document.getElementById('regDisplay')
    if (!grid) return
    grid.innerHTML = ''
    for (const reg in registers) {
        const name = reg as RegisterName
        grid.innerHTML += `<div class="reg-box"><b>${name.toUpperCase()}</b><br>0x${registers[name].toString(16)}<br>(${registers[name].toString(10)})<sub>10</sub></div>`
    }
}

function initializeEmulator(): boolean {
    if (!buffer || !textSection) {
        log('No ELF loaded.')
        return false
    }

    const entryPoint = getStartAddr(buffer)

    initRegisters(entryPoint)

    const d = new cs.Capstone(cs.ARCH_X86, cs.MODE_32)

    d.option(cs.OPT_DETAIL, true)

    const instructions = d.disasm(textSection.bytes, textSection.vma)

    const instructionMap: Map<number, CsInstruction> = new Map<
        number,
        CsInstruction
    >(
        instructions.map(
            (insn: CsInstruction) =>
                [insn.address, insn] as [number, CsInstruction]
        )
    )

    emulator = {
        disassembler: d,
        instructions: instructions,
        instructionMap: instructionMap,
        stepCount: 0,
    }

    showInstructions(emulator.instructions)

    isRunning = true

    return true
}

function showInstructions(instructions: CsInstruction[]): void {
    const instrDiv = document.getElementById('instructions')
    if (!instrDiv) return
    instrDiv.innerHTML = instructions
        .map(
            (insn) => `
    <div class="instr-row" data-addr="${insn.address}">
      <div class="instr-dot"></div>
      <span class="addr">0x${insn.address.toString(16)}</span>
      <span class="mnem">${insn.mnemonic}</span>
      <span class="ops">${insn.op_str}</span>
    </div>
  `
        )
        .join('')
}

async function highlightInstruction(addr: number): Promise<void> {
    const instrDiv = document.getElementById('instructions')
    if (!instrDiv) return
    const rows = instrDiv.getElementsByClassName('instr-row')
    for (let i = 0; i < rows.length; i++) {
        const row = rows[i] as HTMLDivElement
        const rowAddr = parseInt(row.dataset.addr || '0', 10)
        if (rowAddr === addr) {
            row.classList.add('active')
            row.scrollIntoView({ behavior: 'smooth', block: 'center' })
        } else {
            row.classList.remove('active')
        }
    }
}

function executeNextInstruction(): boolean {
    if (!emulator || !textSection) return false

    const d = emulator.disassembler

    const eipIdx = registers.eip - textSection.vma

    if (eipIdx < 0 || eipIdx >= textSection.size) {
        log('EIP outside .text')
        return false
    }

    const getVal = (op: CsOperand): number => {
        if (op.type === cs.OP_REG)
            return registers[d.reg_name(op.reg) as RegisterName]
        if (op.type === cs.OP_IMM) return op.imm >>> 0
        if (op.type === cs.OP_MEM) return readMemOp(op, d)
        return 0
    }

    emulator.stepCount++

    const insn = emulator.instructionMap.get(registers.eip)

    if (!insn) {
        log(`No instruction at 0x${registers.eip.toString(16)}`)
        return false
    }
    const ops = insn.detail.op

    if (eipIdx < 0 || eipIdx >= textSection.size) {
        log(
            `EIP 0x${registers.eip.toString(16)} is outside .text bounds. Stopping.`
        )
        return false
    }

    if (++emulator.stepCount > MAX_STEPS) {
        log(`Step limit (${MAX_STEPS}) reached. Stopping.`)
        return false
    }

    const nextEip = registers.eip + insn.size
    let jumped = false

    switch (insn.mnemonic) {
        case 'mov':
            if (ops[0].type === cs.OP_REG) {
                registers[d.reg_name(ops[0].reg) as RegisterName] =
                    getVal(ops[1]) >>> 0
            } else if (ops[0].type === cs.OP_MEM) {
                writeMemOp(ops[0], getVal(ops[1]), d)
            }
            break

        case 'add': {
            const reg = d.reg_name(ops[0].reg) as RegisterName
            const result = (registers[reg] + getVal(ops[1])) >>> 0
            registers[reg] = result
            flags.zf = result === 0
            flags.sf = (result & 0x80000000) !== 0
            break
        }

        case 'sub': {
            const reg = d.reg_name(ops[0].reg) as RegisterName
            const raw = registers[reg] - getVal(ops[1])
            const result = raw >>> 0
            registers[reg] = result
            flags.zf = result === 0
            flags.sf = (result & 0x80000000) !== 0
            flags.cf = raw < 0
            break
        }

        case 'push':
            registers.esp -= WORD_SIZE
            writeMem(registers.esp, getVal(ops[0]))
            break

        case 'pop': {
            const reg = d.reg_name(ops[0].reg) as RegisterName
            registers[reg] = readMemAt(registers.esp)
            registers.esp += WORD_SIZE
            break
        }

        case 'cmp': {
            const v1 = getVal(ops[0])
            const v2 = getVal(ops[1])
            const raw = v1 - v2
            const result = raw >>> 0
            flags.zf = result === 0
            flags.sf = (result & 0x80000000) !== 0
            flags.cf = raw < 0
            flags.of = ((v1 ^ v2) & (v1 ^ result) & 0x80000000) !== 0
            log(
                `  cmp: 0x${v1.toString(16)} vs 0x${v2.toString(16)} -> zf=${flags.zf} sf=${flags.sf} of=${flags.of}`
            )
            break
        }

        case 'jmp':
            registers.eip = getVal(ops[0])
            jumped = true
            break

        case 'je':
            if (flags.zf) {
                registers.eip = getVal(ops[0])
                jumped = true
            }
            break

        case 'jne':
            if (!flags.zf) {
                registers.eip = getVal(ops[0])
                jumped = true
            }
            break

        case 'jl':
            if (flags.sf !== flags.of) {
                registers.eip = getVal(ops[0])
                jumped = true
            }
            break

        case 'jle':
            if (flags.sf !== flags.of || flags.zf) {
                registers.eip = getVal(ops[0])
                jumped = true
            }
            break

        case 'jg':
            if (flags.sf === flags.of && !flags.zf) {
                registers.eip = getVal(ops[0])
                jumped = true
            }
            break

        case 'jge':
            if (flags.sf === flags.of) {
                registers.eip = getVal(ops[0])
                jumped = true
            }
            break

        case 'call':
            registers.esp -= WORD_SIZE
            writeMem(registers.esp, nextEip)
            registers.eip = getVal(ops[0])
            jumped = true
            break

        case 'leave':
            registers.esp = registers.ebp
            registers.ebp = readMemAt(registers.esp)
            registers.esp += WORD_SIZE
            break

        case 'ret': {
            const retAddr = readMemAt(registers.esp)
            registers.esp += WORD_SIZE
            if (retAddr === SENTINEL) {
                log('Reached end of main. Exiting.')
                log('Return value (EAX): ' + registers.eax)
                isRunning = false
                break
            }
            log('Returning to 0x' + retAddr.toString(16))
            registers.eip = retAddr
            jumped = true
            break
        }

        case 'int':
            if (getVal(ops[0]) === 0x80 && registers.eax === 1) {
                log(`Program exited with code ${registers.ebx}`)
                isRunning = false
            }
            break

        case 'nop':
            break

        default:
            log(`[!] Unimplemented: ${insn.mnemonic}`)
            isRunning = false
    }

    if (!jumped) registers.eip = nextEip

    updateUI()
    highlightInstruction(insn.address)

    return isRunning
}

async function runEmulator(): Promise<void> {
    const MAX_STEPS = 1000

    if (!initializeEmulator()) return

    while (isRunning && emulator && emulator.stepCount < MAX_STEPS) {
        if (!executeNextInstruction()) break
    }

    // cleanupEmulator();
}

function stepEmulator(): void {
    if (!emulator) {
        if (!initializeEmulator())
            return;
    }

    executeNextInstruction();
    showMemoryDump(memory, memorySize - 128, 128);

    if (!isRunning) {
        // cleanupEmulator();
        console.log('Emulator stopped.')
    }
}
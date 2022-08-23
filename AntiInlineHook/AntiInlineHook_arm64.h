#ifndef AntiInlineHook_h
#define AntiInlineHook_h

#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <assert.h>

// refs: https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/MSHookFunctionChecker.swift

#if defined(__arm64__) || defined(__arm64e__)

static __attribute__ ((always_inline)) int64_t singExtend(int64_t value) {
    int64_t result = value;
    int64_t sing = value >> (33 - 1) == 1;
    if (sing) {
        result = (((1L << 31L) - 1L) << 33L) | value;
    }
    return result;
}
static __attribute__ ((always_inline)) uint64_t getAdrpPageBase(void *symbol_addr) {
    uint32_t arm = *(uint32_t *)symbol_addr;
    uint32_t immlo = (arm >> 29) & 3;
    uint32_t immhiMask = (uint32_t)(((1 << 19) - 1) << 5);
    uint32_t immhi = (arm & immhiMask) >> 5;
    int64_t imm = ((int64_t)(immhi << 2 | immlo) << 12);
    uintptr_t pcBase = ((uintptr_t)symbol_addr >> 12) << 12;
    return (uint64_t)((int64_t)pcBase + singExtend(imm));
}
static __attribute__ ((always_inline)) uint64_t getAddPageOffset(void *symbol_addr) {
    uint32_t arm = *(uint32_t *)symbol_addr;
    uint32_t add = arm >> 24;
    if (add == 0b10010001) {
        uint32_t add_imm12 = (uint32_t)((arm & (((1 << 12) - 1) << 10)) >> 10);
        uint64_t imm = (uint64_t)add_imm12;
        uint32_t shift = (arm & (3 << 22)) >> 22;
        if (shift == 0) {
            imm = (uint64_t)add_imm12;
        } else if (shift == 1) {
            imm = (uint64_t)(add_imm12 << 12);
        } else {
            return 0;
        }
        return imm;
    }
    return 0;
}
static __attribute__ ((always_inline)) uint16_t getMovImm(void *symbol_addr) {
    uint32_t arm = *(uint32_t *)symbol_addr;
    return (arm & (((uint32_t)1 << 16) - 1) << 5) >> 5;
}

enum InlineHookInstruction {
    ldr_x16 = 1,
    br_x16,
    ldr_x17,
    br_x17,
    adrp_x16,
    add_x16,
    adrp_x17,
    add_x17,
    movz_x16,
    movk_x16,
    movz_x17,
    movk_x17,
    unknownInstruction
};

static __attribute__ ((always_inline)) enum InlineHookInstruction translateInstruction(void *symbol_addr) {
    uint32_t arm = *(uint32_t *)symbol_addr;
    // ldr xt, #imm  (C4.4.5 and C6.2.84)
    uint32_t ldr_register_litetal = (arm & (255 << 24)) >> 24;
    if (ldr_register_litetal == 0b01011000) {
        uint32_t imm19 = (arm & (((1 << 19) - 1) << 5)) >> 5;
        if ((imm19 << 2) == 8) {
            uint32_t rt = arm & 31;
            if (rt == 16) return ldr_x16;
            if (rt == 17) return ldr_x17;
        }
    }
    // br
    uint32_t br = arm >> 10;
    if (br == 0b1101011000011111000000) {
        uint32_t br_rn = (arm & (31 << 5)) >> 5;
        if (br_rn == 16) {
            return br_x16;
        }
        if (br_rn == 17) {
            return br_x17;
        }
    }
    // adrp (C6.2.10)
    uint32_t adrp_op = arm >> 31;
    uint32_t adrp = (arm & (31 << 24)) >> 24;
    uint32_t rd = arm & (31 << 0);
    if (adrp_op == 1 && adrp == 16) {
        // adrp x16, pageBase
        if (rd == 16) {
            return adrp_x16;
        }
        // adrp x17, pageBase
        if (rd == 17) {
            return adrp_x17;
        }
    }
    // add (C4.2.1 and C6.2.4)
    uint32_t add = arm >> 24;
    if (add == 0b10010001) {      // 32-bit: 0b00010001
        uint32_t add_rn = (arm & (31 << 5)) >> 5;
        uint32_t add_rd = arm & 31;
        uint32_t add_imm12 = (uint32_t)((arm & (((1 << 12) - 1) << 10)) >> 10);
        uint64_t imm = (uint64_t)add_imm12;
        uint32_t shift = (arm & (3 << 22)) >> 22;
        if (shift == 0) {
            imm = (uint64_t)add_imm12;
        } else if (shift == 1) {
            imm = (uint64_t)(add_imm12 << 12);
        } else {
            // AArch64.UndefinedFault
            return unknownInstruction;
        }
        // add x16, x16, add_im
        if (add_rn == 16 && add_rd == 16) {
            return add_x16;
        }
        // add x17, x17, add_im
        if (add_rn == 17 && add_rd == 17) {
            return add_x17;
        }
    }
    // movz
    uint32_t movz = arm >> 23;
    if (movz == 0b110100101) {
        uint32_t movz_rd = arm & 31;
        if (movz_rd == 16) {
            return movz_x16;
        }
        if (movz_rd == 17) {
            return movz_x17;
        }
    }
    // movk
    uint32_t movk = arm >> 23;
    if (movk == 0b111100101) {
        uint32_t movk_rd = arm & 31;
        if (movk_rd == 16) {
            return movk_x16;
        }
        if (movk_rd == 17) {
            return movk_x17;
        }
    }
    return unknownInstruction;
}

__attribute__ ((always_inline))
_Bool isInlineHooked(void *symbol_addr) {
    enum InlineHookInstruction firstInstruction = translateInstruction(symbol_addr);
    if (firstInstruction == unknownInstruction) {
        return 0;
    }
    switch (firstInstruction) {
        case ldr_x16: {
            void *secondInstructionAddr = (void *)((uintptr_t)symbol_addr + 4);
            if (translateInstruction(secondInstructionAddr) == br_x16) {
                return 1;
            }
            return 0;
        }
        case ldr_x17: {
            void *secondInstructionAddr = (void *)((uintptr_t)symbol_addr + 4);
            if (translateInstruction(secondInstructionAddr) == br_x17) {
                return 1;
            }
            return 0;
        }
        case adrp_x16: {
            void *secondInstructionAddr = (void *)((uintptr_t)symbol_addr + 4);
            void *thridInstructionAddr = (void *)((uintptr_t)symbol_addr + 8);
            if (translateInstruction(secondInstructionAddr) == add_x16 && translateInstruction(thridInstructionAddr) == br_x16) {
                return 1;
            }
            return 0;
        }
        case adrp_x17: {
            void *secondInstructionAddr = (void *)((uintptr_t)symbol_addr + 4);
            void *thridInstructionAddr = (void *)((uintptr_t)symbol_addr + 8);
            if (translateInstruction(secondInstructionAddr) == add_x17 && translateInstruction(thridInstructionAddr) == br_x17) {
                return 1;
            }
            return 0;
        }
        default:
            return 0;
    }
}


// (xnu vm feature): mmap ==> vm_region
__attribute__ ((always_inline))
void *antiInlineHook(void *orig_func) {
    if (!isInlineHooked(orig_func)) {
        return orig_func;
    }

    void *origFunctionBeginAddr = orig_func;
    switch (firstInstruction) {
    case ldr_x16:
        origFunctionBeginAddr = (void *)((uintptr_t)origFunctionBeginAddr + 16);
        break;
    case ldr_x17:
        origFunctionBeginAddr = (void *)((uintptr_t)origFunctionBeginAddr + 16);
        break;
    case adrp_x16:
        origFunctionBeginAddr = (void *)((uintptr_t)origFunctionBeginAddr + 12);
        break;
    case adrp_x17:
        origFunctionBeginAddr = (void *)((uintptr_t)origFunctionBeginAddr + 12);
        break;
    default:
        return orig_func;
    }
    
    struct vm_region_basic_info_64 info;
    vm_address_t region_address = 1;
    vm_size_t size = 0;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = 0;
    
    while (1) {
        if (region_address == 0) {
            return orig_func;
        }
        kern_return_t kr = vm_region_64(mach_task_self_, &region_address, &size, VM_REGION_BASIC_INFO, (vm_region_info_64_t)&info, &count, &object_name);
        if (kr == KERN_SUCCESS) {
            if (info.protection == (VM_PROT_READ|VM_PROT_EXECUTE)) {
                // ldr
                if (ldr_x16 == firstInstruction) {
                    // 20: max_buffer_insered_Instruction
                    for (int i = 4; i < 20; i++) {
                        void *instructionAddr = (void *)((int64_t)region_address + i * 4);
                        if (ldr_x16 == translateInstruction(instructionAddr) &&
                            br_x16 == translateInstruction((void *)((uintptr_t)instructionAddr + 4)) &&
                            ((uintptr_t)instructionAddr + 1) == (uintptr_t)origFunctionBeginAddr) {
                            return (void *)region_address;
                        }
                    }
                }
               if (ldr_x17 == firstInstruction) {
                    // 20: max_buffer_insered_Instruction
                    for (int i = 4; i < 20; i++) {
                        void *instructionAddr = (void *)((int64_t)region_address + i * 4);
                        if (ldr_x17 == translateInstruction(instructionAddr) &&
                            br_x17 == translateInstruction((void *)((uintptr_t)instructionAddr + 4)) &&
                            ((uintptr_t)instructionAddr + 1) == (uintptr_t)origFunctionBeginAddr) {
                            return (void *)region_address;
                        }
                    }
                }
                // adrp
                if (adrp_x16 == firstInstruction) {
                    // 20: max_buffer_insered_Instruction
                    for (int i = 3; i < 20; i++) {
                        void *instructionAddr = (void *)((int64_t)region_address + i * 4);
                        if (ldr_x16 == translateInstruction(instructionAddr) &&
                            br_x16 == translateInstruction((void *)((uintptr_t)instructionAddr + 4)) &&
                            (*(uintptr_t *)((uintptr_t)instructionAddr + 8)) == (uintptr_t)origFunctionBeginAddr) {
                            return (void *)region_address;
                        }
                        if (movz_x16 == translateInstruction(instructionAddr) &&
                            movk_x16 == translateInstruction((void *)((uintptr_t)instructionAddr + 4)) &&
                            movk_x16 == translateInstruction((void *)((uintptr_t)instructionAddr + 8)) &&
                            movk_x16 == translateInstruction((void *)((uintptr_t)instructionAddr + 12)) &&
                            br_x16 == translateInstruction((void *)((uintptr_t)instructionAddr + 16))) {
                            char buf[32], buf2[32];
                            sprintf(buf, "0x%x0%x%x", getMovImm((void *)((uintptr_t)instructionAddr + 8)), getMovImm((void *)((uintptr_t)instructionAddr + 4)), getMovImm(instructionAddr));
                            sprintf(buf2, "0x%x00%x%x", getMovImm((void *)((uintptr_t)instructionAddr + 8)), getMovImm((void *)((uintptr_t)instructionAddr + 4)), getMovImm(instructionAddr));
                            if (strtoul(buf, 0, 16) == (uint64_t)origFunctionBeginAddr ||
                                strtoul(buf2, 0, 16) == (uint64_t)origFunctionBeginAddr) {
                                return (void *)region_address;
                            }
                        }
                        if (adrp_x16 == translateInstruction(instructionAddr) &&
                            add_x16 == translateInstruction((void *)((uintptr_t)instructionAddr + 4)) &&
                            br_x16 == translateInstruction((void *)((uintptr_t)instructionAddr + 8)) &&
                            getAdrpPageBase(instructionAddr) + getAddPageOffset((void *)((uintptr_t)instructionAddr + 4)) == (uint64_t)origFunctionBeginAddr) {
                            return (void *)region_address;
                        }
                    }
                }
                if (adrp_x17 == firstInstruction) {
                    // 20: max_buffer_insered_Instruction
                    for (int i = 3; i < 20; i++) {
                        void *instructionAddr = (void *)((int64_t)region_address + i * 4);
                        if (ldr_x17 == translateInstruction(instructionAddr) &&
                            br_x17 == translateInstruction((void *)((uintptr_t)instructionAddr + 4)) &&
                            (*(uintptr_t *)((uintptr_t)instructionAddr + 8)) == (uintptr_t)origFunctionBeginAddr) {
                            return (void *)region_address;
                        }
                        if (movz_x17 == translateInstruction(instructionAddr) &&
                            movk_x17 == translateInstruction((void *)((uintptr_t)instructionAddr + 4)) &&
                            movk_x17 == translateInstruction((void *)((uintptr_t)instructionAddr + 8)) &&
                            movk_x17 == translateInstruction((void *)((uintptr_t)instructionAddr + 12)) &&
                            br_x17 == translateInstruction((void *)((uintptr_t)instructionAddr + 16))) {
                            char buf[32], buf2[32];
                            sprintf(buf, "0x%x0%x%x", getMovImm((void *)((uintptr_t)instructionAddr + 8)), getMovImm((void *)((uintptr_t)instructionAddr + 4)), getMovImm(instructionAddr));
                            sprintf(buf2, "0x%x00%x%x", getMovImm((void *)((uintptr_t)instructionAddr + 8)), getMovImm((void *)((uintptr_t)instructionAddr + 4)), getMovImm(instructionAddr));
                            if (strtoul(buf, 0, 16) == (uint64_t)origFunctionBeginAddr ||
                                strtoul(buf2, 0, 16) == (uint64_t)origFunctionBeginAddr) {
                                return (void *)region_address;
                            }
                        }
                        if (adrp_x17 == translateInstruction(instructionAddr) &&
                            add_x17 == translateInstruction((void *)((uintptr_t)instructionAddr + 4)) &&
                            br_x17 == translateInstruction((void *)((uintptr_t)instructionAddr + 8)) &&
                            getAdrpPageBase(instructionAddr) + getAddPageOffset((void *)((uintptr_t)instructionAddr + 4)) == (uint64_t)origFunctionBeginAddr) {
                            return (void *)region_address;
                        }
                    }
                }
            }
            region_address += size;
        } else {
            return orig_func;
        }
    }
    return orig_func;
}


#endif


#endif /* AntiInlineHook_h */

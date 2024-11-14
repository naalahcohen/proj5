#include "x86-64.h"	// DO NOT EDIT!!!
#include "elf.h"	// DO NOT EDIT!!!
#include "lib.h"	// DO NOT EDIT!!!
#include "kernel.h"	// DO NOT EDIT!!!

// k-loader.c
//
//    Load a weensy application into memory from a RAM image.

#define SECTORSIZE              512

extern uint8_t _binary_obj_p_allocator_start[];
extern uint8_t _binary_obj_p_allocator_end[];
extern uint8_t _binary_obj_p_allocator2_start[];
extern uint8_t _binary_obj_p_allocator2_end[];
extern uint8_t _binary_obj_p_allocator3_start[];
extern uint8_t _binary_obj_p_allocator3_end[];
extern uint8_t _binary_obj_p_allocator4_start[];
extern uint8_t _binary_obj_p_allocator4_end[];
extern uint8_t _binary_obj_p_fork_start[];
extern uint8_t _binary_obj_p_fork_end[];
extern uint8_t _binary_obj_p_forkexit_start[];
extern uint8_t _binary_obj_p_forkexit_end[];
extern uint8_t _binary_obj_p_test_start[];
extern uint8_t _binary_obj_p_test_end[];

struct ramimage {
    void* begin;
    void* end;
} ramimages[] = {
    { _binary_obj_p_allocator_start, _binary_obj_p_allocator_end },
    { _binary_obj_p_allocator2_start, _binary_obj_p_allocator2_end },
    { _binary_obj_p_allocator3_start, _binary_obj_p_allocator3_end },
    { _binary_obj_p_allocator4_start, _binary_obj_p_allocator4_end },
    { _binary_obj_p_fork_start, _binary_obj_p_fork_end },
    { _binary_obj_p_forkexit_start, _binary_obj_p_forkexit_end },
    { _binary_obj_p_test_start, _binary_obj_p_test_end }
};

static int program_load_segment(proc* p, const elf_program* ph,
                                const uint8_t* src,
                                x86_64_pagetable* (*allocator)(void));

// program_load(p, programnumber)
//    Load the code corresponding to program `programnumber` into the process
//    `p` and set `p->p_registers.reg_rip` to its entry point. Calls
//    `assign_physical_page` to as required. Returns 0 on success and
//    -1 on failure (e.g. out-of-memory). `allocator` is passed to
//    `virtual_memory_map`.

int program_load(proc* p, int programnumber,
                 x86_64_pagetable* (*allocator)(void)) {
    // is this a valid program?
    int nprograms = sizeof(ramimages) / sizeof(ramimages[0]);
    assert(programnumber >= 0 && programnumber < nprograms);
    elf_header* eh = (elf_header*) ramimages[programnumber].begin;
    assert(eh->e_magic == ELF_MAGIC);

    // load each loadable program segment into memory
    elf_program* ph = (elf_program*) ((const uint8_t*) eh + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == ELF_PTYPE_LOAD) {
            const uint8_t* pdata = (const uint8_t*) eh + ph[i].p_offset;
            if (program_load_segment(p, &ph[i], pdata, allocator) < 0) {
                return -1;
            }
        }
    }

    // set the entry point from the ELF header
    p->p_registers.reg_rip = eh->e_entry;
    return 0;
}


// program_load_segment(p, ph, src, allocator)
//    Load an ELF segment at virtual address `ph->p_va` in process `p`. Copies
//    `[src, src + ph->p_filesz)` to `dst`, then clears
//    `[ph->p_va + ph->p_filesz, ph->p_va + ph->p_memsz)` to 0.
//    Calls `assign_physical_page` to allocate pages and `virtual_memory_map`
//    to map them in `p->p_pagetable`. Returns 0 on success and -1 on failure.
static int program_load_segment(proc* p, const elf_program* ph,
                              const uint8_t* src,
                              x86_64_pagetable* (*allocator)(void)) {
    uintptr_t va = (uintptr_t) ph->p_va;
    uintptr_t end_file = va + ph->p_filesz, end_mem = va + ph->p_memsz;
    va &= ~(PAGESIZE - 1);    // round to page boundary

    // Calculate final permissions
    int final_perm = PTE_P | PTE_U;
    if (ph->p_flags & ELF_PFLAG_WRITE) {
        final_perm |= PTE_W;
    }

    // allocate memory
    for (uintptr_t addr = va; addr < end_mem; addr += PAGESIZE) {
        // if (assign_physical_page(addr, p->p_pid) < 0) {
        //     console_printf(CPOS(22, 0), 0xC000, 
        //                  "program_load_segment(pid %d): out of physical memory\n",
        //                  p->p_pid);
        //     return -1;
        // }

        //use find free page, map to the result of that page 

        // Initially map with write permissions to allow copying
        int loader = find_free(p->p_pid);
        if (loader < 0 || virtual_memory_map(p->p_pagetable, addr, loader, PAGESIZE,
                             PTE_P | PTE_W | PTE_U) < 0) {
            console_printf(CPOS(22, 0), 0xC000, 
                         "program_load_segment(pid %d): can't map VA %p\n",
                         p->p_pid, addr);
            return -1;
        }
    }

    // ensure new memory mappings are active
    set_pagetable(p->p_pagetable);

    // copy data from executable image into process memory
    memcpy((uint8_t*) va, src, end_file - va);
    memset((uint8_t*) end_file, 0, end_mem - end_file);

    // After copying, set final permissions
    for (uintptr_t addr = va; addr < end_mem; addr += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(p->p_pagetable, addr);
        if (!vmap.pa) {
            return -1;
        }
        
        // For read-only segments, remove write permission
        if (!(ph->p_flags & ELF_PFLAG_WRITE)) {
            // Map as read-only
            if (virtual_memory_map(p->p_pagetable, addr, vmap.pa, PAGESIZE, 
                                 PTE_P | PTE_U) < 0) {
                return -1;
            }
        }
    }

    set_pagetable(kernel_pagetable);
    return 0;
}
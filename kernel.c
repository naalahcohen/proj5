#include "kernel.h"	// DO NOT EDIT!!!
#include "lib.h"	// DO NOT EDIT!!!

// kernel.c
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

static proc processes[NPROC];   // array of process descriptors
                                // Note that `processes[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static unsigned ticks;          // # timer interrupts so far

void schedule(void);
void run(proc* p) __attribute__((noreturn));

static uint8_t disp_global = 1;         // global flag to display memviewer

// PAGEINFO
//
//    The pageinfo[] array keeps track of information about each physical page.
//    There is one entry per physical page.
//    `pageinfo[pn]` holds the information for physical page number `pn`.
//    You can get a physical page number from a physical address `pa` using
//    `PAGENUMBER(pa)`. (This also works for page table entries.)
//    To change a physical page number `pn` into a physical address, use
//    `PAGEADDRESS(pn)`.
//
//    pageinfo[pn].refcount is the number of times physical page `pn` is
//      currently referenced. 0 means it's free.
//    pageinfo[pn].owner is a constant indicating who owns the page.
//      PO_KERNEL means the kernel, PO_RESERVED means reserved memory (such
//      as the console), and a number >=0 means that process ID.
//
//    pageinfo_init() sets up the initial pageinfo[] state.

typedef struct physical_pageinfo {
    int8_t owner;
    int8_t refcount;
} physical_pageinfo;

static physical_pageinfo pageinfo[PAGENUMBER(MEMSIZE_PHYSICAL)];

typedef enum pageowner {
    PO_FREE = 0,                // this page is free
    PO_RESERVED = -1,           // this page is reserved memory
    PO_KERNEL = -2              // this page is used by the kernel
} pageowner_t;

static void pageinfo_init(void);


// Memory functions

void check_virtual_memory(void);
void memshow_physical(void);
void memshow_virtual(x86_64_pagetable* pagetable, const char* name);
void memshow_virtual_animate(void);


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, int program_number);

//step 2: 
//set all five of them to 0
//map every entry to itself 
//make a reserve page fucntion 
//how to copy mappigns into kernel pagetable
void kernel(const char* command) {
    hardware_init();
    pageinfo_init();
    console_clear();
    timer_init(HZ);

   if(virtual_memory_map(kernel_pagetable, (uintptr_t) 0, (uintptr_t) 0, PROC_START_ADDR, PTE_P | PTE_W)== -1){
        current->p_registers.reg_rax = -1; 
   }
   //set rax to -1 
   //need to error check 

   //also want to set consol address, what do you do? there is a kernel macro 
   if (virtual_memory_map(kernel_pagetable, (uintptr_t) CONSOLE_ADDR, (uintptr_t) CONSOLE_ADDR, PAGESIZE, PTE_P | PTE_W | PTE_U)){
        current->p_registers.reg_rax = -1; 
   }
   //need to error check 
   
    // Set up process descriptors
    memset(processes, 0, sizeof(processes));
    for (pid_t i = 0; i < NPROC; i++) {
        processes[i].p_pid = i;
        processes[i].p_state = P_FREE;
    }

    if (command && strcmp(command, "fork") == 0) {
        process_setup(1, 4);
    } else if (command && strcmp(command, "forkexit") == 0) {
        process_setup(1, 5);
    } else if (command && strcmp(command, "test") == 0) {
        process_setup(1, 6);
    } else if (command && strcmp(command, "test2") == 0) {
        for (pid_t i = 1; i <= 2; ++i) {
            process_setup(i, 6);
        }
    } else {
        for (pid_t i = 1; i <= 4; ++i) {
            process_setup(i, i - 1);
        }
    }


    // Switch to the first process using run()
    run(&processes[1]);
}

//helper function 
uintptr_t find_free(int owner) {
    for (int pn = 0; pn < NPAGES; ++pn) {
        if (pageinfo[pn].refcount == 0) {         
            pageinfo[pn].refcount = 1;           
            pageinfo[pn].owner = owner;
            uintptr_t addr = PAGEADDRESS(pn);
            assert(addr % PAGESIZE == 0);  // Ensure alignment
            return addr;
        }
    }
    return (uintptr_t) -1;                                     
}

uintptr_t make_pagetable(pid_t owner) {
    // Allocate pages for page table levels
    uintptr_t l4_page = find_free(owner);
    uintptr_t l3_page = find_free(owner);
    uintptr_t l2_page = find_free(owner);
    uintptr_t l1_page1 = find_free(owner);
    uintptr_t l1_page2 = find_free(owner);

    if (!l4_page || !l3_page || !l2_page || !l1_page1 || !l1_page2) {
        if (l4_page) pageinfo[PAGENUMBER(l4_page)].refcount = 0;
        if (l3_page) pageinfo[PAGENUMBER(l3_page)].refcount = 0;
        if (l2_page) pageinfo[PAGENUMBER(l2_page)].refcount = 0;
        if (l1_page1) pageinfo[PAGENUMBER(l1_page1)].refcount = 0;
        if (l1_page2) pageinfo[PAGENUMBER(l1_page2)].refcount = 0;
        return (uintptr_t)-1;
    }

    x86_64_pagetable* pt4 = (x86_64_pagetable*) l4_page;
    x86_64_pagetable* pt3 = (x86_64_pagetable*) l3_page;
    x86_64_pagetable* pt2 = (x86_64_pagetable*) l2_page;
    x86_64_pagetable* pt1_0 = (x86_64_pagetable*) l1_page1;
    x86_64_pagetable* pt1_1 = (x86_64_pagetable*) l1_page2;

    memset(pt4, 0, PAGESIZE);
    memset(pt3, 0, PAGESIZE);
    memset(pt2, 0, PAGESIZE);
    memset(pt1_0, 0, PAGESIZE);
    memset(pt1_1, 0, PAGESIZE);

    // Set reference counts for page table pages
    pageinfo[PAGENUMBER(l4_page)].refcount = 1;
    pageinfo[PAGENUMBER(l3_page)].refcount = 1;
    pageinfo[PAGENUMBER(l2_page)].refcount = 1;
    pageinfo[PAGENUMBER(l1_page1)].refcount = 1;
    pageinfo[PAGENUMBER(l1_page2)].refcount = 1;

    pt4->entry[0] = (uintptr_t) pt3 | PTE_P | PTE_W | PTE_U;
    pt3->entry[0] = (uintptr_t) pt2 | PTE_P | PTE_W | PTE_U;
    pt2->entry[0] = (uintptr_t) pt1_0 | PTE_P | PTE_W | PTE_U;
    pt2->entry[1] = (uintptr_t) pt1_1 | PTE_P | PTE_W | PTE_U;

    return l4_page;
}

//helper function 
void free_child_resources(x86_64_pagetable* child_pagetable, pid_t child_pid) {
    for (int pn = 0; pn < NPAGES; pn++) {
        if (pageinfo[pn].owner == child_pid) {
            pageinfo[pn].refcount = 0;
            pageinfo[pn].owner = PO_FREE;
        }
    }
}
// process_setup(pid, program_number)
//    Load application program `program_number` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, int program_number) {
    log_printf("got to process setup\n");
    process_init(&processes[pid], 0);

    uintptr_t l4_page = make_pagetable(pid);
    if (l4_page == (uintptr_t)-1) {
        return; // Page table setup failed
    }
    x86_64_pagetable* pt4 = (x86_64_pagetable*) l4_page;

    // Map kernel and console pages
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        if (addr == CONSOLE_ADDR || addr < PROC_START_ADDR) {
            int r = virtual_memory_map(pt4, addr, addr, PAGESIZE, PTE_P | PTE_W);
            if (r < 0) {
                free_child_resources(pt4, pid);
                return;
            }
        }
    }

    // Map the console address specifically with user access
    int r = virtual_memory_map(pt4, CONSOLE_ADDR, CONSOLE_ADDR, PAGESIZE, PTE_P | PTE_W | PTE_U);
    if (r < 0) {
        free_child_resources(pt4, pid);
        return;
    }

    processes[pid].p_pagetable = pt4;

    // Load the program into memory
    r = program_load(&processes[pid], program_number, NULL);
    assert(r >= 0);

    // Set up the stack
    processes[pid].p_registers.reg_rsp = MEMSIZE_VIRTUAL;
    uintptr_t stack_page = processes[pid].p_registers.reg_rsp - PAGESIZE;
    
    uintptr_t free_page = find_free(pid);
    if (free_page == (uintptr_t)-1) {
        free_child_resources(pt4, pid);
        return;
    }
    assign_physical_page(free_page, pid);

    if (virtual_memory_map(processes[pid].p_pagetable, stack_page, free_page,
                          PAGESIZE, PTE_P | PTE_W | PTE_U) < 0) {
        free_child_resources(pt4, pid);
        return;
    }

    processes[pid].p_state = P_RUNNABLE;
}


// assign_physical_page(addr, owner)
//    Allocates the page with physical address `addr` to the given owner.
//    Fails if physical page `addr` was already allocated. Returns 0 on
//    success and -1 on failure. Used by the program loader.

int assign_physical_page(uintptr_t addr, int8_t owner) {
    if ((addr & 0xFFF) != 0
        || addr >= MEMSIZE_PHYSICAL
        || pageinfo[PAGENUMBER(addr)].refcount != 0) {
        return -1;
    } else {
        pageinfo[PAGENUMBER(addr)].refcount = 1;
        pageinfo[PAGENUMBER(addr)].owner = owner;
        return 0;
    }
}

void syscall_mapping(proc* p) {
    uintptr_t mapping_ptr = p->p_registers.reg_rdi;
    uintptr_t ptr = p->p_registers.reg_rsi;

    // added this
    if (mapping_ptr >= KERNEL_START_ADDR || ptr >= KERNEL_START_ADDR) {
        return;  // Block if either address is in kernel space
    }

    // Look up the virtual memory mapping for mapping_ptr
    vamapping map = virtual_memory_lookup(p->p_pagetable, mapping_ptr);

    // Check for user and write access
    if ((map.perm & (PTE_W | PTE_U)) != (PTE_W | PTE_U)) {
        return;  // Ensure the page is writable by the user
    }

    uintptr_t endaddr = mapping_ptr + sizeof(vamapping) - 1;

    // Check for user and write access for the end address
    vamapping end_map = virtual_memory_lookup(p->p_pagetable, endaddr);
    if ((end_map.perm & (PTE_W | PTE_U)) != (PTE_W | PTE_U)) {
        return;  // Ensure write permission for the whole range
    }

    // Perform the memory lookup for `ptr` now that it's validated
    vamapping ptr_lookup = virtual_memory_lookup(p->p_pagetable, ptr);

    // also added: Ensure `ptr` points to user-accessible memory, not kernel space
    if ((ptr_lookup.perm & PTE_U) == 0) {
        return;  // Block if `ptr` does not have user permissions
    }

    // Copy the mapping information safely since both addresses are verified
    memcpy((void *)map.pa, &ptr_lookup, sizeof(vamapping));
}


void syscall_mem_tog(proc* process){

    pid_t p = process->p_registers.reg_rdi;
    if(p == 0) {
        disp_global = !disp_global;
    }
    else {
        if(p < 0 || p > NPROC || p != process->p_pid)
            return;
        process->display_status = !(process->display_status);
    }
}


x86_64_pagetable* allocpage(uintptr_t l4_page_physical) {
    x86_64_pagetable* new_pagetable = (x86_64_pagetable*) l4_page_physical;
    memset(new_pagetable, 0, PAGESIZE);
    return new_pagetable;
}




// exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `reg`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled whenever the kernel is running.

void exception(x86_64_registers* reg) {
    // Copy the saved registers into the `current` process descriptor
    // and always use the kernel's page table.
    current->p_registers = *reg;
    set_pagetable(kernel_pagetable);

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /*log_printf("proc %d: exception %d\n", current->p_pid, reg->reg_intno);*/

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if ((reg->reg_intno != INT_PAGEFAULT && reg->reg_intno != INT_GPF) // no error due to pagefault or general fault
            || (reg->reg_err & PFERR_USER)) // pagefault error in user mode 
    {
        check_virtual_memory();
        if(disp_global){
            memshow_physical();
            memshow_virtual_animate();
        }
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (reg->reg_intno) {

    case INT_SYS_PANIC:
	    // rdi stores pointer for msg string
	    {
		char msg[160];
		uintptr_t addr = current->p_registers.reg_rdi;
		if((void *)addr == NULL)
		    panic(NULL);
		vamapping map = virtual_memory_lookup(current->p_pagetable, addr);
		memcpy(msg, (void *)map.pa, 160);
		panic(msg);

	    }
	    panic(NULL);
	    break;                  // will not be reached

    case INT_SYS_GETPID:
        current->p_registers.reg_rax = current->p_pid;
        break;

    case INT_SYS_YIELD:
        schedule();
        break;                  /* will not be reached */

    case INT_SYS_PAGE_ALLOC: {
        uintptr_t addr = current->p_registers.reg_rdi;
        if(addr % PAGESIZE != 0 || addr >= MEMSIZE_PHYSICAL || (addr >= 0xA0000 && addr < PROC_START_ADDR) || addr == 0){
            current->p_registers.reg_rax = -1; 
            break;
        }
        //do u need to do any checks here?

        uintptr_t freepage = find_free(current->p_pid);
        log_printf("value of the page: %d \n", freepage);
        if(freepage % PAGESIZE != 0 || freepage >= MEMSIZE_PHYSICAL || (freepage >= 0xA0000 && freepage < PROC_START_ADDR) || freepage == 0){
            log_printf("getting here");
            current->p_registers.reg_rax = -1; 
            break;
        }
        if(freepage == (uintptr_t)-1 ){
            current->p_registers.reg_rax = -1; 
            // error?
        }
        else{
            //mapping physical memory
            int result = virtual_memory_map(current->p_pagetable, addr, freepage, PAGESIZE, PTE_P | PTE_W | PTE_U);
            if (result < 0) {
                current->p_registers.reg_rax = -1; 
            } 
            else {
                current->p_registers.reg_rax = 0;  
            }
        }
        break;
    }
    //physical address not the same for child and parent 

    case INT_SYS_FORK: {
        pid_t child_pid = -1;
        for (pid_t i = 1; i < NPROC; i++) {
            if (processes[i].p_state == P_FREE) {
                child_pid = i;
                break;
            }
        }
        if (child_pid == -1) {
            current->p_registers.reg_rax = -1;
            break;
        }
        
        process_init(&processes[child_pid], 0);

        uintptr_t l4_page = make_pagetable(child_pid);
        if (l4_page == (uintptr_t)-1) {
            current->p_registers.reg_rax = -1;
            break;
        }
        x86_64_pagetable* child_pagetable = (x86_64_pagetable*) l4_page;

        // First map kernel pages
        for (uintptr_t addr = 0; addr < PROC_START_ADDR; addr += PAGESIZE) {
            int r = virtual_memory_map(child_pagetable, addr, addr, PAGESIZE, PTE_P | PTE_W);
            if (r < 0) {
                free_child_resources(child_pagetable, child_pid);
                current->p_registers.reg_rax = -1;
                break;
            }
        }

        // Map console
        if (virtual_memory_map(child_pagetable, CONSOLE_ADDR, CONSOLE_ADDR,
                            PAGESIZE, PTE_P | PTE_W | PTE_U) < 0) {
            free_child_resources(child_pagetable, child_pid);
            current->p_registers.reg_rax = -1;
            break;
        }

        // Copy/share other pages
        for (uintptr_t va = PROC_START_ADDR; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
            vamapping parent_mapping = virtual_memory_lookup(current->p_pagetable, va);
            
            if (parent_mapping.pa != 0 && (parent_mapping.perm & PTE_P)) {
                // Check if this is a read-only page
                if ((parent_mapping.perm & PTE_W) == 0) {
                    // Share read-only pages by mapping the same physical page
                    if (virtual_memory_map(child_pagetable, va, parent_mapping.pa,
                                        PAGESIZE, parent_mapping.perm) < 0) {
                        free_child_resources(child_pagetable, child_pid);
                        current->p_registers.reg_rax = -1;
                        break;
                    }
                    pageinfo[PAGENUMBER(parent_mapping.pa)].refcount++;
                } 
                else {
                    // Copy writable pages
                    uintptr_t new_pa = find_free(child_pid);
                    if (new_pa == (uintptr_t)-1) {
                        free_child_resources(child_pagetable, child_pid);
                        current->p_registers.reg_rax = -1;
                        break;
                    }

                    // Set up temporary mapping for copying
                    if (virtual_memory_map(child_pagetable, va, new_pa,
                                        PAGESIZE, parent_mapping.perm) < 0) {
                        free_child_resources(child_pagetable, child_pid);
                        current->p_registers.reg_rax = -1;
                        break;
                    }

                    memcpy((void*)new_pa, (void*)parent_mapping.pa, PAGESIZE);
                }
            }
        }

        // Set up child process
        processes[child_pid].p_registers = current->p_registers;
        processes[child_pid].p_registers.reg_rax = 0;
        current->p_registers.reg_rax = child_pid;
        processes[child_pid].p_pagetable = child_pagetable;
        processes[child_pid].p_state = P_RUNNABLE;
        break;
    }
    case INT_SYS_MAPPING:
    {
	    syscall_mapping(current);
            break;
    }

    case INT_SYS_MEM_TOG:
	{
	    syscall_mem_tog(current);
	    break;
	}

    case INT_TIMER:
        ++ticks;
        schedule();
        break;                  /* will not be reached */

    case INT_PAGEFAULT: {
        // Analyze faulting address and access type.
        uintptr_t addr = rcr2();
        const char* operation = reg->reg_err & PFERR_WRITE
                ? "write" : "read";
        const char* problem = reg->reg_err & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(reg->reg_err & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, reg->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->p_pid, addr, operation, problem, reg->reg_rip);
        current->p_state = P_BROKEN;
        break;
    }

case INT_SYS_EXIT: {
    // First free all user pages in the process's address space
    for (uintptr_t va = PROC_START_ADDR; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping map = virtual_memory_lookup(current->p_pagetable, va);
        if (map.pa && (map.perm & PTE_P)) {
            int page_num = PAGENUMBER(map.pa);
            if (--pageinfo[page_num].refcount == 0) {
                pageinfo[page_num].owner = PO_FREE;
                memset((void*) map.pa, 0, PAGESIZE);  // Clear the page for security
            }
            virtual_memory_map(current->p_pagetable, va, 0, PAGESIZE, 0);
        }
    }

    // Free page tables from bottom up (L1 to L4) ensuring ownership and refcount consistency
    x86_64_pagetable* pt = current->p_pagetable;
    for (int l4i = 0; l4i < 512; l4i++) {
        if (!(pt->entry[l4i] & PTE_P)) {
            continue;
        }
        x86_64_pagetable* l3 = (x86_64_pagetable*) PTE_ADDR(pt->entry[l4i]);
        
        for (int l3i = 0; l3i < 512; l3i++) {
            if (!(l3->entry[l3i] & PTE_P)) {
                continue;
            }
            x86_64_pagetable* l2 = (x86_64_pagetable*) PTE_ADDR(l3->entry[l3i]);
            
            for (int l2i = 0; l2i < 512; l2i++) {
                if (!(l2->entry[l2i] & PTE_P)) {
                    continue;
                }
                x86_64_pagetable* l1 = (x86_64_pagetable*) PTE_ADDR(l2->entry[l2i]);
                
                // Free L1 table
                int l1_pn = PAGENUMBER((uintptr_t) l1);
                if (--pageinfo[l1_pn].refcount == 0) {
                    pageinfo[l1_pn].owner = PO_FREE;
                    memset(l1, 0, PAGESIZE);  // Clear memory for security
                }
            }
            
            // Free L2 table
            int l2_pn = PAGENUMBER((uintptr_t) l2);
            if (--pageinfo[l2_pn].refcount == 0) {
                pageinfo[l2_pn].owner = PO_FREE;
                memset(l2, 0, PAGESIZE);  // Clear memory for security
            }
        }
        
        // Free L3 table
        int l3_pn = PAGENUMBER((uintptr_t) l3);
        if (--pageinfo[l3_pn].refcount == 0) {
            pageinfo[l3_pn].owner = PO_FREE;
            memset(l3, 0, PAGESIZE);  // Clear memory for security
        }
    }

    // Free L4 (top-level) page table
    int l4_pn = PAGENUMBER((uintptr_t) pt);
    if (--pageinfo[l4_pn].refcount == 0) {
        pageinfo[l4_pn].owner = PO_FREE;
        memset(pt, 0, PAGESIZE);  // Clear memory for security
    }

    // Mark process as free and schedule next
    current->p_state = P_FREE;
    current->p_pagetable = NULL;
    schedule();
    break;
}




    default:
        default_exception(current);
        break;                  /* will not be reached */

    }


    // Return to the current process (or run something else).
    if (current->p_state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule(void) {
    pid_t pid = current->p_pid;
    while (1) {
        pid = (pid + 1) % NPROC;
        if (processes[pid].p_state == P_RUNNABLE) {
            run(&processes[pid]);
        }
        // If Control-C was typed, exit the virtual machine.
        check_keyboard();
    }
}


// run(p)
//    Run process `p`. This means reloading all the registers from
//    `p->p_registers` using the `popal`, `popl`, and `iret` instructions.
//
//    As a side effect, sets `current = p`.

void run(proc* p) {
    assert(p->p_state == P_RUNNABLE);
    current = p;

    // Load the process's current pagetable.
    set_pagetable(p->p_pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(&p->p_registers);

 spinloop: goto spinloop;       // should never get here
}


// pageinfo_init
//    Initialize the `pageinfo[]` array.

void pageinfo_init(void) {
    extern char end[];

    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int owner;
        if (physical_memory_isreserved(addr)) {
            owner = PO_RESERVED;
        } else if ((addr >= KERNEL_START_ADDR && addr < (uintptr_t) end)
                   || addr == KERNEL_STACK_TOP - PAGESIZE) {
            owner = PO_KERNEL;
        } else {
            owner = PO_FREE;
        }
        pageinfo[PAGENUMBER(addr)].owner = owner;
        pageinfo[PAGENUMBER(addr)].refcount = (owner != PO_FREE);
    }
}


// check_page_table_mappings
//    Check operating system invariants about kernel mappings for page
//    table `pt`. Panic if any of the invariants are false.

void check_page_table_mappings(x86_64_pagetable* pt) {
    extern char start_data[], end[];
    assert(PTE_ADDR(pt) == (uintptr_t) pt);

    // kernel memory is identity mapped; data is writable
    for (uintptr_t va = KERNEL_START_ADDR; va < (uintptr_t) end;
         va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pt, va);
        if (vam.pa != va) {
            console_printf(CPOS(22, 0), 0xC000, "%p vs %p\n", va, vam.pa);
        }
        assert(vam.pa == va);
        if (va >= (uintptr_t) start_data) {
            assert(vam.perm & PTE_W);
        }
    }

    // kernel stack is identity mapped and writable
    uintptr_t kstack = KERNEL_STACK_TOP - PAGESIZE;
    vamapping vam = virtual_memory_lookup(pt, kstack);
    assert(vam.pa == kstack);
    assert(vam.perm & PTE_W);
}


// check_page_table_ownership
//    Check operating system invariants about ownership and reference
//    counts for page table `pt`. Panic if any of the invariants are false.

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount);

void check_page_table_ownership(x86_64_pagetable* pt, pid_t pid) {
    // calculate expected reference count for page tables
    int owner = pid;
    int expected_refcount = 1;
    if (pt == kernel_pagetable) {
        owner = PO_KERNEL;
        for (int xpid = 0; xpid < NPROC; ++xpid) {
            if (processes[xpid].p_state != P_FREE
                && processes[xpid].p_pagetable == kernel_pagetable) {
                ++expected_refcount;
            }
        }
    }
    check_page_table_ownership_level(pt, 0, owner, expected_refcount);
}

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount) {
    assert(PAGENUMBER(pt) < NPAGES);
    if (pageinfo[PAGENUMBER(pt)].owner != owner) {
    log_printf("Ownership mismatch at level %d: expected %d, found %d\n", 
               level, owner, pageinfo[PAGENUMBER(pt)].owner);
    }
    assert(pageinfo[PAGENUMBER(pt)].owner == owner);
    assert(pageinfo[PAGENUMBER(pt)].refcount == refcount);
    if (level < 3) {
        for (int index = 0; index < NPAGETABLEENTRIES; ++index) {
            if (pt->entry[index]) {
                x86_64_pagetable* nextpt =
                    (x86_64_pagetable*) PTE_ADDR(pt->entry[index]);
                check_page_table_ownership_level(nextpt, level + 1, owner, 1);
            }
        }
    }
}


// check_virtual_memory
//    Check operating system invariants about virtual memory. Panic if any
//    of the invariants are false.

void check_virtual_memory(void) {
    // Process 0 must never be used.
    assert(processes[0].p_state == P_FREE);

    // The kernel page table should be owned by the kernel;
    // its reference count should equal 1, plus the number of processes
    // that don't have their own page tables.
    // Active processes have their own page tables. A process page table
    // should be owned by that process and have reference count 1.
    // All level-2-4 page tables must have reference count 1.

    check_page_table_mappings(kernel_pagetable);
    check_page_table_ownership(kernel_pagetable, -1);

    for (int pid = 0; pid < NPROC; ++pid) {
        if (processes[pid].p_state != P_FREE
            && processes[pid].p_pagetable != kernel_pagetable) {
            check_page_table_mappings(processes[pid].p_pagetable);
            check_page_table_ownership(processes[pid].p_pagetable, pid);
        }
    }

    // Check that all referenced pages refer to active processes
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pageinfo[pn].refcount > 0 && pageinfo[pn].owner >= 0) {
            assert(processes[pageinfo[pn].owner].p_state != P_FREE);
        }
    }
}

// memshow_physical
//    Draw a picture of physical memory on the CGA console.

static const uint16_t memstate_colors[] = {
    'K' | 0x0D00, 'R' | 0x0700, '.' | 0x0700, '1' | 0x0C00,
    '2' | 0x0A00, '3' | 0x0900, '4' | 0x0E00, '5' | 0x0F00,
    '6' | 0x0C00, '7' | 0x0A00, '8' | 0x0900, '9' | 0x0E00,
    'A' | 0x0F00, 'B' | 0x0C00, 'C' | 0x0A00, 'D' | 0x0900,
    'E' | 0x0E00, 'F' | 0x0F00, 'S'
};
#define SHARED_COLOR memstate_colors[18]
#define SHARED

void memshow_physical(void) {
    console_printf(CPOS(0, 32), 0x0F00, "PHYSICAL MEMORY");
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pn % 64 == 0) {
            console_printf(CPOS(1 + pn / 64, 3), 0x0F00, "0x%06X ", pn << 12);
        }

        int owner = pageinfo[pn].owner;
        if (pageinfo[pn].refcount == 0) {
            owner = PO_FREE;
        }
        uint16_t color = memstate_colors[owner - PO_KERNEL];
        // darker color for shared pages
        if (pageinfo[pn].refcount > 1 && pn != PAGENUMBER(CONSOLE_ADDR)){
#ifdef SHARED
            color = SHARED_COLOR | 0x0F00;
#else
	    color &= 0x77FF;
#endif
        }

        console[CPOS(1 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual(pagetable, name)
//    Draw a picture of the virtual memory map `pagetable` (named `name`) on
//    the CGA console.

void memshow_virtual(x86_64_pagetable* pagetable, const char* name) {
    assert((uintptr_t) pagetable == PTE_ADDR(pagetable));

    console_printf(CPOS(10, 26), 0x0F00, "VIRTUAL ADDRESS SPACE FOR %s", name);
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pagetable, va);
        uint16_t color;
        if (vam.pn < 0) {
            color = ' ';
        } else {
            assert(vam.pa < MEMSIZE_PHYSICAL);
            int owner = pageinfo[vam.pn].owner;
            if (pageinfo[vam.pn].refcount == 0) {
                owner = PO_FREE;
            }
            color = memstate_colors[owner - PO_KERNEL];
            // reverse video for user-accessible pages
            if (vam.perm & PTE_U) {
                color = ((color & 0x0F00) << 4) | ((color & 0xF000) >> 4)
                    | (color & 0x00FF);
            }
            // darker color for shared pages
            if (pageinfo[vam.pn].refcount > 1 && va != CONSOLE_ADDR) {
#ifdef SHARED
                color = (SHARED_COLOR | (color & 0xF000));
                if(! (vam.perm & PTE_U))
                    color = color | 0x0F00;

#else
		color &= 0x77FF;
#endif
            }
        }
        uint32_t pn = PAGENUMBER(va);
        if (pn % 64 == 0) {
            console_printf(CPOS(11 + pn / 64, 3), 0x0F00, "0x%06X ", va);
        }
        console[CPOS(11 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual_animate
//    Draw a picture of process virtual memory maps on the CGA console.
//    Starts with process 1, then switches to a new process every 0.25 sec.

void memshow_virtual_animate(void) {
    static unsigned last_ticks = 0;
    static int showing = 1;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        ++showing;
    }

    // the current process may have died -- don't display it if so
    while (showing <= 2*NPROC
           && (processes[showing % NPROC].p_state == P_FREE || processes[showing % NPROC].display_status == 0)) {
        ++showing;
    }
    showing = showing % NPROC;

    if (processes[showing].p_state != P_FREE) {
        char s[4];
        snprintf(s, 4, "%d ", showing);
        memshow_virtual(processes[showing].p_pagetable, s);
    }
}

//reserved page missing 
//ask aboiut colors being different 



//objective: build a tiny little operating system (thin software layer between hardware and the user space)
// kernel: core OS code 

//initially get a virtual address and need to convert that into the physical address, take the bits in the virtual address
//and use them to index into the page table 
    //need to know the base address of L1 table (CR3 points to this base address)
    //get a virtual address coming in, index into L1 table, use the index from the virtual address to know where you should index into L1 table

//mapping to a 4KB page (ex: malloc 10 bytes, creates a new page but only use 10 bytes of the 4KB page until you use it up, then you can get more pages)
    //work at the level of pages, programmer might be working at the level of bytes

//take the virtual address and shift the bits so you can access the part of the number you care about >> 
    // index then offset, shift the index because that is the part you care about 

//bits being repurposed, to do other work, all the permission things (Global, dirty, access, etc...)
//if a process is attempting to access a kernel page
    //check the permissions and set them correctly "A missing component in these steps is the permissions 
    //check for access. Not only is the final translation checked for appropriate read/write, user, and present permissions, 
    // but each individual page table page translation also needs to have valid permissions, i.e. they need to be set with PTE_P ,
    // PTE_W, or PTE_U, or combinations of them." --use a bitwise or 

//step 5: deep copy for fork, isolating the memory 

//step 6: if a page is read only dont copy it over just make it shared between the processes
    //still copy the page tables over but you don't copy the actual pages containing 
    // don't need to do a memcpy 






//step 3: 

//step 5: fork, implementing fork 
//step 6: 
//step 7: 




/**
STEP 2:
objective: implement process isolation by giving each process its own independent page table 
    - each process only has access to its own pages 
    - use page info data struct: allocate new physical pages to processes for page tables, code, data, etc
        - use page info array to keep track of used and avaliable pages  
    
    - create helper function to find free pages, reserve it in pageinfo, and return its page address.
    - reset them all to empty (memset to zero), the kernel already has access to all pages with 
        identity-mapped addresses from virtual to physical
    
    page table type to use for these tables: 
    // Page table entry type and page table type
        typedef uint64_t x86_64_pageentry_t;
        typedef struct __attribute__((aligned(PAGESIZE))) x86_64_pagetable {
            x86_64_pageentry_t entry[NPAGETABLEENTRIES];
        } x86_64_pagetable;

    - how to fill entries?: for weensyOS only need to map 3MB of virtual memory 
        - For all the tables you allocated, each has 8-byte entries, and is 4K in size, so there are 512 entries per table.
            For a regular Page Table, 512 entries mapping each mapping to a 4K page would cover 2MB of virtual memory.
            Thus you need 2 L1 pagetables, and 1 each of the L2, L3, L4 (totaling 5 pages).   
    - Fill in the appropriate entries to connect the page tables.
    - Copy mappings from the kernel page table (below PROC_START_ADDR). 
    You can use a loop with virtual_memory_lookup and virtual_memory_map to copy them. 
    Alternatively, you can copy the mappings from the kernel’s page table into the new page table using memcpy. T
    his is faster, but make sure you copy the right data!
    Assign the table to the process's p_pagetable field.
*/





// PAGEINFO
//
//    The pageinfo[] array keeps track of information about each physical page.
//    There is one entry per physical page.
//    `pageinfo[pn]` holds the information for physical page number `pn`.
//    You can get a physical page number from a physical address `pa` using
//    `PAGENUMBER(pa)`. (This also works for page table entries.)
//    To change a physical page number `pn` into a physical address, use
//    `PAGEADDRESS(pn)`.
//
//    pageinfo[pn].refcount is the number of times physical page `pn` is
//      currently referenced. 0 means it's free.
//    pageinfo[pn].owner is a constant indicating who owns the page.
//      PO_KERNEL means the kernel, PO_RESERVED means reserved memory (such
//      as the console), and a number >=0 means that process ID.
//
//    pageinfo_init() sets up the initial pageinfo[] state.

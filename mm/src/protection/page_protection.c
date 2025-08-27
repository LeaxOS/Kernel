/**
 * @file page_protection.c
 * @brief Page protection mechanisms
 * 
 * @author LeaxOS Team
 * @version 1.0
 */

#include "stdint.h"
#include "stddef.h"
#include "stdbool.h"
#include "string.h"
#include "stdio.h"
#include "mm_common.h"
#include "memory_protection.h"
#include "mm.h"

/* ========================================================================
 * PAGE PROTECTION IMPLEMENTATION
 * ======================================================================== */

/** Global protection statistics */
static protection_stats_t g_protection_stats = {0};
static mm_spinlock_t g_protection_lock = MM_SPINLOCK_INIT("page_protection");

/** Hardware capabilities */
static hw_protection_caps_t g_hw_caps = {0};
static bool g_protection_initialized = false;

/** Enabled protection features */
static uint32_t g_enabled_features = 0;

/** Protection violation handler */
static protection_violation_handler_t g_violation_handler = NULL;

/* ========================================================================
 * HARDWARE DETECTION
 * ======================================================================== */

/**
 * @brief Detect hardware protection capabilities
 */
static void detect_hw_protection_caps(void) {
    /* In a real implementation, this would use CPUID to detect:
     * - NX bit support (CPUID.80000001H:EDX.NX[bit 20])
     * - SMEP support (CPUID.07H:EBX.SMEP[bit 7])
     * - SMAP support (CPUID.07H:EBX.SMAP[bit 20])
     * - PKU support (CPUID.07H:ECX.PKU[bit 3])
     * - CET support (CPUID.07H:ECX.CET[bit 7])
     * 
     * For simulation, we'll assume modern CPU with most features
     */
    
    g_hw_caps.nx_supported = true;
    g_hw_caps.smep_supported = true;
    g_hw_caps.smap_supported = true;
    g_hw_caps.pku_supported = true;
    g_hw_caps.cet_supported = false;  /* Less common */
    g_hw_caps.mpx_supported = false;  /* Deprecated */
    
    g_hw_caps.max_protection_keys = 16;
    g_hw_caps.address_bits = 48;
    g_hw_caps.physical_bits = 52;
    
    printk(KERN_INFO "Protection: Hardware capabilities detected\n");
    printk(KERN_INFO "  NX: %s, SMEP: %s, SMAP: %s, PKU: %s\n",
           g_hw_caps.nx_supported ? "yes" : "no",
           g_hw_caps.smep_supported ? "yes" : "no",
           g_hw_caps.smap_supported ? "yes" : "no",
           g_hw_caps.pku_supported ? "yes" : "no");
}

/**
 * @brief Enable hardware protection feature
 * @param feature Feature to enable
 * @return true if enabled successfully
 */
static bool enable_hw_feature(mem_prot_features_t feature) {
    switch (feature) {
    case MEM_PROT_NX:
        if (g_hw_caps.nx_supported) {
            /* Set EFER.NXE bit */
            printk(KERN_DEBUG "Protection: NX bit enabled\n");
            return true;
        }
        break;
        
    case MEM_PROT_SMEP:
        if (g_hw_caps.smep_supported) {
            /* Set CR4.SMEP bit */
            printk(KERN_DEBUG "Protection: SMEP enabled\n");
            return true;
        }
        break;
        
    case MEM_PROT_SMAP:
        if (g_hw_caps.smap_supported) {
            /* Set CR4.SMAP bit */
            printk(KERN_DEBUG "Protection: SMAP enabled\n");
            return true;
        }
        break;
        
    case MEM_PROT_PKU:
        if (g_hw_caps.pku_supported) {
            /* Set CR4.PKE bit */
            printk(KERN_DEBUG "Protection: PKU enabled\n");
            return true;
        }
        break;
        
    default:
        return false;
    }
    
    return false;
}

/* ========================================================================
 * PAGE TABLE PROTECTION
 * ======================================================================== */

/**
 * @brief Convert protection flags to page table bits
 * @param prot Protection flags
 * @return Page table entry bits
 */
static uint64_t prot_to_pte_bits(uint32_t prot) {
    uint64_t pte_bits = 0;
    
    /* Present bit - always set for valid mappings */
    pte_bits |= (1ULL << 0);  /* Present */
    
    /* Write permission */
    if (prot & VM_PROT_WRITE) {
        pte_bits |= (1ULL << 1);  /* Writable */
    }
    
    /* User access */
    if (prot & PROT_USER) {
        pte_bits |= (1ULL << 2);  /* User */
    }
    
    /* Cache control */
    if (prot & PROT_CACHE_DIS) {
        pte_bits |= (1ULL << 4);  /* Cache Disable */
    }
    
    /* Accessed and Dirty bits */
    if (prot & PROT_ACCESSED) {
        pte_bits |= (1ULL << 5);  /* Accessed */
    }
    if (prot & PROT_DIRTY) {
        pte_bits |= (1ULL << 6);  /* Dirty */
    }
    
    /* Global bit */
    if (prot & PROT_GLOBAL) {
        pte_bits |= (1ULL << 8);  /* Global */
    }
    
    /* No-Execute bit (if supported) */
    if (!(prot & VM_PROT_EXEC) && g_hw_caps.nx_supported) {
        pte_bits |= (1ULL << 63); /* NX */
    }
    
    return pte_bits;
}

/**
 * @brief Convert page table bits to protection flags
 * @param pte_bits Page table entry bits
 * @return Protection flags
 */
static uint32_t pte_bits_to_prot(uint64_t pte_bits) {
    uint32_t prot = 0;
    
    /* Always readable if present */
    if (pte_bits & (1ULL << 0)) {
        prot |= VM_PROT_READ;
    }
    
    /* Write permission */
    if (pte_bits & (1ULL << 1)) {
        prot |= VM_PROT_WRITE;
    }
    
    /* Execute permission (inverse of NX bit) */
    if (!(pte_bits & (1ULL << 63))) {
        prot |= VM_PROT_EXEC;
    }
    
    /* User access */
    if (pte_bits & (1ULL << 2)) {
        prot |= PROT_USER;
    }
    
    /* Other flags */
    if (pte_bits & (1ULL << 4)) prot |= PROT_CACHE_DIS;
    if (pte_bits & (1ULL << 5)) prot |= PROT_ACCESSED;
    if (pte_bits & (1ULL << 6)) prot |= PROT_DIRTY;
    if (pte_bits & (1ULL << 8)) prot |= PROT_GLOBAL;
    
    return prot;
}

/**
 * @brief Update page table entry protection
 * @param addr Virtual address
 * @param prot New protection flags
 * @return MM_SUCCESS on success, error code on failure
 */
static mm_error_t update_pte_protection(void *addr, uint32_t prot) {
    /* In a real implementation, this would:
     * 1. Walk page tables to find PTE
     * 2. Update protection bits
     * 3. Flush TLB if necessary
     * 
     * For simulation, we'll just update statistics
     */
    
    uint64_t page_addr = (uint64_t)addr & PAGE_MASK;
    uint64_t pte_bits = prot_to_pte_bits(prot);
    
    mm_spin_lock(&g_protection_lock);
    
    /* Update statistics based on protection */
    if (!(prot & VM_PROT_WRITE)) {
        g_protection_stats.read_only_pages++;
    }
    if (!(prot & VM_PROT_EXEC)) {
        g_protection_stats.no_exec_pages++;
    }
    if (prot & PROT_USER) {
        g_protection_stats.user_pages++;
    } else {
        g_protection_stats.kernel_pages++;
    }
    g_protection_stats.total_pages++;
    
    mm_spin_unlock(&g_protection_lock);
    
    printk(KERN_DEBUG "Protection: Updated page 0x%llx with prot 0x%x (pte=0x%llx)\n",
           page_addr, prot, pte_bits);
    
    return MM_SUCCESS;
}

/* ========================================================================
 * PUBLIC INTERFACE IMPLEMENTATION
 * ======================================================================== */

mm_error_t memory_protection_init(void) {
    if (g_protection_initialized) {
        return MM_SUCCESS;
    }
    
    printk(KERN_INFO "Protection: Initializing memory protection subsystem\n");
    
    /* Detect hardware capabilities */
    detect_hw_protection_caps();
    
    /* Enable basic protection features */
    if (g_hw_caps.nx_supported) {
        if (enable_hw_feature(MEM_PROT_NX)) {
            g_enabled_features |= MEM_PROT_NX;
        }
    }
    
    if (g_hw_caps.smep_supported) {
        if (enable_hw_feature(MEM_PROT_SMEP)) {
            g_enabled_features |= MEM_PROT_SMEP;
        }
    }
    
    if (g_hw_caps.smap_supported) {
        if (enable_hw_feature(MEM_PROT_SMAP)) {
            g_enabled_features |= MEM_PROT_SMAP;
        }
    }
    
    /* Initialize statistics */
    memset(&g_protection_stats, 0, sizeof(g_protection_stats));
    
    g_protection_initialized = true;
    
    printk(KERN_INFO "Protection: Initialization complete (features=0x%x)\n",
           g_enabled_features);
    
    return MM_SUCCESS;
}

void memory_protection_shutdown(void) {
    if (!g_protection_initialized) {
        return;
    }
    
    /* Disable protection features */
    g_enabled_features = 0;
    g_protection_initialized = false;
    
    printk(KERN_INFO "Protection: Subsystem shutdown\n");
}

mm_error_t get_hw_protection_caps(hw_protection_caps_t *caps) {
    if (!caps) {
        return MM_ERROR_INVALID;
    }
    
    *caps = g_hw_caps;
    return MM_SUCCESS;
}

mm_error_t set_protection_feature(mem_prot_features_t feature, bool enable) {
    if (!g_protection_initialized) {
        return MM_ERROR_INIT;
    }
    
    if (enable) {
        if (enable_hw_feature(feature)) {
            g_enabled_features |= feature;
            return MM_SUCCESS;
        } else {
            return MM_ERROR_INVALID;
        }
    } else {
        g_enabled_features &= ~feature;
        return MM_SUCCESS;
    }
}

bool is_protection_feature_enabled(mem_prot_features_t feature) {
    return (g_enabled_features & feature) != 0;
}

mm_error_t set_memory_protection(void *addr, size_t size, uint32_t prot) {
    if (!addr || size == 0) {
        return MM_ERROR_INVALID;
    }
    
    if (!g_protection_initialized) {
        return MM_ERROR_INIT;
    }
    
    /* Align to page boundaries */
    uint64_t start_addr = (uint64_t)addr & PAGE_MASK;
    uint64_t end_addr = ((uint64_t)addr + size + PAGE_SIZE - 1) & PAGE_MASK;
    
    printk(KERN_DEBUG "Protection: Setting protection 0x%x for range 0x%llx-0x%llx\n",
           prot, start_addr, end_addr);
    
    /* Update protection for each page */
    for (uint64_t page_addr = start_addr; page_addr < end_addr; page_addr += PAGE_SIZE) {
        mm_error_t result = update_pte_protection((void *)page_addr, prot);
        if (result != MM_SUCCESS) {
            return result;
        }
    }
    
    return MM_SUCCESS;
}

mm_error_t get_memory_protection(void *addr, uint32_t *prot) {
    if (!addr || !prot) {
        return MM_ERROR_INVALID;
    }
    
    /* In a real implementation, this would walk page tables */
    /* For simulation, return default protection */
    *prot = VM_PROT_READ | VM_PROT_WRITE;
    
    return MM_SUCCESS;
}

mm_error_t make_readonly(void *addr, size_t size) {
    uint32_t current_prot;
    mm_error_t result = get_memory_protection(addr, &current_prot);
    if (result != MM_SUCCESS) {
        return result;
    }
    
    /* Remove write permission */
    current_prot &= ~VM_PROT_WRITE;
    
    return set_memory_protection(addr, size, current_prot);
}

mm_error_t make_writable(void *addr, size_t size) {
    uint32_t current_prot;
    mm_error_t result = get_memory_protection(addr, &current_prot);
    if (result != MM_SUCCESS) {
        return result;
    }
    
    /* Add write permission */
    current_prot |= VM_PROT_WRITE;
    
    return set_memory_protection(addr, size, current_prot);
}

mm_error_t make_noexec(void *addr, size_t size) {
    uint32_t current_prot;
    mm_error_t result = get_memory_protection(addr, &current_prot);
    if (result != MM_SUCCESS) {
        return result;
    }
    
    /* Remove execute permission */
    current_prot &= ~VM_PROT_EXEC;
    
    return set_memory_protection(addr, size, current_prot);
}

mm_error_t make_executable(void *addr, size_t size) {
    uint32_t current_prot;
    mm_error_t result = get_memory_protection(addr, &current_prot);
    if (result != MM_SUCCESS) {
        return result;
    }
    
    /* Add execute permission */
    current_prot |= VM_PROT_EXEC;
    
    return set_memory_protection(addr, size, current_prot);
}

mm_error_t register_protection_handler(protection_violation_handler_t handler) {
    if (!handler) {
        return MM_ERROR_INVALID;
    }
    
    g_violation_handler = handler;
    return MM_SUCCESS;
}

bool handle_protection_violation(protection_violation_t *violation) {
    if (!violation) {
        return false;
    }
    
    /* Update statistics */
    mm_spin_lock(&g_protection_lock);
    
    g_protection_stats.total_violations++;
    
    switch (violation->type) {
    case PROT_VIOLATION_READ:
        g_protection_stats.read_violations++;
        break;
    case PROT_VIOLATION_WRITE:
        g_protection_stats.write_violations++;
        break;
    case PROT_VIOLATION_EXEC:
        g_protection_stats.exec_violations++;
        break;
    case PROT_VIOLATION_USER:
        g_protection_stats.privilege_violations++;
        break;
    case PROT_VIOLATION_STACK:
        g_protection_stats.stack_violations++;
        break;
    case PROT_VIOLATION_HEAP:
        g_protection_stats.heap_violations++;
        break;
    default:
        break;
    }
    
    mm_spin_unlock(&g_protection_lock);
    
    /* Log the violation */
    printk(KERN_WARNING "Protection violation: type=%d, addr=0x%llx, ip=0x%llx\n",
           violation->type, violation->address, violation->ip);
    
    /* Call registered handler if available */
    if (g_violation_handler) {
        return g_violation_handler(violation);
    }
    
    /* Default action: terminate */
    return false;
}

mm_error_t get_protection_stats(protection_stats_t *stats) {
    if (!stats) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_protection_lock);
    *stats = g_protection_stats;
    mm_spin_unlock(&g_protection_lock);
    
    return MM_SUCCESS;
}

void print_protection_info(void) {
    printk(KERN_INFO "Memory Protection Information:\n");
    printk(KERN_INFO "  Initialized: %s\n", g_protection_initialized ? "yes" : "no");
    printk(KERN_INFO "  Enabled features: 0x%x\n", g_enabled_features);
    
    printk(KERN_INFO "  Hardware capabilities:\n");
    printk(KERN_INFO "    NX: %s\n", g_hw_caps.nx_supported ? "supported" : "not supported");
    printk(KERN_INFO "    SMEP: %s\n", g_hw_caps.smep_supported ? "supported" : "not supported");
    printk(KERN_INFO "    SMAP: %s\n", g_hw_caps.smap_supported ? "supported" : "not supported");
    printk(KERN_INFO "    PKU: %s\n", g_hw_caps.pku_supported ? "supported" : "not supported");
    
    printk(KERN_INFO "  Active features:\n");
    printk(KERN_INFO "    NX: %s\n", (g_enabled_features & MEM_PROT_NX) ? "enabled" : "disabled");
    printk(KERN_INFO "    SMEP: %s\n", (g_enabled_features & MEM_PROT_SMEP) ? "enabled" : "disabled");
    printk(KERN_INFO "    SMAP: %s\n", (g_enabled_features & MEM_PROT_SMAP) ? "enabled" : "disabled");
}

void print_protection_stats(void) {
    printk(KERN_INFO "Protection Statistics:\n");
    printk(KERN_INFO "  Total pages: %llu\n", g_protection_stats.total_pages);
    printk(KERN_INFO "  Read-only pages: %llu\n", g_protection_stats.read_only_pages);
    printk(KERN_INFO "  No-exec pages: %llu\n", g_protection_stats.no_exec_pages);
    printk(KERN_INFO "  Kernel pages: %llu\n", g_protection_stats.kernel_pages);
    printk(KERN_INFO "  User pages: %llu\n", g_protection_stats.user_pages);
    
    printk(KERN_INFO "  Total violations: %llu\n", g_protection_stats.total_violations);
    printk(KERN_INFO "  Read violations: %llu\n", g_protection_stats.read_violations);
    printk(KERN_INFO "  Write violations: %llu\n", g_protection_stats.write_violations);
    printk(KERN_INFO "  Execute violations: %llu\n", g_protection_stats.exec_violations);
    printk(KERN_INFO "  Privilege violations: %llu\n", g_protection_stats.privilege_violations);
    printk(KERN_INFO "  Stack violations: %llu\n", g_protection_stats.stack_violations);
    printk(KERN_INFO "  Heap violations: %llu\n", g_protection_stats.heap_violations);
}

void reset_protection_stats(void) {
    mm_spin_lock(&g_protection_lock);
    memset(&g_protection_stats, 0, sizeof(g_protection_stats));
    mm_spin_unlock(&g_protection_lock);
    
    printk(KERN_INFO "Protection: Statistics reset\n");
}

/**
 * @file guard_pages.c
 * @brief Implémentation des pages de garde pour LeaxOS
 * 
 * Ce fichier implémente les mécanismes de pages de garde :
 * - Protection contre les débordements de pile
 * - Protection contre les débordements de tas
 * - Détection des accès non autorisés
 * - Gestion des pages canaries
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#include "../../../Include/stdint.h"
#include "../../../Include/stddef.h"
#include "../../../Include/stdbool.h"
#include "../../../Include/string.h"
#include "../../../Include/stdio.h"
#include "../../include/mm_common.h"
#include "../../include/memory_protection.h"
#include "../../include/mm.h"

/* ========================================================================
 * INTERNAL GUARD PAGE STRUCTURES
 * ======================================================================== */

/** Internal guard page structure */
typedef struct guard_page {
    void *address;                 /**< Guard page address */
    size_t size;                   /**< Guard page size */
    guard_type_t type;             /**< Guard type */
    uint32_t flags;                /**< Guard flags */
    char description[64];          /**< Description */
    uint64_t creation_time;        /**< Creation timestamp */
    uint64_t access_count;         /**< Access attempts */
    uint64_t violation_count;      /**< Violations detected */
    bool active;                   /**< Guard is active */
    
    /* Linked list */
    struct guard_page *next;
} guard_page_t;

/** Guard page management */
static guard_page_t *g_guard_pages = NULL;
static mm_spinlock_t g_guard_lock = MM_SPINLOCK_INIT("guard_pages");
static uint32_t g_guard_count = 0;
static bool g_guard_system_enabled = false;

/** Guard page statistics */
static struct {
    uint64_t total_guards;
    uint64_t active_guards;
    uint64_t stack_guards;
    uint64_t heap_guards;
    uint64_t canary_guards;
    uint64_t total_violations;
    uint64_t stack_violations;
    uint64_t heap_violations;
    uint64_t buffer_violations;
} g_guard_stats = {0};

/* ========================================================================
 * GUARD PAGE UTILITIES
 * ======================================================================== */

/**
 * @brief Find guard page by address
 * @param addr Address to search
 * @return Guard page structure or NULL
 */
static guard_page_t *find_guard_page(void *addr) {
    uint64_t search_addr = (uint64_t)addr & PAGE_MASK;
    
    for (guard_page_t *guard = g_guard_pages; guard; guard = guard->next) {
        uint64_t guard_addr = (uint64_t)guard->address & PAGE_MASK;
        if (guard_addr == search_addr) {
            return guard;
        }
    }
    return NULL;
}

/**
 * @brief Allocate guard page structure
 * @return New guard page structure or NULL
 */
static guard_page_t *allocate_guard_page(void) {
    /* In a real implementation, this would use a slab allocator */
    guard_page_t *guard = kmalloc(sizeof(guard_page_t));
    if (guard) {
        memset(guard, 0, sizeof(*guard));
    }
    return guard;
}

/**
 * @brief Free guard page structure
 * @param guard Guard page to free
 */
static void free_guard_page(guard_page_t *guard) {
    if (guard) {
        kfree(guard);
    }
}

/**
 * @brief Add guard to active list
 * @param guard Guard page to add
 */
static void add_guard_to_list(guard_page_t *guard) {
    guard->next = g_guard_pages;
    g_guard_pages = guard;
    g_guard_count++;
}

/**
 * @brief Remove guard from active list
 * @param guard Guard page to remove
 */
static void remove_guard_from_list(guard_page_t *guard) {
    if (g_guard_pages == guard) {
        g_guard_pages = guard->next;
    } else {
        for (guard_page_t *curr = g_guard_pages; curr; curr = curr->next) {
            if (curr->next == guard) {
                curr->next = guard->next;
                break;
            }
        }
    }
    guard->next = NULL;
    g_guard_count--;
}

/**
 * @brief Set page protection for guard page
 * @param addr Page address
 * @param guard_type Type of guard
 * @return MM_SUCCESS on success
 */
static mm_error_t set_guard_protection(void *addr, guard_type_t guard_type) {
    /* Guard pages are typically marked as not present or no-access */
    uint32_t prot = 0;  /* No permissions */
    
    switch (guard_type) {
    case GUARD_TYPE_CANARY:
        /* Canary pages might allow read access for checking */
        prot = VM_PROT_READ;
        break;
        
    default:
        /* All other guard types: no access */
        prot = 0;
        break;
    }
    
    return set_memory_protection(addr, PAGE_SIZE, prot);
}

/* ========================================================================
 * PUBLIC INTERFACE IMPLEMENTATION
 * ======================================================================== */

mm_error_t guard_pages_init(void) {
    printk(KERN_INFO "Guard: Initializing guard page system\n");
    
    /* Initialize statistics */
    memset(&g_guard_stats, 0, sizeof(g_guard_stats));
    
    g_guard_system_enabled = true;
    
    printk(KERN_INFO "Guard: System initialized\n");
    
    return MM_SUCCESS;
}

void guard_pages_shutdown(void) {
    if (!g_guard_system_enabled) {
        return;
    }
    
    mm_spin_lock(&g_guard_lock);
    
    /* Remove all guard pages */
    while (g_guard_pages) {
        guard_page_t *guard = g_guard_pages;
        remove_guard_from_list(guard);
        
        /* Restore normal protection */
        set_memory_protection(guard->address, guard->size, VM_PROT_READ | VM_PROT_WRITE);
        
        free_guard_page(guard);
    }
    
    g_guard_system_enabled = false;
    
    mm_spin_unlock(&g_guard_lock);
    
    printk(KERN_INFO "Guard: System shutdown\n");
}

mm_error_t create_guard_page(void *addr, size_t size, guard_page_flags_t flags, const char *description) {
    if (!addr || size == 0 || !g_guard_system_enabled) {
        return MM_ERROR_INVALID;
    }
    
    /* Align to page boundaries */
    uint64_t start_addr = (uint64_t)addr & PAGE_MASK;
    size_t aligned_size = (size + PAGE_SIZE - 1) & PAGE_MASK;
    
    mm_spin_lock(&g_guard_lock);
    
    /* Check if guard already exists */
    if (find_guard_page((void *)start_addr)) {
        mm_spin_unlock(&g_guard_lock);
        return MM_ERROR_EXISTS;
    }
    
    /* Allocate guard structure */
    guard_page_t *guard = allocate_guard_page();
    if (!guard) {
        mm_spin_unlock(&g_guard_lock);
        return MM_ERROR_NO_MEMORY;
    }
    
    /* Initialize guard */
    guard->address = (void *)start_addr;
    guard->size = aligned_size;
    guard->flags = flags;
    guard->creation_time = 0;  /* Would be real timestamp */
    guard->active = true;
    
    /* Determine guard type from flags */
    if (flags & GUARD_FLAG_STACK) {
        guard->type = GUARD_TYPE_STACK_OVERFLOW;
        g_guard_stats.stack_guards++;
    } else if (flags & GUARD_FLAG_HEAP) {
        guard->type = GUARD_TYPE_HEAP_OVERFLOW;
        g_guard_stats.heap_guards++;
    } else if (flags & GUARD_FLAG_CANARY) {
        guard->type = GUARD_TYPE_CANARY;
        g_guard_stats.canary_guards++;
    } else {
        guard->type = GUARD_TYPE_CUSTOM;
    }
    
    /* Set description */
    if (description) {
        strncpy(guard->description, description, sizeof(guard->description) - 1);
        guard->description[sizeof(guard->description) - 1] = '\0';
    } else {
        snprintf(guard->description, sizeof(guard->description), "Guard_%p", addr);
    }
    
    /* Add to active list */
    add_guard_to_list(guard);
    
    g_guard_stats.total_guards++;
    g_guard_stats.active_guards++;
    
    mm_spin_unlock(&g_guard_lock);
    
    /* Set protection on the pages */
    mm_error_t result = set_guard_protection((void *)start_addr, guard->type);
    if (result != MM_SUCCESS) {
        /* Clean up on failure */
        remove_guard_page((void *)start_addr);
        return result;
    }
    
    printk(KERN_DEBUG "Guard: Created guard page at 0x%llx, size %zu (%s)\n",
           start_addr, aligned_size, guard->description);
    
    return MM_SUCCESS;
}

mm_error_t remove_guard_page(void *addr) {
    if (!addr || !g_guard_system_enabled) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_guard_lock);
    
    guard_page_t *guard = find_guard_page(addr);
    if (!guard) {
        mm_spin_unlock(&g_guard_lock);
        return MM_ERROR_INVALID;
    }
    
    /* Remove from list */
    remove_guard_from_list(guard);
    
    /* Update statistics */
    g_guard_stats.active_guards--;
    switch (guard->type) {
    case GUARD_TYPE_STACK_OVERFLOW:
    case GUARD_TYPE_STACK_UNDERFLOW:
        g_guard_stats.stack_guards--;
        break;
    case GUARD_TYPE_HEAP_OVERFLOW:
    case GUARD_TYPE_HEAP_UNDERFLOW:
        g_guard_stats.heap_guards--;
        break;
    case GUARD_TYPE_CANARY:
        g_guard_stats.canary_guards--;
        break;
    default:
        break;
    }
    
    void *guard_addr = guard->address;
    size_t guard_size = guard->size;
    
    mm_spin_unlock(&g_guard_lock);
    
    /* Restore normal protection */
    mm_error_t result = set_memory_protection(guard_addr, guard_size, VM_PROT_READ | VM_PROT_WRITE);
    
    /* Free guard structure */
    free_guard_page(guard);
    
    printk(KERN_DEBUG "Guard: Removed guard page at %p\n", addr);
    
    return result;
}

mm_error_t create_stack_guard(void *stack_base, size_t stack_size) {
    if (!stack_base || stack_size == 0) {
        return MM_ERROR_INVALID;
    }
    
    /* Create guard page at the bottom of the stack */
    void *guard_addr = (void *)((uint64_t)stack_base - PAGE_SIZE);
    
    return create_guard_page(guard_addr, PAGE_SIZE, GUARD_FLAG_STACK,
                           "Stack overflow guard");
}

mm_error_t create_heap_guard(void *heap_ptr, size_t size) {
    if (!heap_ptr || size == 0) {
        return MM_ERROR_INVALID;
    }
    
    /* Create guard pages before and after the heap region */
    void *before_guard = (void *)((uint64_t)heap_ptr - PAGE_SIZE);
    void *after_guard = (void *)(((uint64_t)heap_ptr + size + PAGE_SIZE - 1) & PAGE_MASK);
    
    mm_error_t result1 = create_guard_page(before_guard, PAGE_SIZE, GUARD_FLAG_HEAP,
                                         "Heap underflow guard");
    mm_error_t result2 = create_guard_page(after_guard, PAGE_SIZE, GUARD_FLAG_HEAP,
                                         "Heap overflow guard");
    
    if (result1 != MM_SUCCESS) {
        return result1;
    }
    if (result2 != MM_SUCCESS) {
        remove_guard_page(before_guard);
        return result2;
    }
    
    return MM_SUCCESS;
}

mm_error_t create_canary_page(void *addr, const char *description) {
    if (!addr) {
        return MM_ERROR_INVALID;
    }
    
    return create_guard_page(addr, PAGE_SIZE, GUARD_FLAG_CANARY, description);
}

bool is_guard_page(void *addr) {
    if (!addr || !g_guard_system_enabled) {
        return false;
    }
    
    mm_spin_lock(&g_guard_lock);
    guard_page_t *guard = find_guard_page(addr);
    bool is_guard = (guard != NULL && guard->active);
    mm_spin_unlock(&g_guard_lock);
    
    return is_guard;
}

bool handle_guard_page_violation(void *addr, uint32_t error_code) {
    if (!addr || !g_guard_system_enabled) {
        return false;
    }
    
    mm_spin_lock(&g_guard_lock);
    
    guard_page_t *guard = find_guard_page(addr);
    if (!guard || !guard->active) {
        mm_spin_unlock(&g_guard_lock);
        return false;
    }
    
    /* Update statistics */
    guard->access_count++;
    guard->violation_count++;
    g_guard_stats.total_violations++;
    
    switch (guard->type) {
    case GUARD_TYPE_STACK_OVERFLOW:
    case GUARD_TYPE_STACK_UNDERFLOW:
        g_guard_stats.stack_violations++;
        break;
    case GUARD_TYPE_HEAP_OVERFLOW:
    case GUARD_TYPE_HEAP_UNDERFLOW:
        g_guard_stats.heap_violations++;
        break;
    case GUARD_TYPE_BUFFER_OVERFLOW:
        g_guard_stats.buffer_violations++;
        break;
    default:
        break;
    }
    
    /* Log the violation */
    printk(KERN_WARNING "Guard: Violation detected at %p (%s)\n",
           addr, guard->description);
    printk(KERN_WARNING "  Type: %d, Error: 0x%x, Violations: %llu\n",
           guard->type, error_code, guard->violation_count);
    
    mm_spin_unlock(&g_guard_lock);
    
    /* For most guard types, this is a fatal error */
    switch (guard->type) {
    case GUARD_TYPE_CANARY:
        /* Canary violations might be recoverable */
        return true;
        
    default:
        /* Stack/heap overflows are usually fatal */
        return false;
    }
}

mm_error_t get_guard_page_info(void *addr, guard_page_info_t *info) {
    if (!addr || !info || !g_guard_system_enabled) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_guard_lock);
    
    guard_page_t *guard = find_guard_page(addr);
    if (!guard) {
        mm_spin_unlock(&g_guard_lock);
        return MM_ERROR_INVALID;
    }
    
    /* Fill info structure */
    info->address = guard->address;
    info->size = guard->size;
    info->flags = guard->flags;
    strncpy(info->description, guard->description, sizeof(info->description) - 1);
    info->description[sizeof(info->description) - 1] = '\0';
    info->creation_time = guard->creation_time;
    info->access_count = guard->access_count;
    info->violation_count = guard->violation_count;
    info->active = guard->active;
    
    mm_spin_unlock(&g_guard_lock);
    
    return MM_SUCCESS;
}

mm_error_t get_guard_stats(guard_page_stats_t *stats) {
    if (!stats) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_guard_lock);
    
    stats->total_guards = g_guard_stats.total_guards;
    stats->active_guards = g_guard_stats.active_guards;
    stats->stack_guards = g_guard_stats.stack_guards;
    stats->heap_guards = g_guard_stats.heap_guards;
    stats->canary_guards = g_guard_stats.canary_guards;
    stats->total_violations = g_guard_stats.total_violations;
    stats->stack_violations = g_guard_stats.stack_violations;
    stats->heap_violations = g_guard_stats.heap_violations;
    stats->buffer_violations = g_guard_stats.buffer_violations;
    
    mm_spin_unlock(&g_guard_lock);
    
    return MM_SUCCESS;
}

void print_guard_page_info(void *addr) {
    guard_page_info_t info;
    
    if (get_guard_page_info(addr, &info) != MM_SUCCESS) {
    printk(KERN_ERR "Guard: No guard page at address %p\n", addr);
        return;
    }
    
    printk(KERN_INFO "Guard Page at %p:\n", info.address);
    printk(KERN_INFO "  Size: %zu bytes\n", info.size);
    printk(KERN_INFO "  Flags: 0x%x\n", info.flags);
    printk(KERN_INFO "  Description: %s\n", info.description);
    printk(KERN_INFO "  Active: %s\n", info.active ? "yes" : "no");
    printk(KERN_INFO "  Created: %llu\n", info.creation_time);
    printk(KERN_INFO "  Access count: %llu\n", info.access_count);
    printk(KERN_INFO "  Violations: %llu\n", info.violation_count);
}

void print_all_guard_pages(void) {
    printk(KERN_INFO "Guard Pages (%u active):\n", g_guard_count);
    
    mm_spin_lock(&g_guard_lock);
    
    for (guard_page_t *guard = g_guard_pages; guard; guard = guard->next) {
        printk(KERN_INFO "  %p: %s (size=%zu, violations=%llu)\n",
               guard->address, guard->description, guard->size, guard->violation_count);
    }
    
    mm_spin_unlock(&g_guard_lock);
}

void print_guard_stats(void) {
    guard_page_stats_t stats;
    
    if (get_guard_stats(&stats) != MM_SUCCESS) {
        return;
    }
    
    printk(KERN_INFO "Guard Page Statistics:\n");
    printk(KERN_INFO "  Total guards: %llu\n", stats.total_guards);
    printk(KERN_INFO "  Active guards: %llu\n", stats.active_guards);
    printk(KERN_INFO "  Stack guards: %llu\n", stats.stack_guards);
    printk(KERN_INFO "  Heap guards: %llu\n", stats.heap_guards);
    printk(KERN_INFO "  Canary guards: %llu\n", stats.canary_guards);
    printk(KERN_INFO "  Total violations: %llu\n", stats.total_violations);
    printk(KERN_INFO "  Stack violations: %llu\n", stats.stack_violations);
    printk(KERN_INFO "  Heap violations: %llu\n", stats.heap_violations);
    printk(KERN_INFO "  Buffer violations: %llu\n", stats.buffer_violations);
}

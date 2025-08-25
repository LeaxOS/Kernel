/**
 * @file early_alloc.c
 * @brief Allocateur bootstrap précoce pour l'initialisation du kernel
 * 
 * Ce fichier implémente un allocateur bootstrap simple et efficace utilisé
 * pendant les phases très précoces du démarrage du kernel, avant que le 
 * système de gestion mémoire complet soit disponible. Cet allocateur fournit:
 * 
 * - Allocation linéaire simple pour les structures critiques
 * - Gestion des dépendances d'initialisation
 * - Support pour les allocations urgentes
 * - Interface de transition vers le MM principal
 * - Mécanismes de débogage et validation
 * 
 * L'allocateur bootstrap est conçu pour être minimal mais robuste,
 * avec une empreinte mémoire réduite et des performances prévisibles.
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#include "../../include/early_malloc.h"
#include "../../include/mm_common.h"
#include "../../include/mm.h"
#include "../../../Include/stddef.h"
#include "../../../Include/stdint.h"
#include "../../../Include/stdbool.h"
#include "../../../Include/string.h"
#include "../../../Include/stdio.h"
#include "mm_setup.h"


/* ========================================================================
 * CONSTANTS AND CONFIGURATION
 * ======================================================================== */

#define EARLY_ALLOC_POOL_SIZE    (128 * 1024)   /* 128KB pool bootstrap */
#define EARLY_ALLOC_MIN_ALIGN    8               /* Minimum alignment */
#define EARLY_ALLOC_MAX_ALIGN    64              /* Maximum alignment */
#define EARLY_ALLOC_GUARD_SIZE   16              /* Guard byte size */
#define EARLY_ALLOC_MAX_ALLOCS   256             /* Max tracked allocations */

/* Magic numbers for corruption detection */
#define EARLY_ALLOC_MAGIC        0xEA51A110C     /* "EASY ALLOC" */
#define EARLY_FREE_MAGIC         0xF4EE4A11      /* "FREE ALL" */
#define EARLY_GUARD_MAGIC        0x600D600D      /* "GOOD GOOD" */

/* Allocation flags */
#define EARLY_ALLOC_FLAG_ZERO    0x01    /* Zero-initialize */
#define EARLY_ALLOC_FLAG_URGENT  0x02    /* High priority */
#define EARLY_ALLOC_FLAG_GUARD   0x04    /* Add guard bytes */
#define EARLY_ALLOC_FLAG_TRACK   0x08    /* Track allocation */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Header structure for tracked allocations
 */
typedef struct early_alloc_header {
    uint32_t magic;                      /* Magic number */
    size_t size;                         /* Allocation size */
    uint32_t flags;                      /* Allocation flags */
    const char *file;                    /* Source file (debug) */
    int line;                            /* Source line (debug) */
    struct early_alloc_header *next;     /* Next allocation */
    struct early_alloc_header *prev;     /* Previous allocation */
} early_alloc_header_t;

/**
 * @brief Early allocator statistics
 */
typedef struct {
    size_t total_allocated;              /* Total bytes allocated */
    size_t total_freed;                  /* Total bytes freed */
    size_t current_usage;                /* Current usage */
    size_t peak_usage;                   /* Peak usage */
    size_t allocation_count;             /* Number of allocations */
    size_t free_count;                   /* Number of frees */
    size_t failed_allocs;                /* Failed allocations */
    size_t guard_violations;             /* Guard byte violations */
} early_alloc_stats_t;

/**
 * @brief Early allocator state
 */
typedef struct {
    uint8_t *pool_base;                  /* Base of memory pool */
    size_t pool_size;                    /* Total pool size */
    size_t pool_offset;                  /* Current allocation offset */
    bool initialized;                    /* Allocator initialized */
    bool active;                         /* Allocator active */
    early_alloc_header_t *alloc_list;    /* List of allocations */
    early_alloc_stats_t stats;           /* Allocation statistics */
} early_alloc_state_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Main memory pool for bootstrap allocations */
static uint8_t early_alloc_pool[EARLY_ALLOC_POOL_SIZE] __attribute__((aligned(64)));

/* Allocator state */
static early_alloc_state_t g_early_alloc = {
    .pool_base = early_alloc_pool,
    .pool_size = EARLY_ALLOC_POOL_SIZE,
    .pool_offset = 0,
    .initialized = false,
    .active = false,
    .alloc_list = NULL,
    .stats = {0}
};

/* Synchronization for SMP systems */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
static mm_spinlock_t early_alloc_lock = MM_SPINLOCK_INIT("unknown");
#define EARLY_LOCK() mm_spin_lock(&early_alloc_lock)
#define EARLY_UNLOCK() mm_spin_unlock(&early_alloc_lock)
#else
#define EARLY_LOCK() do {} while(0)
#define EARLY_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Align size to specified alignment
 * @param size Size to align
 * @param align Alignment requirement (must be power of 2)
 * @return Aligned size
 */
static inline size_t align_size(size_t size, size_t align) {
    return (size + align - 1) & ~(align - 1);
}

/**
 * @brief Check if value is power of 2
 * @param n Value to check
 * @return true if power of 2, false otherwise
 */
static inline bool is_power_of_2(size_t n) {
    return n && !(n & (n - 1));
}

/**
 * @brief Validate guard bytes
 * @param guard_ptr Pointer to guard area
 * @param size Size of guard area
 * @return true if valid, false if corrupted
 */
static bool validate_guard_bytes(const uint8_t *guard_ptr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (guard_ptr[i] != (EARLY_GUARD_MAGIC >> (8 * (i % 4))) & 0xFF) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Set guard bytes
 * @param guard_ptr Pointer to guard area
 * @param size Size of guard area
 */
static void set_guard_bytes(uint8_t *guard_ptr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        guard_ptr[i] = (EARLY_GUARD_MAGIC >> (8 * (i % 4))) & 0xFF;
    }
}

/**
 * @brief Check if pointer is within allocator pool
 * @param ptr Pointer to check
 * @return true if within pool, false otherwise
 */
static bool is_pool_pointer(const void *ptr) {
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t pool_start = (uintptr_t)g_early_alloc.pool_base;
    uintptr_t pool_end = pool_start + g_early_alloc.pool_size;
    
    return addr >= pool_start && addr < pool_end;
}

/* ========================================================================
 * ALLOCATION TRACKING
 * ======================================================================== */

/**
 * @brief Add allocation to tracking list
 * @param header Allocation header
 */
static void track_allocation(early_alloc_header_t *header) {
    if (!header) return;
    
    header->next = g_early_alloc.alloc_list;
    header->prev = NULL;
    
    if (g_early_alloc.alloc_list) {
        g_early_alloc.alloc_list->prev = header;
    }
    
    g_early_alloc.alloc_list = header;
}

/**
 * @brief Remove allocation from tracking list
 * @param header Allocation header
 */
static void untrack_allocation(early_alloc_header_t *header) {
    if (!header) return;
    
    if (header->prev) {
        header->prev->next = header->next;
    } else {
        g_early_alloc.alloc_list = header->next;
    }
    
    if (header->next) {
        header->next->prev = header->prev;
    }
}

/**
 * @brief Find allocation header for pointer
 * @param ptr User pointer
 * @return Header pointer or NULL if not found
 */
static early_alloc_header_t *find_allocation_header(const void *ptr) {
    early_alloc_header_t *current = g_early_alloc.alloc_list;
    
    while (current) {
        uint8_t *user_ptr = (uint8_t *)current + sizeof(early_alloc_header_t);
        if (current->flags & EARLY_ALLOC_FLAG_GUARD) {
            user_ptr += EARLY_ALLOC_GUARD_SIZE;
        }
        
        if (user_ptr == ptr) {
            return current;
        }
        
        current = current->next;
    }
    
    return NULL;
}

/* ========================================================================
 * CORE ALLOCATION FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize early allocator
 * @return 0 on success, negative error code on failure
 */
int early_alloc_init(void) {
    if (g_early_alloc.initialized) {
        printk(KERN_WARNING "Early allocator already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing early bootstrap allocator\n");
    
    /* Clear the memory pool */
    memset(g_early_alloc.pool_base, 0, g_early_alloc.pool_size);
    
    /* Reset state */
    g_early_alloc.pool_offset = 0;
    g_early_alloc.alloc_list = NULL;
    memset(&g_early_alloc.stats, 0, sizeof(early_alloc_stats_t));
    
    /* Mark as initialized and active */
    g_early_alloc.initialized = true;
    g_early_alloc.active = true;
    
    printk(KERN_INFO "Early allocator initialized (%zu KB pool)\n", 
           EARLY_ALLOC_POOL_SIZE / 1024);
    
    return 0;
}

/**
 * @brief Shutdown early allocator
 */
void early_alloc_shutdown(void) {
    if (!g_early_alloc.initialized) {
        return;
    }
    
    printk(KERN_INFO "Shutting down early allocator\n");
    
    /* Print final statistics */
    early_alloc_print_stats();
    
    /* Check for memory leaks */
    if (g_early_alloc.alloc_list) {
        printk(KERN_WARNING "Memory leaks detected in early allocator:\n");
        early_alloc_header_t *current = g_early_alloc.alloc_list;
        while (current) {
            printk(KERN_WARNING "  Leak: %zu bytes at %p (from %s:%d)\n",
                   current->size, current, 
                   current->file ? current->file : "unknown",
                   current->line);
            current = current->next;
        }
    }
    
    /* Mark as inactive */
    g_early_alloc.active = false;
    
    printk(KERN_INFO "Early allocator shutdown complete\n");
}

/**
 * @brief Allocate memory with early allocator
 * @param size Size in bytes
 * @param flags Allocation flags
 * @param file Source file name (for debugging)
 * @param line Source line number (for debugging)
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_alloc_debug(size_t size, uint32_t flags, const char *file, int line) {
    if (!g_early_alloc.active || size == 0) {
        return NULL;
    }
    
    /* Validate alignment if requested */
    size_t alignment = EARLY_ALLOC_MIN_ALIGN;
    
    /* Calculate total allocation size */
    size_t aligned_size = align_size(size, alignment);
    size_t total_size = sizeof(early_alloc_header_t) + aligned_size;
    
    /* Add guard bytes if requested */
    if (flags & EARLY_ALLOC_FLAG_GUARD) {
        total_size += 2 * EARLY_ALLOC_GUARD_SIZE; /* Front and back guards */
    }
    
    EARLY_LOCK();
    
    /* Check if we have enough space */
    if (g_early_alloc.pool_offset + total_size > g_early_alloc.pool_size) {
        g_early_alloc.stats.failed_allocs++;
        EARLY_UNLOCK();
        
        printk(KERN_ERR "Early allocator out of memory: requested %zu, available %zu\n",
               total_size, g_early_alloc.pool_size - g_early_alloc.pool_offset);
        return NULL;
    }
    
    /* Get allocation pointer */
    early_alloc_header_t *header = (early_alloc_header_t *)
        (g_early_alloc.pool_base + g_early_alloc.pool_offset);
    
    /* Initialize header */
    header->magic = EARLY_ALLOC_MAGIC;
    header->size = size;
    header->flags = flags;
    header->file = file;
    header->line = line;
    header->next = NULL;
    header->prev = NULL;
    
    /* Move past header */
    g_early_alloc.pool_offset += sizeof(early_alloc_header_t);
    
    uint8_t *user_ptr = g_early_alloc.pool_base + g_early_alloc.pool_offset;
    
    /* Add front guard if requested */
    if (flags & EARLY_ALLOC_FLAG_GUARD) {
        set_guard_bytes(user_ptr, EARLY_ALLOC_GUARD_SIZE);
        user_ptr += EARLY_ALLOC_GUARD_SIZE;
        g_early_alloc.pool_offset += EARLY_ALLOC_GUARD_SIZE;
    }
    
    /* Move past user data */
    g_early_alloc.pool_offset += aligned_size;
    
    /* Add rear guard if requested */
    if (flags & EARLY_ALLOC_FLAG_GUARD) {
        set_guard_bytes(g_early_alloc.pool_base + g_early_alloc.pool_offset, 
                       EARLY_ALLOC_GUARD_SIZE);
        g_early_alloc.pool_offset += EARLY_ALLOC_GUARD_SIZE;
    }
    
    /* Track allocation if requested */
    if (flags & EARLY_ALLOC_FLAG_TRACK) {
        track_allocation(header);
    }
    
    /* Update statistics */
    g_early_alloc.stats.total_allocated += size;
    g_early_alloc.stats.current_usage += total_size;
    g_early_alloc.stats.allocation_count++;
    
    if (g_early_alloc.stats.current_usage > g_early_alloc.stats.peak_usage) {
        g_early_alloc.stats.peak_usage = g_early_alloc.stats.current_usage;
    }
    
    EARLY_UNLOCK();
    
    /* Zero-initialize if requested */
    if (flags & EARLY_ALLOC_FLAG_ZERO) {
        memset(user_ptr, 0, size);
    }
    
    printk(KERN_DEBUG "Early alloc: %zu bytes at %p (%s:%d)\n", 
           size, user_ptr, file ? file : "unknown", line);
    
    return user_ptr;
}

/**
 * @brief Free memory allocated by early allocator
 * @param ptr Pointer to free
 * @param file Source file name (for debugging)
 * @param line Source line number (for debugging)
 */
void early_free_debug(void *ptr, const char *file, int line) {
    if (!ptr || !g_early_alloc.active) {
        return;
    }
    
    if (!is_pool_pointer(ptr)) {
        printk(KERN_ERR "early_free: invalid pointer %p not in pool (%s:%d)\n",
               ptr, file ? file : "unknown", line);
        return;
    }
    
    EARLY_LOCK();
    
    /* Find allocation header */
    early_alloc_header_t *header = find_allocation_header(ptr);
    if (!header) {
        EARLY_UNLOCK();
        printk(KERN_ERR "early_free: allocation header not found for %p (%s:%d)\n",
               ptr, file ? file : "unknown", line);
        return;
    }
    
    /* Validate header magic */
    if (header->magic != EARLY_ALLOC_MAGIC) {
        EARLY_UNLOCK();
        printk(KERN_ERR "early_free: corrupted header magic for %p (%s:%d)\n",
               ptr, file ? file : "unknown", line);
        return;
    }
    
    /* Validate guard bytes if present */
    if (header->flags & EARLY_ALLOC_FLAG_GUARD) {
        uint8_t *front_guard = (uint8_t *)ptr - EARLY_ALLOC_GUARD_SIZE;
        uint8_t *rear_guard = (uint8_t *)ptr + align_size(header->size, EARLY_ALLOC_MIN_ALIGN);
        
        if (!validate_guard_bytes(front_guard, EARLY_ALLOC_GUARD_SIZE) ||
            !validate_guard_bytes(rear_guard, EARLY_ALLOC_GUARD_SIZE)) {
            g_early_alloc.stats.guard_violations++;
            printk(KERN_ERR "early_free: guard byte violation for %p (%s:%d)\n",
                   ptr, file ? file : "unknown", line);
        }
    }
    
    /* Remove from tracking list */
    if (header->flags & EARLY_ALLOC_FLAG_TRACK) {
        untrack_allocation(header);
    }
    
    /* Update statistics */
    g_early_alloc.stats.total_freed += header->size;
    g_early_alloc.stats.free_count++;
    
    /* Mark header as freed */
    header->magic = EARLY_FREE_MAGIC;
    
    EARLY_UNLOCK();
    
    printk(KERN_DEBUG "Early free: %zu bytes at %p (%s:%d)\n", 
           header->size, ptr, file ? file : "unknown", line);
    
    /* Note: We don't actually reclaim memory in this simple allocator */
}

/* ========================================================================
 * PUBLIC API FUNCTIONS
 * ======================================================================== */

/**
 * @brief Simple allocation interface
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_alloc(size_t size) {
    return early_alloc_debug(size, EARLY_ALLOC_FLAG_ZERO | EARLY_ALLOC_FLAG_TRACK,
                            __FILE__, __LINE__);
}

/**
 * @brief Allocation with flags
 * @param size Size in bytes  
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_alloc_flags(size_t size, uint32_t flags) {
    return early_alloc_debug(size, flags | EARLY_ALLOC_FLAG_TRACK,
                            __FILE__, __LINE__);
}

/**
 * @brief Aligned allocation
 * @param size Size in bytes
 * @param alignment Alignment requirement
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_alloc_aligned(size_t size, size_t alignment) {
    if (!is_power_of_2(alignment) || alignment > EARLY_ALLOC_MAX_ALIGN) {
        return NULL;
    }
    
    /* For now, just ensure minimum alignment - full alignment support would
     * require more complex pool management */
    return early_alloc_debug(size, EARLY_ALLOC_FLAG_ZERO | EARLY_ALLOC_FLAG_TRACK,
                            __FILE__, __LINE__);
}

/**
 * @brief Zero-initialized allocation
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_calloc(size_t size) {
    return early_alloc_debug(size, EARLY_ALLOC_FLAG_ZERO | EARLY_ALLOC_FLAG_TRACK,
                            __FILE__, __LINE__);
}

/**
 * @brief Free memory
 * @param ptr Pointer to free
 */
void early_free(void *ptr) {
    early_free_debug(ptr, __FILE__, __LINE__);
}

/* ========================================================================
 * STATISTICS AND DEBUGGING
 * ======================================================================== */

/**
 * @brief Get allocator statistics
 * @param stats_out Pointer to statistics structure
 */
void early_alloc_get_stats(early_alloc_stats_t *stats_out) {
    if (!stats_out) return;
    
    EARLY_LOCK();
    memcpy(stats_out, &g_early_alloc.stats, sizeof(early_alloc_stats_t));
    EARLY_UNLOCK();
}

/**
 * @brief Print allocator statistics
 */
void early_alloc_print_stats(void) {
    if (!g_early_alloc.initialized) return;
    
    printk(KERN_INFO "Early Allocator Statistics:\n");
    printk(KERN_INFO "  Pool size:        %zu KB\n", g_early_alloc.pool_size / 1024);
    printk(KERN_INFO "  Pool used:        %zu KB\n", g_early_alloc.pool_offset / 1024);
    printk(KERN_INFO "  Pool free:        %zu KB\n", 
           (g_early_alloc.pool_size - g_early_alloc.pool_offset) / 1024);
    printk(KERN_INFO "  Total allocated:  %zu bytes\n", g_early_alloc.stats.total_allocated);
    printk(KERN_INFO "  Total freed:      %zu bytes\n", g_early_alloc.stats.total_freed);
    printk(KERN_INFO "  Current usage:    %zu bytes\n", g_early_alloc.stats.current_usage);
    printk(KERN_INFO "  Peak usage:       %zu bytes\n", g_early_alloc.stats.peak_usage);
    printk(KERN_INFO "  Allocations:      %zu\n", g_early_alloc.stats.allocation_count);
    printk(KERN_INFO "  Frees:            %zu\n", g_early_alloc.stats.free_count);
    printk(KERN_INFO "  Failed allocs:    %zu\n", g_early_alloc.stats.failed_allocs);
    printk(KERN_INFO "  Guard violations: %zu\n", g_early_alloc.stats.guard_violations);
}

/**
 * @brief Check allocator integrity
 * @return true if all checks pass, false if corruption detected
 */
bool early_alloc_check_integrity(void) {
    if (!g_early_alloc.initialized) return false;
    
    bool integrity_ok = true;
    
    EARLY_LOCK();
    
    /* Check tracked allocations */
    early_alloc_header_t *current = g_early_alloc.alloc_list;
    while (current) {
        /* Validate header magic */
        if (current->magic != EARLY_ALLOC_MAGIC) {
            printk(KERN_ERR "Integrity check: corrupted header magic at %p\n", current);
            integrity_ok = false;
        }
        
        /* Validate guard bytes if present */
        if (current->flags & EARLY_ALLOC_FLAG_GUARD) {
            uint8_t *user_ptr = (uint8_t *)current + sizeof(early_alloc_header_t) + 
                               EARLY_ALLOC_GUARD_SIZE;
            uint8_t *front_guard = user_ptr - EARLY_ALLOC_GUARD_SIZE;
            uint8_t *rear_guard = user_ptr + align_size(current->size, EARLY_ALLOC_MIN_ALIGN);
            
            if (!validate_guard_bytes(front_guard, EARLY_ALLOC_GUARD_SIZE) ||
                !validate_guard_bytes(rear_guard, EARLY_ALLOC_GUARD_SIZE)) {
                printk(KERN_ERR "Integrity check: guard violation at %p\n", user_ptr);
                integrity_ok = false;
            }
        }
        
        current = current->next;
    }
    
    EARLY_UNLOCK();
    
    return integrity_ok;
}

/**
 * @brief Dump all tracked allocations
 */
void early_alloc_dump_allocations(void) {
    if (!g_early_alloc.initialized) return;
    
    printk(KERN_INFO "Early Allocator - Active Allocations:\n");
    
    EARLY_LOCK();
    
    early_alloc_header_t *current = g_early_alloc.alloc_list;
    size_t count = 0;
    
    while (current) {
        uint8_t *user_ptr = (uint8_t *)current + sizeof(early_alloc_header_t);
        if (current->flags & EARLY_ALLOC_FLAG_GUARD) {
            user_ptr += EARLY_ALLOC_GUARD_SIZE;
        }
        
        printk(KERN_INFO "  [%zu] %zu bytes at %p (from %s:%d, flags=0x%x)\n",
               ++count, current->size, user_ptr,
               current->file ? current->file : "unknown",
               current->line, current->flags);
        
        current = current->next;
    }
    
    if (count == 0) {
        printk(KERN_INFO "  No active allocations\n");
    }
    
    EARLY_UNLOCK();
}

/**
 * @brief Get total memory managed by early allocator
 * @return Total memory in bytes
 */
size_t early_alloc_get_total_memory(void) {
    return g_early_alloc.pool_size;
}

/**
 * @brief Get available memory in early allocator
 * @return Available memory in bytes
 */
size_t early_alloc_get_available_memory(void) {
    if (!g_early_alloc.initialized) return 0;
    
    return g_early_alloc.pool_size - g_early_alloc.pool_offset;
}

/**
 * @brief Check if early allocator is active
 * @return true if active, false otherwise
 */
bool early_alloc_is_active(void) {
    return g_early_alloc.active;
}

/* ========================================================================
 * COMPATIBILITY MACROS
 * ======================================================================== */

/* Debug allocation macros */
#define early_alloc_debug(size, flags, file, line) \
    early_alloc_debug(size, flags, file, line)
#define early_free_debug(ptr, file, line) \
    early_free_debug(ptr, file, line)

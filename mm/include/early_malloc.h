/**
 * @file early_malloc.h
 * @brief Early memory allocation interface
 * 
 * This header defines the interface for early memory allocation functions
 * used during kernel boot before the full memory management subsystem
 * is available. It provides various specialized allocators optimized for
 * different allocation patterns and sizes.
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_EARLY_MALLOC_H
#define LEAX_KERNEL_MM_EARLY_MALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"

/* Early allocation flags */
#define EARLY_FLAG_ZERO         0x01    /**< Zero-initialize memory */
#define EARLY_FLAG_ATOMIC       0x02    /**< Atomic allocation */
#define EARLY_FLAG_URGENT       0x04    /**< High priority */
#define EARLY_FLAG_GUARD        0x08    /**< Add guard pages/bytes */

/* Forward declarations */
typedef uintptr_t phys_addr_t;

/**
 * @brief Early allocation statistics structure
 */
struct early_alloc_stats {
    uint64_t bootstrap_allocs;   /**< Bootstrap allocations */
    uint64_t bootstrap_frees;    /**< Bootstrap deallocations */
    uint64_t slab_allocs;        /**< Slab allocations */
    uint64_t slab_frees;         /**< Slab deallocations */
    uint64_t buddy_allocs;       /**< Buddy allocations */
    uint64_t buddy_frees;        /**< Buddy deallocations */
    uint64_t region_allocs;      /**< Region allocations */
    uint64_t region_frees;       /**< Region deallocations */
    uint64_t pool_allocs;        /**< Pool allocations */
    uint64_t pool_frees;         /**< Pool deallocations */
    uint64_t bitmap_allocs;      /**< Bitmap allocations */
    uint64_t bitmap_frees;       /**< Bitmap deallocations */
    uint64_t total_allocated;    /**< Total bytes allocated */
    uint64_t total_freed;        /**< Total bytes freed */
    uint64_t peak_usage;         /**< Peak memory usage */
    uint64_t current_usage;      /**< Current memory usage */
};

/* ========================================================================
 * INITIALIZATION AND SHUTDOWN
 * ======================================================================== */

/**
 * @brief Initialize all early memory allocators
 * @return 0 on success, negative error code on failure
 */
int early_mm_init(void);

/**
 * @brief Shutdown early memory allocators
 */
void early_mm_shutdown(void);

/**
 * @brief Check if early memory management is active
 * @return true if active, false otherwise
 */
bool early_mm_is_active(void);

/* ========================================================================
 * MAIN ALLOCATION INTERFACE
 * ======================================================================== */

/**
 * @brief Main early memory allocation function
 * 
 * Automatically selects the most appropriate allocator based on size
 * and allocation pattern. Falls back through multiple allocators if
 * the preferred one fails.
 * 
 * @param size Size in bytes
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_malloc(size_t size, uint32_t flags);

/**
 * @brief Main early memory deallocation function
 * 
 * Automatically determines which allocator owns the memory and
 * calls the appropriate free function.
 * 
 * @param ptr Pointer to memory to free
 * @param size Original allocation size (hint for some allocators)
 */
void early_free(void *ptr, size_t size);

/**
 * @brief Allocate zeroed memory
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_calloc(size_t size);

/**
 * @brief Allocate aligned memory
 * @param size Size in bytes
 * @param alignment Alignment requirement (must be power of 2)
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_malloc_aligned(size_t size, size_t alignment);

/**
 * @brief Emergency allocation for critical situations
 * 
 * Uses the most reliable allocator and reserved memory pools
 * to satisfy allocation requests during emergencies.
 * 
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_emergency_alloc(size_t size);

/* ========================================================================
 * SPECIALIZED ALLOCATOR INTERFACES
 * ======================================================================== */

/**
 * @brief Allocate a memory region
 * 
 * Allocates a large contiguous memory region and tracks it
 * for management purposes. Useful for reserving memory areas.
 * 
 * @param size Size of region in bytes
 * @param alignment Alignment requirement
 * @param name Name for debugging
 * @return Physical address of region, or 0 on failure
 */
phys_addr_t early_region_alloc(size_t size, size_t alignment, const char *name);

/**
 * @brief Free a memory region
 * @param addr Region address
 * @return 0 on success, negative error code on failure
 */
int early_region_free(phys_addr_t addr);

/* ========================================================================
 * STATISTICS AND DEBUGGING
 * ======================================================================== */

/**
 * @brief Get allocation statistics
 * @param stats_out Pointer to structure to fill with statistics
 */
void early_get_stats(struct early_alloc_stats *stats_out);

/**
 * @brief Print early memory allocator statistics
 */
void early_print_stats(void);

/**
 * @brief Check early memory allocator integrity
 * @return true if all allocators are consistent, false otherwise
 */
bool early_check_integrity(void);

/**
 * @brief Dump detailed information about all early allocators
 */
void early_dump_allocators(void);

/**
 * @brief Get total memory managed by early allocators
 * @return Total memory in bytes
 */
size_t early_get_total_memory(void);

/**
 * @brief Get available memory from early allocators
 * @return Available memory in bytes
 */
size_t early_get_available_memory(void);

/* ========================================================================
 * STANDARD LIBRARY COMPATIBILITY
 * ======================================================================== */

/**
 * @brief Standard malloc wrapper for early allocation
 * 
 * Provides standard malloc interface during early boot.
 * Automatically redirects to early_malloc when active.
 * 
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *malloc(size_t size);

/**
 * @brief Standard calloc wrapper for early allocation
 * @param nmemb Number of elements
 * @param size Size of each element
 * @return Pointer to allocated memory, or NULL on failure
 */
void *calloc(size_t nmemb, size_t size);

/**
 * @brief Standard free wrapper for early allocation
 * @param ptr Pointer to memory to free
 */
void free(void *ptr);

/* ========================================================================
 * UTILITY MACROS
 * ======================================================================== */

/**
 * @brief Allocate memory and panic if it fails
 * @param size Size in bytes
 * @return Pointer to allocated memory (never NULL)
 */
#define early_malloc_or_panic(size) \
    ({ \
        void *__ptr = early_malloc((size), 0); \
        if (!__ptr) { \
            panic("Early allocation failed: " #size " bytes"); \
        } \
        __ptr; \
    })

/**
 * @brief Allocate zeroed memory and panic if it fails
 * @param size Size in bytes
 * @return Pointer to allocated memory (never NULL)
 */
#define early_calloc_or_panic(size) \
    ({ \
        void *__ptr = early_calloc(size); \
        if (!__ptr) { \
            panic("Early calloc failed: " #size " bytes"); \
        } \
        __ptr; \
    })

/**
 * @brief Allocate memory for a specific type
 * @param type Type name
 * @return Pointer to allocated memory of specified type
 */
#define early_malloc_type(type) \
    ((type *)early_malloc(sizeof(type), 0))

/**
 * @brief Allocate zeroed memory for a specific type
 * @param type Type name
 * @return Pointer to allocated memory of specified type
 */
#define early_calloc_type(type) \
    ((type *)early_calloc(sizeof(type)))

/**
 * @brief Allocate array of specific type
 * @param type Type name
 * @param count Number of elements
 * @return Pointer to allocated array
 */
#define early_malloc_array(type, count) \
    ((type *)early_malloc(sizeof(type) * (count), 0))

/**
 * @brief Allocate zeroed array of specific type
 * @param type Type name
 * @param count Number of elements
 * @return Pointer to allocated array
 */
#define early_calloc_array(type, count) \
    ((type *)early_calloc(sizeof(type) * (count)))

/**
 * @brief Free memory with automatic size calculation for types
 * @param ptr Pointer to memory
 * @param type Type name (for size hint)
 */
#define early_free_type(ptr, type) \
    early_free((ptr), sizeof(type))

/**
 * @brief Free array with automatic size calculation
 * @param ptr Pointer to array
 * @param type Type name
 * @param count Number of elements
 */
#define early_free_array(ptr, type, count) \
    early_free((ptr), sizeof(type) * (count))

/* Error codes */
#define EARLY_MM_SUCCESS        0       /**< Operation successful */
#define EARLY_MM_ERR_NOMEM     -1       /**< Out of memory */
#define EARLY_MM_ERR_INVALID   -2       /**< Invalid parameter */
#define EARLY_MM_ERR_BUSY      -3       /**< Resource busy */
#define EARLY_MM_ERR_NOTFOUND  -4       /**< Resource not found */
#define EARLY_MM_ERR_EXISTS    -5       /**< Resource already exists */
#define EARLY_MM_ERR_ALIGN     -6       /**< Alignment error */
#define EARLY_MM_ERR_CORRUPT   -7       /**< Data corruption */
#define EARLY_MM_ERR_INIT      -8       /**< Initialization failed */

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_EARLY_MALLOC_H */

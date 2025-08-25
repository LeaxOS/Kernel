/**
 * @file mm.h
 * @brief Memory Management Subsystem Interface
 * 
 * This header defines the main interface for the LeaxOS kernel's memory
 * management subsystem. It provides high-level memory allocation functions,
 * virtual memory management, and integration with the page allocator.
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_H
#define LEAX_KERNEL_MM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"

/* Memory layout and size definitions */

/** Page size and related constants */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096U                 /**< Standard page size (4KB) */
#endif
#define PAGE_SHIFT 12U                  /**< Page size shift (log2(PAGE_SIZE)) */
#define PAGE_MASK (PAGE_SIZE - 1U)      /**< Page alignment mask */

/** Heap configuration */
#define KERNEL_HEAP_MIN_SIZE    (1024U * 1024U)    /**< Minimum kernel heap size (1MB) */
#define KERNEL_HEAP_MAX_SIZE    (256U * 1024U * 1024U) /**< Maximum kernel heap size (256MB) */
#define KERNEL_STACK_SIZE       (8U * 1024U)       /**< Kernel stack size (8KB) */
#define USER_STACK_SIZE         (1024U * 1024U)    /**< Default user stack size (1MB) */

/** Allocation limits */
#define MAX_ALLOC_SIZE          (SIZE_MAX / 2U)    /**< Maximum single allocation */
#define MIN_ALLOC_SIZE          8U                 /**< Minimum allocation size */
#define DEFAULT_ALIGNMENT       sizeof(void*)      /**< Default alignment */
#define MAX_ALIGNMENT           PAGE_SIZE          /**< Maximum alignment */

/** Memory layout constants */
#define KERNEL_VIRT_BASE        0xC0000000U        /**< Kernel virtual base (3GB) */
#define USER_VIRT_MAX           0xBFFFFFFFU        /**< Maximum user virtual address */
#define VMALLOC_START           0xF0000000U        /**< vmalloc area start */
#define VMALLOC_END             0xFFFFF000U        /**< vmalloc area end */

/* Alignment & utility macros */

/** Page alignment macros */
#define PAGE_ALIGN_UP(x)        ((((uintptr_t)(x)) + PAGE_MASK) & ~((uintptr_t)PAGE_MASK))
#define PAGE_ALIGN_DOWN(x)      (((uintptr_t)(x)) & ~((uintptr_t)PAGE_MASK))
#define PAGE_OFFSET(addr)       (((uintptr_t)(addr)) & PAGE_MASK)
#define ADDR_TO_PAGE(addr)      (((uintptr_t)(addr)) >> PAGE_SHIFT)
#define PAGE_TO_ADDR(page)      (((uintptr_t)(page)) << PAGE_SHIFT)

/** Generic alignment macros */
#define ALIGN_UP(x, align)      (((x) + (align) - 1U) & ~((align) - 1U))
#define ALIGN_DOWN(x, align)    ((x) & ~((align) - 1U))
#define IS_ALIGNED(x, align)    (((x) & ((align) - 1U)) == 0)
#define IS_POWER_OF_2(x)        ((x) != 0 && ((x) & ((x) - 1U)) == 0)

/** Memory conversion macros */
#define BYTES_TO_KB(bytes)      ((bytes) >> 10)
#define BYTES_TO_MB(bytes)      ((bytes) >> 20)
#define KB_TO_BYTES(kb)         ((kb) << 10)
#define MB_TO_BYTES(mb)         ((mb) << 20)

/* Type definitions */

/** Address types */
typedef uintptr_t phys_addr_t;          /**< Physical address type */
typedef uintptr_t virt_addr_t;          /**< Virtual address type */
typedef size_t pages_t;                 /**< Page count type */

/** Memory allocation flags */
typedef uint32_t mm_flags_t;
#define MM_FLAG_ZERO        0x01U       /**< Zero-initialize memory */
#define MM_FLAG_DMA         0x02U       /**< DMA-capable memory */
#define MM_FLAG_ATOMIC      0x04U       /**< Atomic allocation (no blocking) */
#define MM_FLAG_HIGHMEM     0x08U       /**< High memory allowed */
#define MM_FLAG_LOWMEM      0x10U       /**< Force low memory */
#define MM_FLAG_URGENT      0x20U       /**< Urgent allocation */
#define MM_FLAG_NOFAIL      0x40U       /**< Must not fail (use reserves) */
#define MM_FLAG_NORETRY     0x80U       /**< Don't retry on failure */

/** Memory protection flags */
typedef uint32_t vm_prot_t;
#define VM_PROT_NONE        0x00U       /**< No access */
#define VM_PROT_READ        0x01U       /**< Read access */
#define VM_PROT_WRITE       0x02U       /**< Write access */
#define VM_PROT_EXEC        0x04U       /**< Execute access */
#define VM_PROT_ALL         (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXEC)

/** Virtual memory area flags */
typedef uint32_t vma_flags_t;
#define VMA_FLAG_SHARED     0x01U       /**< Shared mapping */
#define VMA_FLAG_PRIVATE    0x02U       /**< Private mapping */
#define VMA_FLAG_FIXED      0x04U       /**< Fixed address mapping */
#define VMA_FLAG_GROWSDOWN  0x08U       /**< Stack-like growth */
#define VMA_FLAG_LOCKED     0x10U       /**< Memory locked in RAM */
#define VMA_FLAG_CACHE      0x20U       /**< Cacheable memory */
#define VMA_FLAG_NOCACHE    0x40U       /**< Non-cacheable memory */

/** Memory zone types */
typedef enum {
    MM_ZONE_DMA,            /**< DMA-capable memory (0-16MB) */
    MM_ZONE_NORMAL,         /**< Normal memory */
    MM_ZONE_HIGHMEM,        /**< High memory */
    MM_ZONE_COUNT           /**< Number of zones */
} mm_zone_t;

/** Memory statistics structure */
typedef struct mm_stats {
    /* Physical memory */
    size_t total_pages;         /**< Total physical pages */
    size_t free_pages;          /**< Free physical pages */
    size_t used_pages;          /**< Used physical pages */
    size_t reserved_pages;      /**< Reserved pages */
    size_t cached_pages;        /**< Page cache pages */
    size_t buffer_pages;        /**< Buffer pages */
    
    /* Virtual memory */
    size_t total_vmem;          /**< Total virtual memory */
    size_t used_vmem;           /**< Used virtual memory */
    size_t free_vmem;           /**< Free virtual memory */
    
    /* Heap statistics */
    size_t heap_size;           /**< Current heap size */
    size_t heap_used;           /**< Used heap memory */
    size_t heap_free;           /**< Free heap memory */
    size_t heap_peak;           /**< Peak heap usage */
    
    /* Allocation counters */
    uint64_t alloc_count;       /**< Total allocations */
    uint64_t free_count;        /**< Total frees */
    uint64_t fail_count;        /**< Failed allocations */
} mm_stats_t;

/** Memory configuration */
typedef struct mm_config {
    phys_addr_t phys_start;     /**< Physical memory start */
    phys_addr_t phys_end;       /**< Physical memory end */
    virt_addr_t virt_start;     /**< Virtual memory start */
    virt_addr_t virt_end;       /**< Virtual memory end */
    size_t heap_size;           /**< Initial heap size */
    bool enable_paging;         /**< Enable virtual memory */
    bool enable_swap;           /**< Enable swap support */
    bool enable_debug;          /**< Enable debug features */
} mm_config_t;

/* ========================================================================
 * INLINE UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Convert pages to bytes
 * @param pages Number of pages
 * @return Size in bytes
 */
static inline size_t pages_to_bytes(pages_t pages) {
    return pages << PAGE_SHIFT;
}

/**
 * @brief Convert bytes to pages (rounded up)
 * @param bytes Size in bytes
 * @return Number of pages
 */
static inline pages_t bytes_to_pages(size_t bytes) {
    return (pages_t)((bytes + PAGE_MASK) >> PAGE_SHIFT);
}

/**
 * @brief Check if address is page-aligned
 * @param addr Address to check
 * @return true if page-aligned, false otherwise
 */
static inline bool is_page_aligned(uintptr_t addr) {
    return (addr & PAGE_MASK) == 0;
}

/**
 * @brief Convert virtual address to physical (identity mapping)
 * @param vaddr Virtual address
 * @return Physical address
 * @note This assumes identity mapping, will be updated for real VM
 */
static inline phys_addr_t virt_to_phys(virt_addr_t vaddr) {
    return (phys_addr_t)vaddr;
}

/**
 * @brief Convert physical address to virtual (identity mapping)
 * @param paddr Physical address
 * @return Virtual address
 * @note This assumes identity mapping, will be updated for real VM
 */
static inline virt_addr_t phys_to_virt(phys_addr_t paddr) {
    return (virt_addr_t)paddr;
}

/**
 * @brief Check if alignment value is valid (power of 2)
 * @param alignment Alignment value
 * @return true if valid, false otherwise
 */
static inline bool is_valid_alignment(size_t alignment) {
    return IS_POWER_OF_2(alignment);
}

/**
 * @brief Align size to specified alignment
 * @param size Size to align
 * @param alignment Alignment requirement
 * @return Aligned size
 */
static inline size_t align_size(size_t size, size_t alignment) {
    return ALIGN_UP(size, alignment);
}

/**
 * @brief Check if address is in kernel space
 * @param addr Address to check
 * @return true if kernel address, false otherwise
 */
static inline bool is_kernel_addr(virt_addr_t addr) {
    return addr >= KERNEL_VIRT_BASE;
}

/**
 * @brief Check if address is in user space
 * @param addr Address to check
 * @return true if user address, false otherwise
 */
static inline bool is_user_addr(virt_addr_t addr) {
    return addr < KERNEL_VIRT_BASE;
}

/**
 * @brief Get memory zone for physical address
 * @param paddr Physical address
 * @return Memory zone
 */
static inline mm_zone_t get_memory_zone(phys_addr_t paddr) {
    if (paddr < (16 * 1024 * 1024))  /* < 16MB */
        return MM_ZONE_DMA;
    else if (paddr < (896 * 1024 * 1024))  /* < 896MB */
        return MM_ZONE_NORMAL;
    else
        return MM_ZONE_HIGHMEM;
}

/* ========================================================================
 * CORE MEMORY MANAGEMENT FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize the memory management subsystem
 * @param config Configuration parameters
 * @return 0 on success, negative error code on failure
 */
int mm_init(const mm_config_t *config);

/**
 * @brief Shutdown the memory management subsystem
 */
void mm_shutdown(void);

/**
 * @brief Enable virtual memory management
 * @return 0 on success, negative error code on failure
 */
int mm_enable_paging(void);

/**
 * @brief Disable virtual memory management
 */
void mm_disable_paging(void);

/* ========================================================================
 * KERNEL HEAP ALLOCATION
 * ======================================================================== */

/**
 * @brief Allocate memory from kernel heap
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *kmalloc(size_t size);

/**
 * @brief Allocate zeroed memory from kernel heap
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *kzalloc(size_t size);

/**
 * @brief Allocate array from kernel heap
 * @param nmemb Number of elements
 * @param size Size of each element
 * @return Pointer to allocated memory, or NULL on failure
 */
void *kcalloc(size_t nmemb, size_t size);

/**
 * @brief Reallocate memory block
 * @param ptr Existing memory block
 * @param size New size in bytes
 * @return Pointer to reallocated memory, or NULL on failure
 */
void *krealloc(void *ptr, size_t size);

/**
 * @brief Free memory allocated with kmalloc family
 * @param ptr Pointer to memory to free
 */
void kfree(void *ptr);

/**
 * @brief Allocate aligned memory from kernel heap
 * @param size Size in bytes
 * @param alignment Alignment requirement (must be power of 2)
 * @return Pointer to allocated memory, or NULL on failure
 */
void *kmalloc_aligned(size_t size, size_t alignment);

/**
 * @brief Allocate memory with specific flags
 * @param size Size in bytes
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
void *kmalloc_flags(size_t size, mm_flags_t flags);

/**
 * @brief Allocate memory from specific zone
 * @param size Size in bytes
 * @param zone Target memory zone
 * @return Pointer to allocated memory, or NULL on failure
 */
void *kmalloc_zone(size_t size, mm_zone_t zone);

/**
 * @brief Get size of allocated memory block
 * @param ptr Pointer to memory block
 * @return Size of block, or 0 if invalid
 */
size_t ksize(const void *ptr);

/* ========================================================================
 * PHYSICAL MEMORY MANAGEMENT
 * ======================================================================== */

/**
 * @brief Allocate a single physical page
 * @param flags Allocation flags
 * @return Physical address of page, or 0 on failure
 */
phys_addr_t pmm_alloc_page(mm_flags_t flags);

/**
 * @brief Allocate multiple contiguous physical pages
 * @param count Number of pages
 * @param flags Allocation flags
 * @return Physical address of first page, or 0 on failure
 */
phys_addr_t pmm_alloc_pages(pages_t count, mm_flags_t flags);

/**
 * @brief Free a single physical page
 * @param paddr Physical address of page
 */
void pmm_free_page(phys_addr_t paddr);

/**
 * @brief Free multiple contiguous physical pages
 * @param paddr Physical address of first page
 * @param count Number of pages
 */
void pmm_free_pages(phys_addr_t paddr, pages_t count);

/**
 * @brief Reserve physical memory region
 * @param start Start address
 * @param size Size in bytes
 * @return 0 on success, negative error code on failure
 */
int pmm_reserve_region(phys_addr_t start, size_t size);

/**
 * @brief Unreserve physical memory region
 * @param start Start address
 * @param size Size in bytes
 * @return 0 on success, negative error code on failure
 */
int pmm_unreserve_region(phys_addr_t start, size_t size);

/* ========================================================================
 * VIRTUAL MEMORY MANAGEMENT
 * ======================================================================== */

/**
 * @brief Map virtual address to physical address
 * @param vaddr Virtual address
 * @param paddr Physical address
 * @param size Size in bytes
 * @param prot Protection flags
 * @return 0 on success, negative error code on failure
 */
int vmm_map_pages(virt_addr_t vaddr, phys_addr_t paddr, size_t size, vm_prot_t prot);

/**
 * @brief Unmap virtual address range
 * @param vaddr Virtual address
 * @param size Size in bytes
 * @return 0 on success, negative error code on failure
 */
int vmm_unmap_pages(virt_addr_t vaddr, size_t size);

/**
 * @brief Change protection of virtual memory range
 * @param vaddr Virtual address
 * @param size Size in bytes
 * @param prot New protection flags
 * @return 0 on success, negative error code on failure
 */
int vmm_protect_pages(virt_addr_t vaddr, size_t size, vm_prot_t prot);

/**
 * @brief Allocate virtual memory area
 * @param addr Preferred address (0 = any)
 * @param size Size in bytes
 * @param prot Protection flags
 * @param flags VMA flags
 * @return Virtual address on success, 0 on failure
 */
virt_addr_t vmm_alloc_area(virt_addr_t addr, size_t size, vm_prot_t prot, vma_flags_t flags);

/**
 * @brief Free virtual memory area
 * @param addr Virtual address
 * @param size Size in bytes
 * @return 0 on success, negative error code on failure
 */
int vmm_free_area(virt_addr_t addr, size_t size);

/* ========================================================================
 * MEMORY INFORMATION AND DEBUGGING
 * ======================================================================== */

/**
 * @brief Get memory statistics
 * @param stats Pointer to statistics structure
 */
void mm_get_stats(mm_stats_t *stats);

/**
 * @brief Get amount of free memory
 * @return Free memory in bytes
 */
size_t mm_get_free_memory(void);

/**
 * @brief Get amount of used memory
 * @return Used memory in bytes
 */
size_t mm_get_used_memory(void);

/**
 * @brief Get total memory size
 * @return Total memory in bytes
 */
size_t mm_get_total_memory(void);

/**
 * @brief Check if pointer is valid
 * @param ptr Pointer to validate
 * @return true if valid, false otherwise
 */
bool mm_is_valid_ptr(const void *ptr);

/**
 * @brief Check if address range is valid
 * @param addr Start address
 * @param size Size in bytes
 * @return true if valid, false otherwise
 */
bool mm_is_valid_range(const void *addr, size_t size);

/**
 * @brief Check if system is low on memory
 * @return true if low memory, false otherwise
 */
bool mm_is_low_memory(void);

/**
 * @brief Get memory fragmentation percentage
 * @return Fragmentation percentage (0-100)
 */
unsigned int mm_get_fragmentation(void);

/**
 * @brief Perform memory consistency check
 * @return true if consistent, false if corruption detected
 */
bool mm_check_integrity(void);

/**
 * @brief Print memory debug information
 */
void mm_print_debug(void);

/**
 * @brief Print memory layout information
 */
void mm_print_layout(void);

/**
 * @brief Dump memory allocation statistics
 */
void mm_dump_stats(void);

/* ========================================================================
 * MEMORY PRESSURE AND OPTIMIZATION
 * ======================================================================== */

/**
 * @brief Trigger memory reclaim
 * @param target_pages Target number of pages to free
 * @return Number of pages actually freed
 */
size_t mm_reclaim_memory(size_t target_pages);

/**
 * @brief Compact memory (reduce fragmentation)
 * @return Number of pages coalesced
 */
size_t mm_compact_memory(void);

/**
 * @brief Set low memory threshold
 * @param threshold Threshold in bytes
 */
void mm_set_low_threshold(size_t threshold);

/**
 * @brief Get current low memory threshold
 * @return Threshold in bytes
 */
size_t mm_get_low_threshold(void);

/* Error code */

#define MM_SUCCESS          0       /**< Operation successful */
#define MM_ERR_NOMEM       -1       /**< Out of memory */
#define MM_ERR_INVALID     -2       /**< Invalid parameter */
#define MM_ERR_BUSY        -3       /**< Resource busy */
#define MM_ERR_NOTFOUND    -4       /**< Resource not found */
#define MM_ERR_EXISTS      -5       /**< Resource already exists */
#define MM_ERR_PERM        -6       /**< Permission denied */
#define MM_ERR_ALIGN       -7       /**< Alignment error */
#define MM_ERR_RANGE       -8       /**< Address range error */
#define MM_ERR_CORRUPT     -9       /**< Data corruption */
#define MM_ERR_INIT        -10      /**< Initialization failed */

#ifdef __cplusplus
}
#endif

#endif
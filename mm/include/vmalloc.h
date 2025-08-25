/**
 * @file vmalloc.h
 * @brief Virtual Memory Allocator Interface
 * 
 * This header defines the interface for the LeaxOS kernel's virtual memory
 * allocator, which provides functions for allocating and managing virtual
 * memory regions. This includes vmalloc/vfree operations, memory mapping,
 * and virtual memory area (VMA) management.
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_VMALLOC_H
#define LEAX_KERNEL_MM_VMALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"
#include "mm_common.h"

/* ========================================================================
 * FORWARD DECLARATIONS AND BASIC TYPES
 * ======================================================================== */

/** Forward declarations */
typedef struct vm_area_struct vm_area_t;
typedef struct vm_region_struct vm_region_t;
typedef struct vmalloc_info vmalloc_info_t;

/** Address types */
typedef uintptr_t virt_addr_t;
typedef uintptr_t phys_addr_t;
typedef size_t vm_size_t;

/* ========================================================================
 * VIRTUAL MEMORY CONSTANTS AND LAYOUT
 * ======================================================================== */

/** Virtual page size definitions */
#ifndef VM_PAGE_SIZE
#define VM_PAGE_SIZE 4096U              /**< Virtual page size (4KB) */
#endif
#define VM_PAGE_SHIFT 12U               /**< Page shift for calculations */
#define VM_PAGE_MASK (VM_PAGE_SIZE - 1U) /**< Page alignment mask */

/** Virtual memory layout constants */
#define VMALLOC_MIN_SIZE        VM_PAGE_SIZE        /**< Minimum vmalloc size */
#define VMALLOC_MAX_SIZE        (256U * 1024U * 1024U) /**< Maximum single vmalloc (256MB) */
#define VMALLOC_AREA_SIZE       (256U * 1024U * 1024U) /**< Total vmalloc area size */
#define VMALLOC_GUARD_SIZE      VM_PAGE_SIZE        /**< Guard page size */

/** Default virtual memory areas */
#define VMALLOC_START           0xF0000000U         /**< vmalloc area start */
#define VMALLOC_END             0xFFFFF000U         /**< vmalloc area end */
#define VMAP_START              0xE0000000U         /**< vmap area start */
#define VMAP_END                0xEFFFFFFFU         /**< vmap area end */

/** Virtual memory allocation alignment */
#define VMALLOC_ALIGN           VM_PAGE_SIZE        /**< Default vmalloc alignment */
#define VMALLOC_MAX_ALIGN       (64U * 1024U)      /**< Maximum alignment */

/* ========================================================================
 * VIRTUAL MEMORY FLAGS AND ATTRIBUTES
 * ======================================================================== */

/** Virtual memory protection flags */
typedef uint32_t vm_prot_t;
#define VM_PROT_NONE            0x00U   /**< No access */
#define VM_PROT_READ            0x01U   /**< Read access */
#define VM_PROT_WRITE           0x02U   /**< Write access */
#define VM_PROT_EXEC            0x04U   /**< Execute access */
#define VM_PROT_ALL             (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXEC)

/** Virtual memory allocation flags */
typedef uint32_t vmalloc_flags_t;
#define VMALLOC_FLAG_NONE       0x00U   /**< No special flags */
#define VMALLOC_FLAG_ZERO       0x01U   /**< Zero-initialize memory */
#define VMALLOC_FLAG_ATOMIC     0x02U   /**< Atomic allocation */
#define VMALLOC_FLAG_HIGHMEM    0x04U   /**< Allow high memory pages */
#define VMALLOC_FLAG_DMA        0x08U   /**< DMA-capable memory */
#define VMALLOC_FLAG_NOCACHE    0x10U   /**< Non-cacheable memory */
#define VMALLOC_FLAG_WRITE_COMBINE 0x20U /**< Write-combining memory */
#define VMALLOC_FLAG_GUARD      0x40U   /**< Add guard pages */
#define VMALLOC_FLAG_USER       0x80U   /**< User-accessible mapping */

/* Note: vma_flags_t is now defined in mm_common.h to avoid duplication */

/** Memory mapping flags */
typedef uint32_t mmap_flags_t;
#define MMAP_FLAG_ANONYMOUS     0x01U   /**< Anonymous mapping */
#define MMAP_FLAG_FILE          0x02U   /**< File-backed mapping */
#define MMAP_FLAG_DEVICE        0x04U   /**< Device mapping */
#define MMAP_FLAG_HUGE_PAGES    0x08U   /**< Use huge pages */
#define MMAP_FLAG_POPULATE      0x10U   /**< Pre-populate pages */
#define MMAP_FLAG_NORESERVE     0x20U   /**< Don't reserve swap space */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/** Virtual memory region structure */
struct vm_region_struct {
    virt_addr_t start;              /**< Start virtual address */
    virt_addr_t end;                /**< End virtual address */
    vm_size_t size;                 /**< Size in bytes */
    vm_prot_t protection;           /**< Protection flags */
    vmalloc_flags_t flags;          /**< Allocation flags */
    struct vm_region_struct *next;  /**< Next region in list */
    struct vm_region_struct *prev;  /**< Previous region in list */
    uint32_t ref_count;             /**< Reference count */
    void *private_data;             /**< Private data pointer */
};

/** Virtual memory area structure */
struct vm_area_struct {
    virt_addr_t vm_start;           /**< Start virtual address */
    virt_addr_t vm_end;             /**< End virtual address */
    vm_prot_t vm_prot;              /**< Protection flags */
    vma_flags_t vm_flags;           /**< VMA flags */
    struct vm_area_struct *vm_next; /**< Next VMA */
    struct vm_area_struct *vm_prev; /**< Previous VMA */
    uint32_t vm_ref_count;          /**< Reference count */
    void *vm_private_data;          /**< Private data */
    
    /* File mapping information */
    void *vm_file;                  /**< File object (if file-backed) */
    size_t vm_offset;               /**< Offset in file */
    
    /* Memory management */
    phys_addr_t *vm_pages;          /**< Array of physical pages */
    size_t vm_page_count;           /**< Number of pages */
};

/** vmalloc information structure */
struct vmalloc_info {
    virt_addr_t addr;               /**< Virtual address */
    vm_size_t size;                 /**< Allocated size */
    phys_addr_t *pages;             /**< Physical pages array */
    size_t page_count;              /**< Number of pages */
    vmalloc_flags_t flags;          /**< Allocation flags */
    uint32_t ref_count;             /**< Reference count */
    struct vmalloc_info *next;      /**< Next allocation */
    struct vmalloc_info *prev;      /**< Previous allocation */
};

/** Virtual memory statistics */
typedef struct vmalloc_stats {
    /* Area statistics */
    size_t total_size;              /**< Total vmalloc area size */
    size_t used_size;               /**< Used vmalloc memory */
    size_t free_size;               /**< Free vmalloc memory */
    size_t largest_free;            /**< Largest free block */
    
    /* Allocation statistics */
    uint32_t active_allocs;         /**< Number of active allocations */
    uint32_t total_allocs;          /**< Total allocations made */
    uint32_t failed_allocs;         /**< Failed allocations */
    
    /* Fragmentation */
    uint32_t free_chunks;           /**< Number of free chunks */
    uint32_t fragmentation_pct;     /**< Fragmentation percentage */
    
    /* Page statistics */
    size_t mapped_pages;            /**< Number of mapped pages */
    size_t guard_pages;             /**< Number of guard pages */
} vmalloc_stats_t;

/** Virtual memory configuration */
typedef struct vmalloc_config {
    virt_addr_t start_addr;         /**< Start of vmalloc area */
    virt_addr_t end_addr;           /**< End of vmalloc area */
    size_t min_chunk_size;          /**< Minimum chunk size */
    size_t max_chunk_size;          /**< Maximum chunk size */
    bool enable_guard_pages;        /**< Enable guard pages */
    bool enable_debug;              /**< Enable debug mode */
    size_t reserved_size;           /**< Reserved memory size */
} vmalloc_config_t;

/* ========================================================================
 * UTILITY MACROS
 * ======================================================================== */

/** Virtual memory alignment macros */
#define VM_ALIGN_UP(addr)           (((addr) + VM_PAGE_MASK) & ~VM_PAGE_MASK)
#define VM_ALIGN_DOWN(addr)         ((addr) & ~VM_PAGE_MASK)
#define VM_IS_ALIGNED(addr)         (((addr) & VM_PAGE_MASK) == 0)
#define VM_OFFSET(addr)             ((addr) & VM_PAGE_MASK)

/** Size conversion macros */
#define VM_PAGES_TO_BYTES(pages)    ((pages) << VM_PAGE_SHIFT)
#define VM_BYTES_TO_PAGES(bytes)    (((bytes) + VM_PAGE_MASK) >> VM_PAGE_SHIFT)
#define VM_SIZE_IN_PAGES(size)      VM_BYTES_TO_PAGES(size)

/** Address range macros */
#define VM_RANGE_SIZE(start, end)   ((end) - (start))
#define VM_RANGE_PAGES(start, end)  VM_BYTES_TO_PAGES(VM_RANGE_SIZE(start, end))
#define VM_IN_RANGE(addr, start, end) ((addr) >= (start) && (addr) < (end))
#define VM_RANGES_OVERLAP(s1, e1, s2, e2) ((s1) < (e2) && (s2) < (e1))

/** Validation macros */
#define VM_IS_VALID_ADDR(addr)      ((addr) != 0)
#define VM_IS_VMALLOC_ADDR(addr)    VM_IN_RANGE(addr, VMALLOC_START, VMALLOC_END)
#define VM_IS_VMAP_ADDR(addr)       VM_IN_RANGE(addr, VMAP_START, VMAP_END)

/* ========================================================================
 * CORE VMALLOC FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize the virtual memory allocator
 * @param config Configuration parameters
 * @return 0 on success, negative error code on failure
 */
int vmalloc_init(const vmalloc_config_t *config);

/**
 * @brief Shutdown the virtual memory allocator
 */
void vmalloc_shutdown(void);

/**
 * @brief Allocate virtual memory
 * @param size Size in bytes to allocate
 * @return Virtual address on success, NULL on failure
 */
void *vmalloc(size_t size);

/**
 * @brief Allocate zeroed virtual memory
 * @param size Size in bytes to allocate
 * @return Virtual address on success, NULL on failure
 */
void *vzalloc(size_t size);

/**
 * @brief Allocate virtual memory with specific flags
 * @param size Size in bytes to allocate
 * @param flags Allocation flags
 * @return Virtual address on success, NULL on failure
 */
void *vmalloc_flags(size_t size, vmalloc_flags_t flags);

/**
 * @brief Allocate aligned virtual memory
 * @param size Size in bytes to allocate
 * @param align Alignment requirement (must be power of 2)
 * @return Virtual address on success, NULL on failure
 */
void *vmalloc_aligned(size_t size, size_t align);

/**
 * @brief Free virtual memory allocated with vmalloc
 * @param addr Virtual address to free
 */
void vfree(void *addr);

/**
 * @brief Reallocate virtual memory
 * @param addr Existing virtual address
 * @param new_size New size in bytes
 * @return New virtual address on success, NULL on failure
 */
void *vrealloc(void *addr, size_t new_size);

/* ========================================================================
 * MEMORY MAPPING FUNCTIONS
 * ======================================================================== */

/**
 * @brief Map physical pages to virtual address
 * @param pages Array of physical addresses
 * @param count Number of pages
 * @param prot Protection flags
 * @return Virtual address on success, NULL on failure
 */
void *vmap(phys_addr_t *pages, size_t count, vm_prot_t prot);

/**
 * @brief Unmap virtual address mapped with vmap
 * @param addr Virtual address to unmap
 */
void vunmap(void *addr);

/**
 * @brief Map single physical page
 * @param paddr Physical address
 * @param prot Protection flags
 * @return Virtual address on success, NULL on failure
 */
void *vmap_single(phys_addr_t paddr, vm_prot_t prot);

/**
 * @brief Create persistent mapping
 * @param paddr Physical address
 * @param size Size in bytes
 * @param prot Protection flags
 * @param flags Mapping flags
 * @return Virtual address on success, NULL on failure
 */
void *ioremap(phys_addr_t paddr, size_t size, vm_prot_t prot, mmap_flags_t flags);

/**
 * @brief Remove persistent mapping
 * @param addr Virtual address to unmap
 */
void iounmap(void *addr);

/* ========================================================================
 * VIRTUAL MEMORY AREA MANAGEMENT
 * ======================================================================== */

/**
 * @brief Create virtual memory area
 * @param start Start virtual address (0 = allocate)
 * @param size Size in bytes
 * @param prot Protection flags
 * @param flags VMA flags
 * @return Pointer to VMA structure, NULL on failure
 */
vm_area_t *vma_create(virt_addr_t start, size_t size, vm_prot_t prot, vma_flags_t flags);

/**
 * @brief Destroy virtual memory area
 * @param vma VMA to destroy
 * @return 0 on success, negative error code on failure
 */
int vma_destroy(vm_area_t *vma);

/**
 * @brief Find VMA containing address
 * @param addr Virtual address to search for
 * @return Pointer to VMA, NULL if not found
 */
vm_area_t *vma_find(virt_addr_t addr);

/**
 * @brief Split VMA at specified address
 * @param vma VMA to split
 * @param addr Split address
 * @return Pointer to new VMA, NULL on failure
 */
vm_area_t *vma_split(vm_area_t *vma, virt_addr_t addr);

/**
 * @brief Merge adjacent VMAs
 * @param vma1 First VMA
 * @param vma2 Second VMA
 * @return Pointer to merged VMA, NULL on failure
 */
vm_area_t *vma_merge(vm_area_t *vma1, vm_area_t *vma2);

/**
 * @brief Change VMA protection
 * @param vma VMA to modify
 * @param prot New protection flags
 * @return 0 on success, negative error code on failure
 */
int vma_protect(vm_area_t *vma, vm_prot_t prot);

/**
 * @brief Resize VMA
 * @param vma VMA to resize
 * @param new_size New size in bytes
 * @return 0 on success, negative error code on failure
 */
int vma_resize(vm_area_t *vma, size_t new_size);

/* ========================================================================
 * INFORMATION AND DEBUGGING
 * ======================================================================== */

/**
 * @brief Get vmalloc statistics
 * @param stats Pointer to statistics structure
 */
void vmalloc_get_stats(vmalloc_stats_t *stats);

/**
 * @brief Get information about vmalloc allocation
 * @param addr Virtual address
 * @return Pointer to vmalloc info, NULL if not found
 */
vmalloc_info_t *vmalloc_get_info(void *addr);

/**
 * @brief Get size of vmalloc allocation
 * @param addr Virtual address
 * @return Size in bytes, 0 if not found
 */
size_t vmalloc_size(void *addr);

/**
 * @brief Check if address is valid vmalloc address
 * @param addr Address to check
 * @return true if valid vmalloc address, false otherwise
 */
bool is_vmalloc_addr(const void *addr);

/**
 * @brief Check if address is valid vmap address
 * @param addr Address to check
 * @return true if valid vmap address, false otherwise
 */
bool is_vmap_addr(const void *addr);

/**
 * @brief Get total vmalloc memory usage
 * @return Used memory in bytes
 */
size_t vmalloc_total_size(void);

/**
 * @brief Get available vmalloc memory
 * @return Available memory in bytes
 */
size_t vmalloc_available_size(void);

/**
 * @brief Get largest available vmalloc chunk
 * @return Largest chunk size in bytes
 */
size_t vmalloc_largest_chunk(void);

/**
 * @brief Calculate vmalloc fragmentation
 * @return Fragmentation percentage (0-100)
 */
unsigned int vmalloc_fragmentation(void);

/* ========================================================================
 * MAINTENANCE AND OPTIMIZATION
 * ======================================================================== */

/**
 * @brief Compact vmalloc area (reduce fragmentation)
 * @return Number of chunks coalesced
 */
size_t vmalloc_compact(void);

/**
 * @brief Purge unused vmalloc pages
 * @return Number of pages freed
 */
size_t vmalloc_purge(void);

/**
 * @brief Check vmalloc integrity
 * @return true if consistent, false if corruption detected
 */
bool vmalloc_check_integrity(void);

/**
 * @brief Print vmalloc debug information
 */
void vmalloc_print_debug(void);

/**
 * @brief Print vmalloc memory layout
 */
void vmalloc_print_layout(void);

/**
 * @brief Dump vmalloc statistics
 */
void vmalloc_dump_stats(void);

/**
 * @brief Walk all vmalloc allocations
 * @param callback Function to call for each allocation
 * @param data User data passed to callback
 */
void vmalloc_walk(void (*callback)(vmalloc_info_t *info, void *data), void *data);

/* ========================================================================
 * ADVANCED FEATURES
 * ======================================================================== */

/**
 * @brief Reserve virtual address range
 * @param start Start address
 * @param size Size in bytes
 * @return 0 on success, negative error code on failure
 */
int vmalloc_reserve(virt_addr_t start, size_t size);

/**
 * @brief Unreserve virtual address range
 * @param start Start address
 * @param size Size in bytes
 * @return 0 on success, negative error code on failure
 */
int vmalloc_unreserve(virt_addr_t start, size_t size);

/**
 * @brief Lock virtual memory in RAM
 * @param addr Virtual address
 * @param size Size in bytes
 * @return 0 on success, negative error code on failure
 */
int vmalloc_lock(void *addr, size_t size);

/**
 * @brief Unlock virtual memory
 * @param addr Virtual address
 * @param size Size in bytes
 * @return 0 on success, negative error code on failure
 */
int vmalloc_unlock(void *addr, size_t size);

/**
 * @brief Change memory caching attributes
 * @param addr Virtual address
 * @param size Size in bytes
 * @param cache_type Caching type
 * @return 0 on success, negative error code on failure
 */
int vmalloc_set_cache(void *addr, size_t size, unsigned int cache_type);

/* ========================================================================
 * ERROR CODES
 * ======================================================================== */

#define VMALLOC_SUCCESS         0       /**< Operation successful */
#define VMALLOC_ERR_NOMEM      -1       /**< Out of virtual memory */
#define VMALLOC_ERR_INVALID    -2       /**< Invalid parameter */
#define VMALLOC_ERR_BUSY       -3       /**< Address range busy */
#define VMALLOC_ERR_NOTFOUND   -4       /**< Address not found */
#define VMALLOC_ERR_EXISTS     -5       /**< Address already exists */
#define VMALLOC_ERR_PERM       -6       /**< Permission denied */
#define VMALLOC_ERR_ALIGN      -7       /**< Alignment error */
#define VMALLOC_ERR_RANGE      -8       /**< Address range error */
#define VMALLOC_ERR_CORRUPT    -9       /**< Data corruption */
#define VMALLOC_ERR_INIT       -10      /**< Not initialized */
#define VMALLOC_ERR_FRAGMENT   -11      /**< Too fragmented */
#define VMALLOC_ERR_LOCKED     -12      /**< Memory locked */

/* ========================================================================
 * CACHE TYPE DEFINITIONS
 * ======================================================================== */

#define VM_CACHE_DEFAULT        0       /**< Default caching */
#define VM_CACHE_UNCACHED       1       /**< Uncached memory */
#define VM_CACHE_WRITE_COMBINE  2       /**< Write-combining */
#define VM_CACHE_WRITE_THROUGH  3       /**< Write-through */
#define VM_CACHE_WRITE_BACK     4       /**< Write-back */

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_VMALLOC_H */

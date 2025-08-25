/**
 * @file mmap.h
 * @brief Memory Mapping Interface
 * 
 * This header defines the interface for the LeaxOS kernel's memory mapping
 * subsystem. It provides functions for mapping files, devices, and anonymous
 * memory into virtual address spaces, supporting both kernel and user space
 * memory mappings.
 * 
 * Features:
 * - File-backed memory mappings
 * - Anonymous memory mappings
 * - Shared and private mappings
 * - Memory protection and permissions
 * - Copy-on-write semantics
 * - Memory synchronization
 * - Large page support
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_MMAP_H
#define LEAX_KERNEL_MM_MMAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"

/* Forward type declarations */
typedef int32_t off_t;              /**< File offset type */
typedef uint32_t mode_t;            /**< File mode type */
typedef uint32_t atomic_t;          /**< Atomic counter type */

/* Red-black tree node (simplified) */
struct rb_node {
    uintptr_t rb_parent_color;      /**< Parent and color */
    struct rb_node *rb_right;       /**< Right child */
    struct rb_node *rb_left;        /**< Left child */
};

/* Forward declaration for process memory management */
struct mm_struct;

/* ========================================================================
 * CONSTANTS AND CONFIGURATION
 * ======================================================================== */

/** Virtual memory area limits */
#define MMAP_MIN_ADDR               0x1000U         /**< Minimum mappable address (4KB) */
#define MMAP_MAX_SIZE               (SIZE_MAX / 2)  /**< Maximum mapping size */
#define MMAP_MAX_AREAS              65536U          /**< Maximum VMAs per process */
#define MMAP_ALIGN_DEFAULT          0x1000U         /**< Default alignment (4KB) */
#define MMAP_ALIGN_HUGE             0x200000U       /**< Huge page alignment (2MB) */

/** Mapping granularity */
#ifndef PAGE_SIZE
#define PAGE_SIZE                   4096U           /**< Standard page size */
#endif
#define HUGE_PAGE_SIZE              (2 * 1024 * 1024U) /**< Huge page size (2MB) */
#define SUPER_PAGE_SIZE             (1024 * 1024 * 1024U) /**< Super page size (1GB) */

/** Protection flags (compatible with POSIX) */
typedef uint32_t mmap_prot_t;
#define PROT_NONE                   0x00U           /**< No access */
#define PROT_READ                   0x01U           /**< Read access */
#define PROT_WRITE                  0x02U           /**< Write access */
#define PROT_EXEC                   0x04U           /**< Execute access */
#define PROT_SEM                    0x08U           /**< Semaphore access */
#define PROT_GROWSDOWN              0x10U           /**< Stack-like growth */
#define PROT_GROWSUP                0x20U           /**< Heap-like growth */

/** Mapping flags (compatible with POSIX) */
typedef uint32_t mmap_flags_t;
#define MAP_SHARED                  0x0001U         /**< Share changes */
#define MAP_PRIVATE                 0x0002U         /**< Private copy-on-write */
#define MAP_FIXED                   0x0010U         /**< Fixed address */
#define MAP_ANONYMOUS               0x0020U         /**< Anonymous mapping */
#define MAP_ANON                    MAP_ANONYMOUS   /**< Alias for MAP_ANONYMOUS */
#define MAP_GROWSDOWN               0x0100U         /**< Stack-like area */
#define MAP_DENYWRITE               0x0800U         /**< Deny write access to file */
#define MAP_EXECUTABLE              0x1000U         /**< Executable mapping */
#define MAP_LOCKED                  0x2000U         /**< Lock pages in memory */
#define MAP_NORESERVE               0x4000U         /**< Don't reserve swap space */
#define MAP_POPULATE                0x8000U         /**< Populate page tables */
#define MAP_NONBLOCK                0x10000U        /**< Non-blocking allocation */
#define MAP_STACK                   0x20000U        /**< Stack allocation */
#define MAP_HUGETLB                 0x40000U        /**< Use huge pages */
#define MAP_SYNC                    0x80000U        /**< Synchronous mapping */
#define MAP_FIXED_NOREPLACE         0x100000U       /**< Fixed without replacement */

/** Memory synchronization flags */
typedef uint32_t msync_flags_t;
#define MS_ASYNC                    0x01U           /**< Asynchronous sync */
#define MS_SYNC                     0x02U           /**< Synchronous sync */
#define MS_INVALIDATE               0x04U           /**< Invalidate caches */

/** Memory advice flags */
typedef uint32_t madvise_flags_t;
#define MADV_NORMAL                 0x00U           /**< No special treatment */
#define MADV_RANDOM                 0x01U           /**< Random access pattern */
#define MADV_SEQUENTIAL             0x02U           /**< Sequential access */
#define MADV_WILLNEED               0x03U           /**< Will need these pages */
#define MADV_DONTNEED               0x04U           /**< Don't need these pages */
#define MADV_FREE                   0x08U           /**< Free pages if needed */
#define MADV_REMOVE                 0x09U           /**< Remove mapping */
#define MADV_DONTFORK               0x0AU           /**< Don't fork this area */
#define MADV_DOFORK                 0x0BU           /**< Do fork this area */
#define MADV_MERGEABLE              0x0CU           /**< Pages can be merged */
#define MADV_UNMERGEABLE            0x0DU           /**< Pages cannot be merged */
#define MADV_HUGEPAGE               0x0EU           /**< Use huge pages */
#define MADV_NOHUGEPAGE             0x0FU           /**< Don't use huge pages */

/** Memory locking flags */
typedef uint32_t mlock_flags_t;
#define MLOCK_ONFAULT               0x01U           /**< Lock on page fault */

/** Virtual memory area types */
typedef enum {
    VMA_TYPE_ANON,              /**< Anonymous memory */
    VMA_TYPE_FILE,              /**< File-backed memory */
    VMA_TYPE_DEVICE,            /**< Device memory */
    VMA_TYPE_SHARED,            /**< Shared memory */
    VMA_TYPE_STACK,             /**< Stack area */
    VMA_TYPE_HEAP,              /**< Heap area */
    VMA_TYPE_VDSO,              /**< Virtual dynamic shared object */
    VMA_TYPE_VSYSCALL,          /**< Virtual system call */
    VMA_TYPE_COUNT
} vma_type_t;

/** Virtual memory area states */
typedef enum {
    VMA_STATE_ACTIVE,           /**< Active mapping */
    VMA_STATE_INACTIVE,         /**< Inactive mapping */
    VMA_STATE_SWAPPED,          /**< Swapped out */
    VMA_STATE_MIGRATING,        /**< Being migrated */
    VMA_STATE_LOCKED,           /**< Locked in memory */
    VMA_STATE_ERROR             /**< Error state */
} vma_state_t;

/* ========================================================================
 * FORWARD DECLARATIONS AND STRUCTURES
 * ======================================================================== */

/* Forward declarations */
typedef struct vma vma_t;
typedef struct vma_ops vma_ops_t;
typedef struct mmap_region mmap_region_t;
typedef struct file file_t;  /* From filesystem */

/** Virtual Memory Area (VMA) operations */
struct vma_ops {
    /* Memory management operations */
    int (*open)(vma_t *vma);
    void (*close)(vma_t *vma);
    
    /* Page fault handling */
    int (*fault)(vma_t *vma, uintptr_t addr, uint32_t flags);
    int (*page_mkwrite)(vma_t *vma, uintptr_t addr);
    
    /* Access control */
    int (*access)(vma_t *vma, uintptr_t addr, size_t len, int prot, int flags);
    
    /* Memory advice */
    int (*set_policy)(vma_t *vma, int policy);
    int (*get_policy)(vma_t *vma, int *policy);
    
    /* Name for debugging */
    const char *name;
};

/** Virtual Memory Area structure */
struct vma {
    /* Address range */
    uintptr_t vm_start;         /**< Start virtual address */
    uintptr_t vm_end;           /**< End virtual address */
    
    /* Properties */
    mmap_prot_t vm_prot;        /**< Access permissions */
    mmap_flags_t vm_flags;      /**< Mapping flags */
    vma_type_t vm_type;         /**< VMA type */
    vma_state_t vm_state;       /**< Current state */
    
    /* File mapping information */
    file_t *vm_file;            /**< Mapped file (if any) */
    uint64_t vm_offset;         /**< Offset in file */
    
    /* Memory management */
    size_t vm_pgoff;            /**< Page offset */
    atomic_t vm_refcount;       /**< Reference count */
    
    /* Operations */
    const vma_ops_t *vm_ops;    /**< VMA operations */
    void *vm_private_data;      /**< Private data */
    
    /* Tree and list management */
    struct vma *vm_next;        /**< Next VMA in list */
    struct vma *vm_prev;        /**< Previous VMA in list */
    struct rb_node vm_rb;       /**< Red-black tree node */
    
    /* Statistics and debugging */
    uint64_t vm_create_time;    /**< Creation timestamp */
    uint32_t vm_fault_count;    /**< Page fault counter */
    uint32_t vm_access_count;   /**< Access counter */
    uint32_t vm_magic;          /**< Magic number */
};

/** Memory mapping region */
struct mmap_region {
    uintptr_t start;            /**< Start address */
    uintptr_t end;              /**< End address */
    size_t size;                /**< Region size */
    mmap_prot_t prot;           /**< Protection flags */
    mmap_flags_t flags;         /**< Mapping flags */
    uint32_t ref_count;         /**< Reference count */
    vma_t *vma_list;            /**< List of VMAs */
    void *private_data;         /**< Private data */
};

/** Memory mapping statistics */
typedef struct mmap_stats {
    /* VMA statistics */
    uint32_t total_vmas;        /**< Total VMAs */
    uint32_t active_vmas;       /**< Active VMAs */
    uint32_t file_vmas;         /**< File-backed VMAs */
    uint32_t anon_vmas;         /**< Anonymous VMAs */
    uint32_t shared_vmas;       /**< Shared VMAs */
    
    /* Memory usage */
    size_t total_mapped;        /**< Total mapped memory */
    size_t file_mapped;         /**< File-backed memory */
    size_t anon_mapped;         /**< Anonymous memory */
    size_t shared_mapped;       /**< Shared memory */
    size_t locked_mapped;       /**< Locked memory */
    
    /* Page statistics */
    uint64_t total_pages;       /**< Total mapped pages */
    uint64_t resident_pages;    /**< Resident pages */
    uint64_t swapped_pages;     /**< Swapped pages */
    uint64_t dirty_pages;       /**< Dirty pages */
    
    /* Performance counters */
    uint64_t map_count;         /**< Total map operations */
    uint64_t unmap_count;       /**< Total unmap operations */
    uint64_t fault_count;       /**< Total page faults */
    uint64_t cow_count;         /**< Copy-on-write faults */
    uint64_t sync_count;        /**< Sync operations */
    
    /* Error counters */
    uint64_t map_failed;        /**< Failed map operations */
    uint64_t fault_failed;      /**< Failed page faults */
    uint64_t oom_killed;        /**< OOM kills */
} mmap_stats_t;

/** Memory mapping configuration */
typedef struct mmap_config {
    uintptr_t user_vm_start;    /**< User VM start address */
    uintptr_t user_vm_end;      /**< User VM end address */
    uintptr_t kernel_vm_start;  /**< Kernel VM start address */
    uintptr_t kernel_vm_end;    /**< Kernel VM end address */
    size_t max_map_count;       /**< Maximum mappings per process */
    size_t default_stack_size;  /**< Default stack size */
    size_t max_locked_memory;   /**< Maximum locked memory */
    bool enable_huge_pages;     /**< Enable huge page support */
    bool enable_debugging;      /**< Enable debug features */
    bool enable_overcommit;     /**< Enable memory overcommit */
} mmap_config_t;

/* ========================================================================
 * CORE MEMORY MAPPING FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize the memory mapping subsystem
 * @param config Configuration parameters
 * @return 0 on success, negative error code on failure
 */
int mmap_init(const mmap_config_t *config);

/**
 * @brief Shutdown the memory mapping subsystem
 */
void mmap_shutdown(void);

/**
 * @brief Map memory into virtual address space
 * @param addr Preferred address (0 for any)
 * @param length Size of mapping
 * @param prot Protection flags
 * @param flags Mapping flags
 * @param fd File descriptor (-1 for anonymous)
 * @param offset Offset in file
 * @return Virtual address on success, MAP_FAILED on error
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

/**
 * @brief Unmap memory from virtual address space
 * @param addr Start address
 * @param length Size to unmap
 * @return 0 on success, negative error code on failure
 */
int munmap(void *addr, size_t length);

/**
 * @brief Change protection of memory region
 * @param addr Start address
 * @param len Size of region
 * @param prot New protection flags
 * @return 0 on success, negative error code on failure
 */
int mprotect(void *addr, size_t len, int prot);

/**
 * @brief Synchronize mapped memory with backing store
 * @param addr Start address
 * @param length Size to synchronize
 * @param flags Synchronization flags
 * @return 0 on success, negative error code on failure
 */
int msync(void *addr, size_t length, int flags);

/**
 * @brief Lock pages in memory
 * @param addr Start address
 * @param len Size to lock
 * @return 0 on success, negative error code on failure
 */
int mlock(const void *addr, size_t len);

/**
 * @brief Lock pages in memory with flags
 * @param addr Start address
 * @param len Size to lock
 * @param flags Locking flags
 * @return 0 on success, negative error code on failure
 */
int mlock2(const void *addr, size_t len, int flags);

/**
 * @brief Unlock pages from memory
 * @param addr Start address
 * @param len Size to unlock
 * @return 0 on success, negative error code on failure
 */
int munlock(const void *addr, size_t len);

/**
 * @brief Lock all pages of calling process
 * @param flags Locking flags
 * @return 0 on success, negative error code on failure
 */
int mlockall(int flags);

/**
 * @brief Unlock all pages of calling process
 * @return 0 on success, negative error code on failure
 */
int munlockall(void);

/**
 * @brief Give advice about memory usage
 * @param addr Start address
 * @param length Size of region
 * @param advice Advice type
 * @return 0 on success, negative error code on failure
 */
int madvise(void *addr, size_t length, int advice);

/**
 * @brief Remap pages of memory
 * @param old_address Current address
 * @param old_size Current size
 * @param new_size New size
 * @param flags Remap flags
 * @param new_address New address (if MREMAP_FIXED)
 * @return New address on success, MAP_FAILED on error
 */
void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);

/* ========================================================================
 * VMA MANAGEMENT FUNCTIONS
 * ======================================================================== */

/**
 * @brief Find VMA containing address
 * @param mm Memory management structure
 * @param addr Address to find
 * @return Pointer to VMA, or NULL if not found
 */
vma_t *find_vma(struct mm_struct *mm, uintptr_t addr);

/**
 * @brief Find VMA intersecting with range
 * @param mm Memory management structure
 * @param start_addr Start address
 * @param end_addr End address
 * @return Pointer to VMA, or NULL if none found
 */
vma_t *find_vma_intersection(struct mm_struct *mm, uintptr_t start_addr, uintptr_t end_addr);

/**
 * @brief Create a new VMA
 * @param start Start address
 * @param end End address
 * @param prot Protection flags
 * @param flags Mapping flags
 * @param file Backing file (optional)
 * @param offset File offset
 * @return Pointer to VMA, or NULL on failure
 */
vma_t *vma_create(uintptr_t start, uintptr_t end, mmap_prot_t prot, 
                  mmap_flags_t flags, file_t *file, uint64_t offset);

/**
 * @brief Destroy a VMA
 * @param vma VMA to destroy
 */
void vma_destroy(vma_t *vma);

/**
 * @brief Insert VMA into memory management structure
 * @param mm Memory management structure
 * @param vma VMA to insert
 * @return 0 on success, negative error code on failure
 */
int vma_insert(struct mm_struct *mm, vma_t *vma);

/**
 * @brief Remove VMA from memory management structure
 * @param mm Memory management structure
 * @param vma VMA to remove
 * @return 0 on success, negative error code on failure
 */
int vma_remove(struct mm_struct *mm, vma_t *vma);

/**
 * @brief Split VMA at given address
 * @param vma VMA to split
 * @param addr Split address
 * @return Pointer to new VMA, or NULL on failure
 */
vma_t *vma_split(vma_t *vma, uintptr_t addr);

/**
 * @brief Merge adjacent VMAs
 * @param vma1 First VMA
 * @param vma2 Second VMA
 * @return Pointer to merged VMA, or NULL if cannot merge
 */
vma_t *vma_merge(vma_t *vma1, vma_t *vma2);

/**
 * @brief Check if two VMAs can be merged
 * @param vma1 First VMA
 * @param vma2 Second VMA
 * @return true if can merge, false otherwise
 */
bool vma_can_merge(const vma_t *vma1, const vma_t *vma2);

/**
 * @brief Expand VMA
 * @param vma VMA to expand
 * @param delta Size to expand by
 * @return 0 on success, negative error code on failure
 */
int vma_expand(vma_t *vma, size_t delta);

/**
 * @brief Shrink VMA
 * @param vma VMA to shrink
 * @param delta Size to shrink by
 * @return 0 on success, negative error code on failure
 */
int vma_shrink(vma_t *vma, size_t delta);

/* ========================================================================
 * PAGE FAULT HANDLING
 * ======================================================================== */

/**
 * @brief Handle page fault
 * @param addr Faulting address
 * @param error_code Error code from hardware
 * @param regs CPU registers
 * @return 0 if handled, negative error code on failure
 */
int handle_page_fault(uintptr_t addr, uint32_t error_code, void *regs);

/**
 * @brief Handle anonymous page fault
 * @param vma VMA containing fault
 * @param addr Faulting address
 * @param flags Fault flags
 * @return 0 on success, negative error code on failure
 */
int handle_anon_fault(vma_t *vma, uintptr_t addr, uint32_t flags);

/**
 * @brief Handle file page fault
 * @param vma VMA containing fault
 * @param addr Faulting address
 * @param flags Fault flags
 * @return 0 on success, negative error code on failure
 */
int handle_file_fault(vma_t *vma, uintptr_t addr, uint32_t flags);

/**
 * @brief Handle copy-on-write fault
 * @param vma VMA containing fault
 * @param addr Faulting address
 * @return 0 on success, negative error code on failure
 */
int handle_cow_fault(vma_t *vma, uintptr_t addr);

/**
 * @brief Handle swap fault
 * @param vma VMA containing fault
 * @param addr Faulting address
 * @param entry Swap entry
 * @return 0 on success, negative error code on failure
 */
int handle_swap_fault(vma_t *vma, uintptr_t addr, uint64_t entry);

/* ========================================================================
 * SHARED MEMORY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Create shared memory object
 * @param name Object name
 * @param flags Creation flags
 * @param mode Access mode
 * @return File descriptor on success, negative error code on failure
 */
int shm_open(const char *name, int flags, mode_t mode);

/**
 * @brief Remove shared memory object
 * @param name Object name
 * @return 0 on success, negative error code on failure
 */
int shm_unlink(const char *name);

/**
 * @brief Map shared memory
 * @param addr Preferred address
 * @param length Size of mapping
 * @param prot Protection flags
 * @param flags Mapping flags
 * @param name Shared memory name
 * @param offset Offset in object
 * @return Virtual address on success, MAP_FAILED on error
 */
void *shm_map(void *addr, size_t length, int prot, int flags, const char *name, off_t offset);

/* ========================================================================
 * MEMORY INFORMATION AND STATISTICS
 * ======================================================================== */

/**
 * @brief Get memory mapping statistics
 * @param stats Pointer to statistics structure
 */
void mmap_get_stats(mmap_stats_t *stats);

/**
 * @brief Get VMA information
 * @param vma Target VMA
 * @param info Pointer to info structure
 */
void vma_get_info(const vma_t *vma, struct vma_info *info);

/**
 * @brief Check if address range is mapped
 * @param addr Start address
 * @param length Size to check
 * @return true if fully mapped, false otherwise
 */
bool mmap_is_mapped(const void *addr, size_t length);

/**
 * @brief Check if address is valid for mapping
 * @param addr Address to check
 * @param length Size to check
 * @return true if valid, false otherwise
 */
bool mmap_is_valid_addr(const void *addr, size_t length);

/**
 * @brief Get total mapped memory size
 * @return Total mapped memory in bytes
 */
size_t mmap_get_total_size(void);

/**
 * @brief Get number of active mappings
 * @return Number of active VMAs
 */
uint32_t mmap_get_mapping_count(void);

/**
 * @brief Print memory mapping information
 * @param mm Memory management structure
 */
void mmap_print_mappings(struct mm_struct *mm);

/**
 * @brief Dump VMA information
 * @param vma VMA to dump
 */
void vma_dump_info(const vma_t *vma);

/* ========================================================================
 * DEBUGGING AND VALIDATION
 * ======================================================================== */

/**
 * @brief Validate VMA structure
 * @param vma VMA to validate
 * @return true if valid, false if corrupted
 */
bool vma_validate(const vma_t *vma);

/**
 * @brief Validate all VMAs in memory management structure
 * @param mm Memory management structure
 * @return true if all valid, false if any corruption
 */
bool mmap_validate_all(struct mm_struct *mm);

/**
 * @brief Check for VMA overlaps
 * @param mm Memory management structure
 * @return Number of overlaps found
 */
uint32_t mmap_check_overlaps(struct mm_struct *mm);

/**
 * @brief Check VMA consistency
 * @param vma VMA to check
 * @return true if consistent, false otherwise
 */
bool vma_check_consistency(const vma_t *vma);

/**
 * @brief Enable debug mode for memory mapping
 * @param enable Enable/disable debug mode
 */
void mmap_set_debug(bool enable);

/* ========================================================================
 * UTILITY FUNCTIONS AND MACROS
 * ======================================================================== */

/**
 * @brief Round address down to page boundary
 * @param addr Address to round
 * @return Page-aligned address
 */
static inline uintptr_t mmap_page_align_down(uintptr_t addr) {
    return addr & ~(PAGE_SIZE - 1);
}

/**
 * @brief Round address up to page boundary
 * @param addr Address to round
 * @return Page-aligned address
 */
static inline uintptr_t mmap_page_align_up(uintptr_t addr) {
    return (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

/**
 * @brief Check if address is page-aligned
 * @param addr Address to check
 * @return true if aligned, false otherwise
 */
static inline bool mmap_is_page_aligned(uintptr_t addr) {
    return (addr & (PAGE_SIZE - 1)) == 0;
}

/**
 * @brief Get VMA size in bytes
 * @param vma VMA to measure
 * @return Size in bytes
 */
static inline size_t vma_size(const vma_t *vma) {
    return vma->vm_end - vma->vm_start;
}

/**
 * @brief Get VMA size in pages
 * @param vma VMA to measure
 * @return Size in pages
 */
static inline size_t vma_pages(const vma_t *vma) {
    return (vma->vm_end - vma->vm_start) >> 12;  /* Divide by PAGE_SIZE */
}

/**
 * @brief Check if address is within VMA
 * @param vma VMA to check
 * @param addr Address to test
 * @return true if address is in VMA, false otherwise
 */
static inline bool vma_contains(const vma_t *vma, uintptr_t addr) {
    return addr >= vma->vm_start && addr < vma->vm_end;
}

/**
 * @brief Check if VMA is anonymous
 * @param vma VMA to check
 * @return true if anonymous, false otherwise
 */
static inline bool vma_is_anonymous(const vma_t *vma) {
    return vma->vm_file == NULL;
}

/**
 * @brief Check if VMA is shared
 * @param vma VMA to check
 * @return true if shared, false otherwise
 */
static inline bool vma_is_shared(const vma_t *vma) {
    return (vma->vm_flags & MAP_SHARED) != 0;
}

/**
 * @brief Check if VMA is writable
 * @param vma VMA to check
 * @return true if writable, false otherwise
 */
static inline bool vma_is_writable(const vma_t *vma) {
    return (vma->vm_prot & PROT_WRITE) != 0;
}

/**
 * @brief Check if VMA is executable
 * @param vma VMA to check
 * @return true if executable, false otherwise
 */
static inline bool vma_is_executable(const vma_t *vma) {
    return (vma->vm_prot & PROT_EXEC) != 0;
}

/* Utility macros */
#define MAP_FAILED                  ((void *) -1)   /**< mmap failure return value */
#define VMA_MAGIC                   0x564D4121U     /**< "VMA!" magic number */

/* Page fault error codes */
#define FAULT_FLAG_WRITE            0x01U           /**< Write fault */
#define FAULT_FLAG_MKWRITE          0x02U           /**< Make writable fault */
#define FAULT_FLAG_ALLOW_RETRY      0x04U           /**< Allow retry */
#define FAULT_FLAG_RETRY_NOWAIT     0x08U           /**< Retry without waiting */
#define FAULT_FLAG_KILLABLE         0x10U           /**< Killable fault */
#define FAULT_FLAG_TRIED            0x20U           /**< Already tried */
#define FAULT_FLAG_USER             0x40U           /**< User-space fault */
#define FAULT_FLAG_REMOTE           0x80U           /**< Remote fault */
#define FAULT_FLAG_INSTRUCTION      0x100U          /**< Instruction fetch fault */

/* Error codes */
#define MMAP_SUCCESS                0               /**< Success */
#define MMAP_ERR_NOMEM             -1               /**< Out of memory */
#define MMAP_ERR_INVALID           -2               /**< Invalid parameter */
#define MMAP_ERR_BUSY              -3               /**< Resource busy */
#define MMAP_ERR_NOTFOUND          -4               /**< Mapping not found */
#define MMAP_ERR_EXISTS            -5               /**< Mapping already exists */
#define MMAP_ERR_PERM              -6               /**< Permission denied */
#define MMAP_ERR_FAULT             -7               /**< Page fault error */
#define MMAP_ERR_RANGE             -8               /**< Address range error */
#define MMAP_ERR_ALIGN             -9               /**< Alignment error */
#define MMAP_ERR_OVERFLOW          -10              /**< Address space overflow */
#define MMAP_ERR_LIMIT             -11              /**< Limit exceeded */
#define MMAP_ERR_LOCKED            -12              /**< Memory locked */
#define MMAP_ERR_IO                -13              /**< I/O error */

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_MMAP_H */

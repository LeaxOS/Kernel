/**
 * @file mm_common.h
 * @brief Définitions communes pour le système de gestion mémoire
 * 
 * Ce fichier contient toutes les définitions communes utilisées par
 * les différents composants du système de gestion mémoire pour éviter
 * les duplications et les conflits.
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_COMMON_H
#define LEAX_KERNEL_MM_COMMON_H

#include "../../../Include/stdint.h"
#include "../../../Include/stddef.h"
#include "../../../Include/stdbool.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * KERNEL LOGGING DEFINITIONS
 * ======================================================================== */

#ifndef printk
#define printk printf
#endif

#ifndef panic
#define panic(msg) do { printf("PANIC: %s\n", msg); while(1); } while(0)
#endif

/* Kernel log levels */
#ifndef KERN_EMERG
#define KERN_EMERG    "0"  /* Emergency */
#define KERN_ALERT    "1"  /* Alert */
#define KERN_CRIT     "2"  /* Critical */
#define KERN_ERR      "3"  /* Error */
#define KERN_WARNING  "4"  /* Warning */
#define KERN_NOTICE   "5"  /* Notice */
#define KERN_INFO     "6"  /* Info */
#define KERN_DEBUG    "7"  /* Debug */
#endif

/* ========================================================================
 * GFP (GET FREE PAGES) FLAGS
 * ======================================================================== */

/** GFP allocation flags */
typedef uint32_t gfp_t;

/* Basic allocation constraints */
#define GFP_WAIT        (1 << 0)        /* Can wait/sleep */
#define GFP_NOWAIT      (1 << 1)        /* Cannot wait */
#define GFP_ATOMIC      (1 << 2)        /* Atomic allocation */
#define GFP_IO          (1 << 3)        /* Can start I/O */
#define GFP_FS          (1 << 4)        /* Can call filesystem */
#define GFP_COLD        (1 << 5)        /* Cache cold allocation */
#define GFP_NOWARN      (1 << 6)        /* No allocation warnings */
#define GFP_HIGHMEM     (1 << 7)        /* Can use high memory */
#define GFP_DMA         (1 << 8)        /* DMA memory zone */
#define GFP_DMA32       (1 << 9)        /* DMA32 memory zone */
#define GFP_NORMAL      (1 << 10)       /* Normal memory zone */
#define GFP_MOVABLE     (1 << 11)       /* Movable memory */
#define GFP_RECLAIMABLE (1 << 12)       /* Reclaimable memory */
#define GFP_COMP        (1 << 13)       /* Compression OK */
#define GFP_ZERO        (1 << 14)       /* Zero-initialize */
#define GFP_NOMEMALLOC  (1 << 15)       /* Don't use emergency pools */
#define GFP_NORETRY     (1 << 16)       /* Don't retry on failure */

/* Common combinations */
#define GFP_KERNEL      (GFP_WAIT | GFP_IO | GFP_FS)
#define GFP_USER        (GFP_WAIT | GFP_IO | GFP_FS | GFP_HIGHMEM)
#define GFP_HIGHUSER    (GFP_USER | GFP_HIGHMEM)
#define GFP_NOIO        (GFP_WAIT)
#define GFP_NOFS        (GFP_WAIT | GFP_IO)

/* ========================================================================
 * MEMORY PROTECTION FLAGS
 * ======================================================================== */

/** Memory protection flags */
typedef uint32_t vm_prot_t;
#define VM_PROT_NONE        0x00U       /**< No access */
#define VM_PROT_READ        0x01U       /**< Read access */
#define VM_PROT_WRITE       0x02U       /**< Write access */
#define VM_PROT_EXEC        0x04U       /**< Execute access */
#define VM_PROT_ALL         (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXEC)

/* ========================================================================
 * VIRTUAL MEMORY AREA FLAGS
 * ======================================================================== */

/** Virtual memory area flags */
typedef uint32_t vma_flags_t;
#define VMA_FLAG_SHARED     0x01U       /**< Shared mapping */
#define VMA_FLAG_PRIVATE    0x02U       /**< Private mapping */
#define VMA_FLAG_FIXED      0x04U       /**< Fixed address mapping */
#define VMA_FLAG_GROWSDOWN  0x08U       /**< Stack-like growth */
#define VMA_FLAG_GROWSUP    0x10U       /**< Heap-like growth */
#define VMA_FLAG_LOCKED     0x20U       /**< Memory locked in RAM */
#define VMA_FLAG_RESERVED   0x40U       /**< Reserved area */
#define VMA_FLAG_CACHE      0x80U       /**< Cacheable memory */

/* ========================================================================
 * MEMORY ALIGNMENT MACROS
 * ======================================================================== */

#ifndef PAGE_SIZE
#define PAGE_SIZE           4096U       /**< Standard page size */
#endif

#ifndef PAGE_SHIFT
#define PAGE_SHIFT          12U         /**< Page size shift */
#endif

#define PAGE_MASK           (~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr)    (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define PAGE_ALIGNED(addr)  (((addr) & (PAGE_SIZE - 1)) == 0)

/* Generic alignment macros */
#define ALIGN(x, a)         (((x) + (a) - 1) & ~((a) - 1))
#define IS_ALIGNED(x, a)    (((x) & ((a) - 1)) == 0)

/* Cache line alignment */
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES      64U         /**< L1 cache line size */
#endif

#define L1_CACHE_ALIGN(x)   ALIGN(x, L1_CACHE_BYTES)
#define L1_CACHE_ALIGNED(x) IS_ALIGNED(x, L1_CACHE_BYTES)

/* ========================================================================
 * ERROR CODES
 * ======================================================================== */

/** Memory management error codes */
typedef enum {
    MM_SUCCESS = 0,                 /* Success */
    MM_ERROR_NOMEM = -1,            /* Out of memory */
    MM_ERROR_INVALID = -2,          /* Invalid parameter */
    MM_ERROR_BUSY = -3,             /* Resource busy */
    MM_ERROR_EXISTS = -4,           /* Already exists */
    MM_ERROR_NOTFOUND = -5,         /* Not found */
    MM_ERROR_CORRUPT = -6,          /* Corruption detected */
    MM_ERROR_LIMIT = -7,            /* Limit exceeded */
    MM_ERROR_INIT = -8,             /* Initialization failed */
    MM_ERROR_DOUBLE_FREE = -9,      /* Double free detected */
    MM_ERROR_RANGE = -10,           /* Address range error */
    MM_ERROR_FRAGMENT = -11,        /* Too fragmented */
    MM_ERROR_LOCKED = -12           /* Memory locked */
} mm_error_t;

/* ========================================================================
 * COMMON MAGIC NUMBERS
 * ======================================================================== */

#define MM_MAGIC_ALLOC      0xDEADBEEFU /* Allocated memory */
#define MM_MAGIC_FREE       0xFEEDFACEU /* Freed memory */
#define MM_MAGIC_GUARD      0xCAFEBABEU /* Guard pattern */
#define MM_MAGIC_CORRUPT    0xDEADC0DEU /* Corruption marker */

/* ========================================================================
 * SYNCHRONIZATION PRIMITIVES
 * ======================================================================== */

/** Simple spinlock implementation for MM */
typedef struct {
    volatile uint32_t locked;
    const char *name;
} mm_spinlock_t;

#define MM_SPINLOCK_INIT(name) { 0, name }

static inline void mm_spin_lock(mm_spinlock_t *lock) {
    /* Simple atomic test-and-set implementation */
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        /* Busy wait with pause */
        __asm__ volatile("pause" ::: "memory");
    }
}

static inline void mm_spin_unlock(mm_spinlock_t *lock) {
    __sync_lock_release(&lock->locked);
}

static inline bool mm_spin_trylock(mm_spinlock_t *lock) {
    return !__sync_lock_test_and_set(&lock->locked, 1);
}

/* ========================================================================
 * MEMORY BARRIERS
 * ======================================================================== */

/** Memory barrier types */
typedef enum {
    MEMORY_BARRIER_FULL = 0,        /* Full memory barrier */
    MEMORY_BARRIER_READ,            /* Read memory barrier */
    MEMORY_BARRIER_WRITE,           /* Write memory barrier */
    MEMORY_BARRIER_ACQUIRE,         /* Acquire barrier */
    MEMORY_BARRIER_RELEASE,         /* Release barrier */
    MEMORY_BARRIER_COUNT
} memory_barrier_type_t;

static inline void mm_memory_barrier(memory_barrier_type_t type) {
    switch (type) {
    case MEMORY_BARRIER_FULL:
        __asm__ volatile("mfence" ::: "memory");
        break;
    case MEMORY_BARRIER_READ:
        __asm__ volatile("lfence" ::: "memory");
        break;
    case MEMORY_BARRIER_WRITE:
        __asm__ volatile("sfence" ::: "memory");
        break;
    case MEMORY_BARRIER_ACQUIRE:
    case MEMORY_BARRIER_RELEASE:
        __asm__ volatile("" ::: "memory");
        break;
    default:
        break;
    }
}

#define mm_mb()     mm_memory_barrier(MEMORY_BARRIER_FULL)
#define mm_rmb()    mm_memory_barrier(MEMORY_BARRIER_READ)
#define mm_wmb()    mm_memory_barrier(MEMORY_BARRIER_WRITE)

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_COMMON_H */

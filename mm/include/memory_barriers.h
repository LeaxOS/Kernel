/**
 * @file memory_barriers.h
 * @brief Memory Barriers and Synchronization Primitives
 * 
 * This header defines memory barriers and synchronization primitives for the
 * LeaxOS kernel. Memory barriers ensure proper ordering of memory operations
 * in multi-processor environments and prevent compiler/CPU reordering that
 * could lead to race conditions or inconsistent memory states.
 * 
 * Features:
 * - Full memory barriers (read/write)
 * - Read memory barriers
 * - Write memory barriers
 * - Acquire/Release semantics
 * - Compiler barriers
 * - Cache coherency operations
 * - Architecture-specific optimizations
 * - SMP-safe synchronization
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_MEMORY_BARRIERS_H
#define LEAX_KERNEL_MM_MEMORY_BARRIERS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"

/* ========================================================================
 * ARCHITECTURE DETECTION
 * ======================================================================== */

/** Detect target architecture */
#if defined(__x86_64__) || defined(_M_X64)
    #define ARCH_X86_64 1
    #define ARCH_BARRIER_SUPPORTED 1
#elif defined(__i386__) || defined(_M_IX86)
    #define ARCH_X86_32 1
    #define ARCH_BARRIER_SUPPORTED 1
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define ARCH_ARM64 1
    #define ARCH_BARRIER_SUPPORTED 1
#elif defined(__arm__) || defined(_M_ARM)
    #define ARCH_ARM32 1
    #define ARCH_BARRIER_SUPPORTED 1
#elif defined(__riscv) && (__riscv_xlen == 64)
    #define ARCH_RISCV64 1
    #define ARCH_BARRIER_SUPPORTED 1
#elif defined(__riscv) && (__riscv_xlen == 32)
    #define ARCH_RISCV32 1
    #define ARCH_BARRIER_SUPPORTED 1
#else
    #define ARCH_GENERIC 1
    #define ARCH_BARRIER_SUPPORTED 0
    #warning "Memory barriers not fully supported on this architecture"
#endif

/* ========================================================================
 * COMPILER DETECTION AND INTRINSICS
 * ======================================================================== */

/** Detect compiler and define intrinsics */
#if defined(__GNUC__) || defined(__clang__)
    #define COMPILER_BARRIER()      __asm__ __volatile__("" ::: "memory")
    #define LIKELY(x)               __builtin_expect(!!(x), 1)
    #define UNLIKELY(x)             __builtin_expect(!!(x), 0)
    #define ALWAYS_INLINE           __attribute__((always_inline)) inline
    #define NEVER_INLINE            __attribute__((noinline))
#elif defined(_MSC_VER)
    #include "intrin.h"
    #define COMPILER_BARRIER()      _ReadWriteBarrier()
    #define LIKELY(x)               (x)
    #define UNLIKELY(x)             (x)
    #define ALWAYS_INLINE           __forceinline
    #define NEVER_INLINE            __declspec(noinline)
#else
    #define COMPILER_BARRIER()      do { volatile int x = 0; (void)x; } while(0)
    #define LIKELY(x)               (x)
    #define UNLIKELY(x)             (x)
    #define ALWAYS_INLINE           inline
    #define NEVER_INLINE
#endif

/* ========================================================================
 * MEMORY ORDERING SEMANTICS
 * ======================================================================== */

/** Memory ordering types */
typedef enum {
    MEMORY_ORDER_RELAXED = 0,   /**< No ordering constraints */
    MEMORY_ORDER_CONSUME,       /**< Consume ordering (deprecated) */
    MEMORY_ORDER_ACQUIRE,       /**< Acquire ordering */
    MEMORY_ORDER_RELEASE,       /**< Release ordering */
    MEMORY_ORDER_ACQ_REL,       /**< Acquire-release ordering */
    MEMORY_ORDER_SEQ_CST        /**< Sequential consistency */
} memory_order_t;

/** Memory barrier types */
typedef enum {
    BARRIER_FULL = 0,           /**< Full memory barrier */
    BARRIER_READ,               /**< Read memory barrier */
    BARRIER_WRITE,              /**< Write memory barrier */
    BARRIER_ACQUIRE,            /**< Acquire barrier */
    BARRIER_RELEASE,            /**< Release barrier */
    BARRIER_COMPILER            /**< Compiler barrier only */
} barrier_type_t;

/* ========================================================================
 * ARCHITECTURE-SPECIFIC MEMORY BARRIERS
 * ======================================================================== */

#if defined(ARCH_X86_64) || defined(ARCH_X86_32)

/** x86/x86_64 memory barriers */
#define CPU_MEMORY_BARRIER()    __asm__ __volatile__("mfence" ::: "memory")
#define CPU_READ_BARRIER()      __asm__ __volatile__("lfence" ::: "memory")
#define CPU_WRITE_BARRIER()     __asm__ __volatile__("sfence" ::: "memory")

/** x86 specific barriers */
#define CPU_ACQUIRE_BARRIER()   COMPILER_BARRIER()  /* x86 has strong ordering */
#define CPU_RELEASE_BARRIER()   COMPILER_BARRIER()  /* x86 has strong ordering */

/** Cache operations */
#define CPU_CACHE_FLUSH()       __asm__ __volatile__("wbinvd" ::: "memory")
#define CPU_PREFETCH(addr)      __builtin_prefetch((addr), 0, 3)
#define CPU_PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)

#elif defined(ARCH_ARM64)

/** ARM64 memory barriers */
#define CPU_MEMORY_BARRIER()    __asm__ __volatile__("dmb sy" ::: "memory")
#define CPU_READ_BARRIER()      __asm__ __volatile__("dmb ld" ::: "memory")
#define CPU_WRITE_BARRIER()     __asm__ __volatile__("dmb st" ::: "memory")

/** ARM64 acquire/release barriers */
#define CPU_ACQUIRE_BARRIER()   __asm__ __volatile__("dmb ld" ::: "memory")
#define CPU_RELEASE_BARRIER()   __asm__ __volatile__("dmb st" ::: "memory")

/** Cache operations */
#define CPU_CACHE_FLUSH()       __asm__ __volatile__("dc civac, %0" :: "r"(0) : "memory")
#define CPU_PREFETCH(addr)      __builtin_prefetch((addr), 0, 3)
#define CPU_PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)

#elif defined(ARCH_ARM32)

/** ARM32 memory barriers */
#if defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__)
    #define CPU_MEMORY_BARRIER()    __asm__ __volatile__("dmb" ::: "memory")
    #define CPU_READ_BARRIER()      __asm__ __volatile__("dmb" ::: "memory")
    #define CPU_WRITE_BARRIER()     __asm__ __volatile__("dmb st" ::: "memory")
#else
    #define CPU_MEMORY_BARRIER()    __asm__ __volatile__("mcr p15, 0, %0, c7, c10, 5" :: "r"(0) : "memory")
    #define CPU_READ_BARRIER()      CPU_MEMORY_BARRIER()
    #define CPU_WRITE_BARRIER()     CPU_MEMORY_BARRIER()
#endif

/** ARM32 acquire/release barriers */
#define CPU_ACQUIRE_BARRIER()   CPU_READ_BARRIER()
#define CPU_RELEASE_BARRIER()   CPU_WRITE_BARRIER()

/** Cache operations */
#define CPU_CACHE_FLUSH()       __asm__ __volatile__("mcr p15, 0, %0, c7, c14, 0" :: "r"(0) : "memory")
#define CPU_PREFETCH(addr)      __asm__ __volatile__("pld [%0]" :: "r"(addr))
#define CPU_PREFETCH_WRITE(addr) __asm__ __volatile__("pldw [%0]" :: "r"(addr))

#elif defined(ARCH_RISCV64) || defined(ARCH_RISCV32)

/** RISC-V memory barriers */
#define CPU_MEMORY_BARRIER()    __asm__ __volatile__("fence rw,rw" ::: "memory")
#define CPU_READ_BARRIER()      __asm__ __volatile__("fence r,r" ::: "memory")
#define CPU_WRITE_BARRIER()     __asm__ __volatile__("fence w,w" ::: "memory")

/** RISC-V acquire/release barriers */
#define CPU_ACQUIRE_BARRIER()   __asm__ __volatile__("fence r,rw" ::: "memory")
#define CPU_RELEASE_BARRIER()   __asm__ __volatile__("fence rw,w" ::: "memory")

/** Cache operations (RISC-V specific extensions may be needed) */
#define CPU_CACHE_FLUSH()       CPU_MEMORY_BARRIER()
#define CPU_PREFETCH(addr)      ((void)(addr))  /* No standard prefetch */
#define CPU_PREFETCH_WRITE(addr) ((void)(addr))

#else

/** Generic/fallback memory barriers */
#define CPU_MEMORY_BARRIER()    COMPILER_BARRIER()
#define CPU_READ_BARRIER()      COMPILER_BARRIER()
#define CPU_WRITE_BARRIER()     COMPILER_BARRIER()
#define CPU_ACQUIRE_BARRIER()   COMPILER_BARRIER()
#define CPU_RELEASE_BARRIER()   COMPILER_BARRIER()
#define CPU_CACHE_FLUSH()       COMPILER_BARRIER()
#define CPU_PREFETCH(addr)      ((void)(addr))
#define CPU_PREFETCH_WRITE(addr) ((void)(addr))

#endif

/* ========================================================================
 * HIGH-LEVEL MEMORY BARRIER INTERFACE
 * ======================================================================== */

/**
 * @brief Full memory barrier
 * 
 * Ensures that all memory operations (both reads and writes) that appear
 * before this barrier in program order are completed before any memory
 * operations that appear after this barrier.
 */
static ALWAYS_INLINE void memory_barrier(void) {
    CPU_MEMORY_BARRIER();
}

/**
 * @brief Read memory barrier
 * 
 * Ensures that all read operations that appear before this barrier in
 * program order are completed before any read operations that appear
 * after this barrier.
 */
static ALWAYS_INLINE void read_barrier(void) {
    CPU_READ_BARRIER();
}

/**
 * @brief Write memory barrier
 * 
 * Ensures that all write operations that appear before this barrier in
 * program order are completed before any write operations that appear
 * after this barrier.
 */
static ALWAYS_INLINE void write_barrier(void) {
    CPU_WRITE_BARRIER();
}

/**
 * @brief Acquire memory barrier
 * 
 * Ensures that subsequent memory operations cannot be reordered before
 * this barrier. Used in lock acquisition scenarios.
 */
static ALWAYS_INLINE void acquire_barrier(void) {
    CPU_ACQUIRE_BARRIER();
}

/**
 * @brief Release memory barrier
 * 
 * Ensures that preceding memory operations cannot be reordered after
 * this barrier. Used in lock release scenarios.
 */
static ALWAYS_INLINE void release_barrier(void) {
    CPU_RELEASE_BARRIER();
}

/**
 * @brief Compiler barrier
 * 
 * Prevents the compiler from reordering memory operations across this
 * barrier, but provides no CPU-level guarantees.
 */
static ALWAYS_INLINE void compiler_barrier(void) {
    COMPILER_BARRIER();
}

/* ========================================================================
 * CACHE COHERENCY OPERATIONS
 * ======================================================================== */

/**
 * @brief Flush all caches
 * 
 * Forces all dirty cache lines to be written to memory and invalidates
 * all cache entries. This is an expensive operation.
 */
static ALWAYS_INLINE void cache_flush_all(void) {
    CPU_CACHE_FLUSH();
}

/**
 * @brief Prefetch memory for reading
 * 
 * Hint to the processor that the specified memory location will be
 * accessed for reading in the near future.
 * 
 * @param addr Address to prefetch
 */
static ALWAYS_INLINE void prefetch_read(const void *addr) {
    CPU_PREFETCH(addr);
}

/**
 * @brief Prefetch memory for writing
 * 
 * Hint to the processor that the specified memory location will be
 * accessed for writing in the near future.
 * 
 * @param addr Address to prefetch
 */
static ALWAYS_INLINE void prefetch_write(void *addr) {
    CPU_PREFETCH_WRITE(addr);
}

/* ========================================================================
 * ATOMIC OPERATIONS WITH MEMORY ORDERING
 * ======================================================================== */

/**
 * @brief Generic memory barrier with specified ordering
 * 
 * @param order Memory ordering constraint
 */
static ALWAYS_INLINE void memory_barrier_ordered(memory_order_t order) {
    switch (order) {
        case MEMORY_ORDER_RELAXED:
            /* No barrier needed */
            break;
        case MEMORY_ORDER_CONSUME:
        case MEMORY_ORDER_ACQUIRE:
            acquire_barrier();
            break;
        case MEMORY_ORDER_RELEASE:
            release_barrier();
            break;
        case MEMORY_ORDER_ACQ_REL:
            memory_barrier();
            break;
        case MEMORY_ORDER_SEQ_CST:
            memory_barrier();
            break;
    }
}

/**
 * @brief Execute barrier of specified type
 * 
 * @param type Type of memory barrier to execute
 */
static ALWAYS_INLINE void execute_barrier(barrier_type_t type) {
    switch (type) {
        case BARRIER_FULL:
            memory_barrier();
            break;
        case BARRIER_READ:
            read_barrier();
            break;
        case BARRIER_WRITE:
            write_barrier();
            break;
        case BARRIER_ACQUIRE:
            acquire_barrier();
            break;
        case BARRIER_RELEASE:
            release_barrier();
            break;
        case BARRIER_COMPILER:
            compiler_barrier();
            break;
    }
}

/* ========================================================================
 * SMP-SPECIFIC BARRIERS
 * ======================================================================== */

#ifdef CONFIG_SMP

/**
 * @brief SMP-safe memory barrier
 * 
 * On SMP systems, provides full memory barrier. On UP systems,
 * provides only compiler barrier for performance.
 */
#define smp_memory_barrier()    memory_barrier()

/**
 * @brief SMP-safe read barrier
 */
#define smp_read_barrier()      read_barrier()

/**
 * @brief SMP-safe write barrier
 */
#define smp_write_barrier()     write_barrier()

/**
 * @brief SMP-safe acquire barrier
 */
#define smp_acquire_barrier()   acquire_barrier()

/**
 * @brief SMP-safe release barrier
 */
#define smp_release_barrier()   release_barrier()

#else /* !CONFIG_SMP */

/** On UP systems, only compiler barriers are needed */
#define smp_memory_barrier()    compiler_barrier()
#define smp_read_barrier()      compiler_barrier()
#define smp_write_barrier()     compiler_barrier()
#define smp_acquire_barrier()   compiler_barrier()
#define smp_release_barrier()   compiler_barrier()

#endif /* CONFIG_SMP */

/* ========================================================================
 * MEMORY BARRIER DEBUGGING AND VERIFICATION
 * ======================================================================== */

#ifdef CONFIG_DEBUG_MEMORY_BARRIERS

/** Debug counters for memory barriers */
extern uint64_t barrier_count_full;
extern uint64_t barrier_count_read;
extern uint64_t barrier_count_write;
extern uint64_t barrier_count_acquire;
extern uint64_t barrier_count_release;

/**
 * @brief Get memory barrier statistics
 * 
 * @param full_count Pointer to store full barrier count
 * @param read_count Pointer to store read barrier count
 * @param write_count Pointer to store write barrier count
 * @param acquire_count Pointer to store acquire barrier count
 * @param release_count Pointer to store release barrier count
 */
void get_barrier_stats(uint64_t *full_count, uint64_t *read_count,
                      uint64_t *write_count, uint64_t *acquire_count,
                      uint64_t *release_count);

/**
 * @brief Reset memory barrier statistics
 */
void reset_barrier_stats(void);

/**
 * @brief Print memory barrier debug information
 */
void print_barrier_debug(void);

/** Debug versions of barriers that include counting */
#define DEBUG_MEMORY_BARRIER() do { \
    __atomic_fetch_add(&barrier_count_full, 1, __ATOMIC_RELAXED); \
    memory_barrier(); \
} while(0)

#define DEBUG_READ_BARRIER() do { \
    __atomic_fetch_add(&barrier_count_read, 1, __ATOMIC_RELAXED); \
    read_barrier(); \
} while(0)

#define DEBUG_WRITE_BARRIER() do { \
    __atomic_fetch_add(&barrier_count_write, 1, __ATOMIC_RELAXED); \
    write_barrier(); \
} while(0)

#define DEBUG_ACQUIRE_BARRIER() do { \
    __atomic_fetch_add(&barrier_count_acquire, 1, __ATOMIC_RELAXED); \
    acquire_barrier(); \
} while(0)

#define DEBUG_RELEASE_BARRIER() do { \
    __atomic_fetch_add(&barrier_count_release, 1, __ATOMIC_RELAXED); \
    release_barrier(); \
} while(0)

#else /* !CONFIG_DEBUG_MEMORY_BARRIERS */

/** Release versions map directly to the barrier functions */
#define DEBUG_MEMORY_BARRIER()  memory_barrier()
#define DEBUG_READ_BARRIER()    read_barrier()
#define DEBUG_WRITE_BARRIER()   write_barrier()
#define DEBUG_ACQUIRE_BARRIER() acquire_barrier()
#define DEBUG_RELEASE_BARRIER() release_barrier()

#endif /* CONFIG_DEBUG_MEMORY_BARRIERS */

/* ========================================================================
 * CONVENIENCE MACROS
 * ======================================================================== */

/** Memory barrier aliases for common use cases */
#define mb()        memory_barrier()       /**< Full memory barrier */
#define rmb()       read_barrier()         /**< Read memory barrier */
#define wmb()       write_barrier()        /**< Write memory barrier */
#define smp_mb()    smp_memory_barrier()   /**< SMP memory barrier */
#define smp_rmb()   smp_read_barrier()     /**< SMP read barrier */
#define smp_wmb()   smp_write_barrier()    /**< SMP write barrier */

/** Barrier before/after critical sections */
#define barrier_before_critical()  acquire_barrier()
#define barrier_after_critical()   release_barrier()

/** Memory ordering for specific scenarios */
#define load_acquire_barrier()      acquire_barrier()
#define store_release_barrier()     release_barrier()

/* ========================================================================
 * MEMORY BARRIER UTILITIES
 * ======================================================================== */

/**
 * @brief Check if memory barriers are supported on current architecture
 * 
 * @return true if hardware memory barriers are supported, false otherwise
 */
static ALWAYS_INLINE bool are_memory_barriers_supported(void) {
    return ARCH_BARRIER_SUPPORTED;
}

/**
 * @brief Get the strength of memory ordering for current architecture
 * 
 * @return 0 for weak ordering, 1 for strong ordering
 */
static ALWAYS_INLINE int get_memory_ordering_strength(void) {
#if defined(ARCH_X86_64) || defined(ARCH_X86_32)
    return 1;  /* x86 has strong memory ordering */
#else
    return 0;  /* Most other architectures have weak ordering */
#endif
}

/**
 * @brief Execute a memory barrier appropriate for the current context
 * 
 * This function chooses the most appropriate barrier based on the
 * current execution context and architecture.
 */
static ALWAYS_INLINE void context_appropriate_barrier(void) {
#ifdef CONFIG_SMP
    smp_memory_barrier();
#else
    compiler_barrier();
#endif
}

/* ========================================================================
 * LEGACY COMPATIBILITY
 * ======================================================================== */

/** Legacy barrier names for compatibility */
#define MEMORY_BARRIER      memory_barrier
#define READ_BARRIER        read_barrier
#define WRITE_BARRIER       write_barrier
#define COMPILER_FENCE      compiler_barrier

/** Legacy SMP barrier names */
#define SMP_MEMORY_BARRIER  smp_memory_barrier
#define SMP_READ_BARRIER    smp_read_barrier
#define SMP_WRITE_BARRIER   smp_write_barrier

/* ========================================================================
 * COMPILER AND PLATFORM FEATURE DETECTION
 * ======================================================================== */

/** Feature detection macros */
#define HAS_MEMORY_BARRIERS     ARCH_BARRIER_SUPPORTED
#define HAS_ACQUIRE_RELEASE     ARCH_BARRIER_SUPPORTED
#define HAS_CACHE_PREFETCH      1
#define HAS_COMPILER_BARRIERS   1

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_MEMORY_BARRIERS_H */

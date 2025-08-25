/**
 * @file slab.h
 * @brief Slab Allocator Interface
 * 
 * This header defines the interface for the LeaxOS kernel's slab allocator,
 * which provides functions for allocating and managing memory slabs. Slab
 * allocation is a memory management mechanism that allows for efficient
 * allocation and deallocation of memory blocks of fixed sizes.
 * 
 * The slab allocator reduces fragmentation and improves performance by:
 * - Pre-allocating objects of common sizes
 * - Maintaining object pools for fast allocation/deallocation
 * - Reducing internal fragmentation
 * - Supporting constructor/destructor callbacks
 * - Providing cache-friendly memory layout
 *  
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_SLAB_H
#define LEAX_KERNEL_MM_SLAB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"
#include "mm_common.h"

/* ========================================================================
 * CONSTANTS AND CONFIGURATION
 * ======================================================================== */

/** Slab configuration limits */
#define SLAB_MIN_SIZE               8U              /**< Minimum object size */
#define SLAB_MAX_SIZE               (1024U * 1024U) /**< Maximum object size (1MB) */
#define SLAB_MIN_ALIGN              sizeof(void*)   /**< Minimum alignment */
#define SLAB_MAX_ALIGN              4096U           /**< Maximum alignment */
#define SLAB_MAX_CACHES             256U            /**< Maximum number of caches */
#define SLAB_NAME_MAX               32U             /**< Maximum cache name length */

/** Default slab sizes (common allocation sizes) */
#define SLAB_SIZES_COUNT            13U             /**< Number of default sizes */
extern const size_t slab_default_sizes[SLAB_SIZES_COUNT];

/** Slab cache flags */
typedef uint32_t slab_flags_t;
#define SLAB_FLAG_NONE              0x00U           /**< No special flags */
#define SLAB_FLAG_ZERO              0x01U           /**< Zero-initialize objects */
#define SLAB_FLAG_DMA               0x02U           /**< DMA-capable memory */
#define SLAB_FLAG_ATOMIC            0x04U           /**< Atomic allocation only */
#define SLAB_FLAG_NOFAIL            0x08U           /**< Must not fail */
#define SLAB_FLAG_RECLAIMABLE       0x10U           /**< Memory can be reclaimed */
#define SLAB_FLAG_POISON            0x20U           /**< Poison objects on free */
#define SLAB_FLAG_RED_ZONE          0x40U           /**< Add red zones for debugging */
#define SLAB_FLAG_TRACK_CALLER      0x80U           /**< Track allocation caller */

/** Slab object states */
typedef enum {
    SLAB_OBJ_FREE,              /**< Object is free */
    SLAB_OBJ_ALLOCATED,         /**< Object is allocated */
    SLAB_OBJ_POISONED,          /**< Object is poisoned */
    SLAB_OBJ_CORRUPTED          /**< Object corruption detected */
} slab_obj_state_t;

/** Memory patterns for debugging */
#define SLAB_POISON_FREE            0xDEADBEEFU     /**< Pattern for freed objects */
#define SLAB_POISON_ALLOC           0xABCDEF00U     /**< Pattern for allocated objects */
#define SLAB_RED_ZONE_PATTERN       0x5A5A5A5AU     /**< Red zone pattern */

/* ========================================================================
 * FORWARD DECLARATIONS AND BASIC TYPES
 * ======================================================================== */

/* Forward declarations */
typedef struct slab_cache slab_cache_t;
typedef struct slab slab_t;
typedef struct slab_obj slab_obj_t;

/** Constructor callback function type */
typedef void (*slab_ctor_t)(void *obj, slab_cache_t *cache, slab_flags_t flags);

/** Destructor callback function type */
typedef void (*slab_dtor_t)(void *obj, slab_cache_t *cache, slab_flags_t flags);

/** Slab object structure (for debugging and tracking) */
struct slab_obj {
    uint32_t magic;             /**< Magic number for validation */
    slab_obj_state_t state;     /**< Current object state */
    size_t size;                /**< Object size */
    void *caller;               /**< Allocation caller (if tracking enabled) */
    uint64_t alloc_time;        /**< Allocation timestamp */
    struct slab_obj *next;      /**< Next object in free list */
};

/** Individual slab structure */
struct slab {
    void *start_addr;           /**< Start address of slab */
    void *free_list;            /**< Free objects list */
    uint32_t total_objs;        /**< Total objects in slab */
    uint32_t free_objs;         /**< Number of free objects */
    uint32_t active_objs;       /**< Number of active objects */
    slab_cache_t *cache;        /**< Parent cache */
    struct slab *next;          /**< Next slab in cache */
    struct slab *prev;          /**< Previous slab in cache */
    uint32_t magic;             /**< Magic number for validation */
};

/** Slab cache statistics */
typedef struct slab_stats {
    /* Object statistics */
    uint64_t total_objs;        /**< Total objects allocated */
    uint64_t active_objs;       /**< Currently allocated objects */
    uint64_t free_objs;         /**< Currently free objects */
    
    /* Slab statistics */
    uint32_t total_slabs;       /**< Total slabs in cache */
    uint32_t active_slabs;      /**< Slabs with allocated objects */
    uint32_t free_slabs;        /**< Completely free slabs */
    uint32_t partial_slabs;     /**< Partially allocated slabs */
    
    /* Memory usage */
    size_t memory_used;         /**< Total memory used */
    size_t memory_wasted;       /**< Wasted memory (fragmentation) */
    size_t memory_overhead;     /**< Metadata overhead */
    
    /* Performance counters */
    uint64_t alloc_count;       /**< Total allocations */
    uint64_t free_count;        /**< Total frees */
    uint64_t alloc_miss;        /**< Cache misses on allocation */
    uint64_t free_miss;         /**< Cache misses on free */
    uint64_t grow_count;        /**< Number of cache grows */
    uint64_t shrink_count;      /**< Number of cache shrinks */
    
    /* Error counters */
    uint64_t alloc_fail;        /**< Failed allocations */
    uint64_t corruption_count;  /**< Detected corruptions */
    uint64_t double_free;       /**< Double free attempts */
} slab_stats_t;

/** Slab cache structure */
struct slab_cache {
    char name[SLAB_NAME_MAX];   /**< Cache name */
    size_t obj_size;            /**< Object size */
    size_t align;               /**< Object alignment */
    size_t slab_size;           /**< Size of each slab */
    uint32_t objs_per_slab;     /**< Objects per slab */
    slab_flags_t flags;         /**< Cache flags */
    
    /* Callback functions */
    slab_ctor_t constructor;    /**< Object constructor */
    slab_dtor_t destructor;     /**< Object destructor */
    
    /* Slab lists */
    slab_t *free_slabs;         /**< List of free slabs */
    slab_t *partial_slabs;      /**< List of partial slabs */
    slab_t *full_slabs;         /**< List of full slabs */
    
    /* Statistics and management */
    slab_stats_t stats;         /**< Cache statistics */
    uint32_t magic;             /**< Magic number for validation */
    bool initialized;           /**< Initialization flag */
    
    /* Threading and synchronization */
    void *lock;                 /**< Cache lock (opaque pointer) */
    
    /* Cache management */
    struct slab_cache *next;    /**< Next cache in global list */
    struct slab_cache *prev;    /**< Previous cache in global list */
    uint32_t ref_count;         /**< Reference counter */
};

/** Global slab allocator statistics */
typedef struct slab_global_stats {
    uint32_t total_caches;      /**< Total number of caches */
    uint32_t active_caches;     /**< Active caches */
    size_t total_memory;        /**< Total memory managed */
    size_t used_memory;         /**< Memory currently in use */
    size_t free_memory;         /**< Free memory available */
    size_t overhead_memory;     /**< Metadata overhead */
    uint64_t total_allocs;      /**< Total allocations across all caches */
    uint64_t total_frees;       /**< Total frees across all caches */
    uint64_t cache_hits;        /**< Cache hit count */
    uint64_t cache_misses;      /**< Cache miss count */
    uint32_t fragmentation;     /**< Fragmentation percentage */
} slab_global_stats_t;

/** Slab allocator configuration */
typedef struct slab_config {
    size_t initial_cache_count; /**< Initial number of caches */
    size_t max_slab_size;       /**< Maximum slab size */
    size_t min_objects_per_slab;/**< Minimum objects per slab */
    bool enable_debugging;      /**< Enable debug features */
    bool enable_statistics;     /**< Enable detailed statistics */
    bool enable_poisoning;      /**< Enable object poisoning */
    bool enable_red_zones;      /**< Enable red zone detection */
    size_t red_zone_size;       /**< Red zone size */
} slab_config_t;

/* ========================================================================
 * CORE SLAB ALLOCATOR FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize the slab allocator subsystem
 * @param config Configuration parameters (NULL for defaults)
 * @return 0 on success, negative error code on failure
 */
int slab_init(const slab_config_t *config);

/**
 * @brief Shutdown the slab allocator subsystem
 */
void slab_shutdown(void);

/**
 * @brief Create a new slab cache
 * @param name Cache name (for debugging)
 * @param size Object size
 * @param align Object alignment (0 for default)
 * @param flags Cache flags
 * @param ctor Constructor callback (optional)
 * @param dtor Destructor callback (optional)
 * @return Pointer to cache, or NULL on failure
 */
slab_cache_t *slab_create_cache(const char *name, size_t size, size_t align,
                                slab_flags_t flags, slab_ctor_t ctor, slab_dtor_t dtor);

/**
 * @brief Destroy a slab cache
 * @param cache Cache to destroy
 * @return 0 on success, negative error code on failure
 */
int slab_destroy_cache(slab_cache_t *cache);

/**
 * @brief Allocate an object from a cache
 * @param cache Source cache
 * @param flags Allocation flags
 * @return Pointer to allocated object, or NULL on failure
 */
void *slab_alloc(slab_cache_t *cache, slab_flags_t flags);

/**
 * @brief Free an object back to its cache
 * @param obj Object to free
 */
void slab_free(void *obj);

/**
 * @brief Allocate an object from cache with caller tracking
 * @param cache Source cache
 * @param flags Allocation flags
 * @param caller Caller address for tracking
 * @return Pointer to allocated object, or NULL on failure
 */
void *slab_alloc_track(slab_cache_t *cache, slab_flags_t flags, void *caller);

/**
 * @brief Get the cache that owns an object
 * @param obj Object pointer
 * @return Pointer to owning cache, or NULL if invalid
 */
slab_cache_t *slab_get_cache(const void *obj);

/**
 * @brief Get object size for a given object
 * @param obj Object pointer
 * @return Object size, or 0 if invalid
 */
size_t slab_get_obj_size(const void *obj);

/* ========================================================================
 * GENERAL-PURPOSE ALLOCATORS (KMALLOC-STYLE)
 * ======================================================================== */

/**
 * @brief General purpose allocation (uses appropriate slab cache)
 * @param size Size to allocate
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
void *slab_kmalloc(size_t size, slab_flags_t flags);

/**
 * @brief General purpose zeroed allocation
 * @param size Size to allocate
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
void *slab_kzalloc(size_t size, slab_flags_t flags);

/**
 * @brief General purpose array allocation
 * @param nmemb Number of elements
 * @param size Size of each element
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
void *slab_kcalloc(size_t nmemb, size_t size, slab_flags_t flags);

/**
 * @brief Free memory allocated with slab_kmalloc family
 * @param ptr Pointer to free
 */
void slab_kfree(void *ptr);

/**
 * @brief Get size of allocated memory block
 * @param ptr Pointer to memory block
 * @return Size of block, or 0 if invalid
 */
size_t slab_ksize(const void *ptr);

/* ========================================================================
 * CACHE MANAGEMENT FUNCTIONS
 * ======================================================================== */

/**
 * @brief Find cache by name
 * @param name Cache name
 * @return Pointer to cache, or NULL if not found
 */
slab_cache_t *slab_find_cache(const char *name);

/**
 * @brief Get cache for specific size
 * @param size Object size
 * @return Pointer to appropriate cache, or NULL if too large
 */
slab_cache_t *slab_get_cache_for_size(size_t size);

/**
 * @brief Shrink cache (free empty slabs)
 * @param cache Cache to shrink
 * @return Number of slabs freed
 */
uint32_t slab_shrink_cache(slab_cache_t *cache);

/**
 * @brief Grow cache (add more slabs)
 * @param cache Cache to grow
 * @param count Number of slabs to add
 * @return Number of slabs actually added
 */
uint32_t slab_grow_cache(slab_cache_t *cache, uint32_t count);

/**
 * @brief Rebalance cache (optimize slab distribution)
 * @param cache Cache to rebalance
 * @return 0 on success, negative error code on failure
 */
int slab_rebalance_cache(slab_cache_t *cache);

/**
 * @brief Set cache allocation limit
 * @param cache Target cache
 * @param max_slabs Maximum number of slabs
 * @return 0 on success, negative error code on failure
 */
int slab_set_cache_limit(slab_cache_t *cache, uint32_t max_slabs);

/**
 * @brief Get cache allocation limit
 * @param cache Target cache
 * @return Current limit, or 0 if unlimited
 */
uint32_t slab_get_cache_limit(const slab_cache_t *cache);

/* ========================================================================
 * STATISTICS AND MONITORING
 * ======================================================================== */

/**
 * @brief Get cache statistics
 * @param cache Target cache
 * @param stats Pointer to statistics structure
 */
void slab_get_cache_stats(const slab_cache_t *cache, slab_stats_t *stats);

/**
 * @brief Get global allocator statistics
 * @param stats Pointer to global statistics structure
 */
void slab_get_global_stats(slab_global_stats_t *stats);

/**
 * @brief Get cache efficiency (allocation success rate)
 * @param cache Target cache
 * @return Efficiency percentage (0-100)
 */
unsigned int slab_get_cache_efficiency(const slab_cache_t *cache);

/**
 * @brief Get cache fragmentation percentage
 * @param cache Target cache
 * @return Fragmentation percentage (0-100)
 */
unsigned int slab_get_cache_fragmentation(const slab_cache_t *cache);

/**
 * @brief Check if cache is healthy (no corruption)
 * @param cache Target cache
 * @return true if healthy, false if corruption detected
 */
bool slab_check_cache_health(const slab_cache_t *cache);

/**
 * @brief Print cache debug information
 * @param cache Target cache
 */
void slab_print_cache_debug(const slab_cache_t *cache);

/**
 * @brief Print all caches information
 */
void slab_print_all_caches(void);

/**
 * @brief Dump detailed allocator state
 */
void slab_dump_state(void);

/* ========================================================================
 * MEMORY VALIDATION AND DEBUGGING
 * ======================================================================== */

/**
 * @brief Validate object integrity
 * @param obj Object to validate
 * @return true if valid, false if corrupted
 */
bool slab_validate_obj(const void *obj);

/**
 * @brief Validate cache integrity
 * @param cache Cache to validate
 * @return true if valid, false if corrupted
 */
bool slab_validate_cache(const slab_cache_t *cache);

/**
 * @brief Validate all caches
 * @return true if all valid, false if any corruption
 */
bool slab_validate_all(void);

/**
 * @brief Check for memory leaks in cache
 * @param cache Cache to check
 * @return Number of leaked objects
 */
uint32_t slab_check_leaks(const slab_cache_t *cache);

/**
 * @brief Check for double-free attempts
 * @param obj Object to check
 * @return true if double-free detected, false otherwise
 */
bool slab_check_double_free(const void *obj);

/**
 * @brief Poison object memory (for debugging)
 * @param obj Object to poison
 * @param pattern Poison pattern
 */
void slab_poison_obj(void *obj, uint32_t pattern);

/**
 * @brief Check if object is poisoned
 * @param obj Object to check
 * @param pattern Expected poison pattern
 * @return true if properly poisoned, false otherwise
 */
bool slab_check_poison(const void *obj, uint32_t pattern);

/* ========================================================================
 * MEMORY PRESSURE AND RECLAIM
 * ======================================================================== */

/**
 * @brief Reclaim memory from all caches
 * @param target_bytes Target bytes to reclaim
 * @return Bytes actually reclaimed
 */
size_t slab_reclaim_memory(size_t target_bytes);

/**
 * @brief Shrink all caches
 * @return Total number of slabs freed
 */
uint32_t slab_shrink_all_caches(void);

/**
 * @brief Compact allocator (reduce fragmentation)
 * @return Number of slabs coalesced
 */
uint32_t slab_compact(void);

/**
 * @brief Set low memory threshold
 * @param threshold Threshold in bytes
 */
void slab_set_low_threshold(size_t threshold);

/**
 * @brief Get current low memory threshold
 * @return Threshold in bytes
 */
size_t slab_get_low_threshold(void);

/**
 * @brief Check if allocator is in low memory state
 * @return true if low memory, false otherwise
 */
bool slab_is_low_memory(void);

/* ========================================================================
 * UTILITY FUNCTIONS AND MACROS
 * ======================================================================== */

/**
 * @brief Calculate optimal slab size for given object size
 * @param obj_size Object size
 * @param min_objs Minimum objects per slab
 * @return Optimal slab size
 */
size_t slab_calc_optimal_size(size_t obj_size, uint32_t min_objs);

/**
 * @brief Calculate objects per slab
 * @param slab_size Slab size
 * @param obj_size Object size
 * @return Number of objects that fit in slab
 */
uint32_t slab_calc_objs_per_slab(size_t slab_size, size_t obj_size);

/**
 * @brief Round size up to next slab cache size
 * @param size Input size
 * @return Rounded size
 */
size_t slab_round_up_size(size_t size);

/**
 * @brief Check if size is a valid slab cache size
 * @param size Size to check
 * @return true if valid, false otherwise
 */
bool slab_is_valid_size(size_t size);

/**
 * @brief Get alignment for given size
 * @param size Object size
 * @return Appropriate alignment
 */
size_t slab_get_alignment(size_t size);

/* Utility macros */
#define SLAB_ALIGN_UP(x, align)     (((x) + (align) - 1) & ~((align) - 1))
#define SLAB_ALIGN_DOWN(x, align)   ((x) & ~((align) - 1))
#define SLAB_IS_ALIGNED(x, align)   (((x) & ((align) - 1)) == 0)
#define SLAB_OFFSET(base, obj)      ((uintptr_t)(obj) - (uintptr_t)(base))

/* Magic numbers for validation */
#define SLAB_CACHE_MAGIC            0x534C4143U     /**< "SLAC" */
#define SLAB_MAGIC                  0x534C4142U     /**< "SLAB" */
#define SLAB_OBJ_MAGIC              0x534C4F42U     /**< "SLOB" */

/* Error codes */
#define SLAB_SUCCESS                0               /**< Success */
#define SLAB_ERR_NOMEM             -1               /**< Out of memory */
#define SLAB_ERR_INVALID           -2               /**< Invalid parameter */
#define SLAB_ERR_BUSY              -3               /**< Cache busy */
#define SLAB_ERR_NOTFOUND          -4               /**< Cache not found */
#define SLAB_ERR_EXISTS            -5               /**< Cache already exists */
#define SLAB_ERR_CORRUPT           -6               /**< Corruption detected */
#define SLAB_ERR_LIMIT             -7               /**< Limit exceeded */
#define SLAB_ERR_INIT              -8               /**< Initialization failed */
#define SLAB_ERR_DOUBLE_FREE       -9               /**< Double free detected */

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_SLAB_H */

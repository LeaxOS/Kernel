/**
 * @file early_malloc.c
 * @brief Early memory allocation functions
 * 
 * This file implements various early memory allocators for the LeaxOS kernel.
 * These allocators are designed to work during the boot process before the
 * full memory management subsystem is initialized. The allocators include:
 * 
 * - Bootstrap allocator: Simple linear allocator for initial allocations
 * - Early slab allocator: Fixed-size object allocator for small objects
 * - Early buddy allocator: Power-of-2 page-based allocator
 * - Early region allocator: Large contiguous memory region allocator
 * - Early pool allocator: Pre-allocated memory pools for specific sizes
 * - Early bitmap allocator: Bitmap-based page allocator for fine control
 *
 * @author LeaxOS team
 * @date 2025
 * @version 1.0
 */

#include "mm.h"
#include "page_alloc.h"
#include "slab.h"
#include "vmalloc.h"
#include "mmap.h"
#include "memory_barriers.h"
#include "stdint.h"
#include "stdbool.h"
#include "stddef.h"
#include "string.h"
#include "stdio.h"


/* ========================================================================
 * CONSTANTS AND CONFIGURATION
 * ======================================================================== */

/* Early allocator configuration */
#define EARLY_BOOTSTRAP_SIZE    (256 * 1024)   /* 256KB bootstrap pool */
#define EARLY_SLAB_POOLS        8              /* Number of slab pools */
#define EARLY_BUDDY_MAX_ORDER   10             /* Max buddy allocation order */
#define EARLY_REGION_MAX_COUNT  16             /* Max tracked regions */
#define EARLY_POOL_COUNT        4              /* Number of memory pools */
#define EARLY_BITMAP_SIZE       (64 * 1024)    /* 64KB bitmap area */

/* Allocation alignment */
#define EARLY_MIN_ALIGN         8              /* Minimum alignment */
#define EARLY_PAGE_ALIGN        PAGE_SIZE      /* Page alignment */

/* Magic numbers for corruption detection */
#define EARLY_MAGIC_ALLOC       0xDEADBEEF
#define EARLY_MAGIC_FREE        0xFEEDFACE
#define EARLY_MAGIC_GUARD       0xCAFEBABE

/* Allocation flags for early allocators */
#define EARLY_FLAG_ZERO         0x01    /* Zero-initialize memory */
#define EARLY_FLAG_ATOMIC       0x02    /* Atomic allocation */
#define EARLY_FLAG_URGENT       0x04    /* High priority */
#define EARLY_FLAG_GUARD        0x08    /* Add guard pages/bytes */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/* Bootstrap allocator header */
struct early_bootstrap_header {
    uint32_t magic;          /* Magic number for validation */
    size_t size;             /* Size of allocation */
    uint32_t flags;          /* Allocation flags */
    struct early_bootstrap_header *next;  /* Next allocation */
};

/* Early slab cache definition */
struct early_slab_cache {
    size_t object_size;      /* Size of objects in this cache */
    size_t objects_per_slab; /* Number of objects per slab */
    void *free_list;         /* Free object list */
    void *slab_list;         /* List of slabs */
    size_t total_objects;    /* Total objects created */
    size_t free_objects;     /* Free objects available */
    bool active;             /* Cache is active */
};

/* Early buddy allocator block */
struct early_buddy_block {
    struct early_buddy_block *next;  /* Next block in free list */
    unsigned int order;              /* Block order (log2 size) */
    bool allocated;                  /* Allocation status */
};

/* Early region descriptor */
struct early_region {
    phys_addr_t start;       /* Region start address */
    size_t size;             /* Region size */
    uint32_t flags;          /* Region flags */
    bool in_use;             /* Region in use */
    const char *name;        /* Region name for debugging */
};

/* Early memory pool */
struct early_pool {
    void *base;              /* Pool base address */
    size_t total_size;       /* Total pool size */
    size_t used_size;        /* Used pool size */
    size_t object_size;      /* Fixed object size */
    void *free_list;         /* Free object list */
    size_t free_count;       /* Free object count */
    bool active;             /* Pool is active */
};

/* Early bitmap allocator */
struct early_bitmap {
    uint8_t *bitmap;         /* Allocation bitmap */
    size_t total_bits;       /* Total bits in bitmap */
    size_t free_bits;        /* Free bits available */
    phys_addr_t base_addr;   /* Base physical address */
    size_t granularity;      /* Allocation granularity */
    bool active;             /* Allocator is active */
};

/* Allocation statistics */
struct early_alloc_stats {
    uint64_t bootstrap_allocs;
    uint64_t bootstrap_frees;
    uint64_t slab_allocs;
    uint64_t slab_frees;
    uint64_t buddy_allocs;
    uint64_t buddy_frees;
    uint64_t region_allocs;
    uint64_t region_frees;
    uint64_t pool_allocs;
    uint64_t pool_frees;
    uint64_t bitmap_allocs;
    uint64_t bitmap_frees;
    uint64_t total_allocated;
    uint64_t total_freed;
    uint64_t peak_usage;
    uint64_t current_usage;
};

/* ========================================================================
 * GLOBAL VARIABLES AND STATE
 * ======================================================================== */

/* Early memory management state */
static bool early_mm_initialized = false;
static bool early_mm_active = false;

/* Bootstrap allocator */
static uint8_t bootstrap_pool[EARLY_BOOTSTRAP_SIZE] __attribute__((aligned(64)));
static size_t bootstrap_offset = 0;
static struct early_bootstrap_header *bootstrap_alloc_list = NULL;

/* Early slab caches */
static struct early_slab_cache slab_caches[EARLY_SLAB_POOLS];
static const size_t slab_sizes[] = { 8, 16, 32, 64, 128, 256, 512, 1024 };

/* Early buddy allocator */
static struct early_buddy_block *buddy_free_lists[EARLY_BUDDY_MAX_ORDER + 1];
static uint8_t buddy_memory[1024 * 1024] __attribute__((aligned(PAGE_SIZE))); /* 1MB buddy pool */
static bool buddy_initialized = false;

/* Early region allocator */
static struct early_region early_regions[EARLY_REGION_MAX_COUNT];
static size_t region_count = 0;

/* Early memory pools */
static struct early_pool memory_pools[EARLY_POOL_COUNT];
static uint8_t pool_memory[4][16384] __attribute__((aligned(64))); /* 4x16KB pools */

/* Early bitmap allocator */
static struct early_bitmap bitmap_allocator;
static uint8_t bitmap_data[EARLY_BITMAP_SIZE / 8]; /* Bitmap storage */
static uint8_t bitmap_memory[EARLY_BITMAP_SIZE] __attribute__((aligned(PAGE_SIZE)));

/* Statistics */
static struct early_alloc_stats stats = {0};

/* Synchronization for SMP systems */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
static mm_spinlock_t early_mm_lock = MM_SPINLOCK_INIT("unknown");
#define EARLY_LOCK() mm_spin_lock(&early_mm_lock)
#define EARLY_UNLOCK() mm_spin_unlock(&early_mm_lock)
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
 * @param align Alignment requirement
 * @return Aligned size
 */
static inline size_t align_size(size_t size, size_t align) {
    return (size + align - 1) & ~(align - 1);
}

/**
 * @brief Check if a pointer is valid
 * @param ptr Pointer to check
 * @return true if valid, false otherwise
 */
static bool is_valid_ptr(const void *ptr) {
    if (!ptr) return false;
    
    uintptr_t addr = (uintptr_t)ptr;
    
    /* Check if within our managed memory areas */
    if (addr >= (uintptr_t)bootstrap_pool && 
        addr < (uintptr_t)bootstrap_pool + EARLY_BOOTSTRAP_SIZE) {
        return true;
    }
    
    if (addr >= (uintptr_t)buddy_memory && 
        addr < (uintptr_t)buddy_memory + sizeof(buddy_memory)) {
        return true;
    }
    
    if (addr >= (uintptr_t)bitmap_memory && 
        addr < (uintptr_t)bitmap_memory + EARLY_BITMAP_SIZE) {
        return true;
    }
    
    /* Check memory pools */
    for (int i = 0; i < EARLY_POOL_COUNT; i++) {
        if (addr >= (uintptr_t)pool_memory[i] && 
            addr < (uintptr_t)pool_memory[i] + sizeof(pool_memory[i])) {
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Find the appropriate slab cache for a size
 * @param size Requested size
 * @return Cache index, or -1 if too large
 */
static int find_slab_cache(size_t size) {
    for (int i = 0; i < EARLY_SLAB_POOLS; i++) {
        if (size <= slab_sizes[i]) {
            return i;
        }
    }
    return -1; /* Too large for slab */
}

/**
 * @brief Calculate buddy order for size
 * @param size Size in bytes
 * @return Buddy order
 */
static unsigned int size_to_buddy_order(size_t size) {
    size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    unsigned int order = 0;
    
    while ((1U << order) < pages) {
        order++;
    }
    
    return order;
}

/**
 * @brief Set bits in bitmap
 * @param bitmap Bitmap array
 * @param start_bit Starting bit position
 * @param count Number of bits to set
 */
static void bitmap_set_bits(uint8_t *bitmap, size_t start_bit, size_t count) {
    for (size_t i = 0; i < count; i++) {
        size_t bit_idx = start_bit + i;
        size_t byte_idx = bit_idx / 8;
        size_t bit_offset = bit_idx % 8;
        bitmap[byte_idx] |= (1 << bit_offset);
    }
}

/**
 * @brief Clear bits in bitmap
 * @param bitmap Bitmap array
 * @param start_bit Starting bit position
 * @param count Number of bits to clear
 */
static void bitmap_clear_bits(uint8_t *bitmap, size_t start_bit, size_t count) {
    for (size_t i = 0; i < count; i++) {
        size_t bit_idx = start_bit + i;
        size_t byte_idx = bit_idx / 8;
        size_t bit_offset = bit_idx % 8;
        bitmap[byte_idx] &= ~(1 << bit_offset);
    }
}

/**
 * @brief Find free bits in bitmap
 * @param bitmap Bitmap array
 * @param total_bits Total bits in bitmap
 * @param count Number of consecutive bits needed
 * @return Starting bit position, or SIZE_MAX if not found
 */
static size_t bitmap_find_free_bits(const uint8_t *bitmap, size_t total_bits, size_t count) {
    size_t consecutive = 0;
    size_t start_bit = 0;
    
    for (size_t i = 0; i < total_bits; i++) {
        size_t byte_idx = i / 8;
        size_t bit_offset = i % 8;
        
        if (!(bitmap[byte_idx] & (1 << bit_offset))) {
            if (consecutive == 0) {
                start_bit = i;
            }
            consecutive++;
            
            if (consecutive >= count) {
                return start_bit;
            }
        } else {
            consecutive = 0;
        }
    }
    
    return SIZE_MAX; /* Not found */
}

/* ========================================================================
 * BOOTSTRAP ALLOCATOR IMPLEMENTATION
 * ======================================================================== */

/**
 * @brief Initialize bootstrap allocator
 * @return 0 on success, negative error code on failure
 */
static int bootstrap_init(void) {
    if (bootstrap_offset != 0) {
        printk(KERN_WARNING "Bootstrap allocator already initialized\n");
        return -1;
    }
    
    bootstrap_offset = 0;
    bootstrap_alloc_list = NULL;
    
    /* Clear the bootstrap pool */
    memset(bootstrap_pool, 0, EARLY_BOOTSTRAP_SIZE);
    
    printk(KERN_INFO "Bootstrap allocator initialized (%d KB)\n", 
           EARLY_BOOTSTRAP_SIZE / 1024);
    return 0;
}

/**
 * @brief Bootstrap memory allocation
 * @param size Size in bytes
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
static void *bootstrap_alloc(size_t size, uint32_t flags) {
    if (size == 0) {
        return NULL;
    }
    
    /* Align size for header and alignment requirements */
    size_t aligned_size = align_size(size, EARLY_MIN_ALIGN);
    size_t total_size = sizeof(struct early_bootstrap_header) + aligned_size;
    
    /* Add guard bytes if requested */
    if (flags & EARLY_FLAG_GUARD) {
        total_size += 2 * sizeof(uint32_t); /* Before and after guards */
    }
    
    EARLY_LOCK();
    
    /* Check if we have enough space */
    if (bootstrap_offset + total_size > EARLY_BOOTSTRAP_SIZE) {
        EARLY_UNLOCK();
        printk(KERN_ERR "Bootstrap pool exhausted! Need %zu bytes, have %zu\n",
               total_size, EARLY_BOOTSTRAP_SIZE - bootstrap_offset);
        return NULL;
    }
    
    /* Get pointer to allocation */
    struct early_bootstrap_header *header = 
        (struct early_bootstrap_header *)(&bootstrap_pool[bootstrap_offset]);
    
    /* Initialize header */
    header->magic = EARLY_MAGIC_ALLOC;
    header->size = size;
    header->flags = flags;
    header->next = bootstrap_alloc_list;
    bootstrap_alloc_list = header;
    
    /* Move past header */
    bootstrap_offset += sizeof(struct early_bootstrap_header);
    
    /* Add front guard if requested */
    if (flags & EARLY_FLAG_GUARD) {
        *(uint32_t *)(&bootstrap_pool[bootstrap_offset]) = EARLY_MAGIC_GUARD;
        bootstrap_offset += sizeof(uint32_t);
    }
    
    /* Get user pointer */
    void *ptr = &bootstrap_pool[bootstrap_offset];
    bootstrap_offset += aligned_size;
    
    /* Add rear guard if requested */
    if (flags & EARLY_FLAG_GUARD) {
        *(uint32_t *)(&bootstrap_pool[bootstrap_offset]) = EARLY_MAGIC_GUARD;
        bootstrap_offset += sizeof(uint32_t);
    }
    
    EARLY_UNLOCK();
    
    /* Zero-initialize if requested */
    if (flags & EARLY_FLAG_ZERO) {
        memset(ptr, 0, size);
    }
    
    /* Update statistics */
    stats.bootstrap_allocs++;
    stats.total_allocated += size;
    stats.current_usage += size;
    if (stats.current_usage > stats.peak_usage) {
        stats.peak_usage = stats.current_usage;
    }
    
    return ptr;
}

/**
 * @brief Bootstrap memory deallocation (no-op for linear allocator)
 * @param ptr Pointer to memory to free
 */
static void bootstrap_free(void *ptr) {
    if (!ptr) {
        return;
    }
    
    /* Bootstrap allocator doesn't support individual frees */
    /* This is just for statistics and validation */
    
    /* Find the allocation in our list for validation */
    EARLY_LOCK();
    struct early_bootstrap_header *current = bootstrap_alloc_list;
    while (current) {
        char *data_ptr = (char *)current + sizeof(struct early_bootstrap_header);
        if (current->flags & EARLY_FLAG_GUARD) {
            data_ptr += sizeof(uint32_t);
        }
        
        if (data_ptr == ptr) {
            /* Validate magic numbers */
            if (current->magic != EARLY_MAGIC_ALLOC) {
                printk(KERN_ERR "Bootstrap free: corrupted header for %p\n", ptr);
            }
            
            /* Validate guards if present */
            if (current->flags & EARLY_FLAG_GUARD) {
                uint32_t *front_guard = (uint32_t *)(data_ptr - sizeof(uint32_t));
                uint32_t *rear_guard = (uint32_t *)(data_ptr + 
                    align_size(current->size, EARLY_MIN_ALIGN));
                
                if (*front_guard != EARLY_MAGIC_GUARD) {
                    printk(KERN_ERR "Bootstrap free: front guard corrupted for %p\n", ptr);
                }
                if (*rear_guard != EARLY_MAGIC_GUARD) {
                    printk(KERN_ERR "Bootstrap free: rear guard corrupted for %p\n", ptr);
                }
            }
            
            /* Mark as freed */
            current->magic = EARLY_MAGIC_FREE;
            stats.bootstrap_frees++;
            stats.total_freed += current->size;
            stats.current_usage -= current->size;
            break;
        }
        current = current->next;
    }
    EARLY_UNLOCK();
}

/* ========================================================================
 * EARLY SLAB ALLOCATOR IMPLEMENTATION
 * ======================================================================== */

/**
 * @brief Initialize early slab allocator
 * @return 0 on success, negative error code on failure
 */
static int early_slab_init(void) {
    /* Initialize slab caches */
    for (int i = 0; i < EARLY_SLAB_POOLS; i++) {
        slab_caches[i].object_size = slab_sizes[i];
        slab_caches[i].objects_per_slab = PAGE_SIZE / slab_sizes[i];
        slab_caches[i].free_list = NULL;
        slab_caches[i].slab_list = NULL;
        slab_caches[i].total_objects = 0;
        slab_caches[i].free_objects = 0;
        slab_caches[i].active = true;
    }
    
    printk(KERN_INFO "Early slab allocator initialized (%d caches)\n", EARLY_SLAB_POOLS);
    return 0;
}

/**
 * @brief Allocate object from early slab cache
 * @param size Requested size
 * @param flags Allocation flags
 * @return Pointer to allocated object, or NULL on failure
 */
static void *early_slab_alloc(size_t size, uint32_t flags) {
    int cache_idx = find_slab_cache(size);
    if (cache_idx < 0) {
        return NULL; /* Too large for slab */
    }
    
    struct early_slab_cache *cache = &slab_caches[cache_idx];
    
    EARLY_LOCK();
    
    /* Check if we have free objects */
    if (!cache->free_list) {
        /* Need to allocate a new slab from buddy allocator */
        void *slab = early_buddy_alloc_pages(1, flags);
        if (!slab) {
            EARLY_UNLOCK();
            return NULL;
        }
        
        /* Initialize slab with free objects */
        char *obj_ptr = (char *)slab;
        for (size_t i = 0; i < cache->objects_per_slab; i++) {
            *(void **)obj_ptr = cache->free_list;
            cache->free_list = obj_ptr;
            obj_ptr += cache->object_size;
            cache->free_objects++;
            cache->total_objects++;
        }
    }
    
    /* Get object from free list */
    void *obj = cache->free_list;
    cache->free_list = *(void **)obj;
    cache->free_objects--;
    
    EARLY_UNLOCK();
    
    /* Zero-initialize if requested */
    if (flags & EARLY_FLAG_ZERO) {
        memset(obj, 0, cache->object_size);
    }
    
    /* Update statistics */
    stats.slab_allocs++;
    stats.total_allocated += cache->object_size;
    stats.current_usage += cache->object_size;
    if (stats.current_usage > stats.peak_usage) {
        stats.peak_usage = stats.current_usage;
    }
    
    return obj;
}

/**
 * @brief Free object to early slab cache
 * @param ptr Pointer to object to free
 * @param size Original allocation size
 */
static void early_slab_free(void *ptr, size_t size) {
    if (!ptr) {
        return;
    }
    
    int cache_idx = find_slab_cache(size);
    if (cache_idx < 0) {
        return; /* Not a slab object */
    }
    
    struct early_slab_cache *cache = &slab_caches[cache_idx];
    
    EARLY_LOCK();
    
    /* Add object back to free list */
    *(void **)ptr = cache->free_list;
    cache->free_list = ptr;
    cache->free_objects++;
    
    EARLY_UNLOCK();
    
    /* Update statistics */
    stats.slab_frees++;
    stats.total_freed += cache->object_size;
    stats.current_usage -= cache->object_size;
}

/* ========================================================================
 * EARLY BUDDY ALLOCATOR IMPLEMENTATION
 * ======================================================================== */

/**
 * @brief Initialize early buddy allocator
 * @return 0 on success, negative error code on failure
 */
static int early_buddy_init(void) {
    if (buddy_initialized) {
        printk(KERN_WARNING "Buddy allocator already initialized\n");
        return -1;
    }
    
    /* Initialize free lists */
    for (int i = 0; i <= EARLY_BUDDY_MAX_ORDER; i++) {
        buddy_free_lists[i] = NULL;
    }
    
    /* Create initial large block */
    size_t total_pages = sizeof(buddy_memory) / PAGE_SIZE;
    unsigned int max_order = 0;
    while ((1U << (max_order + 1)) <= total_pages) {
        max_order++;
    }
    
    if (max_order > EARLY_BUDDY_MAX_ORDER) {
        max_order = EARLY_BUDDY_MAX_ORDER;
    }
    
    struct early_buddy_block *initial_block = (struct early_buddy_block *)buddy_memory;
    initial_block->next = NULL;
    initial_block->order = max_order;
    initial_block->allocated = false;
    
    buddy_free_lists[max_order] = initial_block;
    buddy_initialized = true;
    
    printk(KERN_INFO "Early buddy allocator initialized (%zu KB, max order %u)\n",
           sizeof(buddy_memory) / 1024, max_order);
    return 0;
}

/**
 * @brief Allocate pages from early buddy allocator
 * @param pages Number of pages to allocate
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
static void *early_buddy_alloc_pages(size_t pages, uint32_t flags) {
    if (!buddy_initialized || pages == 0) {
        return NULL;
    }
    
    unsigned int order = size_to_buddy_order(pages * PAGE_SIZE);
    if (order > EARLY_BUDDY_MAX_ORDER) {
        return NULL; /* Too large */
    }
    
    EARLY_LOCK();
    
    /* Find a suitable block */
    unsigned int alloc_order = order;
    while (alloc_order <= EARLY_BUDDY_MAX_ORDER && !buddy_free_lists[alloc_order]) {
        alloc_order++;
    }
    
    if (alloc_order > EARLY_BUDDY_MAX_ORDER) {
        EARLY_UNLOCK();
        return NULL; /* No suitable block */
    }
    
    /* Remove block from free list */
    struct early_buddy_block *block = buddy_free_lists[alloc_order];
    buddy_free_lists[alloc_order] = block->next;
    
    /* Split block if necessary */
    while (alloc_order > order) {
        alloc_order--;
        
        /* Create buddy block */
        size_t buddy_offset = (1U << alloc_order) * PAGE_SIZE;
        struct early_buddy_block *buddy = 
            (struct early_buddy_block *)((char *)block + buddy_offset);
        
        buddy->next = buddy_free_lists[alloc_order];
        buddy->order = alloc_order;
        buddy->allocated = false;
        
        buddy_free_lists[alloc_order] = buddy;
    }
    
    block->allocated = true;
    block->order = order;
    
    EARLY_UNLOCK();
    
    void *ptr = (void *)block;
    
    /* Zero-initialize if requested */
    if (flags & EARLY_FLAG_ZERO) {
        memset(ptr, 0, (1U << order) * PAGE_SIZE);
    }
    
    /* Update statistics */
    stats.buddy_allocs++;
    size_t alloc_size = (1U << order) * PAGE_SIZE;
    stats.total_allocated += alloc_size;
    stats.current_usage += alloc_size;
    if (stats.current_usage > stats.peak_usage) {
        stats.peak_usage = stats.current_usage;
    }
    
    return ptr;
}

/**
 * @brief Free pages to early buddy allocator
 * @param ptr Pointer to memory to free
 * @param pages Number of pages (used for validation)
 */
static void early_buddy_free_pages(void *ptr, size_t pages) {
    if (!ptr || !buddy_initialized) {
        return;
    }
    
    /* Verify the pointer is within our memory range */
    if (ptr < (void *)buddy_memory || 
        ptr >= (void *)((char *)buddy_memory + sizeof(buddy_memory))) {
        printk(KERN_ERR "Buddy free: invalid pointer %p\n", ptr);
        return;
    }
    
    struct early_buddy_block *block = (struct early_buddy_block *)ptr;
    
    EARLY_LOCK();
    
    if (!block->allocated) {
        printk(KERN_ERR "Buddy free: double free detected for %p\n", ptr);
        EARLY_UNLOCK();
        return;
    }
    
    unsigned int order = block->order;
    block->allocated = false;
    
    /* Try to coalesce with buddy blocks */
    while (order < EARLY_BUDDY_MAX_ORDER) {
        size_t block_size = (1U << order) * PAGE_SIZE;
        uintptr_t block_addr = (uintptr_t)block;
        uintptr_t buddy_addr = block_addr ^ block_size;
        
        /* Check if buddy is within our memory range */
        if (buddy_addr < (uintptr_t)buddy_memory || 
            buddy_addr >= (uintptr_t)buddy_memory + sizeof(buddy_memory)) {
            break;
        }
        
        struct early_buddy_block *buddy = (struct early_buddy_block *)buddy_addr;
        
        /* Check if buddy is free and same order */
        if (buddy->allocated || buddy->order != order) {
            break;
        }
        
        /* Remove buddy from free list */
        struct early_buddy_block **prev = &buddy_free_lists[order];
        while (*prev && *prev != buddy) {
            prev = &(*prev)->next;
        }
        if (*prev) {
            *prev = buddy->next;
        }
        
        /* Coalesce blocks */
        if (buddy_addr < block_addr) {
            block = buddy;
        }
        order++;
        block->order = order;
    }
    
    /* Add block to appropriate free list */
    block->next = buddy_free_lists[order];
    buddy_free_lists[order] = block;
    
    EARLY_UNLOCK();
    
    /* Update statistics */
    stats.buddy_frees++;
    size_t free_size = (1U << order) * PAGE_SIZE;
    stats.total_freed += free_size;
    stats.current_usage -= free_size;
}

/* ========================================================================
 * EARLY REGION ALLOCATOR IMPLEMENTATION
 * ======================================================================== */

/**
 * @brief Initialize early region allocator
 * @return 0 on success, negative error code on failure
 */
static int early_region_init(void) {
    /* Initialize region descriptors */
    for (size_t i = 0; i < EARLY_REGION_MAX_COUNT; i++) {
        early_regions[i].start = 0;
        early_regions[i].size = 0;
        early_regions[i].flags = 0;
        early_regions[i].in_use = false;
        early_regions[i].name = NULL;
    }
    
    region_count = 0;
    
    printk(KERN_INFO "Early region allocator initialized (%d max regions)\n", 
           EARLY_REGION_MAX_COUNT);
    return 0;
}

/**
 * @brief Allocate a memory region
 * @param size Size of region in bytes
 * @param alignment Alignment requirement
 * @param name Name for debugging
 * @return Physical address of region, or 0 on failure
 */
static phys_addr_t early_region_alloc(size_t size, size_t alignment, const char *name) {
    if (size == 0 || region_count >= EARLY_REGION_MAX_COUNT) {
        return 0;
    }
    
    /* Use buddy allocator to get the actual memory */
    size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    void *ptr = early_buddy_alloc_pages(pages, EARLY_FLAG_ZERO);
    if (!ptr) {
        return 0;
    }
    
    EARLY_LOCK();
    
    /* Find free region descriptor */
    struct early_region *region = NULL;
    for (size_t i = 0; i < EARLY_REGION_MAX_COUNT; i++) {
        if (!early_regions[i].in_use) {
            region = &early_regions[i];
            break;
        }
    }
    
    if (!region) {
        EARLY_UNLOCK();
        early_buddy_free_pages(ptr, pages);
        return 0;
    }
    
    /* Initialize region */
    region->start = (phys_addr_t)ptr;
    region->size = size;
    region->flags = 0;
    region->in_use = true;
    region->name = name;
    
    region_count++;
    
    EARLY_UNLOCK();
    
    /* Update statistics */
    stats.region_allocs++;
    
    printk(KERN_DEBUG "Region '%s' allocated: 0x%lx (%zu bytes)\n",
           name ? name : "unnamed", region->start, size);
    
    return region->start;
}

/**
 * @brief Free a memory region
 * @param addr Region address
 * @return 0 on success, negative error code on failure
 */
static int early_region_free(phys_addr_t addr) {
    if (addr == 0) {
        return -1;
    }
    
    EARLY_LOCK();
    
    /* Find the region */
    struct early_region *region = NULL;
    for (size_t i = 0; i < EARLY_REGION_MAX_COUNT; i++) {
        if (early_regions[i].in_use && early_regions[i].start == addr) {
            region = &early_regions[i];
            break;
        }
    }
    
    if (!region) {
        EARLY_UNLOCK();
        printk(KERN_ERR "Region free: region not found for address 0x%lx\n", addr);
        return -1;
    }
    
    /* Free the underlying memory */
    size_t pages = (region->size + PAGE_SIZE - 1) / PAGE_SIZE;
    early_buddy_free_pages((void *)region->start, pages);
    
    /* Mark region as free */
    printk(KERN_DEBUG "Region '%s' freed: 0x%lx (%zu bytes)\n",
           region->name ? region->name : "unnamed", region->start, region->size);
    
    region->start = 0;
    region->size = 0;
    region->flags = 0;
    region->in_use = false;
    region->name = NULL;
    
    region_count--;
    
    EARLY_UNLOCK();
    
    /* Update statistics */
    stats.region_frees++;
    
    return 0;
}

/* ========================================================================
 * EARLY POOL ALLOCATOR IMPLEMENTATION
 * ======================================================================== */

/**
 * @brief Initialize early pool allocator
 * @return 0 on success, negative error code on failure
 */
static int early_pool_init(void) {
    /* Fixed pool sizes */
    const size_t pool_object_sizes[] = { 32, 64, 128, 256 };
    
    /* Initialize memory pools */
    for (int i = 0; i < EARLY_POOL_COUNT; i++) {
        memory_pools[i].base = pool_memory[i];
        memory_pools[i].total_size = sizeof(pool_memory[i]);
        memory_pools[i].used_size = 0;
        memory_pools[i].object_size = pool_object_sizes[i];
        memory_pools[i].free_list = NULL;
        memory_pools[i].free_count = 0;
        memory_pools[i].active = true;
        
        /* Initialize free list */
        char *ptr = (char *)memory_pools[i].base;
        size_t objects = memory_pools[i].total_size / memory_pools[i].object_size;
        
        for (size_t j = 0; j < objects; j++) {
            *(void **)ptr = memory_pools[i].free_list;
            memory_pools[i].free_list = ptr;
            memory_pools[i].free_count++;
            ptr += memory_pools[i].object_size;
        }
    }
    
    printk(KERN_INFO "Early pool allocator initialized (%d pools)\n", EARLY_POOL_COUNT);
    return 0;
}

/**
 * @brief Allocate object from memory pool
 * @param size Requested size
 * @param flags Allocation flags
 * @return Pointer to allocated object, or NULL on failure
 */
static void *early_pool_alloc(size_t size, uint32_t flags) {
    if (size == 0) {
        return NULL;
    }
    
    /* Find appropriate pool */
    struct early_pool *pool = NULL;
    for (int i = 0; i < EARLY_POOL_COUNT; i++) {
        if (memory_pools[i].active && size <= memory_pools[i].object_size) {
            pool = &memory_pools[i];
            break;
        }
    }
    
    if (!pool) {
        return NULL; /* No suitable pool */
    }
    
    EARLY_LOCK();
    
    if (!pool->free_list) {
        EARLY_UNLOCK();
        return NULL; /* Pool exhausted */
    }
    
    /* Get object from free list */
    void *obj = pool->free_list;
    pool->free_list = *(void **)obj;
    pool->free_count--;
    pool->used_size += pool->object_size;
    
    EARLY_UNLOCK();
    
    /* Zero-initialize if requested */
    if (flags & EARLY_FLAG_ZERO) {
        memset(obj, 0, pool->object_size);
    }
    
    /* Update statistics */
    stats.pool_allocs++;
    stats.total_allocated += pool->object_size;
    stats.current_usage += pool->object_size;
    if (stats.current_usage > stats.peak_usage) {
        stats.peak_usage = stats.current_usage;
    }
    
    return obj;
}

/**
 * @brief Free object back to memory pool
 * @param ptr Pointer to object to free
 */
static void early_pool_free(void *ptr) {
    if (!ptr) {
        return;
    }
    
    /* Find which pool this object belongs to */
    struct early_pool *pool = NULL;
    for (int i = 0; i < EARLY_POOL_COUNT; i++) {
        if (ptr >= memory_pools[i].base &&
            ptr < (char *)memory_pools[i].base + memory_pools[i].total_size) {
            pool = &memory_pools[i];
            break;
        }
    }
    
    if (!pool) {
        printk(KERN_ERR "Pool free: object %p not found in any pool\n", ptr);
        return;
    }
    
    EARLY_LOCK();
    
    /* Add object back to free list */
    *(void **)ptr = pool->free_list;
    pool->free_list = ptr;
    pool->free_count++;
    pool->used_size -= pool->object_size;
    
    EARLY_UNLOCK();
    
    /* Update statistics */
    stats.pool_frees++;
    stats.total_freed += pool->object_size;
    stats.current_usage -= pool->object_size;
}

/* ========================================================================
 * EARLY BITMAP ALLOCATOR IMPLEMENTATION
 * ======================================================================== */

/**
 * @brief Initialize early bitmap allocator
 * @return 0 on success, negative error code on failure
 */
static int early_bitmap_init(void) {
    bitmap_allocator.bitmap = bitmap_data;
    bitmap_allocator.total_bits = EARLY_BITMAP_SIZE / 64; /* 64-byte granularity */
    bitmap_allocator.free_bits = bitmap_allocator.total_bits;
    bitmap_allocator.base_addr = (phys_addr_t)bitmap_memory;
    bitmap_allocator.granularity = 64;
    bitmap_allocator.active = true;
    
    /* Clear bitmap (all free) */
    memset(bitmap_data, 0, sizeof(bitmap_data));
    
    printk(KERN_INFO "Early bitmap allocator initialized (%zu bits, %zu granularity)\n",
           bitmap_allocator.total_bits, bitmap_allocator.granularity);
    return 0;
}

/**
 * @brief Allocate memory using bitmap allocator
 * @param size Size in bytes
 * @param alignment Alignment requirement
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
static void *early_bitmap_alloc(size_t size, size_t alignment, uint32_t flags) {
    if (!bitmap_allocator.active || size == 0) {
        return NULL;
    }
    
    /* Calculate required bits */
    size_t required_bits = (size + bitmap_allocator.granularity - 1) / 
                          bitmap_allocator.granularity;
    
    EARLY_LOCK();
    
    if (bitmap_allocator.free_bits < required_bits) {
        EARLY_UNLOCK();
        return NULL; /* Not enough free space */
    }
    
    /* Find free bits */
    size_t start_bit = bitmap_find_free_bits(bitmap_allocator.bitmap,
                                            bitmap_allocator.total_bits,
                                            required_bits);
    
    if (start_bit == SIZE_MAX) {
        EARLY_UNLOCK();
        return NULL; /* No contiguous space */
    }
    
    /* Mark bits as allocated */
    bitmap_set_bits(bitmap_allocator.bitmap, start_bit, required_bits);
    bitmap_allocator.free_bits -= required_bits;
    
    EARLY_UNLOCK();
    
    /* Calculate address */
    void *ptr = (void *)(bitmap_allocator.base_addr + 
                        start_bit * bitmap_allocator.granularity);
    
    /* Zero-initialize if requested */
    if (flags & EARLY_FLAG_ZERO) {
        memset(ptr, 0, size);
    }
    
    /* Update statistics */
    stats.bitmap_allocs++;
    stats.total_allocated += required_bits * bitmap_allocator.granularity;
    stats.current_usage += required_bits * bitmap_allocator.granularity;
    if (stats.current_usage > stats.peak_usage) {
        stats.peak_usage = stats.current_usage;
    }
    
    return ptr;
}

/**
 * @brief Free memory allocated by bitmap allocator
 * @param ptr Pointer to memory to free
 * @param size Original allocation size
 */
static void early_bitmap_free(void *ptr, size_t size) {
    if (!ptr || !bitmap_allocator.active || size == 0) {
        return;
    }
    
    /* Verify pointer is within our range */
    uintptr_t addr = (uintptr_t)ptr;
    if (addr < bitmap_allocator.base_addr ||
        addr >= bitmap_allocator.base_addr + EARLY_BITMAP_SIZE) {
        printk(KERN_ERR "Bitmap free: invalid pointer %p\n", ptr);
        return;
    }
    
    /* Calculate bit position and count */
    size_t start_bit = (addr - bitmap_allocator.base_addr) / bitmap_allocator.granularity;
    size_t bit_count = (size + bitmap_allocator.granularity - 1) / 
                       bitmap_allocator.granularity;
    
    EARLY_LOCK();
    
    /* Clear bits */
    bitmap_clear_bits(bitmap_allocator.bitmap, start_bit, bit_count);
    bitmap_allocator.free_bits += bit_count;
    
    EARLY_UNLOCK();
    
    /* Update statistics */
    stats.bitmap_frees++;
    stats.total_freed += bit_count * bitmap_allocator.granularity;
    stats.current_usage -= bit_count * bitmap_allocator.granularity;
}

/* ========================================================================
 * MAIN EARLY MEMORY ALLOCATOR INTERFACE
 * ======================================================================== */

/**
 * @brief Initialize all early memory allocators
 * @return 0 on success, negative error code on failure
 */
int early_mm_init(void) {
    if (early_mm_initialized) {
        printk(KERN_WARNING "Early memory management already initialized\n");
        return -1;
    }
    
    printk(KERN_INFO "Initializing early memory management\n");
    
    /* Initialize statistics */
    memset(&stats, 0, sizeof(stats));
    
    /* Initialize all allocators */
    int ret = 0;
    
    ret |= bootstrap_init();
    ret |= early_slab_init();
    ret |= early_buddy_init();
    ret |= early_region_init();
    ret |= early_pool_init();
    ret |= early_bitmap_init();
    
    if (ret != 0) {
        printk(KERN_ERR "Failed to initialize early memory allocators\n");
        return ret;
    }
    
    early_mm_initialized = true;
    early_mm_active = true;
    
    printk(KERN_INFO "Early memory management initialized successfully\n");
    return 0;
}

/**
 * @brief Shutdown early memory allocators
 */
void early_mm_shutdown(void) {
    if (!early_mm_initialized) {
        return;
    }
    
    early_mm_active = false;
    
    printk(KERN_INFO "Shutting down early memory management\n");
    printk(KERN_INFO "Final statistics:\n");
    printk(KERN_INFO "  Total allocated: %lu bytes\n", stats.total_allocated);
    printk(KERN_INFO "  Total freed:     %lu bytes\n", stats.total_freed);
    printk(KERN_INFO "  Peak usage:      %lu bytes\n", stats.peak_usage);
    printk(KERN_INFO "  Current usage:   %lu bytes\n", stats.current_usage);
    
    early_mm_initialized = false;
}

/**
 * @brief Main early memory allocation function
 * @param size Size in bytes
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_malloc(size_t size, uint32_t flags) {
    if (!early_mm_active || size == 0) {
        return NULL;
    }
    
    void *ptr = NULL;
    
    /* Choose allocator based on size */
    if (size <= 32) {
        /* Try pool allocator first for small objects */
        ptr = early_pool_alloc(size, flags);
        if (ptr) return ptr;
        
        /* Fall back to slab allocator */
        ptr = early_slab_alloc(size, flags);
        if (ptr) return ptr;
    } else if (size <= 1024) {
        /* Try slab allocator for medium objects */
        ptr = early_slab_alloc(size, flags);
        if (ptr) return ptr;
        
        /* Fall back to pool allocator */
        ptr = early_pool_alloc(size, flags);
        if (ptr) return ptr;
    } else if (size <= 4096) {
        /* Try bitmap allocator for small pages */
        ptr = early_bitmap_alloc(size, EARLY_MIN_ALIGN, flags);
        if (ptr) return ptr;
        
        /* Fall back to buddy allocator */
        size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        ptr = early_buddy_alloc_pages(pages, flags);
        if (ptr) return ptr;
    } else {
        /* Use buddy allocator for large allocations */
        size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        ptr = early_buddy_alloc_pages(pages, flags);
        if (ptr) return ptr;
    }
    
    /* Last resort: bootstrap allocator */
    ptr = bootstrap_alloc(size, flags);
    if (ptr) return ptr;
    
    printk(KERN_ERR "Early malloc failed: no allocator could satisfy %zu bytes\n", size);
    return NULL;
}

/**
 * @brief Main early memory deallocation function
 * @param ptr Pointer to memory to free
 * @param size Original allocation size (needed for some allocators)
 */
void early_free(void *ptr, size_t size) {
    if (!ptr || !early_mm_active) {
        return;
    }
    
    /* Determine which allocator owns this memory */
    if (is_valid_ptr(ptr)) {
        /* Check pools first */
        for (int i = 0; i < EARLY_POOL_COUNT; i++) {
            if (ptr >= memory_pools[i].base &&
                ptr < (char *)memory_pools[i].base + memory_pools[i].total_size) {
                early_pool_free(ptr);
                return;
            }
        }
        
        /* Check bitmap allocator */
        uintptr_t addr = (uintptr_t)ptr;
        if (addr >= bitmap_allocator.base_addr &&
            addr < bitmap_allocator.base_addr + EARLY_BITMAP_SIZE) {
            early_bitmap_free(ptr, size);
            return;
        }
        
        /* Check buddy allocator */
        if (addr >= (uintptr_t)buddy_memory &&
            addr < (uintptr_t)buddy_memory + sizeof(buddy_memory)) {
            size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
            early_buddy_free_pages(ptr, pages);
            return;
        }
        
        /* Check slab allocator */
        if (size <= 1024) {
            early_slab_free(ptr, size);
            return;
        }
        
        /* Check bootstrap allocator */
        if (addr >= (uintptr_t)bootstrap_pool &&
            addr < (uintptr_t)bootstrap_pool + EARLY_BOOTSTRAP_SIZE) {
            bootstrap_free(ptr);
            return;
        }
    }
    
    printk(KERN_WARNING "Early free: unable to determine allocator for %p\n", ptr);
}

/**
 * @brief Allocate zeroed memory
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_calloc(size_t size) {
    return early_malloc(size, EARLY_FLAG_ZERO);
}

/**
 * @brief Allocate aligned memory
 * @param size Size in bytes
 * @param alignment Alignment requirement
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_malloc_aligned(size_t size, size_t alignment) {
    if (alignment <= EARLY_MIN_ALIGN) {
        return early_malloc(size, 0);
    }
    
    /* For now, only bitmap allocator supports custom alignment */
    return early_bitmap_alloc(size, alignment, 0);
}

/**
 * @brief Get allocation statistics
 * @param stats_out Pointer to structure to fill with statistics
 */
void early_get_stats(struct early_alloc_stats *stats_out) {
    if (stats_out) {
        EARLY_LOCK();
        memcpy(stats_out, &stats, sizeof(struct early_alloc_stats));
        EARLY_UNLOCK();
    }
}

/**
 * @brief Print early memory allocator statistics
 */
void early_print_stats(void) {
    printk(KERN_INFO "=== Early Memory Allocator Statistics ===\n");
    printk(KERN_INFO "Bootstrap: %lu allocs, %lu frees\n", 
           stats.bootstrap_allocs, stats.bootstrap_frees);
    printk(KERN_INFO "Slab:      %lu allocs, %lu frees\n", 
           stats.slab_allocs, stats.slab_frees);
    printk(KERN_INFO "Buddy:     %lu allocs, %lu frees\n", 
           stats.buddy_allocs, stats.buddy_frees);
    printk(KERN_INFO "Region:    %lu allocs, %lu frees\n", 
           stats.region_allocs, stats.region_frees);
    printk(KERN_INFO "Pool:      %lu allocs, %lu frees\n", 
           stats.pool_allocs, stats.pool_frees);
    printk(KERN_INFO "Bitmap:    %lu allocs, %lu frees\n", 
           stats.bitmap_allocs, stats.bitmap_frees);
    printk(KERN_INFO "Total allocated: %lu bytes\n", stats.total_allocated);
    printk(KERN_INFO "Total freed:     %lu bytes\n", stats.total_freed);
    printk(KERN_INFO "Current usage:   %lu bytes\n", stats.current_usage);
    printk(KERN_INFO "Peak usage:      %lu bytes\n", stats.peak_usage);
    printk(KERN_INFO "=========================================\n");
}

/**
 * @brief Check early memory allocator integrity
 * @return true if all allocators are consistent, false otherwise
 */
bool early_check_integrity(void) {
    if (!early_mm_initialized) {
        return false;
    }
    
    bool integrity_ok = true;
    
    /* Check bootstrap allocator */
    struct early_bootstrap_header *current = bootstrap_alloc_list;
    while (current) {
        if (current->magic != EARLY_MAGIC_ALLOC && current->magic != EARLY_MAGIC_FREE) {
            printk(KERN_ERR "Bootstrap integrity: corrupted header at %p\n", current);
            integrity_ok = false;
        }
        current = current->next;
    }
    
    /* Check buddy allocator consistency */
    for (int order = 0; order <= EARLY_BUDDY_MAX_ORDER; order++) {
        struct early_buddy_block *block = buddy_free_lists[order];
        while (block) {
            if (block->allocated) {
                printk(KERN_ERR "Buddy integrity: allocated block in free list (order %d)\n", order);
                integrity_ok = false;
            }
            if (block->order != order) {
                printk(KERN_ERR "Buddy integrity: wrong order block in list (expected %d, got %u)\n", 
                       order, block->order);
                integrity_ok = false;
            }
            block = block->next;
        }
    }
    
    /* Check memory pools */
    for (int i = 0; i < EARLY_POOL_COUNT; i++) {
        if (memory_pools[i].active) {
            size_t expected_objects = memory_pools[i].total_size / memory_pools[i].object_size;
            size_t used_objects = (memory_pools[i].total_size - memory_pools[i].used_size) / 
                                 memory_pools[i].object_size;
            
            if (memory_pools[i].free_count + used_objects != expected_objects) {
                printk(KERN_ERR "Pool integrity: object count mismatch in pool %d\n", i);
                integrity_ok = false;
            }
        }
    }
    
    /* Check bitmap allocator */
    if (bitmap_allocator.active) {
        size_t set_bits = 0;
        for (size_t i = 0; i < bitmap_allocator.total_bits; i++) {
            size_t byte_idx = i / 8;
            size_t bit_offset = i % 8;
            if (bitmap_data[byte_idx] & (1 << bit_offset)) {
                set_bits++;
            }
        }
        
        if (set_bits + bitmap_allocator.free_bits != bitmap_allocator.total_bits) {
            printk(KERN_ERR "Bitmap integrity: bit count mismatch\n");
            integrity_ok = false;
        }
    }
    
    return integrity_ok;
}

/**
 * @brief Dump detailed information about all early allocators
 */
void early_dump_allocators(void) {
    printk(KERN_INFO "=== Early Memory Allocator Dump ===\n");
    
    /* Bootstrap allocator */
    printk(KERN_INFO "Bootstrap Allocator:\n");
    printk(KERN_INFO "  Pool size: %d bytes\n", EARLY_BOOTSTRAP_SIZE);
    printk(KERN_INFO "  Used:      %zu bytes (%.1f%%)\n", 
           bootstrap_offset, (float)bootstrap_offset * 100.0f / EARLY_BOOTSTRAP_SIZE);
    printk(KERN_INFO "  Free:      %zu bytes\n", EARLY_BOOTSTRAP_SIZE - bootstrap_offset);
    
    /* Slab allocator */
    printk(KERN_INFO "Slab Allocator:\n");
    for (int i = 0; i < EARLY_SLAB_POOLS; i++) {
        printk(KERN_INFO "  Cache %d (%zu bytes): %zu total, %zu free\n",
               i, slab_caches[i].object_size, slab_caches[i].total_objects,
               slab_caches[i].free_objects);
    }
    
    /* Buddy allocator */
    printk(KERN_INFO "Buddy Allocator:\n");
    printk(KERN_INFO "  Memory size: %zu KB\n", sizeof(buddy_memory) / 1024);
    for (int order = 0; order <= EARLY_BUDDY_MAX_ORDER; order++) {
        int count = 0;
        struct early_buddy_block *block = buddy_free_lists[order];
        while (block) {
            count++;
            block = block->next;
        }
        if (count > 0) {
            printk(KERN_INFO "  Order %d: %d free blocks (%zu KB each)\n",
                   order, count, ((1U << order) * PAGE_SIZE) / 1024);
        }
    }
    
    /* Region allocator */
    printk(KERN_INFO "Region Allocator:\n");
    printk(KERN_INFO "  Active regions: %zu/%d\n", region_count, EARLY_REGION_MAX_COUNT);
    for (size_t i = 0; i < EARLY_REGION_MAX_COUNT; i++) {
        if (early_regions[i].in_use) {
            printk(KERN_INFO "  Region '%s': 0x%lx (%zu bytes)\n",
                   early_regions[i].name ? early_regions[i].name : "unnamed",
                   early_regions[i].start, early_regions[i].size);
        }
    }
    
    /* Memory pools */
    printk(KERN_INFO "Memory Pools:\n");
    for (int i = 0; i < EARLY_POOL_COUNT; i++) {
        if (memory_pools[i].active) {
            float usage = (float)memory_pools[i].used_size * 100.0f / memory_pools[i].total_size;
            printk(KERN_INFO "  Pool %d (%zu bytes): %zu/%zu objects (%.1f%% used)\n",
                   i, memory_pools[i].object_size, 
                   (memory_pools[i].total_size / memory_pools[i].object_size) - memory_pools[i].free_count,
                   memory_pools[i].total_size / memory_pools[i].object_size, usage);
        }
    }
    
    /* Bitmap allocator */
    printk(KERN_INFO "Bitmap Allocator:\n");
    if (bitmap_allocator.active) {
        float usage = (float)(bitmap_allocator.total_bits - bitmap_allocator.free_bits) * 
                     100.0f / bitmap_allocator.total_bits;
        printk(KERN_INFO "  Total bits: %zu\n", bitmap_allocator.total_bits);
        printk(KERN_INFO "  Free bits:  %zu\n", bitmap_allocator.free_bits);
        printk(KERN_INFO "  Usage:      %.1f%%\n", usage);
        printk(KERN_INFO "  Granularity: %zu bytes\n", bitmap_allocator.granularity);
    }
    
    printk(KERN_INFO "===================================\n");
}

/**
 * @brief Emergency allocation for critical situations
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *early_emergency_alloc(size_t size) {
    printk(KERN_EMERG "Emergency allocation requested: %zu bytes\n", size);
    
    /* Try each allocator in order of likelihood to succeed */
    void *ptr = bootstrap_alloc(size, EARLY_FLAG_URGENT);
    if (ptr) {
        printk(KERN_EMERG "Emergency allocation satisfied by bootstrap allocator\n");
        return ptr;
    }
    
    /* Try to get memory from buddy allocator reserves */
    if (size <= PAGE_SIZE) {
        ptr = early_buddy_alloc_pages(1, EARLY_FLAG_URGENT);
        if (ptr) {
            printk(KERN_EMERG "Emergency allocation satisfied by buddy allocator\n");
            return ptr;
        }
    }
    
    printk(KERN_EMERG "Emergency allocation failed - system may be unstable\n");
    return NULL;
}

/* ========================================================================
 * COMPATIBILITY AND WRAPPER FUNCTIONS
 * ======================================================================== */

/**
 * @brief Standard malloc wrapper for early allocation
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *malloc(size_t size) {
    if (early_mm_active) {
        return early_malloc(size, 0);
    }
    return NULL;
}

/**
 * @brief Standard calloc wrapper for early allocation
 * @param nmemb Number of elements
 * @param size Size of each element
 * @return Pointer to allocated memory, or NULL on failure
 */
void *calloc(size_t nmemb, size_t size) {
    if (early_mm_active && nmemb > 0 && size > 0) {
        size_t total_size = nmemb * size;
        /* Check for overflow */
        if (total_size / nmemb != size) {
            return NULL;
        }
        return early_malloc(total_size, EARLY_FLAG_ZERO);
    }
    return NULL;
}

/**
 * @brief Standard free wrapper for early allocation
 * @param ptr Pointer to memory to free
 */
void free(void *ptr) {
    if (early_mm_active && ptr) {
        /* We can't determine size easily, so use 0 as hint */
        early_free(ptr, 0);
    }
}

/**
 * @brief Check if early memory management is active
 * @return true if active, false otherwise
 */
bool early_mm_is_active(void) {
    return early_mm_active;
}

/**
 * @brief Get total memory managed by early allocators
 * @return Total memory in bytes
 */
size_t early_get_total_memory(void) {
    size_t total = 0;
    
    total += EARLY_BOOTSTRAP_SIZE;
    total += sizeof(buddy_memory);
    total += EARLY_BITMAP_SIZE;
    
    for (int i = 0; i < EARLY_POOL_COUNT; i++) {
        total += memory_pools[i].total_size;
    }
    
    return total;
}

/**
 * @brief Get available memory from early allocators
 * @return Available memory in bytes
 */
size_t early_get_available_memory(void) {
    size_t available = 0;
    
    /* Bootstrap allocator */
    available += EARLY_BOOTSTRAP_SIZE - bootstrap_offset;
    
    /* Bitmap allocator */
    if (bitmap_allocator.active) {
        available += bitmap_allocator.free_bits * bitmap_allocator.granularity;
    }
    
    /* Memory pools */
    for (int i = 0; i < EARLY_POOL_COUNT; i++) {
        if (memory_pools[i].active) {
            available += memory_pools[i].free_count * memory_pools[i].object_size;
        }
    }
    
    /* Buddy allocator - approximate by counting free blocks */
    for (int order = 0; order <= EARLY_BUDDY_MAX_ORDER; order++) {
        int count = 0;
        struct early_buddy_block *block = buddy_free_lists[order];
        while (block) {
            count++;
            block = block->next;
        }
        available += count * (1U << order) * PAGE_SIZE;
    }
    
    return available;
}

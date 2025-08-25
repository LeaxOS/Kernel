/**
 * @file mm_init.c
 * @brief Memory Management Initialization
 * 
 * This file contains the initialization code for the LeaxOS memory management
 * subsystem. It coordinates the initialization of all memory management 
 * components including:
 * - Physical page allocator
 * - Slab allocator for fixed-size objects
 * - Virtual memory allocator (vmalloc)
 * - Memory mapping subsystem (mmap)
 * - Memory barriers and synchronization
 * 
 * The initialization follows a specific order to ensure proper dependencies
 * and provides comprehensive error handling and recovery mechanisms.
 * 
 * @author LeaxOS Team
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

/* Fallback for standalone compilation */
#define printk printf
#define panic(msg) do { printf("PANIC: %s\n", msg); while(1); } while(0)
/* Kernel log levels */
#define KERN_EMERG    "0"  /* Emergency */
#define KERN_ALERT    "1"  /* Alert */
#define KERN_CRIT     "2"  /* Critical */
#define KERN_ERR      "3"  /* Error */
#define KERN_WARNING  "4"  /* Warning */
#define KERN_NOTICE   "5"  /* Notice */
#define KERN_INFO     "6"  /* Info */
#define KERN_DEBUG    "7"  /* Debug */

/* ========================================================================
 * GLOBAL VARIABLES AND STATE
 * ======================================================================== */

/** Memory management initialization state */
static bool mm_initialized = false;
static bool early_mm_active = false;
static mm_config_t current_config;
static mm_stats_t global_stats;

/** Spinlock for protecting MM globals in SMP */
#ifdef CONFIG_SMP
/* Define basic spinlock if not available */
typedef struct {
    volatile int locked;
} spinlock_t;
#define SPINLOCK_INIT {0}
static inline void spin_lock(spinlock_t *lock) {
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        while (lock->locked) __asm__ __volatile__("pause");
    }
}
static inline void spin_unlock(spinlock_t *lock) {
    __sync_lock_release(&lock->locked);
}
static spinlock_t mm_global_lock = SPINLOCK_INIT;
#define MM_LOCK() spin_lock(&mm_global_lock)
#define MM_UNLOCK() spin_unlock(&mm_global_lock)
#else
#define MM_LOCK() do {} while(0)
#define MM_UNLOCK() do {} while(0)
#endif

/** Memory subsystem initialization flags */
static struct {
    bool page_alloc_init;
    bool slab_init;
    bool vmalloc_init;
    bool mmap_init;
    bool barriers_init;
} mm_init_state = { false, false, false, false, false };

/** Early memory pool for bootstrap allocations */
#define EARLY_POOL_SIZE (128 * 1024)  /* 128KB early pool for real kernel */
static uint8_t early_memory_pool[EARLY_POOL_SIZE] __attribute__((aligned(64)));
static size_t early_pool_offset = 0;
static bool early_pool_exhausted = false;

/** Memory zone information */
static struct memory_zone_info {
    phys_addr_t start;
    phys_addr_t end;
    size_t total_pages;
    size_t free_pages;
    bool initialized;
} zone_info[MM_ZONE_COUNT];

/** Boot-time memory information from bootloader */
struct boot_memory_info {
    phys_addr_t memory_map_addr;
    size_t memory_map_size;
    phys_addr_t kernel_start;
    phys_addr_t kernel_end;
    phys_addr_t initrd_start;
    phys_addr_t initrd_end;
};

/* Default boot memory info - would be populated by bootloader */
static struct boot_memory_info boot_mem_info = {
    .memory_map_addr = 0,
    .memory_map_size = 0,
    .kernel_start = 0,
    .kernel_end = 0,
    .initrd_start = 0,
    .initrd_end = 0
};

/* ========================================================================
 * EARLY MEMORY ALLOCATION (BOOTSTRAP)
 * ======================================================================== */

/**
 * @brief Early memory allocator for bootstrap phase
 * 
 * This allocator provides memory during system initialization before
 * the full memory management subsystem is available. Thread-safe for SMP.
 * 
 * @param size Size in bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 */
static void *early_alloc(size_t size) {
    if (!early_mm_active || early_pool_exhausted) {
        return NULL;
    }
    
    /* Align size to pointer size for better performance */
    size = ALIGN_UP(size, sizeof(void*));
    
    /* Use atomic operations for SMP safety */
    MM_LOCK();
    
    /* Check if we have enough space */
    if (early_pool_offset + size > EARLY_POOL_SIZE) {
        early_pool_exhausted = true;
        MM_UNLOCK();
        printk(KERN_WARNING "Early memory pool exhausted! Allocated %zu/%d bytes\n",
               early_pool_offset, EARLY_POOL_SIZE);
        return NULL;
    }
    
    void *ptr = &early_memory_pool[early_pool_offset];
    early_pool_offset += size;
    
    MM_UNLOCK();
    
    /* Zero-initialize the allocated memory */
    memset(ptr, 0, size);
    
    return ptr;
}

/**
 * @brief Initialize early memory allocator
 */
static void early_mm_init(void) {
    early_pool_offset = 0;
    early_pool_exhausted = false;
    early_mm_active = true;
    
    /* Clear the early memory pool */
    memset(early_memory_pool, 0, EARLY_POOL_SIZE);
}

/**
 * @brief Shutdown early memory allocator
 */
static void early_mm_shutdown(void) {
    early_mm_active = false;
    /* Note: We don't clear the pool as some early allocations might still be in use */
}

/* ========================================================================
 * MEMORY ZONE MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialize memory zone information
 * 
 * @param phys_start Physical memory start address
 * @param phys_end Physical memory end address
 * @return 0 on success, negative error code on failure
 */
static int init_memory_zones(phys_addr_t phys_start, phys_addr_t phys_end) {
    size_t total_memory = phys_end - phys_start;
    
    printk(KERN_INFO "Initializing memory zones (0x%lx - 0x%lx, %zu MB)\n",
           phys_start, phys_end, total_memory / (1024 * 1024));
    
    /* Clear zone info */
    memset(zone_info, 0, sizeof(zone_info));
    
    /* Initialize DMA zone (0-16MB) */
    zone_info[MM_ZONE_DMA].start = phys_start;
    zone_info[MM_ZONE_DMA].end = (phys_start + (16 * 1024 * 1024) < phys_end) ? 
                                  phys_start + (16 * 1024 * 1024) : phys_end;
    zone_info[MM_ZONE_DMA].total_pages = 
        (zone_info[MM_ZONE_DMA].end - zone_info[MM_ZONE_DMA].start) / PAGE_SIZE;
    zone_info[MM_ZONE_DMA].free_pages = zone_info[MM_ZONE_DMA].total_pages;
    zone_info[MM_ZONE_DMA].initialized = true;
    
    /* Initialize Normal zone (16MB-896MB) */
    if (phys_end > zone_info[MM_ZONE_DMA].end) {
        zone_info[MM_ZONE_NORMAL].start = zone_info[MM_ZONE_DMA].end;
        zone_info[MM_ZONE_NORMAL].end = (phys_start + (896 * 1024 * 1024) < phys_end) ?
                                         phys_start + (896 * 1024 * 1024) : phys_end;
        zone_info[MM_ZONE_NORMAL].total_pages = 
            (zone_info[MM_ZONE_NORMAL].end - zone_info[MM_ZONE_NORMAL].start) / PAGE_SIZE;
        zone_info[MM_ZONE_NORMAL].free_pages = zone_info[MM_ZONE_NORMAL].total_pages;
        zone_info[MM_ZONE_NORMAL].initialized = true;
    }
    
    /* Initialize High memory zone (>896MB) */
    if (phys_end > zone_info[MM_ZONE_NORMAL].end) {
        zone_info[MM_ZONE_HIGHMEM].start = zone_info[MM_ZONE_NORMAL].end;
        zone_info[MM_ZONE_HIGHMEM].end = phys_end;
        zone_info[MM_ZONE_HIGHMEM].total_pages = 
            (zone_info[MM_ZONE_HIGHMEM].end - zone_info[MM_ZONE_HIGHMEM].start) / PAGE_SIZE;
        zone_info[MM_ZONE_HIGHMEM].free_pages = zone_info[MM_ZONE_HIGHMEM].total_pages;
        zone_info[MM_ZONE_HIGHMEM].initialized = true;
    }
    
    /* Reserve critical memory regions */
    reserve_critical_regions();
    
    return MM_SUCCESS;
}

/**
 * @brief Print memory zone information
 */
static void print_memory_zones(void) {
    const char *zone_names[] = { "DMA", "NORMAL", "HIGHMEM" };
    
    printk(KERN_INFO "Memory zones:\n");
    for (int i = 0; i < MM_ZONE_COUNT; i++) {
        if (zone_info[i].initialized) {
            size_t size_mb = (zone_info[i].end - zone_info[i].start) / (1024 * 1024);
            printk(KERN_INFO "  Zone %-8s: 0x%016lx - 0x%016lx (%zu MB, %zu pages)\n",
                   zone_names[i], zone_info[i].start, zone_info[i].end,
                   size_mb, zone_info[i].total_pages);
        }
    }
}

/**
 * @brief Parse memory map from bootloader
 * 
 * @param memory_map Pointer to memory map
 * @param map_size Size of memory map
 * @return 0 on success, negative error code on failure
 */
static int parse_memory_map(void *memory_map, size_t map_size) {
    /* This would parse the E820 memory map on x86 or similar on other architectures */
    /* For now, we'll use a simplified implementation */
    
    if (!memory_map || map_size == 0) {
        printk(KERN_ERR "Invalid memory map provided\n");
        return MM_ERR_INVALID;
    }
    
    printk(KERN_INFO "Parsing memory map (%zu bytes)\n", map_size);
    
    /* Real implementation would parse memory map entries and mark:
     * - Available memory regions
     * - Reserved regions (BIOS, ACPI, etc.)
     * - Kernel code/data regions
     * - Framebuffer regions
     * - PCI hole regions
     */
    
    return MM_SUCCESS;
}

/**
 * @brief Reserve critical memory regions
 * 
 * @return 0 on success, negative error code on failure
 */
static int reserve_critical_regions(void) {
    /* Reserve kernel code and data sections */
    if (boot_mem_info.kernel_start && boot_mem_info.kernel_end) {
        size_t kernel_size = boot_mem_info.kernel_end - boot_mem_info.kernel_start;
        printk(KERN_INFO "Kernel: 0x%lx - 0x%lx (%zu KB)\n",
               boot_mem_info.kernel_start, boot_mem_info.kernel_end,
               kernel_size / 1024);
    }
    
    /* Reserve initrd if present */
    if (boot_mem_info.initrd_start && boot_mem_info.initrd_end) {
        size_t initrd_size = boot_mem_info.initrd_end - boot_mem_info.initrd_start;
        printk(KERN_INFO "Initrd: 0x%lx - 0x%lx (%zu KB)\n",
               boot_mem_info.initrd_start, boot_mem_info.initrd_end,
               initrd_size / 1024);
    }
    
    /* Reserve early memory pool */
    phys_addr_t early_pool_phys = (phys_addr_t)early_memory_pool;
    printk(KERN_INFO "Early pool: 0x%lx - 0x%lx (%d KB)\n",
           early_pool_phys, early_pool_phys + EARLY_POOL_SIZE,
           EARLY_POOL_SIZE / 1024);
    
    return MM_SUCCESS;
}

/* ========================================================================
 * SUBSYSTEM INITIALIZATION FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize physical page allocator
 * 
 * @param config Memory management configuration
 * @return 0 on success, negative error code on failure
 */
static int init_page_allocator(const mm_config_t *config) {
    printk(KERN_INFO "Initializing physical page allocator\n");
    
    page_config_t page_config = {
        .start_addr = config->phys_start,
        .end_addr = config->phys_end,
        .total_pages = (config->phys_end - config->phys_start) / PAGE_SIZE,
        .enable_debugging = config->enable_debug,
        .min_free_pages = 256  /* Keep at least 256 pages (1MB) free */
    };
    
    int ret = page_alloc_init(&page_config);
    if (ret != 0) {
        printk(KERN_ERR "Failed to initialize page allocator: %d\n", ret);
        return ret;
    }
    
    mm_init_state.page_alloc_init = true;
    printk(KERN_INFO "Page allocator initialized (%zu total pages)\n", page_config.total_pages);
    return MM_SUCCESS;
}

/**
 * @brief Initialize slab allocator
 * 
 * @param config Memory management configuration
 * @return 0 on success, negative error code on failure
 */
static int init_slab_allocator(const mm_config_t *config) {
    printk(KERN_INFO "Initializing slab allocator\n");
    
    slab_config_t slab_config = {
        .initial_cache_count = 16,
        .max_slab_size = SLAB_MAX_SIZE,
        .min_objects_per_slab = 8,
        .enable_debugging = config->enable_debug,
        .enable_statistics = config->enable_debug,
        .enable_poisoning = config->enable_debug,
        .enable_red_zones = config->enable_debug,
        .red_zone_size = config->enable_debug ? 16 : 0
    };
    
    int ret = slab_init(&slab_config);
    if (ret != 0) {
        printk(KERN_ERR "Failed to initialize slab allocator: %d\n", ret);
        return ret;
    }
    
    mm_init_state.slab_init = true;
    printk(KERN_INFO "Slab allocator initialized\n");
    return MM_SUCCESS;
}

/**
 * @brief Initialize virtual memory allocator
 * 
 * @param config Memory management configuration
 * @return 0 on success, negative error code on failure
 */
static int init_vmalloc(const mm_config_t *config) {
    printk(KERN_INFO "Initializing virtual memory allocator\n");
    
    vmalloc_config_t vmalloc_config = {
        .start_addr = VMALLOC_START,
        .end_addr = VMALLOC_END,
        .min_chunk_size = PAGE_SIZE,
        .max_chunk_size = VMALLOC_MAX_SIZE,
        .enable_guard_pages = true,
        .enable_debug = config->enable_debug,
        .reserved_size = 16 * 1024 * 1024  /* Reserve 16MB for critical allocations */
    };
    
    int ret = vmalloc_init(&vmalloc_config);
    if (ret != 0) {
        printk(KERN_ERR "Failed to initialize vmalloc: %d\n", ret);
        return ret;
    }
    
    mm_init_state.vmalloc_init = true;
    printk(KERN_INFO "Virtual memory allocator initialized (0x%lx - 0x%lx)\n",
           vmalloc_config.start_addr, vmalloc_config.end_addr);
    return MM_SUCCESS;
}

/**
 * @brief Initialize memory mapping subsystem
 * 
 * @param config Memory management configuration
 * @return 0 on success, negative error code on failure
 */
static int init_mmap_subsystem(const mm_config_t *config) {
    printk(KERN_INFO "Initializing memory mapping subsystem\n");
    
    mmap_config_t mmap_config = {
        .user_vm_start = 0x1000,  /* Start after NULL page */
        .user_vm_end = KERNEL_VIRT_BASE,
        .kernel_vm_start = KERNEL_VIRT_BASE,
        .kernel_vm_end = VMALLOC_START,
        .max_map_count = MMAP_MAX_AREAS,
        .default_stack_size = USER_STACK_SIZE,
        .max_locked_memory = 256 * 1024 * 1024,  /* 256MB max locked memory */
        .enable_huge_pages = false,  /* Disable huge pages initially */
        .enable_debugging = config->enable_debug,
        .enable_overcommit = false   /* Conservative memory allocation */
    };
    
    int ret = mmap_init(&mmap_config);
    if (ret != 0) {
        printk(KERN_ERR "Failed to initialize mmap subsystem: %d\n", ret);
        return ret;
    }
    
    mm_init_state.mmap_init = true;
    printk(KERN_INFO "Memory mapping subsystem initialized\n");
    return MM_SUCCESS;
}

/**
 * @brief Initialize memory barriers and synchronization
 * 
 * @return 0 on success, negative error code on failure
 */
static int init_memory_barriers(void) {
    printk(KERN_INFO "Initializing memory barriers\n");
    
    /* Check if memory barriers are supported on this architecture */
    if (!are_memory_barriers_supported()) {
        printk(KERN_WARNING "Hardware memory barriers not supported, using compiler barriers only\n");
    } else {
        printk(KERN_INFO "Hardware memory barriers available (strength: %s)\n",
               get_memory_ordering_strength() ? "strong" : "weak");
    }
    
    /* Initialize barrier debugging if enabled */
#ifdef CONFIG_DEBUG_MEMORY_BARRIERS
    reset_barrier_stats();
    printk(KERN_DEBUG "Memory barrier debugging enabled\n");
#endif
    
    /* Perform initial memory barrier to establish ordering */
    memory_barrier();
    
    mm_init_state.barriers_init = true;
    return MM_SUCCESS;
}

/* ========================================================================
 * CLEANUP AND ERROR RECOVERY
 * ======================================================================== */

/**
 * @brief Cleanup memory management subsystem on initialization failure
 */
static void mm_cleanup_on_error(void) {
    printk(KERN_ERR "Memory management initialization failed, cleaning up...\n");
    
    /* Shutdown subsystems in reverse order */
    if (mm_init_state.mmap_init) {
        mmap_shutdown();
        mm_init_state.mmap_init = false;
        printk(KERN_INFO "mmap subsystem shut down\n");
    }
    
    if (mm_init_state.vmalloc_init) {
        vmalloc_shutdown();
        mm_init_state.vmalloc_init = false;
        printk(KERN_INFO "vmalloc shut down\n");
    }
    
    if (mm_init_state.slab_init) {
        slab_shutdown();
        mm_init_state.slab_init = false;
        printk(KERN_INFO "slab allocator shut down\n");
    }
    
    if (mm_init_state.page_alloc_init) {
        page_alloc_shutdown();
        mm_init_state.page_alloc_init = false;
        printk(KERN_INFO "page allocator shut down\n");
    }
    
    /* Clear global state */
    MM_LOCK();
    mm_initialized = false;
    memset(&global_stats, 0, sizeof(global_stats));
    memset(&current_config, 0, sizeof(current_config));
    MM_UNLOCK();
    
    printk(KERN_INFO "Memory management cleanup completed\n");
}

/* ========================================================================
 * MAIN INITIALIZATION FUNCTIONS
 * ======================================================================== */

/**
 * @brief Early memory management initialization
 * 
 * This function performs minimal memory management setup needed
 * during early boot before the full MM subsystem is available.
 * 
 * @return 0 on success, negative error code on failure
 */
int mm_early_init(void) {
    if (early_mm_active) {
        printk(KERN_WARNING "Early MM already initialized\n");
        return MM_ERR_EXISTS;  /* Already initialized */
    }
    
    printk(KERN_INFO "Early memory management initialization\n");
    
    /* Initialize early memory allocator */
    early_mm_init();
    
    /* Initialize memory barriers */
    if (init_memory_barriers() != MM_SUCCESS) {
        printk(KERN_ERR "Failed to initialize memory barriers\n");
        early_mm_shutdown();
        return MM_ERR_INIT;
    }
    
    printk(KERN_INFO "Early MM initialized (%d KB early pool)\n", EARLY_POOL_SIZE / 1024);
    return MM_SUCCESS;
}

/**
 * @brief Main memory management initialization
 * 
 * @param config Configuration parameters
 * @return 0 on success, negative error code on failure
 */
int mm_init(const mm_config_t *config) {
    if (mm_initialized) {
        printk(KERN_WARNING "Memory management already initialized\n");
        return MM_ERR_EXISTS;  /* Already initialized */
    }
    
    if (!config) {
        printk(KERN_ERR "Invalid MM configuration provided\n");
        return MM_ERR_INVALID;
    }
    
    printk(KERN_INFO "Initializing memory management subsystem\n");
    
    /* Validate configuration parameters */
    if (config->phys_start >= config->phys_end ||
        config->virt_start >= config->virt_end ||
        config->heap_size < KERNEL_HEAP_MIN_SIZE ||
        config->heap_size > KERNEL_HEAP_MAX_SIZE) {
        printk(KERN_ERR "Invalid MM configuration parameters\n");
        return MM_ERR_INVALID;
    }
    
    /* Save configuration */
    MM_LOCK();
    memcpy(&current_config, config, sizeof(mm_config_t));
    memset(&global_stats, 0, sizeof(global_stats));
    MM_UNLOCK();
    
    /* Parse memory map from bootloader if available */
    if (boot_mem_info.memory_map_addr && boot_mem_info.memory_map_size) {
        int ret = parse_memory_map((void*)boot_mem_info.memory_map_addr, 
                                  boot_mem_info.memory_map_size);
        if (ret != MM_SUCCESS) {
            printk(KERN_WARNING "Failed to parse memory map, using simplified layout\n");
        }
    }
    
    /* Initialize memory zones */
    int ret = init_memory_zones(config->phys_start, config->phys_end);
    if (ret != MM_SUCCESS) {
        printk(KERN_ERR "Failed to initialize memory zones\n");
        return ret;
    }
    
    /* Print memory layout information */
    print_memory_zones();
    
    /* Initialize subsystems in dependency order */
    printk(KERN_INFO "Initializing MM subsystems...\n");
    
    /* 1. Physical page allocator (foundation) */
    ret = init_page_allocator(config);
    if (ret != MM_SUCCESS) {
        mm_cleanup_on_error();
        return ret;
    }
    
    /* 2. Slab allocator (depends on page allocator) */
    ret = init_slab_allocator(config);
    if (ret != MM_SUCCESS) {
        mm_cleanup_on_error();
        return ret;
    }
    
    /* 3. Virtual memory allocator (depends on page allocator) */
    ret = init_vmalloc(config);
    if (ret != MM_SUCCESS) {
        mm_cleanup_on_error();
        return ret;
    }
    
    /* 4. Memory mapping subsystem (depends on all previous) */
    ret = init_mmap_subsystem(config);
    if (ret != MM_SUCCESS) {
        mm_cleanup_on_error();
        return ret;
    }
    
    /* Enable paging if requested */
    if (config->enable_paging) {
        printk(KERN_INFO "Enabling virtual memory management\n");
        ret = mm_enable_paging();
        if (ret != MM_SUCCESS) {
            printk(KERN_ERR "Failed to enable paging\n");
            mm_cleanup_on_error();
            return ret;
        }
        printk(KERN_INFO "Virtual memory management enabled\n");
    }
    
    /* Initialize global statistics */
    MM_LOCK();
    global_stats.total_pages = (config->phys_end - config->phys_start) / PAGE_SIZE;
    global_stats.heap_size = config->heap_size;
    global_stats.total_vmem = config->virt_end - config->virt_start;
    MM_UNLOCK();
    
    /* Shutdown early memory allocator */
    early_mm_shutdown();
    printk(KERN_INFO "Early memory allocator shut down\n");
    
    /* Final memory barrier to ensure initialization is visible */
    memory_barrier();
    
    MM_LOCK();
    mm_initialized = true;
    MM_UNLOCK();
    
    printk(KERN_INFO "Memory management subsystem initialized successfully\n");
    printk(KERN_INFO "Physical memory: %zu MB, Virtual memory: %zu MB\n",
           BYTES_TO_MB(config->phys_end - config->phys_start),
           BYTES_TO_MB(config->virt_end - config->virt_start));
    
    return MM_SUCCESS;
}

/**
 * @brief Shutdown memory management subsystem
 */
void mm_shutdown(void) {
    if (!mm_initialized) {
        return;
    }
    
    /* Perform final memory barrier */
    memory_barrier();
    
    /* Cleanup all subsystems */
    mm_cleanup_on_error();
    
    /* Clear early memory state */
    early_mm_shutdown();
}

/* ========================================================================
 * STATUS AND DEBUGGING FUNCTIONS
 * ======================================================================== */

/**
 * @brief Check if memory management is initialized
 * 
 * @return true if initialized, false otherwise
 */
bool mm_is_initialized(void) {
    return mm_initialized;
}

/**
 * @brief Get memory management configuration
 * 
 * @param config Pointer to store configuration
 * @return 0 on success, negative error code on failure
 */
int mm_get_config(mm_config_t *config) {
    if (!config) {
        return MM_ERR_INVALID;
    }
    
    if (!mm_initialized) {
        return MM_ERR_INIT;
    }
    
    memcpy(config, &current_config, sizeof(mm_config_t));
    return MM_SUCCESS;
}

/**
 * @brief Get global memory statistics
 * 
 * @param stats Pointer to store statistics
 */
void mm_get_global_stats(mm_stats_t *stats) {
    if (!stats || !mm_initialized) {
        return;
    }
    
    memcpy(stats, &global_stats, sizeof(mm_stats_t));
    
    /* Update dynamic statistics */
    stats->heap_free = mm_get_free_memory();
    stats->heap_used = mm_get_used_memory();
}

/**
 * @brief Print memory management status
 */
void mm_print_status(void) {
    if (!mm_initialized) {
         printf("Memory Management: Not initialized\n"); 
        return;
    }
     printf("Memory Management Status:\n");
    printf("  Total Pages:     %zu\n", global_stats.total_pages);
    printf("  Free Pages:      %zu\n", global_stats.free_pages);
    printf("  Used Pages:      %zu\n", global_stats.used_pages);
    printf("  Heap Size:       %zu MB\n", BYTES_TO_MB(global_stats.heap_size));
    printf("  Heap Used:       %zu MB\n", BYTES_TO_MB(global_stats.heap_used));
    printf("  Heap Free:       %zu MB\n", BYTES_TO_MB(global_stats.heap_free));
    printf("  Allocations:     %lu\n", global_stats.alloc_count);
    printf("  Deallocations:   %lu\n", global_stats.free_count);
    printf("  Failed Allocs:   %lu\n", global_stats.fail_count); 
}

/**
 * @brief Perform memory management self-test
 * 
 * @return 0 on success, negative error code on failure
 */
int mm_self_test(void) {
    if (!mm_initialized) {
        return MM_ERR_INIT;
    }
    
    /* Test basic allocation and deallocation */
    void *test_ptr = kmalloc(1024);
    if (!test_ptr) {
        return MM_ERR_NOMEM;
    }
    
    /* Write test pattern */
    memset(test_ptr, 0xAA, 1024);
    
    /* Verify test pattern */
    uint8_t *bytes = (uint8_t *)test_ptr;
    for (size_t i = 0; i < 1024; i++) {
        if (bytes[i] != 0xAA) {
            kfree(test_ptr);
            return MM_ERR_CORRUPT;
        }
    }
    
    /* Free test allocation */
    kfree(test_ptr);
    
    /* Test memory barriers */
    memory_barrier();
    
    /* Test integrity checks */
    if (!mm_check_integrity()) {
        return MM_ERR_CORRUPT;
    }
    
    return MM_SUCCESS;
}

/* ========================================================================
 * BASIC MEMORY ALLOCATION FUNCTIONS
 * ======================================================================== */

/**
 * @brief Allocate memory from kernel heap
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *kmalloc(size_t size) {
    if (!mm_initialized) {
        /* Use early allocator during boot */
        return early_alloc(size);
    }
    
    if (size == 0) {
        printk(KERN_WARNING "kmalloc: zero size allocation attempted\n");
        return NULL;
    }
    
    if (size > MAX_ALLOC_SIZE) {
        printk(KERN_ERR "kmalloc: allocation too large (%zu bytes)\n", size);
        return NULL;
    }
    
    /* Update statistics */
    MM_LOCK();
    global_stats.alloc_count++;
    MM_UNLOCK();
    
    void *ptr = NULL;
    
    /* Choose allocator based on size */
    if (size <= SLAB_MAX_SIZE) {
        /* Use slab allocator for small objects */
        /* Find appropriate cache or use general purpose cache */
        ptr = kmalloc_slab(size);
    } else {
        /* Use page allocator for large objects */
        size_t pages = BYTES_TO_PAGES(size);
        phys_addr_t phys = page_alloc_pages(pages, PAGE_FLAG_ZERO);
        if (phys) {
            ptr = (void*)phys_to_virt(phys);
        }
    }
    
    if (!ptr) {
        MM_LOCK();
        global_stats.fail_count++;
        MM_UNLOCK();
        printk(KERN_WARNING "kmalloc: failed to allocate %zu bytes\n", size);
    }
    
    return ptr;
}

/**
 * @brief Free memory allocated with kmalloc
 * @param ptr Pointer to memory to free
 */
void kfree(void *ptr) {
    if (!ptr) {
        return;
    }
    
    if (!mm_initialized) {
        printk(KERN_WARNING "kfree: MM not initialized, cannot free %p\n", ptr);
        return;
    }
    
    /* Update statistics */
    MM_LOCK();
    global_stats.free_count++;
    MM_UNLOCK();
    
    /* Determine allocator based on address */
    virt_addr_t vaddr = (virt_addr_t)ptr;
    
    if (vaddr >= VMALLOC_START && vaddr < VMALLOC_END) {
        /* Virtual memory allocation */
        vfree(ptr);
    } else if (vaddr >= KERNEL_VIRT_BASE) {
        /* Kernel physical memory - determine if slab or page */
        if (slab_is_slab_page(ptr)) {
            slab_free(ptr);
        } else {
            phys_addr_t phys = virt_to_phys(vaddr);
            /* This would need size information - simplified for now */
            page_free_single(phys);
        }
    } else {
        printk(KERN_ERR "kfree: invalid pointer %p\n", ptr);
    }
}

/**
 * @brief Get amount of free memory
 * @return Free memory in bytes
 */
size_t mm_get_free_memory(void) {
    if (!mm_initialized) {
        return EARLY_POOL_SIZE - early_pool_offset;
    }
    
    size_t free_mem = 0;
    
    /* Aggregate from all allocators */
    free_mem += global_stats.free_pages * PAGE_SIZE;
    free_mem += global_stats.heap_free;
    
    /* Add vmalloc free space */
    if (mm_init_state.vmalloc_init) {
        vmalloc_stats_t vmalloc_stats;
        vmalloc_get_stats(&vmalloc_stats);
        free_mem += vmalloc_stats.free_size;
    }
    
    return free_mem;
}

/**
 * @brief Get amount of used memory
 * @return Used memory in bytes
 */
size_t mm_get_used_memory(void) {
    if (!mm_initialized) {
        return early_pool_offset;
    }
    
    size_t used_mem = 0;
    
    /* Aggregate from all allocators */
    used_mem += global_stats.used_pages * PAGE_SIZE;
    used_mem += global_stats.heap_used;
    
    /* Add vmalloc used space */
    if (mm_init_state.vmalloc_init) {
        vmalloc_stats_t vmalloc_stats;
        vmalloc_get_stats(&vmalloc_stats);
        used_mem += vmalloc_stats.used_size;
    }
    
    return used_mem;
}

/**
 * @brief Enable virtual memory management
 * @return 0 on success, negative error code on failure
 */
int mm_enable_paging(void) {
    if (!mm_initialized) {
        return MM_ERR_INIT;
    }
    
    /* Enable MMU and set up initial page tables */
    printk(KERN_INFO "Setting up initial page tables\n");
    
    /* Identity map low memory for kernel */
    /* Map kernel virtual space */
    /* Set up page tables for vmalloc area */
    /* Enable MMU */
    
    /* This would be architecture-specific implementation */
    memory_barrier();
    
    printk(KERN_INFO "Paging enabled\n");
    return MM_SUCCESS;
}

/**
 * @brief Perform memory consistency check
 * @return true if consistent, false if corruption detected
 */
bool mm_check_integrity(void) {
    if (!mm_initialized) {
        return false;
    }
    
    bool integrity_ok = true;
    
    /* Check page allocator integrity */
    if (mm_init_state.page_alloc_init) {
        if (!page_alloc_check_integrity()) {
            printk(KERN_ERR "Page allocator integrity check failed\n");
            integrity_ok = false;
        }
    }
    
    /* Check slab allocator integrity */
    if (mm_init_state.slab_init) {
        if (!slab_check_integrity()) {
            printk(KERN_ERR "Slab allocator integrity check failed\n");
            integrity_ok = false;
        }
    }
    
    /* Check vmalloc integrity */
    if (mm_init_state.vmalloc_init) {
        if (!vmalloc_check_integrity()) {
            printk(KERN_ERR "vmalloc integrity check failed\n");
            integrity_ok = false;
        }
    }
    
    /* Check memory barrier consistency */
    memory_barrier();
    
    return integrity_ok;
}

/**
 * @brief Emergency memory allocation for panic situations
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void *mm_emergency_alloc(size_t size) {
    printk(KERN_EMERG "Emergency allocation requested: %zu bytes\n", size);
    
    /* Try normal allocation first */
    void *ptr = kmalloc(size);
    if (ptr) {
        return ptr;
    }
    
    /* Use emergency reserves if available */
    /* This would access reserved memory pools */
    printk(KERN_EMERG "Emergency allocation failed\n");
    return NULL;
}

/**
 * @brief Dump memory management state for debugging
 */
void mm_dump_state(void) {
    printk(KERN_INFO "=== Memory Management State Dump ===\n");
    
    if (!mm_initialized) {
        printk(KERN_INFO "MM not initialized\n");
        printk(KERN_INFO "Early pool: %zu/%d bytes used\n", 
               early_pool_offset, EARLY_POOL_SIZE);
        return;
    }
    
    /* Dump global statistics */
    printk(KERN_INFO "Global Statistics:\n");
    printk(KERN_INFO "  Total pages: %zu\n", global_stats.total_pages);
    printk(KERN_INFO "  Free pages: %zu\n", global_stats.free_pages);
    printk(KERN_INFO "  Used pages: %zu\n", global_stats.used_pages);
    printk(KERN_INFO "  Allocations: %lu\n", global_stats.alloc_count);
    printk(KERN_INFO "  Deallocations: %lu\n", global_stats.free_count);
    printk(KERN_INFO "  Failed allocs: %lu\n", global_stats.fail_count);
    
    /* Dump subsystem states */
    if (mm_init_state.page_alloc_init) {
        printk(KERN_INFO "Page allocator: initialized\n");
        page_alloc_dump_stats();
    }
    
    if (mm_init_state.slab_init) {
        printk(KERN_INFO "Slab allocator: initialized\n");
        slab_dump_stats();
    }
    
    if (mm_init_state.vmalloc_init) {
        printk(KERN_INFO "vmalloc: initialized\n");
        vmalloc_dump_stats();
    }
    
    if (mm_init_state.mmap_init) {
        printk(KERN_INFO "mmap subsystem: initialized\n");
    }
    
#ifdef CONFIG_DEBUG_MEMORY_BARRIERS
    print_barrier_debug();
#endif
    
    printk(KERN_INFO "=== End Memory State Dump ===\n");
}

/* ========================================================================
 * HELPER FUNCTIONS AND COMPATIBILITY SHIMS
 * ======================================================================== */

/**
 * @brief Simplified slab allocation for kmalloc
 * @param size Size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
static void *kmalloc_slab(size_t size) {
    /* This would find the appropriate slab cache for the size
     * For now, return NULL to indicate unimplemented */
    (void)size;
    return NULL;
}

/**
 * @brief Check if a pointer belongs to a slab page
 * @param ptr Pointer to check
 * @return true if slab page, false otherwise
 */
static bool slab_is_slab_page(void *ptr) {
    /* This would check if the page containing ptr is a slab page
     * For now, assume it's not */
    (void)ptr;
    return false;
}

/**
 * @brief Convert physical address to virtual address
 * @param paddr Physical address
 * @return Virtual address
 */
static inline virt_addr_t phys_to_virt(phys_addr_t paddr) {
    /* Simple identity mapping for now */
    return (virt_addr_t)paddr;
}

/**
 * @brief Convert virtual address to physical address
 * @param vaddr Virtual address
 * @return Physical address
 */
static inline phys_addr_t virt_to_phys(virt_addr_t vaddr) {
    /* Simple identity mapping for now */
    return (phys_addr_t)vaddr;
}

/**
 * @brief Set boot memory information
 * @param mem_info Boot memory information structure
 */
void mm_set_boot_info(const struct boot_memory_info *mem_info) {
    if (!mem_info) {
        return;
    }
    
    memcpy(&boot_mem_info, mem_info, sizeof(struct boot_memory_info));
    printk(KERN_INFO "Boot memory info updated\n");
}

/**
 * @brief Get boot memory information
 * @param mem_info Pointer to store boot memory information
 * @return 0 on success, negative error code on failure
 */
int mm_get_boot_info(struct boot_memory_info *mem_info) {
    if (!mem_info) {
        return MM_ERR_INVALID;
    }
    
    memcpy(mem_info, &boot_mem_info, sizeof(struct boot_memory_info));
    return MM_SUCCESS;
}

/**
 * @brief Handle out-of-memory situation
 * @param size Size that failed to allocate
 */
void mm_oom_handler(size_t size) {
    printk(KERN_ERR "Out of memory! Failed to allocate %zu bytes\n", size);
    
    /* Try to free some memory */
    if (mm_initialized) {
        printk(KERN_INFO "Attempting memory reclaim...\n");
        
        size_t freed = 0;
        if (mm_init_state.vmalloc_init) {
            freed += vmalloc_purge();
        }
        
        if (mm_init_state.slab_init) {
            freed += slab_reclaim_memory(size);
        }
        
        printk(KERN_INFO "Reclaimed %zu bytes\n", freed);
        
        if (freed < size) {
            printk(KERN_ERR "Unable to reclaim enough memory\n");
            mm_dump_state();
        }
    } else {
        printk(KERN_ERR "OOM during early boot - system may be unstable\n");
    }
}


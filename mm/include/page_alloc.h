/**
 * @file page_alloc.h
 * @brief Page-based memory allocator interface
 * 
 * This header defines the interface for the LeaxOS kernel's page-based
 * memory allocator. It provides low-level page allocation and deallocation
 * functions for physical memory management.
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_PAGE_ALLOC_H
#define LEAX_KERNEL_MM_PAGE_ALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"

/* Forward declarations */
typedef uintptr_t phys_addr_t;
typedef size_t pages_t;
typedef uint32_t page_flags_t;

/* Page size definitions */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096U
#endif
#define PAGE_SHIFT 12U
#define PAGE_MASK (PAGE_SIZE - 1U)

/* Page allocation flags */
#define PAGE_FLAG_ZERO      0x01U  /**< Zero-initialize the allocated pages */
#define PAGE_FLAG_DMA       0x02U  /**< Allocate DMA-capable memory */
#define PAGE_FLAG_ATOMIC    0x04U  /**< Atomic allocation (no blocking) */
#define PAGE_FLAG_HIGHMEM   0x08U  /**< Allow high memory allocation */
#define PAGE_FLAG_LOWMEM    0x10U  /**< Force low memory allocation */
#define PAGE_FLAG_URGENT    0x20U  /**< Urgent allocation priority */

/* Memory zones */
typedef enum {
    ZONE_DMA,       /**< DMA-capable memory (0-16MB) */
    ZONE_NORMAL,    /**< Normal memory */
    ZONE_HIGHMEM,   /**< High memory (above 896MB on 32-bit) */
    ZONE_COUNT      /**< Number of memory zones */
} memory_zone_t;

/* Page allocation orders (power of 2) */
#define MAX_ORDER 11    /**< Maximum allocation order (2^11 = 2048 pages) */

/* Page frame structure */
typedef struct page_frame {
    phys_addr_t phys_addr;      /**< Physical address of the page */
    uint32_t ref_count;         /**< Reference counter */
    uint32_t flags;             /**< Page flags */
    struct page_frame *next;    /**< Next page in free list */
    struct page_frame *prev;    /**< Previous page in free list */
} page_frame_t;

/* Memory statistics */
typedef struct page_stats {
    size_t total_pages;         /**< Total number of pages */
    size_t free_pages;          /**< Number of free pages */
    size_t used_pages;          /**< Number of allocated pages */
    size_t reserved_pages;      /**< Number of reserved pages */
    size_t dma_pages;          /**< Number of DMA pages */
    size_t cached_pages;       /**< Number of cached pages */
} page_stats_t;

/* Page allocator configuration */
typedef struct page_config {
    phys_addr_t start_addr;     /**< Start of managed memory */
    phys_addr_t end_addr;       /**< End of managed memory */
    size_t total_pages;         /**< Total pages to manage */
    bool enable_debugging;      /**< Enable debug mode */
    size_t min_free_pages;      /**< Minimum free pages threshold */
} page_config_t;

/**
 * @brief Initialize the page allocator
 * @param config Configuration parameters
 * @return 0 on success, negative error code on failure
 */
int page_alloc_init(const page_config_t *config);

/**
 * @brief Shutdown the page allocator
 */
void page_alloc_shutdown(void);

/**
 * @brief Allocate a single page
 * @param flags Allocation flags
 * @return Physical address of allocated page, or 0 on failure
 */
phys_addr_t page_alloc_single(page_flags_t flags);

/**
 * @brief Allocate multiple contiguous pages
 * @param count Number of pages to allocate
 * @param flags Allocation flags
 * @return Physical address of first page, or 0 on failure
 */
phys_addr_t page_alloc_pages(pages_t count, page_flags_t flags);

/**
 * @brief Allocate pages with specific order (power of 2)
 * @param order Allocation order (0 = 1 page, 1 = 2 pages, etc.)
 * @param flags Allocation flags
 * @return Physical address of first page, or 0 on failure
 */
phys_addr_t page_alloc_order(unsigned int order, page_flags_t flags);

/**
 * @brief Allocate pages from specific memory zone
 * @param count Number of pages to allocate
 * @param zone Target memory zone
 * @param flags Allocation flags
 * @return Physical address of first page, or 0 on failure
 */
phys_addr_t page_alloc_zone(pages_t count, memory_zone_t zone, page_flags_t flags);

/**
 * @brief Free a single page
 * @param paddr Physical address of page to free
 */
void page_free_single(phys_addr_t paddr);

/**
 * @brief Free multiple contiguous pages
 * @param paddr Physical address of first page
 * @param count Number of pages to free
 */
void page_free_pages(phys_addr_t paddr, pages_t count);

/**
 * @brief Free pages allocated with specific order
 * @param paddr Physical address of first page
 * @param order Allocation order used
 */
void page_free_order(phys_addr_t paddr, unsigned int order);

/**
 * @brief Get page frame information
 * @param paddr Physical address
 * @return Pointer to page frame structure, or NULL if invalid
 */
page_frame_t *page_get_frame(phys_addr_t paddr);

/**
 * @brief Increment page reference count
 * @param paddr Physical address
 * @return New reference count, or 0 on error
 */
uint32_t page_ref_inc(phys_addr_t paddr);

/**
 * @brief Decrement page reference count
 * @param paddr Physical address
 * @return New reference count, or 0 on error
 */
uint32_t page_ref_dec(phys_addr_t paddr);

/**
 * @brief Get page reference count
 * @param paddr Physical address
 * @return Reference count, or 0 if invalid
 */
uint32_t page_ref_count(phys_addr_t paddr);

/**
 * @brief Check if page is allocated
 * @param paddr Physical address
 * @return true if allocated, false otherwise
 */
bool page_is_allocated(phys_addr_t paddr);

/**
 * @brief Check if page is free
 * @param paddr Physical address
 * @return true if free, false otherwise
 */
bool page_is_free(phys_addr_t paddr);

/**
 * @brief Get memory statistics
 * @param stats Pointer to statistics structure to fill
 */
void page_get_stats(page_stats_t *stats);

/**
 * @brief Get number of free pages
 * @return Number of free pages
 */
size_t page_get_free_count(void);

/**
 * @brief Get number of used pages
 * @return Number of allocated pages
 */
size_t page_get_used_count(void);

/**
 * @brief Get total number of managed pages
 * @return Total number of pages
 */
size_t page_get_total_count(void);

/**
 * @brief Get free pages in specific zone
 * @param zone Target memory zone
 * @return Number of free pages in zone
 */
size_t page_get_zone_free(memory_zone_t zone);

/**
 * @brief Reserve pages (mark as unusable)
 * @param paddr Physical address of first page
 * @param count Number of pages to reserve
 * @return 0 on success, negative error code on failure
 */
int page_reserve_pages(phys_addr_t paddr, pages_t count);

/**
 * @brief Unreserve pages (mark as available)
 * @param paddr Physical address of first page
 * @param count Number of pages to unreserve
 * @return 0 on success, negative error code on failure
 */
int page_unreserve_pages(phys_addr_t paddr, pages_t count);

/**
 * @brief Defragment memory (coalesce free pages)
 * @return Number of pages coalesced
 */
size_t page_defragment(void);

/**
 * @brief Check allocator integrity
 * @return true if consistent, false if corruption detected
 */
bool page_check_integrity(void);

/**
 * @brief Print allocator debug information
 */
void page_print_debug(void);

/**
 * @brief Set low memory threshold
 * @param threshold Minimum free pages before warning
 */
void page_set_low_threshold(size_t threshold);

/**
 * @brief Get current low memory threshold
 * @return Current threshold value
 */
size_t page_get_low_threshold(void);

/**
 * @brief Check if system is in low memory condition
 * @return true if low on memory, false otherwise
 */
bool page_is_low_memory(void);

/* Utility macros */
#define PAGE_ALIGN_UP(addr)     (((addr) + PAGE_MASK) & ~PAGE_MASK)
#define PAGE_ALIGN_DOWN(addr)   ((addr) & ~PAGE_MASK)
#define PAGE_OFFSET(addr)       ((addr) & PAGE_MASK)
#define ADDR_TO_PAGE_NUM(addr)  ((addr) >> PAGE_SHIFT)
#define PAGE_NUM_TO_ADDR(page)  ((page) << PAGE_SHIFT)
#define IS_PAGE_ALIGNED(addr)   (((addr) & PAGE_MASK) == 0)
#define PAGES_TO_BYTES(pages)   ((pages) << PAGE_SHIFT)
#define BYTES_TO_PAGES(bytes)   (((bytes) + PAGE_MASK) >> PAGE_SHIFT)

/* Error codes */
#define PAGE_ERR_SUCCESS        0    /**< Success */
#define PAGE_ERR_NOMEM         -1    /**< Out of memory */
#define PAGE_ERR_INVALID       -2    /**< Invalid parameter */
#define PAGE_ERR_BUSY          -3    /**< Resource busy */
#define PAGE_ERR_NOTFOUND      -4    /**< Page not found */
#define PAGE_ERR_CORRUPTED     -5    /**< Data corruption detected */
#define PAGE_ERR_INIT          -6    /**< Initialization failed */

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_PAGE_ALLOC_H */
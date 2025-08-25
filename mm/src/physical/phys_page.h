/**
 * @file phys_page.h
 * @brief Structures et définitions pour les pages physiques
 */

#ifndef PHYS_PAGE_H
#define PHYS_PAGE_H

#include "../../../Include/stdint.h"
#include "../../../Include/stddef.h"

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define PAGE_MASK (~(PAGE_SIZE - 1))

/**
 * @brief Flags pour les pages physiques
 */
typedef enum {
    PAGE_FLAG_RESERVED  = (1 << 0),  ///< Page réservée
    PAGE_FLAG_USED      = (1 << 1),  ///< Page utilisée
    PAGE_FLAG_DMA_PAGE  = (1 << 2),  ///< Page utilisable pour DMA
    PAGE_FLAG_KERNEL    = (1 << 3),  ///< Page du kernel
    PAGE_FLAG_USER      = (1 << 4),  ///< Page utilisateur
} page_flags_t;

/**
 * @brief Structure représentant une page physique
 */
typedef struct page {
    uint32_t flags;                 ///< Flags de la page
    uint32_t ref_count;            ///< Compteur de références
    struct page* next;             ///< Page suivante (liste libre)
    struct page* prev;             ///< Page précédente
    void* private_data;            ///< Données privées
} page_t;

/**
 * @brief Zones de mémoire
 */
typedef enum {
    ZONE_DMA,       ///< Zone DMA (< 16MB)
    ZONE_NORMAL,    ///< Zone normale (16MB - 896MB)
    ZONE_HIGH,      ///< Zone haute (> 896MB)
    ZONE_COUNT
} memory_zone_t;

/* Macros utilitaires */
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define PAGE_ALIGN_DOWN(addr) ((addr) & PAGE_MASK)
#define ADDR_TO_PAGE(addr) ((addr) >> PAGE_SHIFT)
#define PAGE_TO_ADDR(page) ((page) << PAGE_SHIFT)

/* Prototypes */
page_t* addr_to_page(uint64_t addr);
uint64_t page_to_addr(page_t* page);
void page_set_flag(page_t* page, page_flags_t flag);
void page_clear_flag(page_t* page, page_flags_t flag);
bool page_has_flag(page_t* page, page_flags_t flag);

#endif /* PHYS_PAGE_H */

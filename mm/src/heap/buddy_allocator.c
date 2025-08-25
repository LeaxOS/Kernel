/**
 * @file buddy_allocator.c
 * @brief Implémentation du Buddy System pour LeaxOS
 * 
 * Le Buddy System est un algorithme d'allocation de pages qui maintient
 * des listes libres de blocs de tailles exponentielles (2^n pages).
 * Il permet une allocation et libération efficaces tout en minimisant
 * la fragmentation externe.
 * 
 * Fonctionnalités principales:
 * - Allocation de blocs de 2^n pages (n = 0 à MAX_ORDER-1)
 * - Fusion automatique des blocs libres adjacents
 * - Gestion de zones mémoire multiples (DMA, Normal, HighMem)
 * - Anti-fragmentation avec types de migration
 * - Statistiques détaillées et monitoring
 * - Support pour allocations urgentes et atomiques
 * - Watermarks et gestion de la pression mémoire
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#include "../../../Include/stdint.h"
#include "../../../Include/stddef.h"
#include "../../../Include/stdbool.h"
#include "../../../Include/string.h"
#include "../../../Include/stdio.h"
#include "../../include/mm_common.h"
#include "../../include/mm.h"
#include "../../include/page_alloc.h"


/* ========================================================================
 * BUDDY ALLOCATOR CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/* Configuration du Buddy System */
#define MAX_ORDER               11      /* Ordre max: 2^10 = 1024 pages */
#define BUDDY_MAX_ZONES         4       /* Zones max */
#define PAGES_PER_SECTION       256     /* Pages par section */

/* Types de zones mémoire */
#define ZONE_DMA                0       /* Zone DMA (< 16MB) */
#define ZONE_DMA32              1       /* Zone DMA32 (< 4GB) */
#define ZONE_NORMAL             2       /* Zone normale */
#define ZONE_HIGHMEM            3       /* High memory */

/* Types de migration pour anti-fragmentation */
#define MIGRATE_UNMOVABLE       0       /* Non déplaçable */
#define MIGRATE_MOVABLE         1       /* Déplaçable */
#define MIGRATE_RECLAIMABLE     2       /* Récupérable */
#define MIGRATE_PCPTYPES        3       /* Types PCP */
#define MIGRATE_RESERVE         3       /* Réserve */
#define MIGRATE_ISOLATE         4       /* Isolé */
#define MIGRATE_TYPES           5       /* Nombre de types */

/* Flags d'allocation */
#define GFP_DMA                 0x01    /* Allocation DMA */
#define GFP_HIGHMEM             0x02    /* Allocation high memory */
#define GFP_ATOMIC              0x04    /* Allocation atomique */
#define GFP_KERNEL              0x08    /* Allocation kernel */
#define GFP_USER                0x10    /* Allocation user */
#define GFP_NOWAIT              0x20    /* Ne pas attendre */
#define GFP_NORETRY             0x40    /* Ne pas réessayer */
#define GFP_NOFAIL              0x80    /* Ne doit pas échouer */

/* États des pages */
#define PG_RESERVED             0x01    /* Page réservée */
#define PG_PRIVATE              0x02    /* Page privée */
#define PG_LOCKED               0x04    /* Page verrouillée */
#define PG_BUDDY                0x08    /* Page dans buddy system */
#define PG_COMPOUND             0x10    /* Page composée */
#define PG_HEAD                 0x20    /* Tête de page composée */
#define PG_TAIL                 0x40    /* Queue de page composée */

/* Watermarks */
#define WMARK_MIN               0       /* Watermark minimum */
#define WMARK_LOW               1       /* Watermark bas */
#define WMARK_HIGH              2       /* Watermark haut */
#define NR_WMARK                3       /* Nombre de watermarks */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Structure d'une page physique
 */
typedef struct page {
    uint32_t flags;                     /* Flags de la page */
    uint32_t private;                   /* Données privées */
    
    union {
        struct {
            struct page *next;          /* Prochaine page dans la liste libre */
            uint8_t order;              /* Ordre de la page dans buddy */
            uint8_t migratetype;        /* Type de migration */
        } buddy;
        
        struct {
            void *s_mem;                /* Mémoire du slab */
            uint16_t inuse;             /* Objets en cours d'usage */
            uint16_t objects;           /* Objets totaux */
        } slab;
    };
    
    uint64_t pfn;                       /* Page Frame Number */
    
} page_t;

/**
 * @brief Liste libre pour un ordre donné
 */
typedef struct free_area {
    struct page *free_list[MIGRATE_TYPES];  /* Listes par type de migration */
    uint32_t nr_free;                   /* Nombre de pages libres */
} free_area_t;

/**
 * @brief Zone mémoire
 */
typedef struct zone {
    /* Identification */
    char name[16];                      /* Nom de la zone */
    uint8_t zone_idx;                   /* Index de la zone */
    
    /* Limites physiques */
    uint64_t zone_start_pfn;            /* PFN de début */
    uint64_t zone_end_pfn;              /* PFN de fin */
    uint64_t spanned_pages;             /* Pages totales */
    uint64_t present_pages;             /* Pages présentes */
    uint64_t managed_pages;             /* Pages gérées */
    
    /* Buddy allocator */
    free_area_t free_area[MAX_ORDER];   /* Aires libres par ordre */
    
    /* Watermarks */
    uint64_t watermark[NR_WMARK];       /* Watermarks de la zone */
    uint64_t lowmem_reserve[BUDDY_MAX_ZONES]; /* Réserves low memory */
    
    /* Statistiques */
    uint64_t vm_stat[NR_VM_ZONE_STAT_ITEMS]; /* Statistiques VM */
    uint64_t nr_free_pages;             /* Pages libres totales */
    
    /* Anti-fragmentation */
    uint64_t min_unmovable_pages;       /* Pages unmovable min */
    uint64_t min_slab_pages;            /* Pages slab min */
    
    /* Per-CPU pages */
    struct per_cpu_pages __percpu *pageset; /* Pages per-CPU */
    
    /* État de la zone */
    bool enabled;                       /* Zone activée */
    bool all_unreclaimable;             /* Tout non récupérable */
    
} zone_t;

/**
 * @brief Pages per-CPU pour optimiser les allocations fréquentes
 */
typedef struct per_cpu_pages {
    int count;                          /* Nombre de pages */
    int high;                           /* Seuil haut */
    int low;                            /* Seuil bas */
    int batch;                          /* Taille de batch */
    struct page *lists[MIGRATE_PCPTYPES]; /* Listes par type */
} per_cpu_pages_t;

/**
 * @brief Nœud NUMA (Node)
 */
typedef struct pglist_data {
    zone_t node_zones[BUDDY_MAX_ZONES]; /* Zones du nœud */
    uint32_t nr_zones;                  /* Nombre de zones */
    uint64_t node_start_pfn;            /* PFN de début du nœud */
    uint64_t node_present_pages;        /* Pages présentes */
    uint64_t node_spanned_pages;        /* Pages totales */
    int node_id;                        /* ID du nœud */
} pglist_data_t;

/**
 * @brief Gestionnaire global du Buddy System
 */
typedef struct buddy_allocator {
    /* Nœuds NUMA */
    pglist_data_t *node_data[MAX_NUMNODES]; /* Nœuds */
    uint32_t nr_online_nodes;           /* Nœuds en ligne */
    
    /* Configuration globale */
    uint64_t totalram_pages;            /* Pages RAM totales */
    uint64_t totalhigh_pages;           /* Pages high memory totales */
    uint64_t totalreserve_pages;        /* Pages réservées totales */
    
    /* Seuils globaux */
    uint64_t min_free_kbytes;           /* KB libres minimum */
    uint64_t extra_free_kbytes;         /* KB libres supplémentaires */
    
    /* Anti-fragmentation */
    bool page_group_by_mobility_disabled; /* Groupement par mobilité désactivé */
    uint32_t pageblock_order;           /* Ordre des blocs de pages */
    
    /* Statistiques globales */
    uint64_t nr_alloc_calls;            /* Appels d'allocation */
    uint64_t nr_free_calls;             /* Appels de libération */
    uint64_t nr_alloc_pages;            /* Pages allouées */
    uint64_t nr_freed_pages;            /* Pages libérées */
    uint64_t nr_failed_allocs;          /* Allocations échouées */
    uint64_t nr_compaction_runs;        /* Compactages effectués */
    
} buddy_allocator_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Gestionnaire principal */
static buddy_allocator_t buddy_allocator;
static bool buddy_initialized = false;

/* Configuration par défaut */
static bool debug_buddy = false;
static uint64_t min_free_kbytes = 16384;   /* 16MB par défaut */

/* Nœud principal (pour systèmes non-NUMA) */
static pglist_data_t contig_page_data;

/* Synchronization */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
static mm_spinlock_t zone_locks[BUDDY_MAX_ZONES] = {MM_SPINLOCK_INIT("unknown"), MM_SPINLOCK_INIT("unknown"), MM_SPINLOCK_INIT("unknown"), MM_SPINLOCK_INIT("unknown")};
#define ZONE_LOCK(zone) mm_spin_lock(&zone_locks[(zone)->zone_idx])
#define ZONE_UNLOCK(zone) mm_spin_unlock(&zone_locks[(zone)->zone_idx])
#else
#define ZONE_LOCK(zone) do {} while(0)
#define ZONE_UNLOCK(zone) do {} while(0)
#endif

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Calcule l'adresse buddy d'une page
 * @param page_idx Index de la page
 * @param order Ordre d'allocation
 * @return Index de la page buddy
 */
static uint64_t __find_buddy_index(uint64_t page_idx, uint32_t order) {
    return page_idx ^ (1ULL << order);
}

/**
 * @brief Vérifie si deux pages sont buddies
 * @param page_idx1 Index de la première page
 * @param page_idx2 Index de la seconde page
 * @param order Ordre d'allocation
 * @return true si elles sont buddies
 */
static bool page_is_buddy(uint64_t page_idx1, uint64_t page_idx2, uint32_t order) {
    uint64_t buddy_idx = __find_buddy_index(page_idx1, order);
    return buddy_idx == page_idx2;
}

/**
 * @brief Obtient la page à partir d'un PFN
 * @param pfn Page Frame Number
 * @return Pointeur vers page ou NULL
 */
static page_t *pfn_to_page(uint64_t pfn) {
    /* Implémentation simplifiée - dans un vrai kernel,
     * on utiliserait une table de correspondance */
    static page_t pages[1024 * 1024]; /* 1M pages max pour test */
    
    if (pfn < sizeof(pages) / sizeof(pages[0])) {
        return &pages[pfn];
    }
    
    return NULL;
}

/**
 * @brief Obtient le PFN à partir d'une page
 * @param page Pointeur vers page
 * @return Page Frame Number
 */
static uint64_t page_to_pfn(page_t *page) {
    return page->pfn;
}

/**
 * @brief Convertit l'ordre en nombre de pages
 * @param order Ordre d'allocation
 * @return Nombre de pages
 */
static uint64_t order_to_pages(uint32_t order) {
    return 1ULL << order;
}

/**
 * @brief Trouve l'ordre minimum pour contenir n pages
 * @param pages Nombre de pages
 * @return Ordre minimum
 */
static uint32_t get_order(uint64_t pages) {
    uint32_t order = 0;
    uint64_t size = 1;
    
    while (size < pages && order < MAX_ORDER - 1) {
        size <<= 1;
        order++;
    }
    
    return order;
}

/* ========================================================================
 * FREE AREA MANAGEMENT
 * ======================================================================== */

/**
 * @brief Ajoute une page à une liste libre
 * @param zone Zone cible
 * @param page Page à ajouter
 * @param order Ordre de la page
 * @param migratetype Type de migration
 */
static void add_to_free_area(zone_t *zone, page_t *page, uint32_t order, 
                            uint8_t migratetype) {
    free_area_t *area = &zone->free_area[order];
    
    /* Ajouter en tête de liste */
    page->buddy.next = area->free_list[migratetype];
    area->free_list[migratetype] = page;
    page->buddy.order = order;
    page->buddy.migratetype = migratetype;
    page->flags |= PG_BUDDY;
    
    area->nr_free++;
    zone->nr_free_pages += order_to_pages(order);
    
    if (debug_buddy) {
        printk(KERN_DEBUG "Added page pfn=%llu to free area order=%u, type=%u\n",
               page->pfn, order, migratetype);
    }
}

/**
 * @brief Retire une page d'une liste libre
 * @param zone Zone source
 * @param page Page à retirer
 * @param order Ordre de la page
 * @param migratetype Type de migration
 */
static void del_from_free_area(zone_t *zone, page_t *page, uint32_t order,
                              uint8_t migratetype) {
    free_area_t *area = &zone->free_area[order];
    page_t **current = &area->free_list[migratetype];
    
    /* Chercher et retirer la page */
    while (*current && *current != page) {
        current = &(*current)->buddy.next;
    }
    
    if (*current) {
        *current = page->buddy.next;
        page->buddy.next = NULL;
        page->flags &= ~PG_BUDDY;
        
        area->nr_free--;
        zone->nr_free_pages -= order_to_pages(order);
        
        if (debug_buddy) {
            printk(KERN_DEBUG "Removed page pfn=%llu from free area order=%u, type=%u\n",
                   page->pfn, order, migratetype);
        }
    }
}

/**
 * @brief Trouve une page libre dans une zone
 * @param zone Zone à chercher
 * @param order Ordre désiré
 * @param migratetype Type de migration
 * @return Pointeur vers page ou NULL
 */
static page_t *find_free_page(zone_t *zone, uint32_t order, uint8_t migratetype) {
    /* Chercher dans l'ordre demandé d'abord */
    for (uint32_t current_order = order; current_order < MAX_ORDER; current_order++) {
        free_area_t *area = &zone->free_area[current_order];
        
        /* Chercher le type de migration demandé */
        if (area->free_list[migratetype]) {
            return area->free_list[migratetype];
        }
        
        /* Chercher dans d'autres types si nécessaire */
        for (uint8_t type = 0; type < MIGRATE_TYPES; type++) {
            if (type != migratetype && area->free_list[type]) {
                return area->free_list[type];
            }
        }
    }
    
    return NULL;
}

/* ========================================================================
 * PAGE SPLITTING AND MERGING
 * ======================================================================== */

/**
 * @brief Divise une page en pages plus petites
 * @param zone Zone contenant la page
 * @param page Page à diviser
 * @param low_order Ordre final désiré
 * @param current_order Ordre actuel
 * @param migratetype Type de migration
 */
static void expand_page(zone_t *zone, page_t *page, uint32_t low_order,
                       uint32_t current_order, uint8_t migratetype) {
    uint64_t size = order_to_pages(current_order);
    uint64_t pfn = page_to_pfn(page);
    
    while (current_order > low_order) {
        current_order--;
        size >>= 1;
        
        /* La seconde moitié devient libre */
        page_t *buddy_page = pfn_to_page(pfn + size);
        add_to_free_area(zone, buddy_page, current_order, migratetype);
        
        if (debug_buddy) {
            printk(KERN_DEBUG "Split page pfn=%llu, new buddy pfn=%llu, order=%u\n",
                   pfn, pfn + size, current_order);
        }
    }
}

/**
 * @brief Fusionne une page avec son buddy si possible
 * @param zone Zone contenant la page
 * @param page Page à fusionner
 * @param order Ordre actuel
 * @param migratetype Type de migration
 * @return Nouvelle page fusionnée ou page originale
 */
static page_t *coalesce_page(zone_t *zone, page_t *page, uint32_t order,
                            uint8_t migratetype) {
    uint64_t pfn = page_to_pfn(page);
    uint64_t buddy_pfn;
    page_t *buddy_page;
    page_t *combined_page;
    
    while (order < MAX_ORDER - 1) {
        buddy_pfn = __find_buddy_index(pfn, order);
        buddy_page = pfn_to_page(buddy_pfn);
        
        /* Vérifier si le buddy est libre et du même type */
        if (!buddy_page || !(buddy_page->flags & PG_BUDDY) ||
            buddy_page->buddy.order != order ||
            buddy_page->buddy.migratetype != migratetype) {
            break;
        }
        
        /* Retirer le buddy de sa liste libre */
        del_from_free_area(zone, buddy_page, order, migratetype);
        
        /* La page combinée est celle avec le PFN le plus bas */
        combined_page = (pfn < buddy_pfn) ? page : buddy_page;
        pfn = page_to_pfn(combined_page);
        order++;
        
        if (debug_buddy) {
            printk(KERN_DEBUG "Coalesced pages pfn=%llu and pfn=%llu into order=%u\n",
                   page_to_pfn(page), buddy_pfn, order);
        }
        
        page = combined_page;
    }
    
    return page;
}

/* ========================================================================
 * ZONE SELECTION
 * ======================================================================== */

/**
 * @brief Sélectionne la zone appropriée pour une allocation
 * @param gfp_mask Flags d'allocation
 * @param node_id ID du nœud NUMA
 * @return Pointeur vers zone ou NULL
 */
static zone_t *select_zone(uint32_t gfp_mask, int node_id) {
    pglist_data_t *node = buddy_allocator.node_data[node_id];
    
    if (!node) {
        node = &contig_page_data;
    }
    
    /* Sélection selon les flags */
    if (gfp_mask & GFP_DMA) {
        return &node->node_zones[ZONE_DMA];
    } else if (gfp_mask & GFP_HIGHMEM) {
        return &node->node_zones[ZONE_HIGHMEM];
    } else {
        return &node->node_zones[ZONE_NORMAL];
    }
}

/**
 * @brief Détermine le type de migration pour une allocation
 * @param gfp_mask Flags d'allocation
 * @return Type de migration
 */
static uint8_t gfpflags_to_migratetype(uint32_t gfp_mask) {
    if (gfp_mask & GFP_KERNEL) {
        return MIGRATE_UNMOVABLE;
    } else if (gfp_mask & GFP_USER) {
        return MIGRATE_MOVABLE;
    } else {
        return MIGRATE_RECLAIMABLE;
    }
}

/* ========================================================================
 * WATERMARK CHECKING
 * ======================================================================== */

/**
 * @brief Vérifie les watermarks d'une zone
 * @param zone Zone à vérifier
 * @param order Ordre d'allocation
 * @param mark Watermark à vérifier
 * @return true si les watermarks sont OK
 */
static bool zone_watermark_ok(zone_t *zone, uint32_t order, uint64_t mark) {
    uint64_t free_pages = zone->nr_free_pages;
    uint64_t min = mark;
    
    /* Tenir compte de l'ordre d'allocation */
    if (order > 0) {
        min += (1ULL << order);
    }
    
    if (free_pages <= min) {
        return false;
    }
    
    /* Vérifier qu'il y a assez de pages dans les ordres inférieurs */
    uint64_t free_pages_check = 0;
    for (uint32_t o = 0; o < order; o++) {
        free_pages_check += zone->free_area[o].nr_free << o;
    }
    
    return free_pages_check >= min;
}

/* ========================================================================
 * MAIN ALLOCATION FUNCTIONS
 * ======================================================================== */

/**
 * @brief Alloue des pages depuis une zone
 * @param zone Zone source
 * @param order Ordre d'allocation
 * @param gfp_mask Flags d'allocation
 * @return Pointeur vers première page ou NULL
 */
static page_t *rmqueue_zone(zone_t *zone, uint32_t order, uint32_t gfp_mask) {
    uint8_t migratetype = gfpflags_to_migratetype(gfp_mask);
    page_t *page;
    
    ZONE_LOCK(zone);
    
    /* Vérifier les watermarks */
    if (!zone_watermark_ok(zone, order, zone->watermark[WMARK_LOW])) {
        ZONE_UNLOCK(zone);
        return NULL;
    }
    
    /* Chercher une page libre */
    page = find_free_page(zone, order, migratetype);
    if (!page) {
        ZONE_UNLOCK(zone);
        return NULL;
    }
    
    /* Retirer la page de la liste libre */
    del_from_free_area(zone, page, page->buddy.order, page->buddy.migratetype);
    
    /* Diviser si nécessaire */
    if (page->buddy.order > order) {
        expand_page(zone, page, order, page->buddy.order, migratetype);
    }
    
    /* Marquer la page comme allouée */
    page->flags &= ~PG_BUDDY;
    page->buddy.order = order;
    
    ZONE_UNLOCK(zone);
    
    /* Mettre à jour les statistiques */
    buddy_allocator.nr_alloc_pages += order_to_pages(order);
    
    if (debug_buddy) {
        printk(KERN_DEBUG "Allocated page pfn=%llu, order=%u from zone %s\n",
               page->pfn, order, zone->name);
    }
    
    return page;
}

/**
 * @brief Alloue des pages avec fallback sur d'autres zones
 * @param order Ordre d'allocation
 * @param gfp_mask Flags d'allocation
 * @param node_id ID du nœud NUMA
 * @return Pointeur vers première page ou NULL
 */
static page_t *__alloc_pages(uint32_t order, uint32_t gfp_mask, int node_id) {
    zone_t *preferred_zone = select_zone(gfp_mask, node_id);
    page_t *page;
    
    if (!preferred_zone || !preferred_zone->enabled) {
        buddy_allocator.nr_failed_allocs++;
        return NULL;
    }
    
    /* Essayer la zone préférée */
    page = rmqueue_zone(preferred_zone, order, gfp_mask);
    if (page) {
        return page;
    }
    
    /* Fallback sur d'autres zones si pas d'allocation DMA stricte */
    if (!(gfp_mask & GFP_DMA)) {
        pglist_data_t *node = buddy_allocator.node_data[node_id];
        if (!node) {
            node = &contig_page_data;
        }
        
        for (uint32_t i = 0; i < node->nr_zones; i++) {
            zone_t *zone = &node->node_zones[i];
            
            if (zone != preferred_zone && zone->enabled) {
                page = rmqueue_zone(zone, order, gfp_mask);
                if (page) {
                    return page;
                }
            }
        }
    }
    
    buddy_allocator.nr_failed_allocs++;
    return NULL;
}

/**
 * @brief Libère des pages vers une zone
 * @param zone Zone de destination
 * @param page Première page à libérer
 * @param order Ordre de libération
 */
static void __free_pages_zone(zone_t *zone, page_t *page, uint32_t order) {
    uint8_t migratetype = page->buddy.migratetype;
    
    ZONE_LOCK(zone);
    
    /* Fusionner avec les buddies */
    page = coalesce_page(zone, page, order, migratetype);
    
    /* Ajouter à la liste libre */
    add_to_free_area(zone, page, page->buddy.order, migratetype);
    
    ZONE_UNLOCK(zone);
    
    /* Mettre à jour les statistiques */
    buddy_allocator.nr_freed_pages += order_to_pages(order);
    
    if (debug_buddy) {
        printk(KERN_DEBUG "Freed page pfn=%llu, final_order=%u to zone %s\n",
               page->pfn, page->buddy.order, zone->name);
    }
}

/* ========================================================================
 * PUBLIC ALLOCATION INTERFACE
 * ======================================================================== */

/**
 * @brief Alloue 2^order pages contiguës
 * @param order Ordre d'allocation (2^order pages)
 * @param gfp_mask Flags d'allocation
 * @return Pointeur vers première page ou NULL
 */
page_t *alloc_pages(uint32_t order, uint32_t gfp_mask) {
    if (!buddy_initialized || order >= MAX_ORDER) {
        return NULL;
    }
    
    buddy_allocator.nr_alloc_calls++;
    
    /* Utiliser le nœud local pour l'instant (pas de NUMA) */
    int node_id = 0;
    
    return __alloc_pages(order, gfp_mask, node_id);
}

/**
 * @brief Alloue une page unique
 * @param gfp_mask Flags d'allocation
 * @return Pointeur vers page ou NULL
 */
page_t *alloc_page(uint32_t gfp_mask) {
    return alloc_pages(0, gfp_mask);
}

/**
 * @brief Libère 2^order pages
 * @param page Première page à libérer
 * @param order Ordre de libération
 */
void free_pages(page_t *page, uint32_t order) {
    if (!buddy_initialized || !page || order >= MAX_ORDER) {
        return;
    }
    
    buddy_allocator.nr_free_calls++;
    
    /* Trouver la zone contenant cette page */
    zone_t *zone = NULL;
    uint64_t pfn = page_to_pfn(page);
    
    pglist_data_t *node = &contig_page_data;
    for (uint32_t i = 0; i < node->nr_zones; i++) {
        zone_t *z = &node->node_zones[i];
        if (pfn >= z->zone_start_pfn && pfn < z->zone_end_pfn) {
            zone = z;
            break;
        }
    }
    
    if (!zone) {
        printk(KERN_ERR "free_pages: page pfn=%llu not found in any zone\n", pfn);
        return;
    }
    
    __free_pages_zone(zone, page, order);
}

/**
 * @brief Libère une page unique
 * @param page Page à libérer
 */
void free_page(page_t *page) {
    free_pages(page, 0);
}

/* ========================================================================
 * ZONE INITIALIZATION
 * ======================================================================== */

/**
 * @brief Initialise une zone mémoire
 * @param zone Zone à initialiser
 * @param name Nom de la zone
 * @param zone_idx Index de la zone
 * @param start_pfn PFN de début
 * @param size Taille en pages
 * @return 0 en cas de succès
 */
static int init_zone(zone_t *zone, const char *name, uint8_t zone_idx,
                    uint64_t start_pfn, uint64_t size) {
    memset(zone, 0, sizeof(zone_t));
    
    /* Configuration de base */
    strncpy(zone->name, name, sizeof(zone->name) - 1);
    zone->zone_idx = zone_idx;
    zone->zone_start_pfn = start_pfn;
    zone->zone_end_pfn = start_pfn + size;
    zone->spanned_pages = size;
    zone->present_pages = size;
    zone->managed_pages = size;
    zone->enabled = true;
    
    /* Initialiser les free areas */
    for (uint32_t order = 0; order < MAX_ORDER; order++) {
        for (uint8_t type = 0; type < MIGRATE_TYPES; type++) {
            zone->free_area[order].free_list[type] = NULL;
        }
        zone->free_area[order].nr_free = 0;
    }
    
    /* Configurer les watermarks */
    zone->watermark[WMARK_MIN] = size / 256;        /* 0.4% */
    zone->watermark[WMARK_LOW] = size / 128;        /* 0.8% */
    zone->watermark[WMARK_HIGH] = size / 64;        /* 1.6% */
    
    /* Ajouter toutes les pages comme libres dans l'ordre maximum */
    uint64_t remaining = size;
    uint64_t current_pfn = start_pfn;
    
    while (remaining > 0) {
        uint32_t order = MAX_ORDER - 1;
        uint64_t block_size = order_to_pages(order);
        
        /* Ajuster l'ordre si le bloc est trop grand */
        while (block_size > remaining && order > 0) {
            order--;
            block_size = order_to_pages(order);
        }
        
        page_t *page = pfn_to_page(current_pfn);
        if (page) {
            page->pfn = current_pfn;
            page->flags = 0;
            add_to_free_area(zone, page, order, MIGRATE_MOVABLE);
        }
        
        current_pfn += block_size;
        remaining -= block_size;
    }
    
    printk(KERN_INFO "Initialized zone %s: pfn [%llu - %llu], %llu pages\n",
           name, start_pfn, start_pfn + size - 1, size);
    
    return 0;
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise le Buddy System
 * @param total_pages Nombre total de pages disponibles
 * @return 0 en cas de succès
 */
int buddy_system_init(uint64_t total_pages) {
    if (buddy_initialized) {
        printk(KERN_WARNING "Buddy system already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing Buddy System allocator\n");
    
    /* Initialiser la structure principale */
    memset(&buddy_allocator, 0, sizeof(buddy_allocator));
    memset(&contig_page_data, 0, sizeof(contig_page_data));
    
    /* Configuration globale */
    buddy_allocator.totalram_pages = total_pages;
    buddy_allocator.min_free_kbytes = min_free_kbytes;
    buddy_allocator.pageblock_order = 9; /* 2MB blocks */
    buddy_allocator.nr_online_nodes = 1;
    buddy_allocator.node_data[0] = &contig_page_data;
    
    /* Initialiser le nœud principal */
    contig_page_data.node_id = 0;
    contig_page_data.node_start_pfn = 0;
    contig_page_data.node_present_pages = total_pages;
    contig_page_data.node_spanned_pages = total_pages;
    
    /* Initialiser les zones (configuration simplifiée) */
    uint64_t dma_pages = min(total_pages, 4096);      /* 16MB pour DMA */
    uint64_t normal_pages = total_pages - dma_pages;
    
    /* Zone DMA */
    if (dma_pages > 0) {
        init_zone(&contig_page_data.node_zones[ZONE_DMA], "DMA", ZONE_DMA, 
                 0, dma_pages);
        contig_page_data.nr_zones++;
    }
    
    /* Zone normale */
    if (normal_pages > 0) {
        init_zone(&contig_page_data.node_zones[ZONE_NORMAL], "Normal", ZONE_NORMAL,
                 dma_pages, normal_pages);
        contig_page_data.nr_zones++;
    }
    
    buddy_initialized = true;
    
    printk(KERN_INFO "Buddy System initialized\n");
    printk(KERN_INFO "  Total pages: %llu (%llu MB)\n", 
           total_pages, (total_pages * PAGE_SIZE) / (1024 * 1024));
    printk(KERN_INFO "  DMA zone: %llu pages\n", dma_pages);
    printk(KERN_INFO "  Normal zone: %llu pages\n", normal_pages);
    printk(KERN_INFO "  Max order: %d (max alloc: %llu pages)\n", 
           MAX_ORDER - 1, 1ULL << (MAX_ORDER - 1));
    
    return 0;
}

/**
 * @brief Affiche les statistiques du Buddy System
 */
void buddy_print_stats(void) {
    if (!buddy_initialized) {
        printk(KERN_INFO "Buddy System not initialized\n");
        return;
    }
    
    printk(KERN_INFO "Buddy System Statistics:\n");
    printk(KERN_INFO "  Allocation calls:     %llu\n", buddy_allocator.nr_alloc_calls);
    printk(KERN_INFO "  Free calls:           %llu\n", buddy_allocator.nr_free_calls);
    printk(KERN_INFO "  Pages allocated:      %llu\n", buddy_allocator.nr_alloc_pages);
    printk(KERN_INFO "  Pages freed:          %llu\n", buddy_allocator.nr_freed_pages);
    printk(KERN_INFO "  Failed allocations:   %llu\n", buddy_allocator.nr_failed_allocs);
    
    pglist_data_t *node = &contig_page_data;
    for (uint32_t i = 0; i < node->nr_zones; i++) {
        zone_t *zone = &node->node_zones[i];
        
        printk(KERN_INFO "  Zone %s:\n", zone->name);
        printk(KERN_INFO "    Free pages: %llu\n", zone->nr_free_pages);
        printk(KERN_INFO "    Watermarks: min=%llu, low=%llu, high=%llu\n",
               zone->watermark[WMARK_MIN], zone->watermark[WMARK_LOW], 
               zone->watermark[WMARK_HIGH]);
        
        printk(KERN_INFO "    Free areas by order:\n");
        for (uint32_t order = 0; order < MAX_ORDER; order++) {
            if (zone->free_area[order].nr_free > 0) {
                printk(KERN_INFO "      Order %u: %u blocks (%llu pages)\n",
                       order, zone->free_area[order].nr_free,
                       zone->free_area[order].nr_free * order_to_pages(order));
            }
        }
    }
    
    /* Calculer l'utilisation mémoire */
    uint64_t allocated_pages = buddy_allocator.nr_alloc_pages - buddy_allocator.nr_freed_pages;
    float usage_percent = (float)allocated_pages / buddy_allocator.totalram_pages * 100.0f;
    
    printk(KERN_INFO "  Memory usage: %llu/%llu pages (%.1f%%)\n",
           allocated_pages, buddy_allocator.totalram_pages, usage_percent);
}

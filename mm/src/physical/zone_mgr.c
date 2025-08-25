/**
 * @file zone_mgr.c
 * @brief Gestion des zones mémoire (DMA, Normal, High)
 * 
 * Ce fichier implémente la gestion des différentes zones de mémoire physique
 * du système. Les zones permettent de classifier la mémoire selon ses
 * capacités et contraintes d'utilisation:
 * 
 * - Zone DMA: Mémoire accessible pour DMA (généralement < 16MB)
 * - Zone Normal: Mémoire normale directement mappée par le kernel
 * - Zone High: Mémoire haute qui doit être mappée temporairement
 * - Zone Movable: Mémoire dont les pages peuvent être déplacées
 * - Zone Device: Mémoire de devices mappés
 * 
 * Le gestionnaire de zones coordonne l'allocation entre ces différentes
 * zones selon les besoins et contraintes des allocateurs.
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
#include "../../include/mm.h"
#include "../../include/page_alloc.h"
#include "phys_page.h"

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
 * CONSTANTS AND CONFIGURATION
 * ======================================================================== */

/* Limites des zones mémoire */
#define ZONE_DMA_LIMIT      (16 * 1024 * 1024)     /* 16MB */
#define ZONE_NORMAL_LIMIT   (896 * 1024 * 1024)    /* 896MB */
#define ZONE_HIGH_START     ZONE_NORMAL_LIMIT

/* Seuils de gestion des zones */
#define ZONE_MIN_FREE_PAGES     32      /* Minimum de pages libres */
#define ZONE_LOW_WATERMARK      64      /* Seuil bas */
#define ZONE_HIGH_WATERMARK     128     /* Seuil haut */
#define ZONE_RECLAIM_THRESHOLD  256     /* Seuil de récupération */

/* Flags de zones */
#define ZONE_FLAG_RECLAIM_BUSY  (1 << 0)   /* Récupération en cours */
#define ZONE_FLAG_CONGESTED     (1 << 1)   /* Zone congestionnée */
#define ZONE_FLAG_DEPLETED      (1 << 2)   /* Zone épuisée */
#define ZONE_FLAG_BALANCED      (1 << 3)   /* Zone équilibrée */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Informations détaillées sur une zone
 */
typedef struct zone_info {
    memory_zone_t type;             /* Type de zone */
    const char *name;               /* Nom de la zone */
    
    /* Limites physiques */
    uint64_t start_pfn;             /* Première page de la zone */
    uint64_t end_pfn;               /* Dernière page + 1 */
    uint64_t spanned_pages;         /* Pages couvertes par la zone */
    uint64_t present_pages;         /* Pages réellement présentes */
    
    /* Compteurs de pages */
    uint64_t total_pages;           /* Pages totales utilisables */
    uint64_t free_pages;            /* Pages libres */
    uint64_t active_pages;          /* Pages actives */
    uint64_t inactive_pages;        /* Pages inactives */
    uint64_t pinned_pages;          /* Pages épinglées */
    uint64_t reserved_pages;        /* Pages réservées */
    
    /* Seuils de gestion */
    uint64_t min_free_pages;        /* Minimum absolu */
    uint64_t low_watermark;         /* Seuil bas */
    uint64_t high_watermark;        /* Seuil haut */
    
    /* État et flags */
    uint32_t flags;                 /* Flags de la zone */
    bool initialized;               /* Zone initialisée */
    bool active;                    /* Zone active */
    
    /* Statistiques */
    uint64_t alloc_count;           /* Allocations totales */
    uint64_t free_count;            /* Libérations totales */
    uint64_t failed_allocs;         /* Allocations échouées */
    uint64_t reclaim_count;         /* Récupérations forcées */
    
    /* Listes de pages par ordre (buddy system) */
    struct list_head free_area[11]; /* 0 à 10 (2^0 à 2^10 pages) */
    uint64_t free_area_count[11];   /* Compteurs par ordre */
    
    /* Protection */
    spinlock_t zone_lock;           /* Verrou de la zone */
} zone_info_t;

/**
 * @brief Statistiques globales des zones
 */
typedef struct {
    uint64_t total_memory;          /* Mémoire totale */
    uint64_t available_memory;      /* Mémoire disponible */
    uint64_t reserved_memory;       /* Mémoire réservée */
    uint64_t dma_memory;            /* Mémoire DMA */
    uint64_t normal_memory;         /* Mémoire normale */
    uint64_t high_memory;           /* Mémoire haute */
    uint32_t zone_pressure;         /* Pression mémoire globale */
    uint32_t reclaim_efficiency;    /* Efficacité récupération */
} zone_stats_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Informations sur les zones */
static zone_info_t zones[ZONE_COUNT];
static zone_stats_t global_zone_stats;
static bool zone_manager_initialized = false;

/* Noms des zones pour affichage */
static const char *zone_names[ZONE_COUNT] = {
    [ZONE_DMA] = "DMA",
    [ZONE_NORMAL] = "Normal", 
    [ZONE_HIGH] = "HighMem"
};

/* Synchronization */
#ifdef CONFIG_SMP
typedef struct {
    volatile int locked;
} spinlock_t;
#define SPINLOCK_INIT {0}
static inline void spin_lock(spinlock_t *lock) {
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        __builtin_ia32_pause();
    }
}
static inline void spin_unlock(spinlock_t *lock) {
    __sync_lock_release(&lock->locked);
}
static spinlock_t zone_mgr_lock = SPINLOCK_INIT;
#define ZONE_MGR_LOCK() spin_lock(&zone_mgr_lock)
#define ZONE_MGR_UNLOCK() spin_unlock(&zone_mgr_lock)
#else
#define ZONE_MGR_LOCK() do {} while(0)
#define ZONE_MGR_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Convertit une adresse physique en numéro de page
 * @param addr Adresse physique
 * @return Numéro de page (PFN)
 */
static inline uint64_t addr_to_pfn(uint64_t addr) {
    return addr >> PAGE_SHIFT;
}

/**
 * @brief Convertit un numéro de page en adresse physique
 * @param pfn Numéro de page
 * @return Adresse physique
 */
static inline uint64_t pfn_to_addr(uint64_t pfn) {
    return pfn << PAGE_SHIFT;
}

/**
 * @brief Détermine la zone pour une adresse physique
 * @param addr Adresse physique
 * @return Type de zone
 */
static memory_zone_t addr_to_zone_type(uint64_t addr) {
    if (addr < ZONE_DMA_LIMIT) {
        return ZONE_DMA;
    } else if (addr < ZONE_NORMAL_LIMIT) {
        return ZONE_NORMAL;
    } else {
        return ZONE_HIGH;
    }
}

/**
 * @brief Vérifie si une zone est sous pression mémoire
 * @param zone Pointeur vers la zone
 * @return true si sous pression
 */
static bool zone_under_pressure(const zone_info_t *zone) {
    if (!zone->initialized) return false;
    
    return zone->free_pages < zone->low_watermark;
}

/**
 * @brief Calcule l'ordre buddy pour un nombre de pages
 * @param pages Nombre de pages
 * @return Ordre buddy
 */
static unsigned int pages_to_order(uint64_t pages) {
    unsigned int order = 0;
    uint64_t size = 1;
    
    while (size < pages) {
        size <<= 1;
        order++;
    }
    
    return order;
}

/* ========================================================================
 * ZONE INITIALIZATION
 * ======================================================================== */

/**
 * @brief Initialise une zone mémoire
 * @param zone_type Type de zone
 * @param start_addr Adresse de début
 * @param end_addr Adresse de fin
 * @return 0 en cas de succès
 */
static int init_memory_zone(memory_zone_t zone_type, uint64_t start_addr, uint64_t end_addr) {
    if (zone_type >= ZONE_COUNT) {
        printk(KERN_ERR "Invalid zone type: %d\n", zone_type);
        return -1;
    }
    
    zone_info_t *zone = &zones[zone_type];
    
    /* Configuration de base */
    zone->type = zone_type;
    zone->name = zone_names[zone_type];
    zone->start_pfn = addr_to_pfn(start_addr);
    zone->end_pfn = addr_to_pfn(end_addr);
    zone->spanned_pages = zone->end_pfn - zone->start_pfn;
    zone->present_pages = zone->spanned_pages; /* Simplifié pour l'instant */
    
    /* Calcul des pages utilisables */
    zone->total_pages = zone->present_pages;
    zone->free_pages = zone->total_pages;
    zone->active_pages = 0;
    zone->inactive_pages = 0;
    zone->pinned_pages = 0;
    zone->reserved_pages = 0;
    
    /* Configuration des seuils */
    zone->min_free_pages = ZONE_MIN_FREE_PAGES;
    zone->low_watermark = zone->total_pages / 64;  /* 1/64 de la zone */
    zone->high_watermark = zone->total_pages / 32; /* 1/32 de la zone */
    
    if (zone->low_watermark < ZONE_LOW_WATERMARK) {
        zone->low_watermark = ZONE_LOW_WATERMARK;
    }
    if (zone->high_watermark < ZONE_HIGH_WATERMARK) {
        zone->high_watermark = ZONE_HIGH_WATERMARK;
    }
    
    /* Initialisation des statistiques */
    zone->alloc_count = 0;
    zone->free_count = 0;
    zone->failed_allocs = 0;
    zone->reclaim_count = 0;
    
    /* Initialisation des listes libres buddy */
    for (int i = 0; i < 11; i++) {
        // INIT_LIST_HEAD(&zone->free_area[i]); /* TODO: Implémenter les listes */
        zone->free_area_count[i] = 0;
    }
    
    /* État initial */
    zone->flags = ZONE_FLAG_BALANCED;
    zone->initialized = true;
    zone->active = true;
    
    printk(KERN_INFO "Zone %s initialized: PFN %llu-%llu (%llu pages, %llu MB)\n",
           zone->name, zone->start_pfn, zone->end_pfn - 1,
           zone->total_pages, (zone->total_pages * PAGE_SIZE) / (1024 * 1024));
    
    return 0;
}

/**
 * @brief Initialise le gestionnaire de zones
 * @param total_memory_start Début de la mémoire physique
 * @param total_memory_end Fin de la mémoire physique
 * @return 0 en cas de succès
 */
int zone_manager_init(uint64_t total_memory_start, uint64_t total_memory_end) {
    if (zone_manager_initialized) {
        printk(KERN_WARNING "Zone manager already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing zone manager (0x%llx - 0x%llx)\n",
           total_memory_start, total_memory_end);
    
    /* Réinitialiser les structures */
    memset(zones, 0, sizeof(zones));
    memset(&global_zone_stats, 0, sizeof(global_zone_stats));
    
    /* Initialiser les zones selon les limites */
    uint64_t current_start = total_memory_start;
    
    /* Zone DMA (0 - 16MB) */
    if (current_start < ZONE_DMA_LIMIT && total_memory_end > current_start) {
        uint64_t dma_end = (total_memory_end < ZONE_DMA_LIMIT) ? 
                          total_memory_end : ZONE_DMA_LIMIT;
        
        if (init_memory_zone(ZONE_DMA, current_start, dma_end) != 0) {
            return -1;
        }
        current_start = dma_end;
    }
    
    /* Zone Normal (16MB - 896MB) */
    if (current_start < ZONE_NORMAL_LIMIT && total_memory_end > current_start) {
        uint64_t normal_end = (total_memory_end < ZONE_NORMAL_LIMIT) ? 
                             total_memory_end : ZONE_NORMAL_LIMIT;
        
        if (init_memory_zone(ZONE_NORMAL, current_start, normal_end) != 0) {
            return -1;
        }
        current_start = normal_end;
    }
    
    /* Zone High (> 896MB) */
    if (total_memory_end > current_start) {
        if (init_memory_zone(ZONE_HIGH, current_start, total_memory_end) != 0) {
            return -1;
        }
    }
    
    /* Calculer les statistiques globales */
    update_global_zone_stats();
    
    zone_manager_initialized = true;
    
    printk(KERN_INFO "Zone manager initialized successfully\n");
    print_zone_info();
    
    return 0;
}

/* ========================================================================
 * ZONE ALLOCATION INTERFACE
 * ======================================================================== */

/**
 * @brief Alloue des pages dans une zone spécifique
 * @param zone_type Type de zone
 * @param order Ordre d'allocation (2^order pages)
 * @param flags Flags d'allocation
 * @return Adresse physique de la première page ou 0 si échec
 */
uint64_t zone_alloc_pages(memory_zone_t zone_type, unsigned int order, uint32_t flags) {
    if (!zone_manager_initialized || zone_type >= ZONE_COUNT) {
        return 0;
    }
    
    zone_info_t *zone = &zones[zone_type];
    
    if (!zone->initialized || !zone->active) {
        return 0;
    }
    
    uint64_t pages_needed = 1ULL << order;
    
    ZONE_MGR_LOCK();
    
    /* Vérifier disponibilité */
    if (zone->free_pages < pages_needed) {
        zone->failed_allocs++;
        ZONE_MGR_UNLOCK();
        
        /* Tenter récupération si autorisée */
        if (!(flags & GFP_ATOMIC)) {
            if (try_zone_reclaim(zone) == 0) {
                return zone_alloc_pages(zone_type, order, flags); /* Retry */
            }
        }
        
        return 0;
    }
    
    /* TODO: Implémentation réelle du buddy allocator */
    /* Pour l'instant, simulation simple */
    uint64_t allocated_pfn = zone->start_pfn + (zone->total_pages - zone->free_pages);
    
    /* Mettre à jour les compteurs */
    zone->free_pages -= pages_needed;
    zone->active_pages += pages_needed;
    zone->alloc_count++;
    
    /* Vérifier les seuils */
    if (zone->free_pages < zone->low_watermark) {
        zone->flags |= ZONE_FLAG_CONGESTED;
        zone->flags &= ~ZONE_FLAG_BALANCED;
    }
    
    ZONE_MGR_UNLOCK();
    
    printk(KERN_DEBUG "Zone %s: allocated %llu pages at PFN %llu\n",
           zone->name, pages_needed, allocated_pfn);
    
    return pfn_to_addr(allocated_pfn);
}

/**
 * @brief Libère des pages dans une zone
 * @param addr Adresse physique de la première page
 * @param order Ordre de libération
 */
void zone_free_pages(uint64_t addr, unsigned int order) {
    if (!zone_manager_initialized || addr == 0) {
        return;
    }
    
    memory_zone_t zone_type = addr_to_zone_type(addr);
    zone_info_t *zone = &zones[zone_type];
    
    if (!zone->initialized) {
        printk(KERN_ERR "Attempting to free pages in uninitialized zone\n");
        return;
    }
    
    uint64_t pages_freed = 1ULL << order;
    uint64_t pfn = addr_to_pfn(addr);
    
    /* Validation */
    if (pfn < zone->start_pfn || pfn >= zone->end_pfn) {
        printk(KERN_ERR "Invalid PFN %llu for zone %s (range: %llu-%llu)\n",
               pfn, zone->name, zone->start_pfn, zone->end_pfn - 1);
        return;
    }
    
    ZONE_MGR_LOCK();
    
    /* TODO: Implémentation réelle du buddy system pour la libération */
    
    /* Mettre à jour les compteurs */
    zone->free_pages += pages_freed;
    zone->active_pages -= pages_freed;
    zone->free_count++;
    
    /* Vérifier les seuils */
    if (zone->free_pages > zone->high_watermark) {
        zone->flags |= ZONE_FLAG_BALANCED;
        zone->flags &= ~ZONE_FLAG_CONGESTED;
    }
    
    ZONE_MGR_UNLOCK();
    
    printk(KERN_DEBUG "Zone %s: freed %llu pages at PFN %llu\n",
           zone->name, pages_freed, pfn);
}

/* ========================================================================
 * ZONE RECLAIM AND BALANCING
 * ======================================================================== */

/**
 * @brief Tente de récupérer de la mémoire dans une zone
 * @param zone Pointeur vers la zone
 * @return Nombre de pages récupérées
 */
static uint64_t try_zone_reclaim(zone_info_t *zone) {
    if (!zone || (zone->flags & ZONE_FLAG_RECLAIM_BUSY)) {
        return 0;
    }
    
    printk(KERN_INFO "Attempting memory reclaim in zone %s\n", zone->name);
    
    zone->flags |= ZONE_FLAG_RECLAIM_BUSY;
    uint64_t pages_reclaimed = 0;
    
    /* TODO: Implémentation de la récupération mémoire */
    /* - Récupération de pages inactives */
    /* - Swap out de pages */
    /* - Compaction de mémoire */
    /* - Libération de caches */
    
    zone->reclaim_count++;
    zone->flags &= ~ZONE_FLAG_RECLAIM_BUSY;
    
    printk(KERN_INFO "Zone %s: reclaimed %llu pages\n", zone->name, pages_reclaimed);
    
    return pages_reclaimed;
}

/**
 * @brief Équilibre les zones mémoire
 * @return 0 en cas de succès
 */
int balance_zones(void) {
    if (!zone_manager_initialized) {
        return -1;
    }
    
    bool needs_balancing = false;
    
    /* Vérifier si un équilibrage est nécessaire */
    for (int i = 0; i < ZONE_COUNT; i++) {
        zone_info_t *zone = &zones[i];
        
        if (zone->initialized && zone_under_pressure(zone)) {
            needs_balancing = true;
            break;
        }
    }
    
    if (!needs_balancing) {
        return 0;
    }
    
    printk(KERN_INFO "Starting zone balancing\n");
    
    /* Tentative de récupération dans les zones sous pression */
    for (int i = 0; i < ZONE_COUNT; i++) {
        zone_info_t *zone = &zones[i];
        
        if (zone->initialized && zone_under_pressure(zone)) {
            try_zone_reclaim(zone);
        }
    }
    
    update_global_zone_stats();
    
    printk(KERN_INFO "Zone balancing completed\n");
    
    return 0;
}

/* ========================================================================
 * STATISTICS AND INFORMATION
 * ======================================================================== */

/**
 * @brief Met à jour les statistiques globales des zones
 */
void update_global_zone_stats(void) {
    memset(&global_zone_stats, 0, sizeof(global_zone_stats));
    
    for (int i = 0; i < ZONE_COUNT; i++) {
        zone_info_t *zone = &zones[i];
        
        if (!zone->initialized) continue;
        
        uint64_t zone_memory = zone->total_pages * PAGE_SIZE;
        uint64_t zone_available = zone->free_pages * PAGE_SIZE;
        
        global_zone_stats.total_memory += zone_memory;
        global_zone_stats.available_memory += zone_available;
        
        switch (zone->type) {
            case ZONE_DMA:
                global_zone_stats.dma_memory += zone_memory;
                break;
            case ZONE_NORMAL:
                global_zone_stats.normal_memory += zone_memory;
                break;
            case ZONE_HIGH:
                global_zone_stats.high_memory += zone_memory;
                break;
            default:
                break;
        }
        
        /* Calculer pression mémoire */
        if (zone->free_pages < zone->low_watermark) {
            global_zone_stats.zone_pressure++;
        }
    }
    
    global_zone_stats.reserved_memory = 
        global_zone_stats.total_memory - global_zone_stats.available_memory;
}

/**
 * @brief Affiche les informations sur les zones
 */
void print_zone_info(void) {
    if (!zone_manager_initialized) {
        printk(KERN_INFO "Zone manager not initialized\n");
        return;
    }
    
    printk(KERN_INFO "Memory Zone Information:\n");
    printk(KERN_INFO "Zone      Start PFN   End PFN     Total Pages Free Pages  Status\n");
    printk(KERN_INFO "================================================================\n");
    
    for (int i = 0; i < ZONE_COUNT; i++) {
        zone_info_t *zone = &zones[i];
        
        if (!zone->initialized) continue;
        
        const char *status = "Unknown";
        if (zone->flags & ZONE_FLAG_BALANCED) status = "Balanced";
        else if (zone->flags & ZONE_FLAG_CONGESTED) status = "Congested";
        else if (zone->flags & ZONE_FLAG_DEPLETED) status = "Depleted";
        
        printk(KERN_INFO "%-8s %10llu %10llu %11llu %10llu  %s\n",
               zone->name, zone->start_pfn, zone->end_pfn - 1,
               zone->total_pages, zone->free_pages, status);
    }
    
    printk(KERN_INFO "================================================================\n");
    printk(KERN_INFO "Total Memory:     %llu MB\n", global_zone_stats.total_memory / (1024 * 1024));
    printk(KERN_INFO "Available Memory: %llu MB\n", global_zone_stats.available_memory / (1024 * 1024));
    printk(KERN_INFO "DMA Memory:       %llu MB\n", global_zone_stats.dma_memory / (1024 * 1024));
    printk(KERN_INFO "Normal Memory:    %llu MB\n", global_zone_stats.normal_memory / (1024 * 1024));
    printk(KERN_INFO "High Memory:      %llu MB\n", global_zone_stats.high_memory / (1024 * 1024));
}

/**
 * @brief Obtient les informations sur une zone
 * @param zone_type Type de zone
 * @param info Pointeur vers structure d'informations
 * @return 0 en cas de succès
 */
int get_zone_info(memory_zone_t zone_type, zone_info_t *info) {
    if (!zone_manager_initialized || zone_type >= ZONE_COUNT || !info) {
        return -1;
    }
    
    zone_info_t *zone = &zones[zone_type];
    
    if (!zone->initialized) {
        return -1;
    }
    
    ZONE_MGR_LOCK();
    memcpy(info, zone, sizeof(zone_info_t));
    ZONE_MGR_UNLOCK();
    
    return 0;
}

/**
 * @brief Obtient les statistiques globales des zones
 * @param stats Pointeur vers structure de statistiques
 */
void get_global_zone_stats(zone_stats_t *stats) {
    if (!stats || !zone_manager_initialized) {
        return;
    }
    
    update_global_zone_stats();
    memcpy(stats, &global_zone_stats, sizeof(zone_stats_t));
}

/**
 * @brief Trouve la meilleure zone pour une allocation
 * @param flags Flags d'allocation
 * @param order Ordre d'allocation
 * @return Type de zone ou ZONE_COUNT si aucune trouvée
 */
memory_zone_t find_suitable_zone(uint32_t flags, unsigned int order) {
    uint64_t pages_needed = 1ULL << order;
    
    /* Préférence selon les flags */
    if (flags & GFP_DMA) {
        /* DMA requis - vérifier zone DMA d'abord */
        if (zones[ZONE_DMA].initialized && zones[ZONE_DMA].free_pages >= pages_needed) {
            return ZONE_DMA;
        }
        return ZONE_COUNT; /* Pas de DMA disponible */
    }
    
    /* Allocation normale - préférer Normal puis High */
    if (zones[ZONE_NORMAL].initialized && zones[ZONE_NORMAL].free_pages >= pages_needed) {
        return ZONE_NORMAL;
    }
    
    if ((flags & GFP_HIGHMEM) && zones[ZONE_HIGH].initialized && 
        zones[ZONE_HIGH].free_pages >= pages_needed) {
        return ZONE_HIGH;
    }
    
    return ZONE_COUNT; /* Aucune zone appropriée */
}

/**
 * @brief Vérifie l'intégrité du gestionnaire de zones
 * @return true si intègre
 */
bool zone_manager_check_integrity(void) {
    if (!zone_manager_initialized) {
        return false;
    }
    
    bool integrity_ok = true;
    
    for (int i = 0; i < ZONE_COUNT; i++) {
        zone_info_t *zone = &zones[i];
        
        if (!zone->initialized) continue;
        
        /* Vérifications de cohérence */
        if (zone->start_pfn >= zone->end_pfn) {
            printk(KERN_ERR "Zone %s: invalid PFN range\n", zone->name);
            integrity_ok = false;
        }
        
        if (zone->free_pages > zone->total_pages) {
            printk(KERN_ERR "Zone %s: free pages > total pages\n", zone->name);
            integrity_ok = false;
        }
        
        if (zone->active_pages + zone->free_pages > zone->total_pages) {
            printk(KERN_ERR "Zone %s: active + free > total pages\n", zone->name);
            integrity_ok = false;
        }
    }
    
    return integrity_ok;
}

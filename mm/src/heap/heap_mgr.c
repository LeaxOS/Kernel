/**
 * @file heap_mgr.c
 * @brief Gestionnaire de heap principal pour LeaxOS
 * 
 * Ce fichier implémente le gestionnaire de heap central qui coordonne
 * les différents allocateurs (SLAB, SLUB, buddy system, etc.) et
 * fournit une interface unifiée pour l'allocation mémoire du kernel.
 * 
 * Fonctionnalités principales:
 * - Interface unifiée d'allocation mémoire
 * - Gestion de multiples allocateurs
 * - Optimisation automatique selon la taille
 * - Statistiques détaillées et monitoring
 * - Support pour allocation critique et atomique
 * - Gestion des zones mémoire spéciales
 * - Détection et prévention de la fragmentation
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
#include "../../include/slab.h"

/* Fallback pour compilation standalone */
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
 * HEAP MANAGER CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/* Types d'allocateurs */
#define ALLOCATOR_SLAB          0x01    /* SLAB allocator */
#define ALLOCATOR_SLUB          0x02    /* SLUB allocator */
#define ALLOCATOR_BUDDY         0x04    /* Buddy system */
#define ALLOCATOR_VMALLOC       0x08    /* Vmalloc */
#define ALLOCATOR_DMA           0x10    /* DMA allocator */
#define ALLOCATOR_PERCPU        0x20    /* Per-CPU allocator */

/* Zones mémoire */
#define ZONE_DMA                0x01    /* Zone DMA */
#define ZONE_DMA32              0x02    /* Zone DMA32 */
#define ZONE_NORMAL             0x04    /* Zone normale */
#define ZONE_HIGHMEM            0x08    /* Zone high memory */

/* Flags d'allocation */
#define GFP_KERNEL              0x01    /* Allocation kernel normale */
#define GFP_ATOMIC              0x02    /* Allocation atomique */
#define GFP_DMA                 0x04    /* Allocation DMA */
#define GFP_HIGHMEM             0x08    /* Allocation high memory */
#define GFP_ZERO                0x10    /* Initialiser à zéro */
#define GFP_NOWAIT              0x20    /* Ne pas attendre */
#define GFP_NORETRY             0x40    /* Ne pas réessayer */

/* Seuils de taille pour choix d'allocateur */
#define SMALL_OBJECT_THRESHOLD  512     /* Objets petits (SLAB/SLUB) */
#define MEDIUM_OBJECT_THRESHOLD 4096    /* Objets moyens */
#define LARGE_OBJECT_THRESHOLD  65536   /* Objets larges (buddy/vmalloc) */

/* Constantes de configuration */
#define MAX_ALLOCATORS          8       /* Allocateurs max */
#define MAX_HEAP_ZONES          4       /* Zones heap max */
#define HEAP_CACHE_SIZE         64      /* Cache d'allocations récentes */
#define FRAGMENTATION_THRESHOLD 0.75f   /* Seuil de fragmentation */

/* États d'allocation */
#define ALLOC_STATE_FREE        0x01    /* Libre */
#define ALLOC_STATE_ALLOCATED   0x02    /* Alloué */
#define ALLOC_STATE_RESERVED    0x04    /* Réservé */
#define ALLOC_STATE_CORRUPTED   0x08    /* Corrompu */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Informations sur une allocation
 */
typedef struct allocation_info {
    void *address;                      /* Adresse allouée */
    size_t size;                        /* Taille demandée */
    size_t actual_size;                 /* Taille réelle allouée */
    uint8_t allocator_type;             /* Type d'allocateur utilisé */
    uint8_t flags;                      /* Flags d'allocation */
    uint8_t state;                      /* État de l'allocation */
    uint32_t caller_id;                 /* ID de l'appelant */
    uint64_t timestamp;                 /* Timestamp d'allocation */
    
    /* Debug et tracking */
    const char *file;                   /* Fichier source */
    int line;                           /* Ligne source */
    const char *function;               /* Fonction appelante */
    
    /* Chaînage */
    struct allocation_info *next;       /* Suivant dans la liste */
    struct allocation_info *prev;       /* Précédent dans la liste */
    
} allocation_info_t;

/**
 * @brief Interface d'allocateur
 */
typedef struct allocator_interface {
    /* Identification */
    char name[32];                      /* Nom de l'allocateur */
    uint8_t type;                       /* Type d'allocateur */
    uint32_t version;                   /* Version */
    
    /* Méthodes principales */
    void* (*alloc)(size_t size, uint32_t flags);
    void (*free)(void *ptr);
    void* (*realloc)(void *ptr, size_t new_size);
    
    /* Méthodes d'information */
    size_t (*get_size)(void *ptr);
    bool (*is_valid)(void *ptr);
    int (*get_stats)(void *stats_buffer);
    
    /* Configuration */
    size_t min_size;                    /* Taille min gérée */
    size_t max_size;                    /* Taille max gérée */
    uint32_t supported_flags;           /* Flags supportés */
    uint32_t supported_zones;           /* Zones supportées */
    
    /* État */
    bool enabled;                       /* Allocateur activé */
    uint32_t priority;                  /* Priorité d'utilisation */
    
    /* Statistiques */
    uint64_t allocations;               /* Allocations totales */
    uint64_t deallocations;             /* Désallocations totales */
    uint64_t bytes_allocated;           /* Octets alloués */
    uint64_t bytes_freed;               /* Octets libérés */
    uint64_t allocation_failures;       /* Échecs d'allocation */
    
} allocator_interface_t;

/**
 * @brief Zone de heap
 */
typedef struct heap_zone {
    /* Identification */
    uint8_t zone_type;                  /* Type de zone */
    char name[32];                      /* Nom de la zone */
    
    /* Limites physiques */
    uint64_t start_pfn;                 /* Page frame de début */
    uint64_t end_pfn;                   /* Page frame de fin */
    uint64_t total_pages;               /* Pages totales */
    uint64_t free_pages;                /* Pages libres */
    
    /* Statistiques */
    uint64_t allocations;               /* Allocations dans cette zone */
    uint64_t bytes_allocated;           /* Octets alloués */
    float fragmentation_level;          /* Niveau de fragmentation */
    
    /* Configuration */
    bool enabled;                       /* Zone active */
    uint32_t priority;                  /* Priorité d'utilisation */
    
} heap_zone_t;

/**
 * @brief Cache d'allocations récentes
 */
typedef struct allocation_cache {
    allocation_info_t *entries[HEAP_CACHE_SIZE];  /* Entrées du cache */
    uint32_t head;                      /* Tête du cache circulaire */
    uint32_t tail;                      /* Queue du cache circulaire */
    uint32_t count;                     /* Nombre d'entrées */
} allocation_cache_t;

/**
 * @brief Gestionnaire principal de heap
 */
typedef struct heap_manager {
    /* Allocateurs enregistrés */
    allocator_interface_t *allocators[MAX_ALLOCATORS];
    uint32_t allocator_count;           /* Nombre d'allocateurs */
    
    /* Zones de heap */
    heap_zone_t zones[MAX_HEAP_ZONES];  /* Zones disponibles */
    uint32_t zone_count;                /* Nombre de zones */
    
    /* Cache et tracking */
    allocation_cache_t cache;           /* Cache d'allocations */
    allocation_info_t *active_allocs;   /* Liste des allocations actives */
    uint32_t active_count;              /* Nombre d'allocations actives */
    
    /* Hash table pour lookup rapide */
    allocation_info_t **alloc_hash;     /* Table de hash */
    uint32_t hash_size;                 /* Taille de la table */
    
    /* Configuration */
    bool debug_mode;                    /* Mode debug activé */
    bool tracking_enabled;              /* Tracking des allocations */
    bool auto_optimization;             /* Optimisation automatique */
    uint32_t default_flags;             /* Flags par défaut */
    
    /* Seuils et limites */
    size_t total_limit;                 /* Limite totale d'allocation */
    size_t current_usage;               /* Usage actuel */
    size_t peak_usage;                  /* Usage pic */
    float fragmentation_threshold;      /* Seuil de fragmentation */
    
} heap_manager_t;

/**
 * @brief Statistiques globales du heap
 */
typedef struct heap_stats {
    /* Allocations */
    uint64_t total_allocations;         /* Allocations totales */
    uint64_t total_deallocations;       /* Désallocations totales */
    uint64_t current_allocations;       /* Allocations actuelles */
    uint64_t peak_allocations;          /* Pic d'allocations */
    
    /* Mémoire */
    uint64_t total_bytes_allocated;     /* Octets alloués totaux */
    uint64_t total_bytes_freed;         /* Octets libérés totaux */
    uint64_t current_bytes_used;        /* Octets actuellement utilisés */
    uint64_t peak_bytes_used;           /* Pic d'utilisation */
    
    /* Performance */
    uint64_t allocation_failures;       /* Échecs d'allocation */
    uint64_t fragmentation_events;      /* Événements de fragmentation */
    uint64_t defragmentation_runs;      /* Exécutions de défragmentation */
    float avg_allocation_time;          /* Temps moyen d'allocation */
    float avg_deallocation_time;        /* Temps moyen de désallocation */
    
    /* Par allocateur */
    uint64_t slab_allocations;          /* Allocations SLAB */
    uint64_t buddy_allocations;         /* Allocations buddy */
    uint64_t vmalloc_allocations;       /* Allocations vmalloc */
    uint64_t dma_allocations;           /* Allocations DMA */
    
    /* Fragmentation */
    float overall_fragmentation;        /* Fragmentation globale */
    float zone_fragmentation[MAX_HEAP_ZONES];  /* Fragmentation par zone */
    
} heap_stats_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Gestionnaire principal */
static heap_manager_t heap_mgr;
static bool heap_initialized = false;
static heap_stats_t global_stats;

/* Configuration par défaut */
static bool debug_heap = false;
static size_t default_heap_limit = 0; /* Illimité par défaut */

/* Timestamp functions */
static uint64_t heap_timestamp_counter = 0;
static inline uint64_t get_heap_timestamp(void) {
    return ++heap_timestamp_counter;
}

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
static spinlock_t heap_lock = SPINLOCK_INIT;
#define HEAP_LOCK() spin_lock(&heap_lock)
#define HEAP_UNLOCK() spin_unlock(&heap_lock)
#else
#define HEAP_LOCK() do {} while(0)
#define HEAP_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * ALLOCATION TRACKING
 * ======================================================================== */

/**
 * @brief Hash function pour les allocations
 * @param ptr Pointeur à hasher
 * @return Hash value
 */
static uint32_t hash_allocation_ptr(void *ptr) {
    uintptr_t addr = (uintptr_t)ptr;
    return (uint32_t)((addr >> 3) % heap_mgr.hash_size);
}

/**
 * @brief Alloue une structure d'info d'allocation
 * @return Pointeur vers info ou NULL
 */
static allocation_info_t *alloc_allocation_info(void) {
    /* Allocation simple pour éviter récursion */
    allocation_info_t *info = (allocation_info_t *)malloc(sizeof(allocation_info_t));
    if (info) {
        memset(info, 0, sizeof(allocation_info_t));
        info->timestamp = get_heap_timestamp();
        info->state = ALLOC_STATE_ALLOCATED;
    }
    return info;
}

/**
 * @brief Libère une structure d'info d'allocation
 * @param info Info à libérer
 */
static void free_allocation_info(allocation_info_t *info) {
    if (info) {
        free(info);
    }
}

/**
 * @brief Ajoute une allocation au tracking
 * @param ptr Pointeur alloué
 * @param size Taille demandée
 * @param actual_size Taille réelle
 * @param allocator_type Type d'allocateur
 * @param flags Flags d'allocation
 * @param file Fichier source
 * @param line Ligne source
 * @param function Fonction appelante
 */
static void track_allocation(void *ptr, size_t size, size_t actual_size,
                           uint8_t allocator_type, uint32_t flags,
                           const char *file, int line, const char *function) {
    if (!heap_mgr.tracking_enabled || !ptr) {
        return;
    }
    
    allocation_info_t *info = alloc_allocation_info();
    if (!info) {
        return;
    }
    
    /* Remplir les informations */
    info->address = ptr;
    info->size = size;
    info->actual_size = actual_size;
    info->allocator_type = allocator_type;
    info->flags = flags;
    info->file = file;
    info->line = line;
    info->function = function;
    
    HEAP_LOCK();
    
    /* Ajouter à la hash table */
    uint32_t hash = hash_allocation_ptr(ptr);
    info->next = heap_mgr.alloc_hash[hash];
    heap_mgr.alloc_hash[hash] = info;
    
    /* Ajouter à la liste active */
    info->prev = NULL;
    info->next = heap_mgr.active_allocs;
    if (heap_mgr.active_allocs) {
        heap_mgr.active_allocs->prev = info;
    }
    heap_mgr.active_allocs = info;
    
    heap_mgr.active_count++;
    heap_mgr.current_usage += actual_size;
    
    if (heap_mgr.current_usage > heap_mgr.peak_usage) {
        heap_mgr.peak_usage = heap_mgr.current_usage;
    }
    
    HEAP_UNLOCK();
    
    /* Mettre à jour statistiques */
    global_stats.total_allocations++;
    global_stats.current_allocations++;
    global_stats.total_bytes_allocated += actual_size;
    global_stats.current_bytes_used += actual_size;
    
    if (global_stats.current_allocations > global_stats.peak_allocations) {
        global_stats.peak_allocations = global_stats.current_allocations;
    }
    
    if (global_stats.current_bytes_used > global_stats.peak_bytes_used) {
        global_stats.peak_bytes_used = global_stats.current_bytes_used;
    }
}

/**
 * @brief Retire une allocation du tracking
 * @param ptr Pointeur à libérer
 * @return Info de l'allocation ou NULL
 */
static allocation_info_t *untrack_allocation(void *ptr) {
    if (!heap_mgr.tracking_enabled || !ptr) {
        return NULL;
    }
    
    HEAP_LOCK();
    
    /* Chercher dans la hash table */
    uint32_t hash = hash_allocation_ptr(ptr);
    allocation_info_t **current = &heap_mgr.alloc_hash[hash];
    allocation_info_t *info = NULL;
    
    while (*current) {
        if ((*current)->address == ptr) {
            info = *current;
            *current = info->next;
            break;
        }
        current = &(*current)->next;
    }
    
    if (info) {
        /* Retirer de la liste active */
        if (info->prev) {
            info->prev->next = info->next;
        } else {
            heap_mgr.active_allocs = info->next;
        }
        
        if (info->next) {
            info->next->prev = info->prev;
        }
        
        heap_mgr.active_count--;
        heap_mgr.current_usage -= info->actual_size;
        
        /* Mettre à jour statistiques */
        global_stats.total_deallocations++;
        global_stats.current_allocations--;
        global_stats.total_bytes_freed += info->actual_size;
        global_stats.current_bytes_used -= info->actual_size;
    }
    
    HEAP_UNLOCK();
    
    return info;
}

/* ========================================================================
 * ALLOCATOR SELECTION
 * ======================================================================== */

/**
 * @brief Sélectionne le meilleur allocateur pour une taille donnée
 * @param size Taille à allouer
 * @param flags Flags d'allocation
 * @return Interface d'allocateur ou NULL
 */
static allocator_interface_t *select_allocator(size_t size, uint32_t flags) {
    allocator_interface_t *best_allocator = NULL;
    uint32_t best_priority = UINT32_MAX;
    
    /* Parcourir tous les allocateurs */
    for (uint32_t i = 0; i < heap_mgr.allocator_count; i++) {
        allocator_interface_t *allocator = heap_mgr.allocators[i];
        
        if (!allocator || !allocator->enabled) {
            continue;
        }
        
        /* Vérifier la compatibilité de taille */
        if (size < allocator->min_size || size > allocator->max_size) {
            continue;
        }
        
        /* Vérifier la compatibilité des flags */
        if ((flags & allocator->supported_flags) != flags) {
            continue;
        }
        
        /* Sélectionner selon la priorité */
        if (allocator->priority < best_priority) {
            best_priority = allocator->priority;
            best_allocator = allocator;
        }
    }
    
    /* Heuristiques par défaut si pas de choix optimal */
    if (!best_allocator) {
        for (uint32_t i = 0; i < heap_mgr.allocator_count; i++) {
            allocator_interface_t *allocator = heap_mgr.allocators[i];
            
            if (!allocator || !allocator->enabled) {
                continue;
            }
            
            /* Choix par type selon la taille */
            if (size <= SMALL_OBJECT_THRESHOLD && allocator->type == ALLOCATOR_SLAB) {
                best_allocator = allocator;
                break;
            } else if (size <= MEDIUM_OBJECT_THRESHOLD && allocator->type == ALLOCATOR_SLUB) {
                best_allocator = allocator;
                break;
            } else if (size <= LARGE_OBJECT_THRESHOLD && allocator->type == ALLOCATOR_BUDDY) {
                best_allocator = allocator;
                break;
            } else if (allocator->type == ALLOCATOR_VMALLOC) {
                best_allocator = allocator;
                break;
            }
        }
    }
    
    return best_allocator;
}

/* ========================================================================
 * MAIN ALLOCATION INTERFACE
 * ======================================================================== */

/**
 * @brief Alloue de la mémoire via le gestionnaire de heap
 * @param size Taille à allouer
 * @param flags Flags d'allocation
 * @param file Fichier source (pour debug)
 * @param line Ligne source (pour debug)
 * @param function Fonction appelante (pour debug)
 * @return Pointeur vers mémoire allouée ou NULL
 */
void *heap_alloc_debug(size_t size, uint32_t flags, const char *file, 
                      int line, const char *function) {
    if (!heap_initialized || size == 0) {
        return NULL;
    }
    
    /* Vérifier les limites */
    if (heap_mgr.total_limit > 0 && 
        heap_mgr.current_usage + size > heap_mgr.total_limit) {
        global_stats.allocation_failures++;
        return NULL;
    }
    
    /* Sélectionner l'allocateur */
    allocator_interface_t *allocator = select_allocator(size, flags);
    if (!allocator) {
        global_stats.allocation_failures++;
        return NULL;
    }
    
    /* Effectuer l'allocation */
    uint64_t start_time = get_heap_timestamp();
    void *ptr = allocator->alloc(size, flags);
    uint64_t end_time = get_heap_timestamp();
    
    if (!ptr) {
        allocator->allocation_failures++;
        global_stats.allocation_failures++;
        return NULL;
    }
    
    /* Obtenir la taille réelle */
    size_t actual_size = allocator->get_size ? allocator->get_size(ptr) : size;
    
    /* Initialiser à zéro si demandé */
    if (flags & GFP_ZERO) {
        memset(ptr, 0, actual_size);
    }
    
    /* Tracking de l'allocation */
    track_allocation(ptr, size, actual_size, allocator->type, flags,
                    file, line, function);
    
    /* Mettre à jour les statistiques de l'allocateur */
    allocator->allocations++;
    allocator->bytes_allocated += actual_size;
    
    /* Mettre à jour les statistiques par type */
    switch (allocator->type) {
        case ALLOCATOR_SLAB:
            global_stats.slab_allocations++;
            break;
        case ALLOCATOR_BUDDY:
            global_stats.buddy_allocations++;
            break;
        case ALLOCATOR_VMALLOC:
            global_stats.vmalloc_allocations++;
            break;
        case ALLOCATOR_DMA:
            global_stats.dma_allocations++;
            break;
    }
    
    /* Mettre à jour temps moyen */
    uint64_t allocation_time = end_time - start_time;
    global_stats.avg_allocation_time = 
        (global_stats.avg_allocation_time * (global_stats.total_allocations - 1) + 
         allocation_time) / global_stats.total_allocations;
    
    if (debug_heap) {
        printk(KERN_DEBUG "heap_alloc: ptr=%p, size=%zu, actual=%zu, allocator=%s, time=%llu\n",
               ptr, size, actual_size, allocator->name, allocation_time);
    }
    
    return ptr;
}

/**
 * @brief Libère de la mémoire via le gestionnaire de heap
 * @param ptr Pointeur à libérer
 * @param file Fichier source (pour debug)
 * @param line Ligne source (pour debug)
 * @param function Fonction appelante (pour debug)
 */
void heap_free_debug(void *ptr, const char *file, int line, const char *function) {
    if (!heap_initialized || !ptr) {
        return;
    }
    
    /* Récupérer les infos de l'allocation */
    allocation_info_t *info = untrack_allocation(ptr);
    
    if (!info) {
        if (debug_heap) {
            printk(KERN_WARNING "heap_free: unknown allocation %p from %s:%d\n",
                   ptr, file, line);
        }
        return;
    }
    
    /* Trouver l'allocateur approprié */
    allocator_interface_t *allocator = NULL;
    for (uint32_t i = 0; i < heap_mgr.allocator_count; i++) {
        if (heap_mgr.allocators[i] && 
            heap_mgr.allocators[i]->type == info->allocator_type) {
            allocator = heap_mgr.allocators[i];
            break;
        }
    }
    
    if (!allocator) {
        printk(KERN_ERR "heap_free: no allocator found for type %u\n", 
               info->allocator_type);
        free_allocation_info(info);
        return;
    }
    
    /* Effectuer la libération */
    uint64_t start_time = get_heap_timestamp();
    allocator->free(ptr);
    uint64_t end_time = get_heap_timestamp();
    
    /* Mettre à jour les statistiques de l'allocateur */
    allocator->deallocations++;
    allocator->bytes_freed += info->actual_size;
    
    /* Mettre à jour temps moyen */
    uint64_t deallocation_time = end_time - start_time;
    global_stats.avg_deallocation_time = 
        (global_stats.avg_deallocation_time * (global_stats.total_deallocations - 1) + 
         deallocation_time) / global_stats.total_deallocations;
    
    if (debug_heap) {
        printk(KERN_DEBUG "heap_free: ptr=%p, size=%zu, allocator=%s, time=%llu\n",
               ptr, info->actual_size, allocator->name, deallocation_time);
    }
    
    free_allocation_info(info);
}

/**
 * @brief Réalloue de la mémoire
 * @param ptr Pointeur existant
 * @param new_size Nouvelle taille
 * @param flags Flags d'allocation
 * @return Nouveau pointeur ou NULL
 */
void *heap_realloc(void *ptr, size_t new_size, uint32_t flags) {
    if (!heap_initialized) {
        return NULL;
    }
    
    if (!ptr) {
        return heap_alloc_debug(new_size, flags, "realloc", 0, "heap_realloc");
    }
    
    if (new_size == 0) {
        heap_free_debug(ptr, "realloc", 0, "heap_realloc");
        return NULL;
    }
    
    /* Récupérer les infos de l'allocation existante */
    HEAP_LOCK();
    uint32_t hash = hash_allocation_ptr(ptr);
    allocation_info_t *info = heap_mgr.alloc_hash[hash];
    
    while (info && info->address != ptr) {
        info = info->next;
    }
    HEAP_UNLOCK();
    
    if (!info) {
        /* Allocation inconnue - allouer normalement */
        return heap_alloc_debug(new_size, flags, "realloc", 0, "heap_realloc");
    }
    
    /* Trouver l'allocateur */
    allocator_interface_t *allocator = NULL;
    for (uint32_t i = 0; i < heap_mgr.allocator_count; i++) {
        if (heap_mgr.allocators[i] && 
            heap_mgr.allocators[i]->type == info->allocator_type) {
            allocator = heap_mgr.allocators[i];
            break;
        }
    }
    
    if (allocator && allocator->realloc) {
        /* Utiliser la méthode realloc de l'allocateur */
        void *new_ptr = allocator->realloc(ptr, new_size);
        
        if (new_ptr) {
            /* Mettre à jour les infos de tracking */
            size_t new_actual_size = allocator->get_size ? 
                allocator->get_size(new_ptr) : new_size;
            
            HEAP_LOCK();
            info->address = new_ptr;
            info->size = new_size;
            
            /* Mettre à jour l'usage */
            heap_mgr.current_usage = heap_mgr.current_usage - info->actual_size + new_actual_size;
            global_stats.current_bytes_used = global_stats.current_bytes_used - info->actual_size + new_actual_size;
            
            info->actual_size = new_actual_size;
            HEAP_UNLOCK();
        }
        
        return new_ptr;
    } else {
        /* Fallback: alloc + copy + free */
        void *new_ptr = heap_alloc_debug(new_size, flags, "realloc", 0, "heap_realloc");
        
        if (new_ptr) {
            size_t copy_size = (new_size < info->size) ? new_size : info->size;
            memcpy(new_ptr, ptr, copy_size);
            heap_free_debug(ptr, "realloc", 0, "heap_realloc");
        }
        
        return new_ptr;
    }
}

/* ========================================================================
 * ALLOCATOR REGISTRATION
 * ======================================================================== */

/**
 * @brief Enregistre un allocateur
 * @param allocator Interface d'allocateur
 * @return 0 en cas de succès
 */
int heap_register_allocator(allocator_interface_t *allocator) {
    if (!heap_initialized || !allocator || 
        heap_mgr.allocator_count >= MAX_ALLOCATORS) {
        return -1;
    }
    
    /* Validation de l'interface */
    if (!allocator->alloc || !allocator->free || !allocator->name[0]) {
        return -1;
    }
    
    HEAP_LOCK();
    heap_mgr.allocators[heap_mgr.allocator_count] = allocator;
    heap_mgr.allocator_count++;
    HEAP_UNLOCK();
    
    printk(KERN_INFO "Registered heap allocator: %s (type=%u, min=%zu, max=%zu)\n",
           allocator->name, allocator->type, allocator->min_size, allocator->max_size);
    
    return 0;
}

/* ========================================================================
 * FRAGMENTATION MANAGEMENT
 * ======================================================================== */

/**
 * @brief Calcule le niveau de fragmentation
 * @return Niveau de fragmentation (0.0 - 1.0)
 */
static float calculate_fragmentation_level(void) {
    if (global_stats.current_bytes_used == 0) {
        return 0.0f;
    }
    
    /* Estimation basée sur la différence entre allocations et usage réel */
    uint64_t theoretical_usage = global_stats.current_allocations * 
        (global_stats.current_bytes_used / global_stats.current_allocations);
    
    if (theoretical_usage == 0) {
        return 0.0f;
    }
    
    float fragmentation = 1.0f - ((float)global_stats.current_bytes_used / theoretical_usage);
    return fragmentation < 0.0f ? 0.0f : fragmentation;
}

/**
 * @brief Vérifie et gère la fragmentation
 */
static void check_fragmentation(void) {
    float fragmentation = calculate_fragmentation_level();
    global_stats.overall_fragmentation = fragmentation;
    
    if (fragmentation > heap_mgr.fragmentation_threshold) {
        global_stats.fragmentation_events++;
        
        if (debug_heap) {
            printk(KERN_WARNING "High fragmentation detected: %.2f%%\n", 
                   fragmentation * 100.0f);
        }
        
        /* Déclencher défragmentation si nécessaire */
        if (heap_mgr.auto_optimization) {
            /* TODO: Implémenter défragmentation */
            global_stats.defragmentation_runs++;
        }
    }
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise le gestionnaire de heap
 * @return 0 en cas de succès
 */
int heap_manager_init(void) {
    if (heap_initialized) {
        printk(KERN_WARNING "Heap manager already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing heap manager\n");
    
    /* Initialiser la structure principale */
    memset(&heap_mgr, 0, sizeof(heap_mgr));
    memset(&global_stats, 0, sizeof(global_stats));
    
    /* Allouer la hash table */
    heap_mgr.hash_size = 1024;
    heap_mgr.alloc_hash = (allocation_info_t **)
        malloc(heap_mgr.hash_size * sizeof(allocation_info_t *));
    
    if (!heap_mgr.alloc_hash) {
        printk(KERN_ERR "Failed to allocate hash table\n");
        return -1;
    }
    
    memset(heap_mgr.alloc_hash, 0, heap_mgr.hash_size * sizeof(allocation_info_t *));
    
    /* Configuration par défaut */
    heap_mgr.debug_mode = debug_heap;
    heap_mgr.tracking_enabled = true;
    heap_mgr.auto_optimization = true;
    heap_mgr.default_flags = GFP_KERNEL;
    heap_mgr.total_limit = default_heap_limit;
    heap_mgr.fragmentation_threshold = FRAGMENTATION_THRESHOLD;
    
    heap_initialized = true;
    
    printk(KERN_INFO "Heap manager initialized\n");
    printk(KERN_INFO "  Hash table size: %u\n", heap_mgr.hash_size);
    printk(KERN_INFO "  Tracking: %s\n", heap_mgr.tracking_enabled ? "enabled" : "disabled");
    printk(KERN_INFO "  Auto optimization: %s\n", heap_mgr.auto_optimization ? "enabled" : "disabled");
    printk(KERN_INFO "  Memory limit: %zu bytes\n", heap_mgr.total_limit);
    
    return 0;
}

/**
 * @brief Obtient les statistiques du heap
 * @param stats Pointeur vers structure de statistiques
 */
void heap_get_stats(heap_stats_t *stats) {
    if (!stats || !heap_initialized) {
        return;
    }
    
    HEAP_LOCK();
    
    /* Mettre à jour fragmentation */
    check_fragmentation();
    
    /* Copier les statistiques */
    memcpy(stats, &global_stats, sizeof(heap_stats_t));
    
    HEAP_UNLOCK();
}

/**
 * @brief Affiche les statistiques du heap
 */
void heap_print_stats(void) {
    if (!heap_initialized) {
        printk(KERN_INFO "Heap manager not initialized\n");
        return;
    }
    
    check_fragmentation();
    
    printk(KERN_INFO "Heap Manager Statistics:\n");
    printk(KERN_INFO "  Total allocations:    %llu\n", global_stats.total_allocations);
    printk(KERN_INFO "  Total deallocations:  %llu\n", global_stats.total_deallocations);
    printk(KERN_INFO "  Current allocations:  %llu\n", global_stats.current_allocations);
    printk(KERN_INFO "  Peak allocations:     %llu\n", global_stats.peak_allocations);
    printk(KERN_INFO "  Current memory used:  %llu bytes\n", global_stats.current_bytes_used);
    printk(KERN_INFO "  Peak memory used:     %llu bytes\n", global_stats.peak_bytes_used);
    printk(KERN_INFO "  Allocation failures:  %llu\n", global_stats.allocation_failures);
    printk(KERN_INFO "  Avg alloc time:       %.2f units\n", global_stats.avg_allocation_time);
    printk(KERN_INFO "  Avg dealloc time:     %.2f units\n", global_stats.avg_deallocation_time);
    printk(KERN_INFO "  Overall fragmentation: %.2f%%\n", global_stats.overall_fragmentation * 100.0f);
    
    printk(KERN_INFO "  Allocations by type:\n");
    printk(KERN_INFO "    SLAB:               %llu\n", global_stats.slab_allocations);
    printk(KERN_INFO "    Buddy:              %llu\n", global_stats.buddy_allocations);
    printk(KERN_INFO "    Vmalloc:            %llu\n", global_stats.vmalloc_allocations);
    printk(KERN_INFO "    DMA:                %llu\n", global_stats.dma_allocations);
    
    printk(KERN_INFO "  Registered allocators: %u\n", heap_mgr.allocator_count);
    for (uint32_t i = 0; i < heap_mgr.allocator_count; i++) {
        if (heap_mgr.allocators[i]) {
            allocator_interface_t *alloc = heap_mgr.allocators[i];
            printk(KERN_INFO "    %s: %llu allocs, %llu bytes, %llu failures\n",
                   alloc->name, alloc->allocations, alloc->bytes_allocated, 
                   alloc->allocation_failures);
        }
    }
}

/* Macros pour simplifier l'utilisation */
#define kmalloc(size, flags) heap_alloc_debug(size, flags, __FILE__, __LINE__, __func__)
#define kfree(ptr) heap_free_debug(ptr, __FILE__, __LINE__, __func__)
#define krealloc(ptr, size, flags) heap_realloc(ptr, size, flags)

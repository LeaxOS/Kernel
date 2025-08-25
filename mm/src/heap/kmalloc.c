/**
 * @file kmalloc.c
 * @brief Allocateur kernel (style malloc) - Interface générale d'allocation mémoire
 * 
 * Ce fichier implémente l'interface principale d'allocation mémoire pour le
 * kernel LeaxOS. Il fournit une API compatible malloc/free avec des extensions
 * spécifiques au kernel:
 * 
 * - kmalloc() / kfree() : Allocation/libération standard
 * - kcalloc() : Allocation avec zéro-initialisation
 * - krealloc() : Redimensionnement d'allocation
 * - kstrdup() : Duplication de chaînes
 * - Support des flags GFP (Get Free Pages)
 * - Gestion des tailles variables (8 bytes à plusieurs MB)
 * - Intégration avec SLAB/SLUB et buddy allocator
 * - Détection des fuites mémoire et corruption
 * - Statistiques et métriques détaillées
 * 
 * L'allocateur route automatiquement les demandes vers le meilleur
 * sous-allocateur selon la taille et les contraintes.
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
#include "../../include/slab.h"
#include "../../include/vmalloc.h"
#include "../../include/page_alloc.h"
#include "../physical/phys_page.h"

/* ========================================================================
 * CONSTANTS AND CONFIGURATION
 * ======================================================================== */

/* Limites de tailles */
#define KMALLOC_MIN_SIZE        8           /* Taille minimale */
#define KMALLOC_MAX_SIZE        (32 * 1024 * 1024) /* 32MB maximum */
#define KMALLOC_LARGE_THRESHOLD (PAGE_SIZE * 2)     /* Seuil grandes allocs */
#define KMALLOC_HUGE_THRESHOLD  (PAGE_SIZE * 16)    /* Seuil énormes allocs */

/* Tailles de caches SLAB prédéfinies */
#define KMALLOC_CACHE_COUNT     13
static const size_t kmalloc_cache_sizes[KMALLOC_CACHE_COUNT] = {
    8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192
};

/* Flags d'allocation internes */
#define KMALLOC_FLAG_SLAB       (1 << 0)   /* Alloué via SLAB */
#define KMALLOC_FLAG_VMALLOC    (1 << 1)   /* Alloué via vmalloc */
#define KMALLOC_FLAG_PAGES      (1 << 2)   /* Alloué via page allocator */
#define KMALLOC_FLAG_TRACKED    (1 << 3)   /* Allocation trackée */
#define KMALLOC_FLAG_ZEROED     (1 << 4)   /* Mémoire zéro-initialisée */

/* Configuration du tracking */
#define KMALLOC_TRACK_MAX       1024        /* Allocations trackées max */
#define KMALLOC_GUARD_SIZE      16          /* Taille guard bytes */
#define KMALLOC_MAGIC_ALLOC     0xABCDEF00  /* Magic allocation */
#define KMALLOC_MAGIC_FREE      0xDEADBEEF  /* Magic libération */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Header d'allocation avec métadonnées
 */
typedef struct kmalloc_header {
    uint32_t magic;                 /* Magic number */
    size_t size;                    /* Taille demandée */
    size_t real_size;               /* Taille réellement allouée */
    uint32_t flags;                 /* Flags d'allocation */
    uint32_t allocator_type;        /* Type d'allocateur utilisé */
    const char *file;               /* Fichier source */
    int line;                       /* Ligne source */
    uint64_t timestamp;             /* Timestamp allocation */
    struct kmalloc_header *next;    /* Liste chaînée */
    struct kmalloc_header *prev;    /* Liste chaînée */
} kmalloc_header_t;

/**
 * @brief Cache SLAB pour kmalloc
 */
typedef struct {
    struct kmem_cache *cache;       /* Cache SLAB */
    size_t object_size;             /* Taille des objets */
    size_t align;                   /* Alignement */
    uint32_t flags;                 /* Flags du cache */
    const char *name;               /* Nom du cache */
    bool active;                    /* Cache actif */
    
    /* Statistiques */
    uint64_t alloc_count;           /* Allocations */
    uint64_t free_count;            /* Libérations */
    uint64_t bytes_allocated;       /* Octets alloués */
    uint64_t active_objects;        /* Objets actifs */
} kmalloc_cache_t;

/**
 * @brief Statistiques kmalloc globales
 */
typedef struct {
    /* Compteurs généraux */
    uint64_t total_allocs;          /* Allocations totales */
    uint64_t total_frees;           /* Libérations totales */
    uint64_t active_allocs;         /* Allocations actives */
    uint64_t failed_allocs;         /* Allocations échouées */
    
    /* Utilisation mémoire */
    uint64_t bytes_allocated;       /* Octets alloués total */
    uint64_t bytes_freed;           /* Octets libérés total */
    uint64_t bytes_active;          /* Octets actifs */
    uint64_t bytes_peak;            /* Pic d'utilisation */
    uint64_t bytes_waste;           /* Gaspillage (fragmentation) */
    
    /* Par allocateur */
    uint64_t slab_allocs;           /* Allocations SLAB */
    uint64_t vmalloc_allocs;        /* Allocations vmalloc */
    uint64_t page_allocs;           /* Allocations pages */
    
    /* Détection d'erreurs */
    uint64_t double_free_detected;  /* Double free détectés */
    uint64_t corruption_detected;   /* Corruptions détectées */
    uint64_t leaks_detected;        /* Fuites détectées */
    
    /* Performance */
    uint64_t cache_hits;            /* Hits cache */
    uint64_t cache_misses;          /* Misses cache */
} kmalloc_stats_t;

/**
 * @brief État global de kmalloc
 */
typedef struct {
    bool initialized;               /* Système initialisé */
    bool tracking_enabled;          /* Tracking des allocations */
    kmalloc_cache_t caches[KMALLOC_CACHE_COUNT]; /* Caches SLAB */
    kmalloc_header_t *alloc_list;   /* Liste des allocations */
    kmalloc_stats_t stats;          /* Statistiques */
    mm_spinlock_t lock;                /* Verrou principal */
} kmalloc_state_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

static kmalloc_state_t g_kmalloc_state = {
    .initialized = false,
    .tracking_enabled = false,
    .alloc_list = NULL,
    .stats = {0}
};

/* Noms des caches pour debugging */
static const char *cache_names[KMALLOC_CACHE_COUNT] = {
    "kmalloc-8", "kmalloc-16", "kmalloc-32", "kmalloc-64",
    "kmalloc-96", "kmalloc-128", "kmalloc-192", "kmalloc-256",
    "kmalloc-512", "kmalloc-1024", "kmalloc-2048", "kmalloc-4096",
    "kmalloc-8192"
};

/* Synchronization */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
#define KMALLOC_LOCK() mm_spin_lock(&g_kmalloc_state.lock)
#define KMALLOC_UNLOCK() mm_spin_unlock(&g_kmalloc_state.lock)
#else
#define KMALLOC_LOCK() do {} while(0)
#define KMALLOC_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Trouve le cache approprié pour une taille
 * @param size Taille demandée
 * @return Index du cache ou -1 si trop grand
 */
static int find_cache_index(size_t size) {
    for (int i = 0; i < KMALLOC_CACHE_COUNT; i++) {
        if (size <= kmalloc_cache_sizes[i]) {
            return i;
        }
    }
    return -1; /* Trop grand pour les caches */
}

/**
 * @brief Calcule la taille réelle d'allocation incluant les métadonnées
 * @param requested_size Taille demandée
 * @param include_header Inclure le header
 * @param include_guards Inclure les guard bytes
 * @return Taille totale
 */
static size_t calculate_real_size(size_t requested_size, bool include_header, bool include_guards) {
    size_t total_size = requested_size;
    
    if (include_header) {
        total_size += sizeof(kmalloc_header_t);
    }
    
    if (include_guards) {
        total_size += 2 * KMALLOC_GUARD_SIZE; /* Front + back guards */
    }
    
    /* Alignement minimum */
    total_size = (total_size + 7) & ~7;
    
    return total_size;
}

/**
 * @brief Valide un pointeur kmalloc
 * @param ptr Pointeur à valider
 * @return Header de l'allocation ou NULL si invalide
 */
static kmalloc_header_t *validate_kmalloc_ptr(const void *ptr) {
    if (!ptr || !g_kmalloc_state.tracking_enabled) {
        return NULL;
    }
    
    /* Le header est juste avant le pointeur utilisateur */
    kmalloc_header_t *header = ((kmalloc_header_t *)ptr) - 1;
    
    /* Vérifier le magic number */
    if (header->magic != KMALLOC_MAGIC_ALLOC) {
        return NULL;
    }
    
    /* Vérifier que le pointeur est dans notre liste */
    kmalloc_header_t *current = g_kmalloc_state.alloc_list;
    while (current) {
        if (current == header) {
            return header;
        }
        current = current->next;
    }
    
    return NULL;
}

/**
 * @brief Ajoute une allocation à la liste de tracking
 * @param header Header de l'allocation
 */
static void track_allocation(kmalloc_header_t *header) {
    if (!header || !g_kmalloc_state.tracking_enabled) {
        return;
    }
    
    header->next = g_kmalloc_state.alloc_list;
    header->prev = NULL;
    
    if (g_kmalloc_state.alloc_list) {
        g_kmalloc_state.alloc_list->prev = header;
    }
    
    g_kmalloc_state.alloc_list = header;
}

/**
 * @brief Retire une allocation de la liste de tracking
 * @param header Header de l'allocation
 */
static void untrack_allocation(kmalloc_header_t *header) {
    if (!header) return;
    
    if (header->prev) {
        header->prev->next = header->next;
    } else {
        g_kmalloc_state.alloc_list = header->next;
    }
    
    if (header->next) {
        header->next->prev = header->prev;
    }
}

/**
 * @brief Obtient un timestamp simple
 * @return Timestamp
 */
static uint64_t get_timestamp(void) {
    /* TODO: Utiliser un timer réel */
    static uint64_t counter = 0;
    return ++counter;
}

/* ========================================================================
 * SLAB CACHE MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise les caches SLAB pour kmalloc
 * @return 0 en cas de succès
 */
static int init_kmalloc_caches(void) {
    printk(KERN_INFO "Initializing kmalloc SLAB caches\n");
    
    for (int i = 0; i < KMALLOC_CACHE_COUNT; i++) {
        kmalloc_cache_t *cache = &g_kmalloc_state.caches[i];
        
        cache->object_size = kmalloc_cache_sizes[i];
        cache->align = (cache->object_size >= 64) ? 64 : 8;
        cache->flags = 0;
        cache->name = cache_names[i];
        cache->active = false;
        
        /* Créer le cache SLAB */
        cache->cache = kmem_cache_create(cache->name,
                                        cache->object_size,
                                        cache->align,
                                        cache->flags,
                                        NULL, NULL);
        
        if (!cache->cache) {
            printk(KERN_ERR "Failed to create cache %s\n", cache->name);
            return -1;
        }
        
        cache->active = true;
        
        /* Initialiser statistiques */
        cache->alloc_count = 0;
        cache->free_count = 0;
        cache->bytes_allocated = 0;
        cache->active_objects = 0;
        
        printk(KERN_DEBUG "Created cache %s (size=%zu, align=%zu)\n",
               cache->name, cache->object_size, cache->align);
    }
    
    printk(KERN_INFO "All kmalloc caches initialized\n");
    return 0;
}

/**
 * @brief Alloue un objet depuis un cache SLAB
 * @param cache_idx Index du cache
 * @param flags Flags d'allocation
 * @return Pointeur vers l'objet ou NULL
 */
static void *alloc_from_cache(int cache_idx, gfp_flags_t flags) {
    if (cache_idx < 0 || cache_idx >= KMALLOC_CACHE_COUNT) {
        return NULL;
    }
    
    kmalloc_cache_t *cache = &g_kmalloc_state.caches[cache_idx];
    
    if (!cache->active) {
        return NULL;
    }
    
    void *obj = kmem_cache_alloc(cache->cache, flags);
    if (obj) {
        cache->alloc_count++;
        cache->bytes_allocated += cache->object_size;
        cache->active_objects++;
        g_kmalloc_state.stats.cache_hits++;
    } else {
        g_kmalloc_state.stats.cache_misses++;
    }
    
    return obj;
}

/**
 * @brief Libère un objet vers un cache SLAB
 * @param cache_idx Index du cache
 * @param obj Objet à libérer
 */
static void free_to_cache(int cache_idx, void *obj) {
    if (cache_idx < 0 || cache_idx >= KMALLOC_CACHE_COUNT || !obj) {
        return;
    }
    
    kmalloc_cache_t *cache = &g_kmalloc_state.caches[cache_idx];
    
    if (!cache->active) {
        return;
    }
    
    kmem_cache_free(cache->cache, obj);
    
    cache->free_count++;
    cache->active_objects--;
}

/* ========================================================================
 * CORE ALLOCATION FUNCTIONS
 * ======================================================================== */

/**
 * @brief Fonction d'allocation interne avec tracking
 * @param size Taille demandée
 * @param flags Flags d'allocation
 * @param file Fichier source
 * @param line Ligne source
 * @return Pointeur vers la mémoire allouée
 */
static void *kmalloc_internal(size_t size, gfp_flags_t flags, const char *file, int line) {
    if (!g_kmalloc_state.initialized || size == 0 || size > KMALLOC_MAX_SIZE) {
        g_kmalloc_state.stats.failed_allocs++;
        return NULL;
    }
    
    KMALLOC_LOCK();
    
    void *ptr = NULL;
    uint32_t alloc_flags = 0;
    int cache_idx = -1;
    
    /* Déterminer la stratégie d'allocation */
    if (size <= kmalloc_cache_sizes[KMALLOC_CACHE_COUNT - 1]) {
        /* Utiliser les caches SLAB */
        cache_idx = find_cache_index(size);
        if (cache_idx >= 0) {
            ptr = alloc_from_cache(cache_idx, flags);
            alloc_flags |= KMALLOC_FLAG_SLAB;
        }
    } else if (size < KMALLOC_HUGE_THRESHOLD) {
        /* Utiliser vmalloc pour allocations moyennes */
        ptr = vmalloc(size);
        alloc_flags |= KMALLOC_FLAG_VMALLOC;
    } else {
        /* Utiliser allocateur de pages pour grandes allocations */
        size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        uint64_t phys_addr = pmm_alloc_pages(pages);
        if (phys_addr) {
            ptr = (void *)phys_to_virt(phys_addr);
            alloc_flags |= KMALLOC_FLAG_PAGES;
        }
    }
    
    if (!ptr) {
        g_kmalloc_state.stats.failed_allocs++;
        KMALLOC_UNLOCK();
        return NULL;
    }
    
    /* Zéro-initialiser si demandé */
    if (flags & GFP_ZERO) {
        size_t real_size = (cache_idx >= 0) ? kmalloc_cache_sizes[cache_idx] : size;
        memset(ptr, 0, real_size);
        alloc_flags |= KMALLOC_FLAG_ZEROED;
    }
    
    /* Créer le header de tracking si activé */
    if (g_kmalloc_state.tracking_enabled) {
        /* Pour le tracking, on doit réserver de l'espace pour le header */
        /* TODO: Implémentation complète du tracking avec headers */
        alloc_flags |= KMALLOC_FLAG_TRACKED;
    }
    
    /* Mettre à jour les statistiques */
    g_kmalloc_state.stats.total_allocs++;
    g_kmalloc_state.stats.active_allocs++;
    g_kmalloc_state.stats.bytes_allocated += size;
    g_kmalloc_state.stats.bytes_active += size;
    
    if (g_kmalloc_state.stats.bytes_active > g_kmalloc_state.stats.bytes_peak) {
        g_kmalloc_state.stats.bytes_peak = g_kmalloc_state.stats.bytes_active;
    }
    
    /* Incrémenter compteur par allocateur */
    if (alloc_flags & KMALLOC_FLAG_SLAB) {
        g_kmalloc_state.stats.slab_allocs++;
    } else if (alloc_flags & KMALLOC_FLAG_VMALLOC) {
        g_kmalloc_state.stats.vmalloc_allocs++;
    } else if (alloc_flags & KMALLOC_FLAG_PAGES) {
        g_kmalloc_state.stats.page_allocs++;
    }
    
    KMALLOC_UNLOCK();
    
    printk(KERN_DEBUG "kmalloc: %zu bytes at %p (flags=0x%x, %s:%d)\n",
           size, ptr, alloc_flags, file ? file : "unknown", line);
    
    return ptr;
}

/**
 * @brief Fonction de libération interne
 * @param ptr Pointeur à libérer
 * @param file Fichier source
 * @param line Ligne source
 */
static void kfree_internal(void *ptr, const char *file, int line) {
    if (!ptr) {
        return;
    }
    
    if (!g_kmalloc_state.initialized) {
        printk(KERN_ERR "kfree called before kmalloc initialization\n");
        return;
    }
    
    KMALLOC_LOCK();
    
    /* TODO: Déterminer comment l'allocation a été faite */
    /* Pour l'instant, tentative de libération via différents allocateurs */
    
    bool freed = false;
    
    /* Essayer les caches SLAB d'abord */
    for (int i = 0; i < KMALLOC_CACHE_COUNT; i++) {
        /* TODO: Vérifier si le pointeur appartient à ce cache */
        /* Pour l'instant, on ne peut pas déterminer facilement */
    }
    
    /* Si pas trouvé dans SLAB, essayer vmalloc */
    if (!freed) {
        /* TODO: Vérifier si c'est une allocation vmalloc */
        vfree(ptr);
        freed = true;
    }
    
    /* Mettre à jour les statistiques */
    g_kmalloc_state.stats.total_frees++;
    if (g_kmalloc_state.stats.active_allocs > 0) {
        g_kmalloc_state.stats.active_allocs--;
    }
    
    KMALLOC_UNLOCK();
    
    printk(KERN_DEBUG "kfree: %p (%s:%d)\n", ptr, file ? file : "unknown", line);
}

/* ========================================================================
 * PUBLIC API FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialise le système kmalloc
 * @return 0 en cas de succès
 */
int kmalloc_init(void) {
    if (g_kmalloc_state.initialized) {
        printk(KERN_WARNING "kmalloc already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing kmalloc subsystem\n");
    
    /* Réinitialiser l'état */
    memset(&g_kmalloc_state.stats, 0, sizeof(kmalloc_stats_t));
    g_kmalloc_state.alloc_list = NULL;
    g_kmalloc_state.tracking_enabled = true; /* Activer par défaut */
    
    /* Initialiser les caches SLAB */
    if (init_kmalloc_caches() != 0) {
        printk(KERN_ERR "Failed to initialize kmalloc caches\n");
        return -1;
    }
    
    g_kmalloc_state.initialized = true;
    
    printk(KERN_INFO "kmalloc subsystem initialized\n");
    printk(KERN_INFO "  Cache sizes: ");
    for (int i = 0; i < KMALLOC_CACHE_COUNT; i++) {
        printk(KERN_CONT "%zu", kmalloc_cache_sizes[i]);
        if (i < KMALLOC_CACHE_COUNT - 1) printk(KERN_CONT ", ");
    }
    printk(KERN_CONT " bytes\n");
    printk(KERN_INFO "  Max allocation: %d MB\n", KMALLOC_MAX_SIZE / (1024 * 1024));
    
    return 0;
}

/**
 * @brief Allocation mémoire kernel standard
 * @param size Taille en octets
 * @param flags Flags d'allocation GFP
 * @return Pointeur vers la mémoire allouée ou NULL
 */
void *kmalloc(size_t size, gfp_flags_t flags) {
    return kmalloc_internal(size, flags, __FILE__, __LINE__);
}

/**
 * @brief Allocation mémoire avec zéro-initialisation
 * @param nmemb Nombre d'éléments
 * @param size Taille de chaque élément
 * @param flags Flags d'allocation GFP
 * @return Pointeur vers la mémoire allouée ou NULL
 */
void *kcalloc(size_t nmemb, size_t size, gfp_flags_t flags) {
    if (nmemb == 0 || size == 0) {
        return NULL;
    }
    
    /* Vérifier overflow */
    if (nmemb > SIZE_MAX / size) {
        return NULL;
    }
    
    return kmalloc_internal(nmemb * size, flags | GFP_ZERO, __FILE__, __LINE__);
}

/**
 * @brief Redimensionne une allocation existante
 * @param ptr Pointeur existant (peut être NULL)
 * @param new_size Nouvelle taille
 * @param flags Flags d'allocation
 * @return Pointeur vers la nouvelle allocation ou NULL
 */
void *krealloc(void *ptr, size_t new_size, gfp_flags_t flags) {
    if (!ptr) {
        return kmalloc(new_size, flags);
    }
    
    if (new_size == 0) {
        kfree(ptr);
        return NULL;
    }
    
    /* TODO: Optimiser en gardant l'allocation si possible */
    
    void *new_ptr = kmalloc(new_size, flags);
    if (!new_ptr) {
        return NULL;
    }
    
    /* TODO: Déterminer la taille de l'ancienne allocation pour copy */
    /* Pour l'instant, on assume que new_size <= old_size */
    memcpy(new_ptr, ptr, new_size);
    
    kfree(ptr);
    return new_ptr;
}

/**
 * @brief Duplique une chaîne de caractères
 * @param s Chaîne source
 * @param flags Flags d'allocation
 * @return Pointeur vers la chaîne dupliquée ou NULL
 */
char *kstrdup(const char *s, gfp_flags_t flags) {
    if (!s) {
        return NULL;
    }
    
    size_t len = strlen(s) + 1;
    char *dup = kmalloc(len, flags);
    
    if (dup) {
        memcpy(dup, s, len);
    }
    
    return dup;
}

/**
 * @brief Libère la mémoire allouée par kmalloc
 * @param ptr Pointeur à libérer
 */
void kfree(void *ptr) {
    kfree_internal(ptr, __FILE__, __LINE__);
}

/* ========================================================================
 * STATISTICS AND DEBUGGING
 * ======================================================================== */

/**
 * @brief Obtient les statistiques kmalloc
 * @param stats Pointeur vers structure de statistiques
 */
void kmalloc_get_stats(kmalloc_stats_t *stats) {
    if (!stats || !g_kmalloc_state.initialized) {
        return;
    }
    
    KMALLOC_LOCK();
    memcpy(stats, &g_kmalloc_state.stats, sizeof(kmalloc_stats_t));
    KMALLOC_UNLOCK();
}

/**
 * @brief Affiche les statistiques kmalloc
 */
void kmalloc_print_stats(void) {
    if (!g_kmalloc_state.initialized) {
        printk(KERN_INFO "kmalloc not initialized\n");
        return;
    }
    
    kmalloc_stats_t stats;
    kmalloc_get_stats(&stats);
    
    printk(KERN_INFO "kmalloc Statistics:\n");
    printk(KERN_INFO "  Total allocations:   %llu\n", stats.total_allocs);
    printk(KERN_INFO "  Total frees:         %llu\n", stats.total_frees);
    printk(KERN_INFO "  Active allocations:  %llu\n", stats.active_allocs);
    printk(KERN_INFO "  Failed allocations:  %llu\n", stats.failed_allocs);
    printk(KERN_INFO "  Bytes allocated:     %llu (%llu MB)\n", 
           stats.bytes_allocated, stats.bytes_allocated / (1024 * 1024));
    printk(KERN_INFO "  Bytes active:        %llu (%llu MB)\n", 
           stats.bytes_active, stats.bytes_active / (1024 * 1024));
    printk(KERN_INFO "  Peak usage:          %llu (%llu MB)\n", 
           stats.bytes_peak, stats.bytes_peak / (1024 * 1024));
    printk(KERN_INFO "  SLAB allocations:    %llu\n", stats.slab_allocs);
    printk(KERN_INFO "  vmalloc allocations: %llu\n", stats.vmalloc_allocs);
    printk(KERN_INFO "  page allocations:    %llu\n", stats.page_allocs);
    printk(KERN_INFO "  Cache hits:          %llu\n", stats.cache_hits);
    printk(KERN_INFO "  Cache misses:        %llu\n", stats.cache_misses);
    
    if (stats.cache_hits + stats.cache_misses > 0) {
        uint64_t hit_rate = (stats.cache_hits * 100) / (stats.cache_hits + stats.cache_misses);
        printk(KERN_INFO "  Cache hit rate:      %llu%%\n", hit_rate);
    }
    
    /* Statistiques par cache */
    printk(KERN_INFO "Cache Statistics:\n");
    for (int i = 0; i < KMALLOC_CACHE_COUNT; i++) {
        kmalloc_cache_t *cache = &g_kmalloc_state.caches[i];
        if (cache->active && cache->alloc_count > 0) {
            printk(KERN_INFO "  %-12s: %8llu allocs, %8llu active, %8llu KB\n",
                   cache->name, cache->alloc_count, cache->active_objects,
                   cache->bytes_allocated / 1024);
        }
    }
}

/**
 * @brief Vérifie l'intégrité du système kmalloc
 * @return true si intègre
 */
bool kmalloc_check_integrity(void) {
    if (!g_kmalloc_state.initialized) {
        return false;
    }
    
    bool integrity_ok = true;
    
    KMALLOC_LOCK();
    
    /* Vérifier les statistiques de base */
    if (g_kmalloc_state.stats.total_frees > g_kmalloc_state.stats.total_allocs) {
        printk(KERN_ERR "kmalloc: more frees than allocs\n");
        integrity_ok = false;
    }
    
    /* TODO: Vérifier l'intégrité des allocations trackées */
    /* TODO: Vérifier l'intégrité des caches SLAB */
    
    KMALLOC_UNLOCK();
    
    return integrity_ok;
}

/**
 * @brief Active/désactive le tracking des allocations
 * @param enable true pour activer, false pour désactiver
 */
void kmalloc_set_tracking(bool enable) {
    KMALLOC_LOCK();
    g_kmalloc_state.tracking_enabled = enable;
    KMALLOC_UNLOCK();
    
    printk(KERN_INFO "kmalloc tracking %s\n", enable ? "enabled" : "disabled");
}

/**
 * @brief Dump des allocations actives (si tracking activé)
 */
void kmalloc_dump_allocations(void) {
    if (!g_kmalloc_state.initialized || !g_kmalloc_state.tracking_enabled) {
        printk(KERN_INFO "kmalloc tracking not active\n");
        return;
    }
    
    printk(KERN_INFO "Active kmalloc allocations:\n");
    
    KMALLOC_LOCK();
    
    kmalloc_header_t *current = g_kmalloc_state.alloc_list;
    size_t count = 0;
    
    while (current) {
        printk(KERN_INFO "  [%zu] %zu bytes at %p (from %s:%d)\n",
               ++count, current->size, current + 1,
               current->file ? current->file : "unknown",
               current->line);
        current = current->next;
    }
    
    if (count == 0) {
        printk(KERN_INFO "  No active allocations\n");
    } else {
        printk(KERN_INFO "  Total: %zu active allocations\n", count);
    }
    
    KMALLOC_UNLOCK();
}

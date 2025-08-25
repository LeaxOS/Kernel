/**
 * @file slub_allocator.c
 * @brief Implémentation de l'allocateur SLUB pour LeaxOS
 * 
 * Le SLUB (Slab Unification Layer) est une version améliorée du SLAB allocator
 * qui simplifie la gestion des caches et améliore les performances sur les
 * systèmes SMP. Il remplace les queues par des pointeurs directs et optimise
 * l'utilisation des caches per-CPU.
 * 
 * Fonctionnalités principales:
 * - Caches simplifiés avec pointeurs directs
 * - Optimisation per-CPU avancée
 * - Allocation/libération rapide avec freelist directe
 * - Mécanisme de fallback efficace
 * - Debug et tracing améliorés
 * - Support pour objets de grande taille
 * - Gestion automatique de la fragmentation
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
#include "../../include/slab.h"

/* Fallback GFP definitions if not included properly */
#ifndef GFP_ZERO
#define GFP_ZERO        (1 << 14)       /* Zero-initialize */
#endif
#ifndef GFP_DMA
#define GFP_DMA         (1 << 8)        /* DMA memory zone */
#endif

/* ========================================================================
 * SLUB ALLOCATOR CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/* Constantes de configuration */
#define SLUB_MAX_CACHES         128     /* Nombre max de caches */
#define SLUB_MAX_ORDER          10      /* Ordre max d'allocation */
#define SLUB_MIN_OBJECTS        16      /* Objets min par slab */
#define SLUB_MAX_OBJECTS        512     /* Objets max par slab */
#define SLUB_CPU_PARTIAL        30      /* Objets partiels per-CPU */

/* Flags SLUB */
#define SLUB_DEBUG              0x01    /* Debug activé */
#define SLUB_TRACE              0x02    /* Traçage activé */
#define SLUB_RED_ZONE           0x04    /* Red zones */
#define SLUB_POISON             0x08    /* Poison objects */
#define SLUB_STORE_USER         0x10    /* Store user info */
#define SLUB_RECLAIM_ACCOUNT    0x20    /* Account for reclaim */

/* États des pages SLUB */
#define SLUB_PAGE_FROZEN        0x01    /* Page gelée (per-CPU) */
#define SLUB_PAGE_PARTIAL       0x02    /* Page partiellement utilisée */
#define SLUB_PAGE_FULL          0x04    /* Page pleine */
#define SLUB_PAGE_ACTIVE        0x08    /* Page active */

/* Constantes de performance */
#define SLUB_FASTPATH_THRESHOLD 8       /* Seuil pour fastpath */
#define SLUB_SLOWPATH_ALLOC     1       /* Allocation slowpath */
#define SLUB_SLOWPATH_FREE      2       /* Libération slowpath */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Page SLUB - structure de gestion d'une page
 */
typedef struct slub_page {
    void *freelist;                     /* Liste des objets libres */
    union {
        struct {
            uint16_t inuse;             /* Objets en cours d'usage */
            uint16_t objects;           /* Nombre total d'objets */
        };
        uint32_t counters;              /* Compteurs combinés */
    };
    
    uint8_t flags;                      /* Flags de la page */
    uint8_t frozen;                     /* Page gelée pour per-CPU */
    
    struct slub_cache *slab_cache;      /* Cache parent */
    struct slub_page *next;             /* Prochaine page dans la liste */
    
#ifdef CONFIG_DEBUG_SLUB
    void *s_mem;                        /* Début de la mémoire */
    uint32_t magic;                     /* Magic number */
#endif
    
} slub_page_t;

/**
 * @brief Cache per-CPU SLUB
 */
typedef struct slub_cpu_cache {
    void **freelist;                    /* Freelist per-CPU */
    slub_page_t *page;                  /* Page courante */
    slub_page_t *partial;               /* Pages partielles */
    uint32_t objects;                   /* Objets dans la freelist */
    uint32_t tid;                       /* Transaction ID */
} slub_cpu_cache_t;

/**
 * @brief Cache SLUB principal
 */
typedef struct slub_cache {
    /* Identification */
    char name[32];                      /* Nom du cache */
    uint32_t flags;                     /* Flags de configuration */
    uint32_t size;                      /* Taille d'un objet */
    uint32_t object_size;               /* Taille réelle de l'objet */
    uint32_t offset;                    /* Offset du pointeur libre */
    uint32_t cpu_partial;               /* Objets partiels per-CPU */
    
    /* Configuration de slab */
    uint32_t oo;                        /* Objets et ordre combinés */
    uint32_t min;                       /* Configuration minimale */
    uint32_t max;                       /* Configuration maximale */
    
    /* Gestion des pages */
    slub_page_t *node_partial;          /* Pages partielles du nœud */
    uint32_t node_nr_partial;           /* Nombre de pages partielles */
    uint32_t min_partial;               /* Minimum de pages partielles */
    
    /* Per-CPU data */
#ifdef CONFIG_SMP
    slub_cpu_cache_t __percpu *cpu_slab; /* Caches per-CPU */
#else
    slub_cpu_cache_t cpu_slab;          /* Cache unique */
#endif
    
    /* Constructeur/Destructeur */
    void (*ctor)(void *obj);            /* Constructeur */
    void (*dtor)(void *obj);            /* Destructeur */
    
    /* Statistiques */
    uint64_t allocations;               /* Allocations totales */
    uint64_t frees;                     /* Libérations totales */
    uint64_t alloc_fastpath;            /* Allocations fastpath */
    uint64_t alloc_slowpath;            /* Allocations slowpath */
    uint64_t free_fastpath;             /* Libérations fastpath */
    uint64_t free_slowpath;             /* Libérations slowpath */
    uint64_t partial_alloc;             /* Allocations depuis partial */
    uint64_t partial_free;              /* Libérations vers partial */
    
    /* Chaînage */
    struct slub_cache *next;            /* Prochain cache */
    
} slub_cache_t;

/**
 * @brief Gestionnaire global SLUB
 */
typedef struct slub_allocator {
    /* Caches enregistrés */
    slub_cache_t *cache_list;           /* Liste des caches */
    uint32_t cache_count;               /* Nombre de caches */
    
    /* Caches kmalloc */
    slub_cache_t *kmalloc_caches[16];   /* Caches kmalloc */
    slub_cache_t *kmalloc_dma_caches[16]; /* Caches DMA */
    
    /* Configuration globale */
    bool debug_enabled;                 /* Debug global */
    bool trace_enabled;                 /* Traçage global */
    uint32_t min_partial;               /* Pages partielles min */
    uint32_t cpu_partial;               /* Objets CPU partiels */
    
    /* Statistiques globales */
    uint64_t total_allocations;         /* Allocations totales */
    uint64_t total_frees;               /* Libérations totales */
    uint64_t fastpath_allocations;      /* Allocations fastpath */
    uint64_t slowpath_allocations;      /* Allocations slowpath */
    uint64_t fastpath_frees;            /* Libérations fastpath */
    uint64_t slowpath_frees;            /* Libérations slowpath */
    uint64_t oom_count;                 /* Erreurs out-of-memory */
    
} slub_allocator_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Gestionnaire principal */
static slub_allocator_t slub_allocator;
static bool slub_initialized = false;

/* Configuration */
static bool debug_slub = false;
static uint32_t slub_min_partial = 5;
static uint32_t slub_cpu_partial = SLUB_CPU_PARTIAL;

/* CPU ID simulation pour systems non-SMP */
#ifndef CONFIG_SMP
static uint32_t current_cpu = 0;
#define smp_processor_id() (current_cpu)
#define this_cpu_ptr(ptr) (&(ptr))
#else
/* Pour SMP, ces fonctions seraient définies ailleurs */
extern uint32_t smp_processor_id(void);
extern void *this_cpu_ptr(void *ptr);
#endif

/* Synchronization */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
static mm_spinlock_t slub_lock = MM_SPINLOCK_INIT("unknown");
#define SLUB_LOCK() mm_spin_lock(&slub_lock)
#define SLUB_UNLOCK() mm_spin_unlock(&slub_lock)
#else
#define SLUB_LOCK() do {} while(0)
#define SLUB_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Encode objets et ordre en un seul nombre
 * @param objects Nombre d'objets
 * @param order Ordre d'allocation
 * @return Valeur encodée
 */
static uint32_t oo_make(uint32_t objects, uint32_t order) {
    return (objects << 16) | order;
}

/**
 * @brief Extrait le nombre d'objets
 * @param oo Valeur encodée
 * @return Nombre d'objets
 */
static uint32_t oo_objects(uint32_t oo) {
    return oo >> 16;
}

/**
 * @brief Extrait l'ordre
 * @param oo Valeur encodée
 * @return Ordre d'allocation
 */
static uint32_t oo_order(uint32_t oo) {
    return oo & 0xFFFF;
}

/**
 * @brief Calcule la configuration optimale pour un cache
 * @param size Taille d'un objet
 * @param flags Flags du cache
 * @param oo Pointeur vers résultat
 * @return true si succès
 */
static bool calculate_sizes(uint32_t size, uint32_t flags, uint32_t *oo) {
    uint32_t order;
    uint32_t objects;
    
    /* Ajuster la taille pour l'alignement */
    size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
    
    /* Essayer différents ordres */
    for (order = 0; order <= SLUB_MAX_ORDER; order++) {
        uint32_t slab_size = PAGE_SIZE << order;
        objects = slab_size / size;
        
        if (objects >= SLUB_MIN_OBJECTS) {
            *oo = oo_make(objects, order);
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Obtient le CPU cache actuel
 * @param cache Cache SLUB
 * @return Pointeur vers CPU cache
 */
static slub_cpu_cache_t *get_cpu_slab(slub_cache_t *cache) {
#ifdef CONFIG_SMP
    return this_cpu_ptr(cache->cpu_slab);
#else
    return &cache->cpu_slab;
#endif
}

/* ========================================================================
 * PAGE MANAGEMENT
 * ======================================================================== */

/**
 * @brief Alloue une nouvelle page pour un cache
 * @param cache Cache parent
 * @param flags Flags d'allocation
 * @return Pointeur vers page ou NULL
 */
static slub_page_t *allocate_slab(slub_cache_t *cache, uint32_t flags) {
    uint32_t order = oo_order(cache->oo);
    uint32_t objects = oo_objects(cache->oo);
    
    /* Allouer les pages */
    void *addr = alloc_pages(order, flags);
    if (!addr) {
        slub_allocator.oom_count++;
        return NULL;
    }
    
    /* Allouer la structure de page */
    slub_page_t *page = (slub_page_t *)malloc(sizeof(slub_page_t));
    if (!page) {
        free_pages(addr, order);
        slub_allocator.oom_count++;
        return NULL;
    }
    
    memset(page, 0, sizeof(slub_page_t));
    
    /* Initialiser la page */
    page->slab_cache = cache;
    page->objects = objects;
    page->inuse = 0;
    page->flags = SLUB_PAGE_ACTIVE;
    page->frozen = 0;
    
#ifdef CONFIG_DEBUG_SLUB
    page->s_mem = addr;
    page->magic = 0xDEADBEEF;
#endif
    
    /* Construire la freelist */
    char *ptr = (char *)addr;
    void **freelist = NULL;
    
    for (uint32_t i = 0; i < objects; i++) {
        void **obj = (void **)ptr;
        *obj = freelist;
        freelist = (void *)obj;
        ptr += cache->size;
    }
    
    page->freelist = freelist;
    
    /* Appeler le constructeur si présent */
    if (cache->ctor) {
        ptr = (char *)addr;
        for (uint32_t i = 0; i < objects; i++) {
            cache->ctor(ptr);
            ptr += cache->size;
        }
    }
    
    if (debug_slub) {
        printk(KERN_DEBUG "Allocated SLUB page: cache=%s, addr=%p, objects=%u, order=%u\n",
               cache->name, addr, objects, order);
    }
    
    return page;
}

/**
 * @brief Libère une page SLUB
 * @param cache Cache parent
 * @param page Page à libérer
 */
static void free_slab(slub_cache_t *cache, slub_page_t *page) {
    if (!cache || !page) {
        return;
    }
    
#ifdef CONFIG_DEBUG_SLUB
    if (page->magic != 0xDEADBEEF) {
        printk(KERN_ERR "SLUB page corruption detected: cache=%s\n", cache->name);
        return;
    }
    
    void *addr = page->s_mem;
#else
    /* Calculer l'adresse depuis la page */
    void *addr = (void *)((uintptr_t)page->freelist & PAGE_MASK);
#endif
    
    uint32_t order = oo_order(cache->oo);
    
    /* Appeler le destructeur si présent */
    if (cache->dtor) {
        char *ptr = (char *)addr;
        for (uint32_t i = 0; i < page->objects; i++) {
            cache->dtor(ptr);
            ptr += cache->size;
        }
    }
    
    /* Libérer les pages */
    free_pages(addr, order);
    
    if (debug_slub) {
        printk(KERN_DEBUG "Freed SLUB page: cache=%s, addr=%p\n", cache->name, addr);
    }
    
    free(page);
}

/**
 * @brief Ajoute une page à la liste des pages partielles
 * @param cache Cache parent
 * @param page Page à ajouter
 */
static void add_partial(slub_cache_t *cache, slub_page_t *page) {
    SLUB_LOCK();
    
    page->next = cache->node_partial;
    cache->node_partial = page;
    cache->node_nr_partial++;
    page->flags |= SLUB_PAGE_PARTIAL;
    
    SLUB_UNLOCK();
}

/**
 * @brief Retire une page de la liste des pages partielles
 * @param cache Cache parent
 * @param page Page à retirer
 */
static void remove_partial(slub_cache_t *cache, slub_page_t *page) {
    SLUB_LOCK();
    
    slub_page_t **current = &cache->node_partial;
    while (*current && *current != page) {
        current = &(*current)->next;
    }
    
    if (*current) {
        *current = page->next;
        cache->node_nr_partial--;
        page->flags &= ~SLUB_PAGE_PARTIAL;
        page->next = NULL;
    }
    
    SLUB_UNLOCK();
}

/* ========================================================================
 * FAST PATH ALLOCATION
 * ======================================================================== */

/**
 * @brief Allocation fastpath - chemin rapide
 * @param cache Cache à utiliser
 * @param flags Flags d'allocation
 * @return Pointeur vers objet ou NULL
 */
static void *slab_alloc_fastpath(slub_cache_t *cache, uint32_t flags) {
    slub_cpu_cache_t *cpu_slab = get_cpu_slab(cache);
    void *object = NULL;
    slub_page_t *page = cpu_slab->page;
    
    if (!page || !page->freelist) {
        return NULL;
    }
    
    /* Essayer d'allouer depuis la freelist */
    object = page->freelist;
    if (object) {
        page->freelist = *(void **)object;
        page->inuse++;
        
        /* Vérifier si la page devient pleine */
        if (!page->freelist) {
            page->flags |= SLUB_PAGE_FULL;
            cpu_slab->page = NULL;
        }
        
        cache->alloc_fastpath++;
        slub_allocator.fastpath_allocations++;
        
        if (debug_slub) {
            printk(KERN_DEBUG "SLUB fastpath alloc: cache=%s, obj=%p\n", 
                   cache->name, object);
        }
    }
    
    return object;
}

/**
 * @brief Libération fastpath - chemin rapide
 * @param cache Cache parent
 * @param object Objet à libérer
 * @param page Page contenant l'objet
 * @return true si libération fastpath réussie
 */
static bool slab_free_fastpath(slub_cache_t *cache, void *object, slub_page_t *page) {
    slub_cpu_cache_t *cpu_slab = get_cpu_slab(cache);
    
    /* Vérifier que c'est la page courante du CPU */
    if (cpu_slab->page != page || page->frozen) {
        return false;
    }
    
    /* Ajouter l'objet à la freelist */
    *(void **)object = page->freelist;
    page->freelist = object;
    page->inuse--;
    
    /* Gérer le changement d'état de la page */
    if (page->flags & SLUB_PAGE_FULL) {
        page->flags &= ~SLUB_PAGE_FULL;
        cpu_slab->page = page;
    }
    
    cache->free_fastpath++;
    slub_allocator.fastpath_frees++;
    
    if (debug_slub) {
        printk(KERN_DEBUG "SLUB fastpath free: cache=%s, obj=%p\n", 
               cache->name, object);
    }
    
    return true;
}

/* ========================================================================
 * SLOW PATH ALLOCATION
 * ======================================================================== */

/**
 * @brief Allocation slowpath - chemin lent avec gestion complète
 * @param cache Cache à utiliser
 * @param flags Flags d'allocation
 * @return Pointeur vers objet ou NULL
 */
static void *slab_alloc_slowpath(slub_cache_t *cache, uint32_t flags) {
    slub_cpu_cache_t *cpu_slab = get_cpu_slab(cache);
    slub_page_t *page = NULL;
    void *object = NULL;
    
    cache->alloc_slowpath++;
    slub_allocator.slowpath_allocations++;
    
    /* Essayer d'obtenir une page depuis les pages partielles */
    SLUB_LOCK();
    if (cache->node_partial) {
        page = cache->node_partial;
        remove_partial(cache, page);
        cache->partial_alloc++;
        
        if (debug_slub) {
            printk(KERN_DEBUG "SLUB using partial page: cache=%s, page=%p\n",
                   cache->name, page);
        }
    }
    SLUB_UNLOCK();
    
    /* Si pas de page partielle, en allouer une nouvelle */
    if (!page) {
        page = allocate_slab(cache, flags);
        if (!page) {
            return NULL;
        }
        
        if (debug_slub) {
            printk(KERN_DEBUG "SLUB allocated new page: cache=%s, page=%p\n",
                   cache->name, page);
        }
    }
    
    /* Essayer d'allouer depuis cette page */
    if (page->freelist) {
        object = page->freelist;
        page->freelist = *(void **)object;
        page->inuse++;
        
        /* Assigner la page au CPU si elle n'est pas pleine */
        if (page->freelist) {
            page->frozen = 1;
            cpu_slab->page = page;
        } else {
            page->flags |= SLUB_PAGE_FULL;
        }
    }
    
    return object;
}

/**
 * @brief Libération slowpath - chemin lent avec gestion complète
 * @param cache Cache parent
 * @param object Objet à libérer
 * @param page Page contenant l'objet
 */
static void slab_free_slowpath(slub_cache_t *cache, void *object, slub_page_t *page) {
    bool was_full = (page->flags & SLUB_PAGE_FULL) != 0;
    
    cache->free_slowpath++;
    slub_allocator.slowpath_frees++;
    
    /* Ajouter l'objet à la freelist */
    *(void **)object = page->freelist;
    page->freelist = object;
    page->inuse--;
    
    if (was_full) {
        /* Page devient partielle */
        page->flags &= ~SLUB_PAGE_FULL;
        add_partial(cache, page);
        cache->partial_free++;
        
        if (debug_slub) {
            printk(KERN_DEBUG "SLUB page became partial: cache=%s, page=%p\n",
                   cache->name, page);
        }
    } else if (page->inuse == 0) {
        /* Page devient libre */
        if (page->flags & SLUB_PAGE_PARTIAL) {
            remove_partial(cache, page);
        }
        
        /* Libérer la page si on a assez de pages partielles */
        if (cache->node_nr_partial >= cache->min_partial) {
            free_slab(cache, page);
            
            if (debug_slub) {
                printk(KERN_DEBUG "SLUB freed empty page: cache=%s, page=%p\n",
                       cache->name, page);
            }
        } else {
            add_partial(cache, page);
        }
    }
}

/* ========================================================================
 * MAIN ALLOCATION INTERFACE
 * ======================================================================== */

/**
 * @brief Trouve la page contenant un objet
 * @param object Pointeur vers objet
 * @return Pointeur vers page ou NULL
 */
static slub_page_t *get_object_page(void *object) {
    /* Implémentation simplifiée - dans un vrai kernel,
     * on utiliserait des structures plus sophistiquées */
    
    /* Pour l'instant, on suppose que l'information est stockée
     * dans une structure globale ou calculée depuis l'adresse */
    
    /* TODO: Implémenter la recherche de page réelle */
    return NULL;
}

/**
 * @brief Alloue un objet depuis un cache SLUB
 * @param cache Cache à utiliser
 * @param flags Flags d'allocation
 * @return Pointeur vers objet ou NULL
 */
void *slub_cache_alloc(slub_cache_t *cache, uint32_t flags) {
    if (!cache) {
        return NULL;
    }
    
    void *object;
    
    /* Essayer le fastpath d'abord */
    object = slab_alloc_fastpath(cache, flags);
    if (object) {
        goto out;
    }
    
    /* Fallback sur le slowpath */
    object = slab_alloc_slowpath(cache, flags);
    
out:
    if (object) {
        /* Initialiser à zéro si demandé */
        if (flags & GFP_ZERO) {
            memset(object, 0, cache->object_size);
        }
        
        /* Appliquer poison si debug activé */
        if (cache->flags & SLUB_POISON) {
            memset(object, 0x5a, cache->object_size);
        }
        
        cache->allocations++;
        slub_allocator.total_allocations++;
    }
    
    return object;
}

/**
 * @brief Libère un objet vers un cache SLUB
 * @param cache Cache parent
 * @param object Objet à libérer
 */
void slub_cache_free(slub_cache_t *cache, void *object) {
    if (!cache || !object) {
        return;
    }
    
    /* Appliquer poison si debug activé */
    if (cache->flags & SLUB_POISON) {
        memset(object, 0x6b, cache->object_size);
    }
    
    /* Trouver la page contenant l'objet */
    slub_page_t *page = get_object_page(object);
    if (!page) {
        printk(KERN_ERR "SLUB: cannot find page for object %p\n", object);
        return;
    }
    
    /* Essayer le fastpath */
    if (!slab_free_fastpath(cache, object, page)) {
        /* Utiliser le slowpath */
        slab_free_slowpath(cache, object, page);
    }
    
    cache->frees++;
    slub_allocator.total_frees++;
}

/* ========================================================================
 * CACHE CREATION AND DESTRUCTION
 * ======================================================================== */

/**
 * @brief Crée un nouveau cache SLUB
 * @param name Nom du cache
 * @param size Taille des objets
 * @param align Alignement requis
 * @param flags Flags de configuration
 * @param ctor Constructeur d'objet
 * @param dtor Destructeur d'objet
 * @return Pointeur vers cache ou NULL
 */
slub_cache_t *slub_cache_create(const char *name, size_t size, size_t align,
                               uint32_t flags, void (*ctor)(void *),
                               void (*dtor)(void *)) {
    if (!slub_initialized || !name || size == 0) {
        return NULL;
    }
    
    /* Allouer la structure du cache */
    slub_cache_t *cache = (slub_cache_t *)malloc(sizeof(slub_cache_t));
    if (!cache) {
        return NULL;
    }
    
    memset(cache, 0, sizeof(slub_cache_t));
    
    /* Configurer le cache */
    strncpy(cache->name, name, sizeof(cache->name) - 1);
    cache->object_size = size;
    cache->flags = flags;
    cache->ctor = ctor;
    cache->dtor = dtor;
    cache->min_partial = slub_allocator.min_partial;
    cache->cpu_partial = slub_allocator.cpu_partial;
    
    /* Calculer la taille réelle avec alignement */
    if (align == 0) {
        align = sizeof(void *);
    }
    cache->size = (size + align - 1) & ~(align - 1);
    
    /* S'assurer que la taille peut contenir un pointeur */
    if (cache->size < sizeof(void *)) {
        cache->size = sizeof(void *);
    }
    
    /* Calculer la configuration optimale */
    if (!calculate_sizes(cache->size, flags, &cache->oo)) {
        printk(KERN_ERR "SLUB: cannot calculate sizes for cache %s\n", name);
        free(cache);
        return NULL;
    }
    
    /* Configuration de fallback */
    cache->min = cache->oo;
    cache->max = cache->oo;
    
    /* Allouer les structures per-CPU */
#ifdef CONFIG_SMP
    cache->cpu_slab = malloc(sizeof(slub_cpu_cache_t) * num_possible_cpus());
    if (!cache->cpu_slab) {
        free(cache);
        return NULL;
    }
    memset(cache->cpu_slab, 0, sizeof(slub_cpu_cache_t) * num_possible_cpus());
#else
    memset(&cache->cpu_slab, 0, sizeof(slub_cpu_cache_t));
#endif
    
    SLUB_LOCK();
    
    /* Ajouter à la liste globale */
    cache->next = slub_allocator.cache_list;
    slub_allocator.cache_list = cache;
    slub_allocator.cache_count++;
    
    SLUB_UNLOCK();
    
    printk(KERN_INFO "Created SLUB cache: %s (size=%u, objects=%u, order=%u)\n",
           name, cache->size, oo_objects(cache->oo), oo_order(cache->oo));
    
    return cache;
}

/**
 * @brief Détruit un cache SLUB
 * @param cache Cache à détruire
 * @return 0 en cas de succès
 */
int slub_cache_destroy(slub_cache_t *cache) {
    if (!cache) {
        return -1;
    }
    
    /* TODO: Vérifier qu'il n'y a pas d'objets actifs */
    
    SLUB_LOCK();
    
    /* Libérer toutes les pages partielles */
    while (cache->node_partial) {
        slub_page_t *page = cache->node_partial;
        remove_partial(cache, page);
        free_slab(cache, page);
    }
    
    /* Retirer de la liste globale */
    slub_cache_t **current = &slub_allocator.cache_list;
    while (*current && *current != cache) {
        current = &(*current)->next;
    }
    
    if (*current) {
        *current = cache->next;
        slub_allocator.cache_count--;
    }
    
    SLUB_UNLOCK();
    
    /* Libérer les structures per-CPU */
#ifdef CONFIG_SMP
    free(cache->cpu_slab);
#endif
    
    printk(KERN_INFO "Destroyed SLUB cache: %s\n", cache->name);
    
    free(cache);
    return 0;
}

/* ========================================================================
 * KMALLOC INTERFACE
 * ======================================================================== */

/**
 * @brief Initialise les caches kmalloc SLUB
 * @return 0 en cas de succès
 */
static int init_slub_kmalloc_caches(void) {
    size_t sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 0};
    
    for (int i = 0; sizes[i] != 0 && i < 16; i++) {
        char name[32];
        snprintf(name, sizeof(name), "kmalloc-%zu", sizes[i]);
        
        slub_cache_t *cache = slub_cache_create(name, sizes[i], 0, 0, NULL, NULL);
        if (!cache) {
            printk(KERN_ERR "Failed to create SLUB kmalloc cache for size %zu\n", sizes[i]);
            return -1;
        }
        
        slub_allocator.kmalloc_caches[i] = cache;
        
        /* Créer aussi la version DMA si nécessaire */
        snprintf(name, sizeof(name), "dma-kmalloc-%zu", sizes[i]);
        slub_cache_t *dma_cache = slub_cache_create(name, sizes[i], 0, 
                                                   SLUB_RECLAIM_ACCOUNT, NULL, NULL);
        if (dma_cache) {
            slub_allocator.kmalloc_dma_caches[i] = dma_cache;
        }
    }
    
    return 0;
}

/**
 * @brief Alloue de la mémoire via SLUB kmalloc
 * @param size Taille à allouer
 * @param flags Flags d'allocation
 * @return Pointeur vers mémoire ou NULL
 */
void *slub_kmalloc(size_t size, uint32_t flags) {
    if (!slub_initialized || size == 0) {
        return NULL;
    }
    
    /* Trouver le cache approprié */
    slub_cache_t *cache = NULL;
    
    for (int i = 0; i < 16; i++) {
        slub_cache_t *candidate = (flags & GFP_DMA) ? 
            slub_allocator.kmalloc_dma_caches[i] : 
            slub_allocator.kmalloc_caches[i];
            
        if (candidate && candidate->object_size >= size) {
            cache = candidate;
            break;
        }
    }
    
    if (!cache) {
        /* Taille trop grande pour SLUB */
        return NULL;
    }
    
    return slub_cache_alloc(cache, flags);
}

/**
 * @brief Libère de la mémoire allouée par SLUB kmalloc
 * @param ptr Pointeur à libérer
 */
void slub_kfree(void *ptr) {
    if (!ptr) {
        return;
    }
    
    /* TODO: Implémenter la recherche du cache approprié */
    /* Pour l'instant, implémentation simplifiée */
    
    if (debug_slub) {
        printk(KERN_DEBUG "slub_kfree: ptr=%p\n", ptr);
    }
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise l'allocateur SLUB
 * @return 0 en cas de succès
 */
int slub_allocator_init(void) {
    if (slub_initialized) {
        printk(KERN_WARNING "SLUB allocator already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing SLUB allocator\n");
    
    /* Initialiser la structure principale */
    memset(&slub_allocator, 0, sizeof(slub_allocator));
    
    /* Configuration par défaut */
    slub_allocator.debug_enabled = debug_slub;
    slub_allocator.trace_enabled = debug_slub;
    slub_allocator.min_partial = slub_min_partial;
    slub_allocator.cpu_partial = slub_cpu_partial;
    
    /* Initialiser les caches kmalloc */
    if (init_slub_kmalloc_caches() != 0) {
        printk(KERN_ERR "Failed to initialize SLUB kmalloc caches\n");
        return -1;
    }
    
    slub_initialized = true;
    
    printk(KERN_INFO "SLUB allocator initialized\n");
    printk(KERN_INFO "  Debug mode: %s\n", slub_allocator.debug_enabled ? "enabled" : "disabled");
    printk(KERN_INFO "  Min partial: %u\n", slub_allocator.min_partial);
    printk(KERN_INFO "  CPU partial: %u\n", slub_allocator.cpu_partial);
    
    return 0;
}

/**
 * @brief Affiche les statistiques SLUB
 */
void slub_print_stats(void) {
    if (!slub_initialized) {
        printk(KERN_INFO "SLUB allocator not initialized\n");
        return;
    }
    
    printk(KERN_INFO "SLUB Allocator Statistics:\n");
    printk(KERN_INFO "  Total allocations:    %llu\n", slub_allocator.total_allocations);
    printk(KERN_INFO "  Total frees:          %llu\n", slub_allocator.total_frees);
    printk(KERN_INFO "  Fastpath allocations: %llu\n", slub_allocator.fastpath_allocations);
    printk(KERN_INFO "  Slowpath allocations: %llu\n", slub_allocator.slowpath_allocations);
    printk(KERN_INFO "  Fastpath frees:       %llu\n", slub_allocator.fastpath_frees);
    printk(KERN_INFO "  Slowpath frees:       %llu\n", slub_allocator.slowpath_frees);
    printk(KERN_INFO "  OOM count:            %llu\n", slub_allocator.oom_count);
    
    float fastpath_ratio = 0.0f;
    if (slub_allocator.total_allocations > 0) {
        fastpath_ratio = (float)slub_allocator.fastpath_allocations / 
                        slub_allocator.total_allocations * 100.0f;
    }
    printk(KERN_INFO "  Fastpath ratio:       %.1f%%\n", fastpath_ratio);
    
    printk(KERN_INFO "  Active caches:        %u\n", slub_allocator.cache_count);
    
    SLUB_LOCK();
    slub_cache_t *cache = slub_allocator.cache_list;
    while (cache) {
        printk(KERN_INFO "    %s: allocs=%llu, frees=%llu, fastpath=%.1f%%\n",
               cache->name, cache->allocations, cache->frees,
               cache->allocations > 0 ? 
                   (float)cache->alloc_fastpath / cache->allocations * 100.0f : 0.0f);
        cache = cache->next;
    }
    SLUB_UNLOCK();
}

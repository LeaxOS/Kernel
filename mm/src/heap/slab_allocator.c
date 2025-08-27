/**
 * @file slab_allocator.c
 * @brief SLAB allocator implementation
 * 
 * @author LeaxOS Team
 * @version 1.0
 */

#include "stdint.h"
#include "stddef.h"
#include "stdbool.h"
#include "string.h"
#include "stdio.h"
#include "mm_common.h"
#include "mm.h"
#include "page_alloc.h"
#include "slab.h"

/* Fallback GFP definitions if not included properly */
#ifndef GFP_ZERO
#define GFP_ZERO        (1 << 14)       /* Zero-initialize */
#endif
#ifndef GFP_DMA
#define GFP_DMA         (1 << 8)        /* DMA memory zone */
#endif

/* ========================================================================
 * SLAB ALLOCATOR CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/* Constantes de configuration */
#define SLAB_MAX_CACHES         128     /* Nombre max de caches */
#define SLAB_MAX_OBJS_PER_SLAB  512     /* Objets max par slab */
#define SLAB_MIN_OBJS_PER_SLAB  4       /* Objets min par slab */
#define SLAB_COLOUR_MAX         64      /* Couleurs max */
#define SLAB_NAME_MAX           32      /* Taille max nom de cache */

/* Flags de cache */
#define SLAB_HWCACHE_ALIGN      0x01    /* Alignement cache hardware */
#define SLAB_RECLAIM_ACCOUNT    0x02    /* Comptabiliser pour reclaim */
#define SLAB_RED_ZONE           0x04    /* Red zone pour debug */
#define SLAB_POISON             0x08    /* Poison pour debug */
#define SLAB_STORE_USER         0x10    /* Stocker info utilisateur */
#define SLAB_PANIC              0x20    /* Panic sur erreur */
#define SLAB_DESTROY_BY_RCU     0x40    /* Destruction par RCU */

/* États des slabs */
#define SLAB_STATE_FULL         0x01    /* Slab plein */
#define SLAB_STATE_PARTIAL      0x02    /* Slab partiellement utilisé */
#define SLAB_STATE_FREE         0x04    /* Slab libre */

/* Patterns de debug */
#define SLAB_POISON_INUSE       0x5a    /* Pattern pour objets en cours d'usage */
#define SLAB_POISON_FREE        0x6b    /* Pattern pour objets libres */
#define SLAB_RED_INACTIVE       0xcc    /* Red zone inactive */
#define SLAB_RED_ACTIVE         0xbb    /* Red zone active */

/* Tailles d'alignement */
#define SLAB_ALIGN_BYTES        8       /* Alignement par défaut */
#define SLAB_HWCACHE_ALIGN_SIZE 64      /* Alignement cache hardware */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Objet dans un slab
 */
typedef struct slab_obj {
    struct slab_obj *next;              /* Prochain objet libre */
    
    /* Debug information si activé */
#ifdef CONFIG_DEBUG_SLAB
    uint32_t magic;                     /* Magic number pour validation */
    void *caller;                       /* Adresse de l'appelant */
    uint64_t timestamp;                 /* Timestamp d'allocation */
#endif
} slab_obj_t;

/**
 * @brief Structure d'un slab
 */
typedef struct slab {
    struct slab *next;                  /* Prochain slab dans la liste */
    struct slab *prev;                  /* Précédent slab dans la liste */
    
    void *s_mem;                        /* Début de la mémoire du slab */
    uint32_t inuse;                     /* Objets en cours d'usage */
    uint32_t free;                      /* Objets libres */
    slab_obj_t *freelist;               /* Liste des objets libres */
    
    uint32_t colour_off;                /* Offset de couleur */
    uint8_t state;                      /* État du slab */
    
    /* Pointeur vers le cache parent */
    struct kmem_cache *cache;           /* Cache parent */
    
} slab_t;

/**
 * @brief Cache d'objets SLAB
 */
typedef struct kmem_cache {
    /* Identification */
    char name[SLAB_NAME_MAX];           /* Nom du cache */
    uint32_t flags;                     /* Flags de configuration */
    
    /* Configuration des objets */
    size_t object_size;                 /* Taille d'un objet */
    size_t size;                        /* Taille réelle avec padding */
    size_t align;                       /* Alignement requis */
    uint32_t num;                       /* Objets par slab */
    
    /* Gestion des slabs */
    slab_t *slabs_full;                 /* Liste des slabs pleins */
    slab_t *slabs_partial;              /* Liste des slabs partiels */
    slab_t *slabs_free;                 /* Liste des slabs libres */
    
    /* Configuration des slabs */
    uint32_t gfporder;                  /* Ordre d'allocation (2^order pages) */
    size_t colour;                      /* Nombre de couleurs */
    size_t colour_off;                  /* Offset entre couleurs */
    size_t colour_next;                 /* Prochaine couleur à utiliser */
    
    /* Constructeur/Destructeur */
    void (*ctor)(void *obj);            /* Constructeur d'objet */
    void (*dtor)(void *obj);            /* Destructeur d'objet */
    
    /* Statistiques */
    uint64_t num_allocations;           /* Allocations totales */
    uint64_t num_frees;                 /* Libérations totales */
    uint64_t num_slabs;                 /* Slabs totaux */
    uint64_t active_objs;               /* Objets actuellement actifs */
    uint64_t active_slabs;              /* Slabs actuellement actifs */
    
    /* Performance */
    uint64_t alloc_hits;                /* Allocations réussies immédiatement */
    uint64_t alloc_misses;              /* Allocations nécessitant nouveau slab */
    uint64_t free_hits;                 /* Libérations vers slab existant */
    uint64_t free_misses;               /* Libérations créant slab libre */
    
    /* Growing/Shrinking */
    uint32_t growing;                   /* Nombre de slabs en cours de création */
    uint32_t grown;                     /* Nombre total de slabs créés */
    uint32_t shrink_count;              /* Nombre de réductions */
    
    /* Chaînage global */
    struct kmem_cache *next;            /* Prochain cache dans la liste globale */
    
#ifdef CONFIG_SMP
    /* Per-CPU caches */
    struct array_cache **cpu_cache;     /* Caches per-CPU */
#endif
    
} kmem_cache_t;

/**
 * @brief Cache per-CPU (pour SMP)
 */
#ifdef CONFIG_SMP
typedef struct array_cache {
    uint32_t avail;                     /* Objets disponibles */
    uint32_t limit;                     /* Limite du cache */
    uint32_t batchcount;                /* Nombre d'objets par batch */
    uint32_t touched;                   /* Récemment touché */
    void *entry[];                      /* Tableau d'objets */
} array_cache_t;
#endif

/**
 * @brief Gestionnaire global SLAB
 */
typedef struct slab_allocator {
    /* Caches enregistrés */
    kmem_cache_t *cache_chain;          /* Chaîne des caches */
    uint32_t cache_count;               /* Nombre de caches */
    
    /* Caches génériques */
    kmem_cache_t *kmalloc_caches[32];   /* Caches kmalloc par taille */
    
    /* Configuration globale */
    bool debug_enabled;                 /* Debug activé */
    bool red_zone_enabled;              /* Red zones activées */
    bool poison_enabled;                /* Poison activé */
    size_t min_partial;                 /* Minimum de slabs partiels */
    
    /* Statistiques globales */
    uint64_t total_allocations;         /* Allocations totales */
    uint64_t total_frees;               /* Libérations totales */
    uint64_t active_caches;             /* Caches actifs */
    uint64_t active_slabs;              /* Slabs actifs */
    uint64_t memory_used;               /* Mémoire utilisée */
    
} slab_allocator_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Gestionnaire principal */
static slab_allocator_t slab_allocator;
static bool slab_initialized = false;

/* Configuration */
static bool debug_slab = false;
static size_t slab_min_partial = 5;
static size_t cache_line_size = 64;

/* Timestamp functions */
static uint64_t slab_timestamp_counter = 0;
static inline uint64_t get_slab_timestamp(void) {
    return ++slab_timestamp_counter;
}

/* Synchronization */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
static mm_spinlock_t slab_lock = MM_SPINLOCK_INIT("unknown");
#define SLAB_LOCK() mm_spin_lock(&slab_lock)
#define SLAB_UNLOCK() mm_spin_unlock(&slab_lock)
#else
#define SLAB_LOCK() do {} while(0)
#define SLAB_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Calcule la puissance de 2 supérieure ou égale
 * @param val Valeur d'entrée
 * @return Puissance de 2
 */
static size_t roundup_pow_of_two(size_t val) {
    if (val == 0) return 1;
    
    val--;
    val |= val >> 1;
    val |= val >> 2;
    val |= val >> 4;
    val |= val >> 8;
    val |= val >> 16;
    val |= val >> 32;
    val++;
    
    return val;
}

/**
 * @brief Calcule l'alignement optimal
 * @param size Taille de l'objet
 * @param flags Flags du cache
 * @return Alignement à utiliser
 */
static size_t cache_line_align(size_t size, uint32_t flags) {
    if (flags & SLAB_HWCACHE_ALIGN) {
        /* Aligner sur la ligne de cache */
        if (size <= cache_line_size / 2) {
            return cache_line_size / 2;
        } else {
            return cache_line_size;
        }
    }
    
    /* Alignement minimal */
    if (size < SLAB_ALIGN_BYTES) {
        return SLAB_ALIGN_BYTES;
    }
    
    /* Aligner sur la prochaine puissance de 2 */
    size_t align = SLAB_ALIGN_BYTES;
    while (align < size && align < cache_line_size) {
        align <<= 1;
    }
    
    return align;
}

/**
 * @brief Calcule le nombre d'objets par slab
 * @param cache_size Taille du cache
 * @param obj_size Taille d'un objet
 * @param gfporder Ordre d'allocation
 * @return Nombre d'objets
 */
static uint32_t calculate_num_objs(size_t cache_size, size_t obj_size, uint32_t gfporder) {
    size_t slab_size = PAGE_SIZE << gfporder;
    size_t mgmt_size = sizeof(slab_t);
    size_t usable_size = slab_size - mgmt_size;
    
    uint32_t num = (uint32_t)(usable_size / obj_size);
    
    /* Limiter entre min et max */
    if (num < SLAB_MIN_OBJS_PER_SLAB) {
        num = SLAB_MIN_OBJS_PER_SLAB;
    } else if (num > SLAB_MAX_OBJS_PER_SLAB) {
        num = SLAB_MAX_OBJS_PER_SLAB;
    }
    
    return num;
}

/* ========================================================================
 * SLAB MANAGEMENT
 * ======================================================================== */

/**
 * @brief Alloue un nouveau slab
 * @param cache Cache parent
 * @param flags Flags d'allocation
 * @return Pointeur vers slab ou NULL
 */
static slab_t *kmem_getpages(kmem_cache_t *cache, uint32_t flags) {
    /* Allouer les pages pour le slab */
    void *addr = alloc_pages(cache->gfporder, flags);
    if (!addr) {
        return NULL;
    }
    
    size_t slab_size = PAGE_SIZE << cache->gfporder;
    
    /* Le slab est à la fin de la zone allouée */
    slab_t *slab = (slab_t *)((char *)addr + slab_size - sizeof(slab_t));
    
    /* Initialiser le slab */
    memset(slab, 0, sizeof(slab_t));
    slab->s_mem = addr;
    slab->cache = cache;
    slab->inuse = 0;
    slab->free = cache->num;
    slab->state = SLAB_STATE_FREE;
    
    /* Calculer l'offset de couleur */
    slab->colour_off = cache->colour_next * cache->colour_off;
    cache->colour_next++;
    if (cache->colour_next >= cache->colour) {
        cache->colour_next = 0;
    }
    
    /* Initialiser la freelist */
    char *objp = (char *)addr + slab->colour_off;
    slab->freelist = NULL;
    
    for (uint32_t i = 0; i < cache->num; i++) {
        slab_obj_t *obj = (slab_obj_t *)objp;
        obj->next = slab->freelist;
        slab->freelist = obj;
        
        /* Poison l'objet si activé */
        if (cache->flags & SLAB_POISON) {
            memset((char *)obj + sizeof(slab_obj_t), SLAB_POISON_FREE, 
                   cache->object_size - sizeof(slab_obj_t));
        }
        
        objp += cache->size;
    }
    
    /* Mettre à jour les statistiques */
    cache->num_slabs++;
    cache->active_slabs++;
    slab_allocator.active_slabs++;
    slab_allocator.memory_used += slab_size;
    
    if (debug_slab) {
        printk(KERN_DEBUG "Created new slab: cache=%s, addr=%p, objs=%u, colour=%zu\n",
               cache->name, addr, cache->num, slab->colour_off);
    }
    
    return slab;
}

/**
 * @brief Libère un slab
 * @param cache Cache parent
 * @param slab Slab à libérer
 */
static void kmem_freepages(kmem_cache_t *cache, slab_t *slab) {
    if (!cache || !slab) {
        return;
    }
    
    size_t slab_size = PAGE_SIZE << cache->gfporder;
    
    /* Appeler le destructeur pour tous les objets si nécessaire */
    if (cache->dtor) {
        char *objp = (char *)slab->s_mem + slab->colour_off;
        for (uint32_t i = 0; i < cache->num; i++) {
            cache->dtor(objp);
            objp += cache->size;
        }
    }
    
    /* Libérer les pages */
    free_pages(slab->s_mem, cache->gfporder);
    
    /* Mettre à jour les statistiques */
    cache->active_slabs--;
    slab_allocator.active_slabs--;
    slab_allocator.memory_used -= slab_size;
    
    if (debug_slab) {
        printk(KERN_DEBUG "Freed slab: cache=%s, addr=%p\n", 
               cache->name, slab->s_mem);
    }
}

/**
 * @brief Retire un slab d'une liste
 * @param slab Slab à retirer
 * @param list Pointeur vers la tête de liste
 */
static void list_del_slab(slab_t *slab, slab_t **list) {
    if (slab->prev) {
        slab->prev->next = slab->next;
    } else {
        *list = slab->next;
    }
    
    if (slab->next) {
        slab->next->prev = slab->prev;
    }
    
    slab->next = NULL;
    slab->prev = NULL;
}

/**
 * @brief Ajoute un slab à une liste
 * @param slab Slab à ajouter
 * @param list Pointeur vers la tête de liste
 */
static void list_add_slab(slab_t *slab, slab_t **list) {
    slab->next = *list;
    slab->prev = NULL;
    
    if (*list) {
        (*list)->prev = slab;
    }
    
    *list = slab;
}

/* ========================================================================
 * ALLOCATION AND DEALLOCATION
 * ======================================================================== */

/**
 * @brief Alloue un objet depuis un slab
 * @param cache Cache à utiliser
 * @param flags Flags d'allocation
 * @return Pointeur vers objet ou NULL
 */
static void *slab_alloc_obj(kmem_cache_t *cache, uint32_t flags) {
    slab_t *slab = NULL;
    void *objp = NULL;
    
    SLAB_LOCK();
    
    /* Chercher dans les slabs partiels d'abord */
    if (cache->slabs_partial) {
        slab = cache->slabs_partial;
        cache->alloc_hits++;
    } else if (cache->slabs_free) {
        /* Utiliser un slab libre */
        slab = cache->slabs_free;
        list_del_slab(slab, &cache->slabs_free);
        list_add_slab(slab, &cache->slabs_partial);
        slab->state = SLAB_STATE_PARTIAL;
        cache->alloc_hits++;
    } else {
        /* Créer un nouveau slab */
        cache->alloc_misses++;
        SLAB_UNLOCK();
        
        slab = kmem_getpages(cache, flags);
        if (!slab) {
            return NULL;
        }
        
        SLAB_LOCK();
        list_add_slab(slab, &cache->slabs_partial);
        slab->state = SLAB_STATE_PARTIAL;
        cache->grown++;
    }
    
    /* Extraire un objet de la freelist */
    if (slab && slab->freelist) {
        slab_obj_t *obj = slab->freelist;
        slab->freelist = obj->next;
        slab->inuse++;
        slab->free--;
        
        objp = (void *)obj;
        
        /* Gérer le changement d'état du slab */
        if (slab->free == 0) {
            /* Slab devient plein */
            list_del_slab(slab, &cache->slabs_partial);
            list_add_slab(slab, &cache->slabs_full);
            slab->state = SLAB_STATE_FULL;
        }
        
        /* Mettre à jour les statistiques */
        cache->num_allocations++;
        cache->active_objs++;
        slab_allocator.total_allocations++;
    }
    
    SLAB_UNLOCK();
    
    if (objp) {
        /* Appeler le constructeur si présent */
        if (cache->ctor) {
            cache->ctor(objp);
        }
        
        /* Initialiser l'objet si poison activé */
        if (cache->flags & SLAB_POISON) {
            memset((char *)objp + sizeof(slab_obj_t), SLAB_POISON_INUSE, 
                   cache->object_size - sizeof(slab_obj_t));
        }
        
        /* Initialiser à zéro si demandé */
        if (flags & GFP_ZERO) {
            memset(objp, 0, cache->object_size);
        }
        
#ifdef CONFIG_DEBUG_SLAB
        /* Enregistrer infos de debug */
        slab_obj_t *obj = (slab_obj_t *)objp;
        obj->magic = 0xDEADBEEF;
        obj->caller = __builtin_return_address(0);
        obj->timestamp = get_slab_timestamp();
#endif
        
        if (debug_slab) {
            printk(KERN_DEBUG "slab_alloc: cache=%s, obj=%p, size=%zu\n",
                   cache->name, objp, cache->object_size);
        }
    }
    
    return objp;
}

/**
 * @brief Libère un objet vers un slab
 * @param cache Cache parent
 * @param objp Pointeur vers objet
 */
static void slab_free_obj(kmem_cache_t *cache, void *objp) {
    if (!cache || !objp) {
        return;
    }
    
#ifdef CONFIG_DEBUG_SLAB
    /* Vérifier la magie */
    slab_obj_t *obj = (slab_obj_t *)objp;
    if (obj->magic != 0xDEADBEEF) {
        printk(KERN_ERR "slab_free: corrupted object %p in cache %s\n",
               objp, cache->name);
        if (cache->flags & SLAB_PANIC) {
            panic("SLAB corruption detected");
        }
        return;
    }
    obj->magic = 0;
#endif
    
    /* Appeler le destructeur si présent */
    if (cache->dtor) {
        cache->dtor(objp);
    }
    
    /* Poison l'objet */
    if (cache->flags & SLAB_POISON) {
        memset((char *)objp + sizeof(slab_obj_t), SLAB_POISON_FREE, 
               cache->object_size - sizeof(slab_obj_t));
    }
    
    /* Trouver le slab contenant cet objet */
    slab_t *slab = NULL;
    
    /* Méthode simple: calculer l'adresse du slab */
    size_t slab_size = PAGE_SIZE << cache->gfporder;
    void *slab_start = (void *)((uintptr_t)objp & ~(slab_size - 1));
    slab = (slab_t *)((char *)slab_start + slab_size - sizeof(slab_t));
    
    SLAB_LOCK();
    
    /* Vérifier que c'est bien le bon slab */
    if (slab->cache != cache) {
        SLAB_UNLOCK();
        printk(KERN_ERR "slab_free: object %p does not belong to cache %s\n",
               objp, cache->name);
        return;
    }
    
    /* Remettre l'objet dans la freelist */
    slab_obj_t *obj = (slab_obj_t *)objp;
    obj->next = slab->freelist;
    slab->freelist = obj;
    slab->inuse--;
    slab->free++;
    
    /* Gérer le changement d'état du slab */
    bool was_full = (slab->state == SLAB_STATE_FULL);
    
    if (slab->free == cache->num) {
        /* Slab devient libre */
        if (was_full) {
            list_del_slab(slab, &cache->slabs_full);
        } else {
            list_del_slab(slab, &cache->slabs_partial);
        }
        list_add_slab(slab, &cache->slabs_free);
        slab->state = SLAB_STATE_FREE;
        cache->free_misses++;
    } else if (was_full) {
        /* Slab devient partiel */
        list_del_slab(slab, &cache->slabs_full);
        list_add_slab(slab, &cache->slabs_partial);
        slab->state = SLAB_STATE_PARTIAL;
        cache->free_hits++;
    } else {
        cache->free_hits++;
    }
    
    /* Mettre à jour les statistiques */
    cache->num_frees++;
    cache->active_objs--;
    slab_allocator.total_frees++;
    
    SLAB_UNLOCK();
    
    if (debug_slab) {
        printk(KERN_DEBUG "slab_free: cache=%s, obj=%p, slab_state=%u\n",
               cache->name, objp, slab->state);
    }
}

/* ========================================================================
 * CACHE CREATION AND DESTRUCTION
 * ======================================================================== */

/**
 * @brief Crée un nouveau cache SLAB
 * @param name Nom du cache
 * @param size Taille des objets
 * @param align Alignement requis
 * @param flags Flags de configuration
 * @param ctor Constructeur d'objet (peut être NULL)
 * @param dtor Destructeur d'objet (peut être NULL)
 * @return Pointeur vers cache ou NULL
 */
kmem_cache_t *kmem_cache_create(const char *name, size_t size, size_t align,
                               uint32_t flags, void (*ctor)(void *),
                               void (*dtor)(void *)) {
    if (!slab_initialized || !name || size == 0) {
        return NULL;
    }
    
    /* Allouer la structure du cache */
    kmem_cache_t *cache = (kmem_cache_t *)malloc(sizeof(kmem_cache_t));
    if (!cache) {
        return NULL;
    }
    
    memset(cache, 0, sizeof(kmem_cache_t));
    
    /* Configurer le cache */
    strncpy(cache->name, name, SLAB_NAME_MAX - 1);
    cache->name[SLAB_NAME_MAX - 1] = '\0';
    cache->object_size = size;
    cache->flags = flags;
    cache->ctor = ctor;
    cache->dtor = dtor;
    
    /* Calculer l'alignement */
    if (align == 0) {
        cache->align = cache_line_align(size, flags);
    } else {
        cache->align = align;
    }
    
    /* Arrondir la taille pour inclure l'alignement */
    cache->size = (size + cache->align - 1) & ~(cache->align - 1);
    
    /* Inclure l'espace pour slab_obj_t */
    if (cache->size < sizeof(slab_obj_t)) {
        cache->size = sizeof(slab_obj_t);
    }
    
    /* Calculer l'ordre d'allocation optimal */
    cache->gfporder = 0;
    while (cache->gfporder < 10) {
        cache->num = calculate_num_objs(cache->size, cache->size, cache->gfporder);
        if (cache->num >= SLAB_MIN_OBJS_PER_SLAB) {
            break;
        }
        cache->gfporder++;
    }
    
    /* Calculer la coloration */
    size_t slab_size = PAGE_SIZE << cache->gfporder;
    size_t left_over = slab_size - (cache->num * cache->size + sizeof(slab_t));
    cache->colour = left_over / cache_line_size;
    cache->colour_off = cache_line_size;
    
    if (cache->colour > SLAB_COLOUR_MAX) {
        cache->colour = SLAB_COLOUR_MAX;
    }
    
    /* Configuration de debug */
    if (slab_allocator.debug_enabled) {
        cache->flags |= SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER;
    }
    
    SLAB_LOCK();
    
    /* Ajouter à la chaîne globale */
    cache->next = slab_allocator.cache_chain;
    slab_allocator.cache_chain = cache;
    slab_allocator.cache_count++;
    slab_allocator.active_caches++;
    
    SLAB_UNLOCK();
    
    printk(KERN_INFO "Created SLAB cache: %s (size=%zu, align=%zu, objs_per_slab=%u, order=%u)\n",
           name, size, cache->align, cache->num, cache->gfporder);
    
    if (debug_slab) {
        printk(KERN_DEBUG "  Real size: %zu, colours: %zu, colour_off: %zu\n",
               cache->size, cache->colour, cache->colour_off);
    }
    
    return cache;
}

/**
 * @brief Détruit un cache SLAB
 * @param cache Cache à détruire
 * @return 0 en cas de succès
 */
int kmem_cache_destroy(kmem_cache_t *cache) {
    if (!cache) {
        return -1;
    }
    
    SLAB_LOCK();
    
    /* Vérifier qu'il n'y a pas d'objets actifs */
    if (cache->active_objs > 0) {
        SLAB_UNLOCK();
        printk(KERN_WARNING "kmem_cache_destroy: cache %s has %llu active objects\n",
               cache->name, cache->active_objs);
        return -1;
    }
    
    /* Libérer tous les slabs */
    while (cache->slabs_full) {
        slab_t *slab = cache->slabs_full;
        list_del_slab(slab, &cache->slabs_full);
        kmem_freepages(cache, slab);
    }
    
    while (cache->slabs_partial) {
        slab_t *slab = cache->slabs_partial;
        list_del_slab(slab, &cache->slabs_partial);
        kmem_freepages(cache, slab);
    }
    
    while (cache->slabs_free) {
        slab_t *slab = cache->slabs_free;
        list_del_slab(slab, &cache->slabs_free);
        kmem_freepages(cache, slab);
    }
    
    /* Retirer de la chaîne globale */
    kmem_cache_t **current = &slab_allocator.cache_chain;
    while (*current && *current != cache) {
        current = &(*current)->next;
    }
    
    if (*current) {
        *current = cache->next;
        slab_allocator.cache_count--;
        slab_allocator.active_caches--;
    }
    
    SLAB_UNLOCK();
    
    printk(KERN_INFO "Destroyed SLAB cache: %s\n", cache->name);
    
    free(cache);
    return 0;
}

/* ========================================================================
 * PUBLIC ALLOCATION INTERFACE
 * ======================================================================== */

/**
 * @brief Alloue un objet depuis un cache
 * @param cache Cache à utiliser
 * @param flags Flags d'allocation
 * @return Pointeur vers objet ou NULL
 */
void *kmem_cache_alloc(kmem_cache_t *cache, uint32_t flags) {
    if (!cache) {
        return NULL;
    }
    
    return slab_alloc_obj(cache, flags);
}

/**
 * @brief Libère un objet vers un cache
 * @param cache Cache parent
 * @param objp Pointeur vers objet
 */
void kmem_cache_free(kmem_cache_t *cache, void *objp) {
    slab_free_obj(cache, objp);
}

/* ========================================================================
 * GENERIC KMALLOC INTERFACE
 * ======================================================================== */

/**
 * @brief Initialise les caches kmalloc génériques
 * @return 0 en cas de succès
 */
static int init_kmalloc_caches(void) {
    size_t sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 0};
    
    for (int i = 0; sizes[i] != 0; i++) {
        char name[32];
        snprintf(name, sizeof(name), "kmalloc-%zu", sizes[i]);
        
        kmem_cache_t *cache = kmem_cache_create(name, sizes[i], 0, 
                                              SLAB_HWCACHE_ALIGN, NULL, NULL);
        
        if (!cache) {
            printk(KERN_ERR "Failed to create kmalloc cache for size %zu\n", sizes[i]);
            return -1;
        }
        
        /* Stocker dans le tableau (utiliser log2 approximatif) */
        int index = 0;
        size_t size = sizes[i];
        while (size > 1) {
            size >>= 1;
            index++;
        }
        
        if (index < 32) {
            slab_allocator.kmalloc_caches[index] = cache;
        }
    }
    
    return 0;
}

/**
 * @brief Alloue de la mémoire via kmalloc
 * @param size Taille à allouer
 * @param flags Flags d'allocation
 * @return Pointeur vers mémoire ou NULL
 */
void *slab_kmalloc(size_t size, uint32_t flags) {
    if (!slab_initialized || size == 0) {
        return NULL;
    }
    
    /* Trouver le cache approprié */
    kmem_cache_t *cache = NULL;
    
    /* Arrondir à la prochaine puissance de 2 */
    size_t alloc_size = roundup_pow_of_two(size);
    
    /* Calculer l'index */
    int index = 0;
    size_t temp_size = alloc_size;
    while (temp_size > 1) {
        temp_size >>= 1;
        index++;
    }
    
    if (index < 32 && slab_allocator.kmalloc_caches[index]) {
        cache = slab_allocator.kmalloc_caches[index];
    }
    
    if (!cache) {
        /* Taille trop grande pour SLAB - utiliser page allocator */
        return NULL;
    }
    
    return kmem_cache_alloc(cache, flags);
}

/**
 * @brief Libère de la mémoire allouée par kmalloc
 * @param ptr Pointeur à libérer
 */
void slab_kfree(void *ptr) {
    if (!ptr) {
        return;
    }
    
    /* Trouver le cache en analysant l'adresse */
    /* Implémentation simplifiée - dans un vrai kernel,
     * on utiliserait des structures de données plus sophistiquées */
    
    /* Pour l'instant, on suppose que l'objet vient d'un cache kmalloc */
    /* En pratique, il faudrait maintenir une table de correspondance */
    
    if (debug_slab) {
        printk(KERN_DEBUG "slab_kfree: ptr=%p\n", ptr);
    }
    
    /* TODO: Implémenter la recherche du cache approprié */
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise l'allocateur SLAB
 * @return 0 en cas de succès
 */
int slab_allocator_init(void) {
    if (slab_initialized) {
        printk(KERN_WARNING "SLAB allocator already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing SLAB allocator\n");
    
    /* Initialiser la structure principale */
    memset(&slab_allocator, 0, sizeof(slab_allocator));
    
    /* Configuration par défaut */
    slab_allocator.debug_enabled = debug_slab;
    slab_allocator.red_zone_enabled = debug_slab;
    slab_allocator.poison_enabled = debug_slab;
    slab_allocator.min_partial = slab_min_partial;
    
    /* Initialiser les caches kmalloc */
    if (init_kmalloc_caches() != 0) {
        printk(KERN_ERR "Failed to initialize kmalloc caches\n");
        return -1;
    }
    
    slab_initialized = true;
    
    printk(KERN_INFO "SLAB allocator initialized\n");
    printk(KERN_INFO "  Debug mode: %s\n", slab_allocator.debug_enabled ? "enabled" : "disabled");
    printk(KERN_INFO "  Red zones: %s\n", slab_allocator.red_zone_enabled ? "enabled" : "disabled");
    printk(KERN_INFO "  Poisoning: %s\n", slab_allocator.poison_enabled ? "enabled" : "disabled");
    printk(KERN_INFO "  Cache line size: %zu bytes\n", cache_line_size);
    
    return 0;
}

/**
 * @brief Affiche les statistiques SLAB
 */
void slab_print_stats(void) {
    if (!slab_initialized) {
        printk(KERN_INFO "SLAB allocator not initialized\n");
        return;
    }
    
    printk(KERN_INFO "SLAB Allocator Statistics:\n");
    printk(KERN_INFO "  Total allocations:    %llu\n", slab_allocator.total_allocations);
    printk(KERN_INFO "  Total frees:          %llu\n", slab_allocator.total_frees);
    printk(KERN_INFO "  Active caches:        %llu\n", slab_allocator.active_caches);
    printk(KERN_INFO "  Active slabs:         %llu\n", slab_allocator.active_slabs);
    printk(KERN_INFO "  Memory used:          %llu bytes\n", slab_allocator.memory_used);
    
    printk(KERN_INFO "  Caches:\n");
    SLAB_LOCK();
    kmem_cache_t *cache = slab_allocator.cache_chain;
    while (cache) {
        float hit_rate = 0.0f;
        if (cache->alloc_hits + cache->alloc_misses > 0) {
            hit_rate = (float)cache->alloc_hits / (cache->alloc_hits + cache->alloc_misses) * 100.0f;
        }
        
        printk(KERN_INFO "    %s: objs=%llu, slabs=%llu, hit_rate=%.1f%%\n",
               cache->name, cache->active_objs, cache->active_slabs, hit_rate);
        
        cache = cache->next;
    }
    SLAB_UNLOCK();
}

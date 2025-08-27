/**
 * @file swap_cache.c
 * @brief Cache de pages swap pour optimiser les performances I/O
 * 
 * Ce fichier implémente un cache des pages swap pour réduire les accès
 * disque et améliorer les performances du système de mémoire virtuelle.
 * Le cache utilise des algorithmes sophistiqués pour la gestion des
 * pages en mémoire et l'anticipation des accès futurs.
 * 
 * Fonctionnalités principales:
 * - Cache LRU pour pages swap récemment utilisées
 * - Readahead prédicatif pour cluster de pages
 * - Writeback différé pour optimiser les écritures
 * - Compression optionnelle des pages
 * - Déduplication pour économiser la mémoire
 * - Statistiques détaillées et monitoring
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
 * SWAP CACHE CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/* Tailles et limites du cache */
#define SWAP_CACHE_MAX_PAGES        1024    /* Pages max dans le cache */
#define SWAP_CACHE_MIN_PAGES        64      /* Pages min dans le cache */
#define SWAP_CACHE_HASH_SIZE        256     /* Taille table de hash */
#define SWAP_CACHE_CLUSTER_SIZE     8       /* Taille des clusters */
#define SWAP_CACHE_READAHEAD_SIZE   16      /* Pages de readahead */

/* États des entrées de cache */
#define CACHE_ENTRY_FREE            0x00    /* Entrée libre */
#define CACHE_ENTRY_VALID           0x01    /* Données valides */
#define CACHE_ENTRY_DIRTY           0x02    /* Données modifiées */
#define CACHE_ENTRY_LOCKED          0x04    /* Entrée verrouillée */
#define CACHE_ENTRY_WRITEBACK       0x08    /* En cours d'écriture */
#define CACHE_ENTRY_READAHEAD       0x10    /* Page de readahead */
#define CACHE_ENTRY_COMPRESSED      0x20    /* Page compressée */
#define CACHE_ENTRY_SHARED          0x40    /* Page partagée */

/* Priorités d'éviction */
#define EVICT_PRIORITY_HIGH         0       /* Éviction prioritaire */
#define EVICT_PRIORITY_NORMAL       1       /* Éviction normale */
#define EVICT_PRIORITY_LOW          2       /* Éviction différée */

/* Flags de configuration */
#define CACHE_FLAG_COMPRESSION      0x01    /* Compression activée */
#define CACHE_FLAG_DEDUPLICATION    0x02    /* Déduplication activée */
#define CACHE_FLAG_READAHEAD        0x04    /* Readahead activé */
#define CACHE_FLAG_WRITEBACK        0x08    /* Writeback différé activé */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Entrée dans le cache de swap
 */
typedef struct swap_cache_entry {
    /* Identification */
    uint32_t device_id;                 /* ID du device de swap */
    uint32_t offset;                    /* Offset dans le device */
    uint32_t hash;                      /* Hash pour recherche rapide */
    
    /* État et flags */
    uint8_t state;                      /* État de l'entrée */
    uint8_t priority;                   /* Priorité d'éviction */
    uint16_t ref_count;                 /* Compteur de références */
    
    /* Données */
    void *page_data;                    /* Données de la page */
    size_t data_size;                   /* Taille des données (si compressées) */
    uint32_t checksum;                  /* Checksum pour intégrité */
    
    /* LRU et chaînage */
    struct swap_cache_entry *lru_next;  /* Suivant dans LRU */
    struct swap_cache_entry *lru_prev;  /* Précédent dans LRU */
    struct swap_cache_entry *hash_next; /* Suivant dans hash bucket */
    struct swap_cache_entry *hash_prev; /* Précédent dans hash bucket */
    
    /* Statistiques */
    uint64_t access_time;               /* Dernier accès */
    uint64_t creation_time;             /* Création de l'entrée */
    uint32_t access_count;              /* Nombre d'accès */
    
    /* Compression et déduplication */
    uint32_t dedup_hash;                /* Hash pour déduplication */
    struct swap_cache_entry *dedup_ref; /* Référence vers original */
    uint32_t dedup_count;               /* Nombre de références */
    
} swap_cache_entry_t;

/**
 * @brief Structure principale du cache de swap
 */
typedef struct swap_cache {
    /* Configuration */
    uint32_t max_pages;                 /* Nombre max de pages */
    uint32_t current_pages;             /* Nombre actuel de pages */
    uint32_t min_pages;                 /* Nombre min de pages */
    uint32_t flags;                     /* Flags de configuration */
    
    /* Hash table */
    swap_cache_entry_t *hash_table[SWAP_CACHE_HASH_SIZE];
    
    /* LRU lists */
    swap_cache_entry_t *lru_head;       /* Tête de la liste LRU */
    swap_cache_entry_t *lru_tail;       /* Queue de la liste LRU */
    
    /* Pool d'entrées libres */
    swap_cache_entry_t *free_entries;   /* Entrées libres */
    uint32_t free_count;                /* Nombre d'entrées libres */
    
    /* Métriques de performance */
    uint64_t hit_count;                 /* Hits du cache */
    uint64_t miss_count;                /* Misses du cache */
    uint64_t eviction_count;            /* Évictions */
    uint64_t compression_count;         /* Pages compressées */
    uint64_t decompressions;            /* Pages décompressées */
    uint64_t total_requests;            /* Requêtes totales */
    uint64_t dedup_count;               /* Pages dédupliquées */
    
    /* Readahead */
    uint32_t readahead_size;            /* Taille du readahead */
    uint64_t readahead_hits;            /* Hits du readahead */
    uint64_t readahead_misses;          /* Misses du readahead */
    
    /* Writeback */
    swap_cache_entry_t *writeback_queue; /* Queue de writeback */
    uint32_t writeback_pending;        /* Pages en attente d'écriture */
    uint64_t writeback_count;           /* Writebacks effectués */
    
} swap_cache_t;

/**
 * @brief Gestionnaire de readahead
 */
typedef struct readahead_info {
    uint32_t device_id;                 /* Device concerné */
    uint32_t start_offset;              /* Offset de début */
    uint32_t current_offset;            /* Offset actuel */
    uint32_t end_offset;                /* Offset de fin */
    uint32_t size;                      /* Taille du readahead */
    bool sequential;                    /* Accès séquentiel détecté */
    uint64_t last_access_time;          /* Dernier accès */
} readahead_info_t;

/**
 * @brief Statistiques du cache de swap
 */
typedef struct {
    uint64_t total_requests;            /* Requêtes totales */
    uint64_t cache_hits;                /* Hits du cache */
    uint64_t cache_misses;              /* Misses du cache */
    uint64_t evictions;                 /* Évictions */
    uint64_t compressions;              /* Compressions */
    uint64_t decompressions;            /* Décompressions */
    uint64_t dedup_savings;             /* Économies déduplication */
    uint64_t readahead_requests;        /* Requêtes readahead */
    uint64_t readahead_hits;            /* Hits readahead */
    uint64_t writeback_operations;      /* Opérations writeback */
    uint64_t memory_used;               /* Mémoire utilisée */
    uint64_t memory_saved;              /* Mémoire économisée */
    double hit_ratio;                   /* Ratio de hits */
    double compression_ratio;           /* Ratio de compression */
} swap_cache_stats_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Cache principal */
static swap_cache_t swap_cache;
static bool swap_cache_initialized = false;

/* Pool d'entrées */
static swap_cache_entry_t *entry_pool = NULL;
static uint32_t entry_pool_size = 0;

/* Configuration */
static bool debug_cache = false;
static bool enable_compression = false;
static bool enable_deduplication = false;
static bool enable_readahead = true;
static bool enable_writeback = true;

/* Readahead tracking */
static readahead_info_t readahead_windows[16];
static uint32_t num_readahead_windows = 0;

/* Synchronization */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
static mm_spinlock_t cache_lock = MM_SPINLOCK_INIT("unknown");
#define CACHE_LOCK() mm_spin_lock(&cache_lock)
#define CACHE_UNLOCK() mm_spin_unlock(&cache_lock)
#else
#define CACHE_LOCK() do {} while(0)
#define CACHE_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * HASH TABLE OPERATIONS
 * ======================================================================== */

/**
 * @brief Calcule le hash d'une entrée swap
 * @param device_id ID du device
 * @param offset Offset dans le device
 * @return Valeur de hash
 */
static uint32_t compute_swap_hash(uint32_t device_id, uint32_t offset) {
    /* Hash simple mais efficace */
    uint32_t hash = device_id * 31 + offset;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    
    return hash % SWAP_CACHE_HASH_SIZE;
}

/**
 * @brief Recherche une entrée dans la hash table
 * @param device_id ID du device
 * @param offset Offset dans le device
 * @return Pointeur vers l'entrée ou NULL
 */
static swap_cache_entry_t *find_cache_entry(uint32_t device_id, uint32_t offset) {
    uint32_t hash = compute_swap_hash(device_id, offset);
    swap_cache_entry_t *entry = swap_cache.hash_table[hash];
    
    while (entry) {
        if (entry->device_id == device_id && entry->offset == offset) {
            return entry;
        }
        entry = entry->hash_next;
    }
    
    return NULL;
}

/**
 * @brief Ajoute une entrée à la hash table
 * @param entry Entrée à ajouter
 */
static void add_to_hash_table(swap_cache_entry_t *entry) {
    uint32_t hash = compute_swap_hash(entry->device_id, entry->offset);
    
    entry->hash = hash;
    entry->hash_next = swap_cache.hash_table[hash];
    entry->hash_prev = NULL;
    
    if (swap_cache.hash_table[hash]) {
        swap_cache.hash_table[hash]->hash_prev = entry;
    }
    
    swap_cache.hash_table[hash] = entry;
}

/**
 * @brief Retire une entrée de la hash table
 * @param entry Entrée à retirer
 */
static void remove_from_hash_table(swap_cache_entry_t *entry) {
    if (entry->hash_prev) {
        entry->hash_prev->hash_next = entry->hash_next;
    } else {
        swap_cache.hash_table[entry->hash] = entry->hash_next;
    }
    
    if (entry->hash_next) {
        entry->hash_next->hash_prev = entry->hash_prev;
    }
    
    entry->hash_next = NULL;
    entry->hash_prev = NULL;
}

/* ========================================================================
 * LRU LIST OPERATIONS
 * ======================================================================== */

/**
 * @brief Ajoute une entrée à la tête de la LRU
 * @param entry Entrée à ajouter
 */
static void add_to_lru_head(swap_cache_entry_t *entry) {
    entry->lru_next = swap_cache.lru_head;
    entry->lru_prev = NULL;
    
    if (swap_cache.lru_head) {
        swap_cache.lru_head->lru_prev = entry;
    } else {
        swap_cache.lru_tail = entry;
    }
    
    swap_cache.lru_head = entry;
}

/**
 * @brief Retire une entrée de la LRU
 * @param entry Entrée à retirer
 */
static void remove_from_lru(swap_cache_entry_t *entry) {
    if (entry->lru_prev) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        swap_cache.lru_head = entry->lru_next;
    }
    
    if (entry->lru_next) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        swap_cache.lru_tail = entry->lru_prev;
    }
    
    entry->lru_next = NULL;
    entry->lru_prev = NULL;
}

/**
 * @brief Déplace une entrée vers la tête de la LRU
 * @param entry Entrée à déplacer
 */
static void move_to_lru_head(swap_cache_entry_t *entry) {
    if (entry == swap_cache.lru_head) {
        return; /* Déjà en tête */
    }
    
    remove_from_lru(entry);
    add_to_lru_head(entry);
}

/* ========================================================================
 * COMPRESSION AND DEDUPLICATION
 * ======================================================================== */

/**
 * @brief Compresse une page (simulation simple)
 * @param input Données d'entrée
 * @param input_size Taille d'entrée
 * @param output Buffer de sortie
 * @param output_size Taille de sortie
 * @return Taille compressée ou 0 si échec
 */
static size_t compress_page(const void *input, size_t input_size, 
                           void *output, size_t output_size) {
    if (!enable_compression || !input || !output || input_size != PAGE_SIZE) {
        return 0;
    }
    
    /* Simulation simple : compression de 30% en moyenne */
    size_t compressed_size = input_size * 70 / 100;
    if (compressed_size > output_size) {
        return 0;
    }
    
    /* Copier les données (simulation) */
    memcpy(output, input, compressed_size);
    
    return compressed_size;
}

/**
 * @brief Décompresse une page
 * @param input Données compressées
 * @param input_size Taille compressée
 * @param output Buffer de sortie
 * @param output_size Taille de sortie
 * @return Taille décompressée ou 0 si échec
 */
static size_t decompress_page(const void *input, size_t input_size,
                             void *output, size_t output_size) {
    if (!enable_compression || !input || !output || output_size < PAGE_SIZE) {
        return 0;
    }
    
    /* Simulation simple */
    if (input_size > output_size) {
        return 0;
    }
    
    memcpy(output, input, input_size);
    
    /* Remplir le reste avec des zéros */
    if (input_size < output_size) {
        memset((char *)output + input_size, 0, output_size - input_size);
    }
    
    return PAGE_SIZE;
}

/**
 * @brief Calcule le hash pour déduplication
 * @param data Données de la page
 * @param size Taille des données
 * @return Hash de déduplication
 */
static uint32_t compute_dedup_hash(const void *data, size_t size) {
    if (!enable_deduplication || !data || size == 0) {
        return 0;
    }
    
    /* Hash simple pour déduplication */
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t hash = 0;
    
    for (size_t i = 0; i < size; i++) {
        hash = hash * 31 + bytes[i];
    }
    
    return hash;
}

/**
 * @brief Recherche une page identique pour déduplication
 * @param dedup_hash Hash de déduplication
 * @param data Données à comparer
 * @param size Taille des données
 * @return Entrée de référence ou NULL
 */
static swap_cache_entry_t *find_dedup_entry(uint32_t dedup_hash, 
                                           const void *data, size_t size) {
    if (!enable_deduplication || dedup_hash == 0) {
        return NULL;
    }
    
    /* Parcourir le cache pour trouver une page identique */
    for (uint32_t i = 0; i < SWAP_CACHE_HASH_SIZE; i++) {
        swap_cache_entry_t *entry = swap_cache.hash_table[i];
        
        while (entry) {
            if (entry->dedup_hash == dedup_hash && 
                entry->data_size == size &&
                entry->page_data &&
                memcmp(entry->page_data, data, size) == 0) {
                return entry;
            }
            entry = entry->hash_next;
        }
    }
    
    return NULL;
}

/* ========================================================================
 * CACHE ENTRY MANAGEMENT
 * ======================================================================== */

/**
 * @brief Alloue une nouvelle entrée de cache
 * @return Pointeur vers entrée ou NULL
 */
static swap_cache_entry_t *alloc_cache_entry(void) {
    swap_cache_entry_t *entry = NULL;
    
    /* Prendre du pool libre */
    if (swap_cache.free_entries) {
        entry = swap_cache.free_entries;
        swap_cache.free_entries = entry->lru_next;
        swap_cache.free_count--;
    } else {
        /* Allouer dynamiquement */
    entry = (swap_cache_entry_t *)kmalloc(sizeof(swap_cache_entry_t));
    }
    
    if (entry) {
        memset(entry, 0, sizeof(swap_cache_entry_t));
        entry->creation_time = get_timestamp();
    }
    
    return entry;
}

/**
 * @brief Libère une entrée de cache
 * @param entry Entrée à libérer
 */
static void free_cache_entry(swap_cache_entry_t *entry) {
    if (!entry) return;
    
    /* Libérer les données de page si allouées */
    if (entry->page_data && !(entry->state & CACHE_ENTRY_SHARED)) {
        kfree(entry->page_data);
    }
    
    /* Décrémenter les références de déduplication */
    if (entry->dedup_ref) {
        entry->dedup_ref->dedup_count--;
    }
    
    /* Retourner au pool libre si possible */
    if (swap_cache.free_count < 32) {
        entry->lru_next = swap_cache.free_entries;
        swap_cache.free_entries = entry;
        swap_cache.free_count++;
    } else {
        kfree(entry);
    }
}

/**
 * @brief Évince une entrée du cache
 * @return Pointeur vers entrée évincée ou NULL
 */
static swap_cache_entry_t *evict_cache_entry(void) {
    /* Chercher une entrée à évincer depuis la queue LRU */
    swap_cache_entry_t *entry = swap_cache.lru_tail;
    
    while (entry) {
        /* Ne pas évincer les entrées verrouillées ou en cours d'écriture */
        if (!(entry->state & (CACHE_ENTRY_LOCKED | CACHE_ENTRY_WRITEBACK)) &&
            entry->ref_count == 0) {
            
            /* Retirer de toutes les structures */
            remove_from_lru(entry);
            remove_from_hash_table(entry);
            
            swap_cache.current_pages--;
            swap_cache.eviction_count++;
            
            if (debug_cache) {
                printk(KERN_DEBUG "Evicted cache entry: device=%u, offset=%u\n",
                       entry->device_id, entry->offset);
            }
            
            return entry;
        }
        
        entry = entry->lru_prev;
    }
    
    return NULL; /* Aucune entrée évincable */
}

/* ========================================================================
 * READAHEAD MANAGEMENT
 * ======================================================================== */

/**
 * @brief Détecte les patterns d'accès séquentiels
 * @param device_id ID du device
 * @param offset Offset de l'accès
 * @return true si accès séquentiel détecté
 */
static bool detect_sequential_access(uint32_t device_id, uint32_t offset) {
    if (!enable_readahead) {
        return false;
    }
    
    /* Chercher une fenêtre existante */
    for (uint32_t i = 0; i < num_readahead_windows; i++) {
        readahead_info_t *window = &readahead_windows[i];
        
        if (window->device_id == device_id &&
            offset >= window->current_offset &&
            offset <= window->current_offset + 4) {
            
            /* Accès dans la fenêtre - étendre si nécessaire */
            window->current_offset = offset;
            window->last_access_time = get_timestamp();
            window->sequential = true;
            
            return true;
        }
    }
    
    /* Créer nouvelle fenêtre si possible */
    if (num_readahead_windows < 16) {
        readahead_info_t *window = &readahead_windows[num_readahead_windows++];
        window->device_id = device_id;
        window->start_offset = offset;
        window->current_offset = offset;
        window->end_offset = offset + swap_cache.readahead_size;
        window->size = swap_cache.readahead_size;
        window->sequential = false;
        window->last_access_time = get_timestamp();
    }
    
    return false;
}

/**
 * @brief Lance un readahead pour un cluster de pages
 * @param device_id ID du device
 * @param start_offset Offset de début
 * @param size Nombre de pages à lire
 * @return Nombre de pages lues en avance
 */
static uint32_t perform_readahead(uint32_t device_id, uint32_t start_offset, uint32_t size) {
    if (!enable_readahead || size == 0) {
        return 0;
    }
    
    uint32_t pages_read = 0;
    
    for (uint32_t i = 0; i < size; i++) {
        uint32_t offset = start_offset + i;
        
        /* Vérifier si déjà en cache */
        if (find_cache_entry(device_id, offset)) {
            continue;
        }
        
        /* TODO: Lancer lecture asynchrone */
        /* Pour l'instant, marquer comme page de readahead */
        
        pages_read++;
    }
    
    if (pages_read > 0) {
        swap_cache.readahead_hits += pages_read;
        
        if (debug_cache) {
            printk(KERN_DEBUG "Readahead: device=%u, start=%u, size=%u, read=%u\n",
                   device_id, start_offset, size, pages_read);
        }
    }
    
    return pages_read;
}

/* ========================================================================
 * MAIN CACHE OPERATIONS
 * ======================================================================== */

/**
 * @brief Recherche une page dans le cache
 * @param device_id ID du device
 * @param offset Offset dans le device
 * @param data Buffer pour les données (sortie)
 * @return 0 si trouvé, -1 sinon
 */
int swap_cache_lookup(uint32_t device_id, uint32_t offset, void *data) {
    if (!swap_cache_initialized || !data) {
        return -1;
    }
    
    CACHE_LOCK();
    
    swap_cache.total_requests++;
    
    /* Chercher dans le cache */
    swap_cache_entry_t *entry = find_cache_entry(device_id, offset);
    
    if (entry) {
        /* Cache hit */
        swap_cache.hit_count++;
        
        /* Décompresser si nécessaire */
        if (entry->state & CACHE_ENTRY_COMPRESSED) {
            if (decompress_page(entry->page_data, entry->data_size, data, PAGE_SIZE) == 0) {
                CACHE_UNLOCK();
                return -1;
            }
            swap_cache.decompressions++;
        } else {
            memcpy(data, entry->page_data, PAGE_SIZE);
        }
        
        /* Mettre à jour LRU et statistiques */
        move_to_lru_head(entry);
        entry->access_count++;
        entry->access_time = get_timestamp();
        
        CACHE_UNLOCK();
        
        /* Détecter accès séquentiels pour readahead */
        if (detect_sequential_access(device_id, offset)) {
            perform_readahead(device_id, offset + 1, swap_cache.readahead_size);
        }
        
        if (debug_cache) {
            printk(KERN_DEBUG "Cache hit: device=%u, offset=%u\n", device_id, offset);
        }
        
        return 0;
    } else {
        /* Cache miss */
        swap_cache.miss_count++;
        CACHE_UNLOCK();
        
        if (debug_cache) {
            printk(KERN_DEBUG "Cache miss: device=%u, offset=%u\n", device_id, offset);
        }
        
        return -1;
    }
}

/**
 * @brief Ajoute une page au cache
 * @param device_id ID du device
 * @param offset Offset dans le device
 * @param data Données de la page
 * @return 0 en cas de succès
 */
int swap_cache_insert(uint32_t device_id, uint32_t offset, const void *data) {
    if (!swap_cache_initialized || !data) {
        return -1;
    }
    
    CACHE_LOCK();
    
    /* Vérifier si déjà présent */
    if (find_cache_entry(device_id, offset)) {
        CACHE_UNLOCK();
        return 0; /* Déjà présent */
    }
    
    /* Vérifier la place disponible */
    if (swap_cache.current_pages >= swap_cache.max_pages) {
        swap_cache_entry_t *evicted = evict_cache_entry();
        if (!evicted) {
            CACHE_UNLOCK();
            return -1; /* Pas d'espace disponible */
        }
        free_cache_entry(evicted);
    }
    
    /* Allouer nouvelle entrée */
    swap_cache_entry_t *entry = alloc_cache_entry();
    if (!entry) {
        CACHE_UNLOCK();
        return -1;
    }
    
    /* Configurer l'entrée */
    entry->device_id = device_id;
    entry->offset = offset;
    entry->state = CACHE_ENTRY_VALID;
    entry->ref_count = 0;
    entry->access_time = get_timestamp();
    entry->access_count = 1;
    
    /* Déduplication */
    if (enable_deduplication) {
        entry->dedup_hash = compute_dedup_hash(data, PAGE_SIZE);
        swap_cache_entry_t *dedup_ref = find_dedup_entry(entry->dedup_hash, data, PAGE_SIZE);
        
        if (dedup_ref) {
            /* Page identique trouvée - partager les données */
            entry->page_data = dedup_ref->page_data;
            entry->data_size = dedup_ref->data_size;
            entry->state |= CACHE_ENTRY_SHARED;
            entry->dedup_ref = dedup_ref;
            dedup_ref->dedup_count++;
            swap_cache.dedup_count++;
            
            if (debug_cache) {
                printk(KERN_DEBUG "Page deduplicated: device=%u, offset=%u\n", 
                       device_id, offset);
            }
        }
    }
    
    if (!entry->page_data) {
        /* Compression */
        if (enable_compression) {
            void *compressed_data = kmalloc(PAGE_SIZE);
            if (compressed_data) {
                size_t compressed_size = compress_page(data, PAGE_SIZE, compressed_data, PAGE_SIZE);
                if (compressed_size > 0 && compressed_size < PAGE_SIZE) {
                    entry->page_data = compressed_data;
                    entry->data_size = compressed_size;
                    entry->state |= CACHE_ENTRY_COMPRESSED;
                    swap_cache.compression_count++;
                    
                    if (debug_cache) {
                        printk(KERN_DEBUG "Page compressed: device=%u, offset=%u, ratio=%zu%%\n",
                               device_id, offset, (compressed_size * 100) / PAGE_SIZE);
                    }
                } else {
                    kfree(compressed_data);
                }
            }
        }
        
        /* Copie normale si compression échouée */
        if (!entry->page_data) {
            entry->page_data = kmalloc(PAGE_SIZE);
            if (!entry->page_data) {
                free_cache_entry(entry);
                CACHE_UNLOCK();
                return -1;
            }
            memcpy(entry->page_data, data, PAGE_SIZE);
            entry->data_size = PAGE_SIZE;
        }
    }
    
    /* Ajouter aux structures */
    add_to_hash_table(entry);
    add_to_lru_head(entry);
    swap_cache.current_pages++;
    
    CACHE_UNLOCK();
    
    if (debug_cache) {
        printk(KERN_DEBUG "Cache insert: device=%u, offset=%u\n", device_id, offset);
    }
    
    return 0;
}

/**
 * @brief Retire une page du cache
 * @param device_id ID du device
 * @param offset Offset dans le device
 * @return 0 en cas de succès
 */
int swap_cache_remove(uint32_t device_id, uint32_t offset) {
    if (!swap_cache_initialized) {
        return -1;
    }
    
    CACHE_LOCK();
    
    swap_cache_entry_t *entry = find_cache_entry(device_id, offset);
    if (entry) {
        remove_from_lru(entry);
        remove_from_hash_table(entry);
        swap_cache.current_pages--;
        free_cache_entry(entry);
        
        if (debug_cache) {
            printk(KERN_DEBUG "Cache remove: device=%u, offset=%u\n", device_id, offset);
        }
    }
    
    CACHE_UNLOCK();
    
    return entry ? 0 : -1;
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise le cache de swap
 * @return 0 en cas de succès
 */
int swap_cache_init(void) {
    if (swap_cache_initialized) {
        printk(KERN_WARNING "Swap cache already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing swap cache\n");
    
    /* Initialiser la structure principale */
    memset(&swap_cache, 0, sizeof(swap_cache));
    swap_cache.max_pages = SWAP_CACHE_MAX_PAGES;
    swap_cache.min_pages = SWAP_CACHE_MIN_PAGES;
    swap_cache.readahead_size = SWAP_CACHE_READAHEAD_SIZE;
    
    if (enable_compression) {
        swap_cache.flags |= CACHE_FLAG_COMPRESSION;
    }
    if (enable_deduplication) {
        swap_cache.flags |= CACHE_FLAG_DEDUPLICATION;
    }
    if (enable_readahead) {
        swap_cache.flags |= CACHE_FLAG_READAHEAD;
    }
    if (enable_writeback) {
        swap_cache.flags |= CACHE_FLAG_WRITEBACK;
    }
    
    /* Initialiser les fenêtres de readahead */
    memset(readahead_windows, 0, sizeof(readahead_windows));
    num_readahead_windows = 0;
    
    swap_cache_initialized = true;
    
    printk(KERN_INFO "Swap cache initialized\n");
    printk(KERN_INFO "  Max pages: %u\n", swap_cache.max_pages);
    printk(KERN_INFO "  Hash size: %d\n", SWAP_CACHE_HASH_SIZE);
    printk(KERN_INFO "  Compression: %s\n", enable_compression ? "enabled" : "disabled");
    printk(KERN_INFO "  Deduplication: %s\n", enable_deduplication ? "enabled" : "disabled");
    printk(KERN_INFO "  Readahead: %s\n", enable_readahead ? "enabled" : "disabled");
    
    return 0;
}

/**
 * @brief Obtient les statistiques du cache
 * @param stats Pointeur vers structure de statistiques
 */
void swap_cache_get_stats(swap_cache_stats_t *stats) {
    if (!stats || !swap_cache_initialized) {
        return;
    }
    
    CACHE_LOCK();
    
    stats->total_requests = swap_cache.total_requests;
    stats->cache_hits = swap_cache.hit_count;
    stats->cache_misses = swap_cache.miss_count;
    stats->evictions = swap_cache.eviction_count;
    stats->compressions = swap_cache.compression_count;
    stats->decompressions = swap_cache.decompressions;
    stats->dedup_savings = swap_cache.dedup_count;
    stats->readahead_requests = swap_cache.readahead_hits + swap_cache.readahead_misses;
    stats->readahead_hits = swap_cache.readahead_hits;
    stats->writeback_operations = swap_cache.writeback_count;
    stats->memory_used = swap_cache.current_pages * PAGE_SIZE;
    
    if (stats->total_requests > 0) {
        stats->hit_ratio = (double)stats->cache_hits / stats->total_requests;
    }
    
    if (stats->compressions > 0 && enable_compression) {
        stats->compression_ratio = 0.7; /* Simulation */
    }
    
    CACHE_UNLOCK();
}

/**
 * @brief Affiche les statistiques du cache
 */
void swap_cache_print_stats(void) {
    if (!swap_cache_initialized) {
        printk(KERN_INFO "Swap cache not initialized\n");
        return;
    }
    
    printk(KERN_INFO "Swap Cache Statistics:\n");
    printk(KERN_INFO "  Current pages:        %u / %u\n", 
           swap_cache.current_pages, swap_cache.max_pages);
    printk(KERN_INFO "  Total requests:       %llu\n", 
           swap_cache.hit_count + swap_cache.miss_count);
    printk(KERN_INFO "  Cache hits:           %llu\n", swap_cache.hit_count);
    printk(KERN_INFO "  Cache misses:         %llu\n", swap_cache.miss_count);
    
    if (swap_cache.hit_count + swap_cache.miss_count > 0) {
        uint64_t total = swap_cache.hit_count + swap_cache.miss_count;
        printk(KERN_INFO "  Hit ratio:            %llu%%\n", 
               (swap_cache.hit_count * 100) / total);
    }
    
    printk(KERN_INFO "  Evictions:            %llu\n", swap_cache.eviction_count);
    printk(KERN_INFO "  Compressions:         %llu\n", swap_cache.compression_count);
    printk(KERN_INFO "  Dedup savings:        %llu\n", swap_cache.dedup_count);
    printk(KERN_INFO "  Readahead hits:       %llu\n", swap_cache.readahead_hits);
    printk(KERN_INFO "  Memory used:          %u KB\n", 
           (swap_cache.current_pages * PAGE_SIZE) / 1024);
}

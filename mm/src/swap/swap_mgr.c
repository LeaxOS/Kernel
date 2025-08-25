/**
 * @file swap_mgr.c
 * @brief Gestionnaire principal du système de swap de LeaxOS
 * 
 * Ce fichier implémente le gestionnaire central du système de swap qui
 * coordonne les différents aspects du swapping : allocation d'espace swap,
 * politique de sélection des pages, interaction avec les devices de swap,
 * et optimisations pour les performances.
 * 
 * Fonctionnalités principales:
 * - Gestion des espaces de swap multiples
 * - Allocation et libération d'entrées swap
 * - Politique de sélection des pages à swapper
 * - Interface avec les drivers de stockage
 * - Statistiques et monitoring du swap
 * - Optimisations pour réduire les I/O
 * - Gestion des priorités de swap
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
 * SWAP CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/* Limites du système de swap */
#define MAX_SWAP_DEVICES        32      /* Nombre max de devices de swap */
#define MAX_SWAP_SIZE           (4ULL * 1024 * 1024 * 1024) /* 4GB max par device */
#define MIN_SWAP_SIZE           (16 * 1024 * 1024)  /* 16MB minimum */
#define SWAP_CLUSTER_SIZE       8       /* Pages swappées ensemble */
#define SWAP_READAHEAD_SIZE     16      /* Pages lues en avance */

/* Types de devices de swap */
#define SWAP_TYPE_FILE          0x01    /* Fichier de swap */
#define SWAP_TYPE_PARTITION     0x02    /* Partition de swap */
#define SWAP_TYPE_DEVICE        0x04    /* Device bloc raw */
#define SWAP_TYPE_NETWORK       0x08    /* Swap réseau (futur) */

/* Priorités de swap */
#define SWAP_PRIORITY_MAX       32767   /* Priorité maximum */
#define SWAP_PRIORITY_MIN       -32768  /* Priorité minimum */
#define SWAP_PRIORITY_DEFAULT   0       /* Priorité par défaut */

/* États des entrées swap */
#define SWAP_ENTRY_FREE         0x00    /* Entrée libre */
#define SWAP_ENTRY_USED         0x01    /* Entrée utilisée */
#define SWAP_ENTRY_BAD          0x02    /* Secteur défectueux */
#define SWAP_ENTRY_LOCKED       0x04    /* Entrée verrouillée */
#define SWAP_ENTRY_DIRTY        0x08    /* Données modifiées */

/* Flags de swap */
#define SWAP_FLAG_PREFER        0x8000  /* Device préféré */
#define SWAP_FLAG_DISCARD       0x4000  /* Support DISCARD/TRIM */
#define SWAP_FLAG_COMPRESS      0x2000  /* Compression activée */
#define SWAP_FLAG_ENCRYPT       0x1000  /* Chiffrement activé */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Entrée dans l'espace de swap
 */
typedef struct swap_entry {
    uint32_t offset;                    /* Offset dans le device */
    uint8_t state;                      /* État de l'entrée */
    uint8_t ref_count;                  /* Compteur de références */
    uint16_t cluster_id;                /* ID du cluster */
    uint32_t timestamp;                 /* Timestamp d'utilisation */
    void *private_data;                 /* Données privées */
} swap_entry_t;

/**
 * @brief Device de swap
 */
typedef struct swap_device {
    char name[64];                      /* Nom du device */
    uint32_t type;                      /* Type de swap */
    uint32_t flags;                     /* Flags de configuration */
    int16_t priority;                   /* Priorité du device */
    bool active;                        /* Device actif */
    
    /* Taille et layout */
    uint64_t total_pages;               /* Pages totales */
    uint64_t free_pages;                /* Pages libres */
    uint64_t used_pages;                /* Pages utilisées */
    uint64_t bad_pages;                 /* Pages défectueuses */
    
    /* Bitmap d'allocation */
    uint8_t *bitmap;                    /* Bitmap des pages libres */
    uint32_t bitmap_size;               /* Taille du bitmap */
    uint32_t search_hint;               /* Hint pour recherche */
    
    /* Interface device */
    void *device_handle;                /* Handle du device */
    int (*read_page)(struct swap_device *dev, uint32_t offset, void *buffer);
    int (*write_page)(struct swap_device *dev, uint32_t offset, const void *buffer);
    int (*discard_page)(struct swap_device *dev, uint32_t offset);
    void (*sync)(struct swap_device *dev);
    
    /* Statistiques */
    uint64_t reads;                     /* Lectures effectuées */
    uint64_t writes;                    /* Écritures effectuées */
    uint64_t discards;                  /* Discards effectués */
    uint64_t errors;                    /* Erreurs I/O */
    uint64_t total_read_time;           /* Temps total de lecture */
    uint64_t total_write_time;          /* Temps total d'écriture */
    
    /* Clustering et cache */
    uint32_t cluster_size;              /* Taille des clusters */
    uint32_t readahead_size;            /* Taille du readahead */
    void *cache;                        /* Cache du device */
    
    /* Synchronisation */
    uint32_t lock;                      /* Verrou du device */
} swap_device_t;

/**
 * @brief Gestionnaire global de swap
 */
typedef struct swap_manager {
    swap_device_t devices[MAX_SWAP_DEVICES];    /* Devices de swap */
    uint32_t num_devices;               /* Nombre de devices actifs */
    uint64_t total_swap_pages;          /* Pages de swap totales */
    uint64_t free_swap_pages;           /* Pages de swap libres */
    uint64_t used_swap_pages;           /* Pages de swap utilisées */
    
    /* Politique de sélection */
    uint32_t allocation_policy;         /* Politique d'allocation */
    uint32_t reclaim_policy;            /* Politique de récupération */
    
    /* Seuils et limites */
    uint32_t low_watermark;             /* Seuil bas */
    uint32_t high_watermark;            /* Seuil haut */
    uint32_t emergency_watermark;       /* Seuil d'urgence */
    
    /* État global */
    bool swapping_enabled;              /* Swap activé */
    bool emergency_mode;                /* Mode d'urgence */
    uint32_t swap_pressure;             /* Pression de swap */
    
} swap_manager_t;

/**
 * @brief Informations de swap d'une page
 */
typedef struct page_swap_info {
    swap_device_t *device;              /* Device de swap */
    uint32_t offset;                    /* Offset dans le device */
    uint32_t cluster_offset;            /* Offset dans le cluster */
    bool valid;                         /* Information valide */
    uint32_t timestamp;                 /* Timestamp de création */
} page_swap_info_t;

/**
 * @brief Statistiques globales du swap
 */
typedef struct {
    uint64_t pages_swapped_out;         /* Pages swappées out */
    uint64_t pages_swapped_in;          /* Pages swappées in */
    uint64_t swap_operations;           /* Opérations de swap totales */
    uint64_t swap_read_operations;      /* Opérations de lecture */
    uint64_t swap_write_operations;     /* Opérations d'écriture */
    uint64_t swap_errors;               /* Erreurs de swap */
    uint64_t swap_cache_hits;           /* Hits du cache de swap */
    uint64_t swap_cache_misses;         /* Misses du cache de swap */
    uint64_t total_swap_time;           /* Temps total passé en swap */
    uint64_t avg_swap_latency;          /* Latence moyenne de swap */
    uint64_t peak_swap_usage;           /* Pic d'utilisation du swap */
    uint32_t current_swap_pressure;     /* Pression actuelle */
} swap_stats_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Gestionnaire global */
static swap_manager_t swap_mgr;
static bool swap_mgr_initialized = false;
static swap_stats_t swap_stats;

/* Configuration */
static bool debug_swap = false;
static uint32_t swap_cluster_default_size = SWAP_CLUSTER_SIZE;
static uint32_t swap_readahead_default_size = SWAP_READAHEAD_SIZE;

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
static spinlock_t swap_lock = SPINLOCK_INIT;
#define SWAP_LOCK() spin_lock(&swap_lock)
#define SWAP_UNLOCK() spin_unlock(&swap_lock)
#else
#define SWAP_LOCK() do {} while(0)
#define SWAP_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * BITMAP MANAGEMENT
 * ======================================================================== */

/**
 * @brief Trouve une page libre dans le bitmap
 * @param device Device de swap
 * @return Offset de la page libre ou -1
 */
static int find_free_swap_page(swap_device_t *device) {
    if (!device || !device->bitmap) {
        return -1;
    }
    
    uint32_t start_byte = device->search_hint / 8;
    uint32_t bitmap_bytes = (device->total_pages + 7) / 8;
    
    /* Recherche à partir du hint */
    for (uint32_t byte_idx = start_byte; byte_idx < bitmap_bytes; byte_idx++) {
        if (device->bitmap[byte_idx] != 0xFF) {
            /* Il y a au moins un bit libre dans ce byte */
            for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
                uint32_t page_idx = byte_idx * 8 + bit_idx;
                if (page_idx >= device->total_pages) {
                    break;
                }
                
                if (!(device->bitmap[byte_idx] & (1 << bit_idx))) {
                    /* Page libre trouvée */
                    device->bitmap[byte_idx] |= (1 << bit_idx);
                    device->search_hint = page_idx + 1;
                    device->free_pages--;
                    device->used_pages++;
                    return page_idx;
                }
            }
        }
    }
    
    /* Recherche depuis le début jusqu'au hint */
    for (uint32_t byte_idx = 0; byte_idx < start_byte; byte_idx++) {
        if (device->bitmap[byte_idx] != 0xFF) {
            for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
                uint32_t page_idx = byte_idx * 8 + bit_idx;
                if (page_idx >= device->total_pages) {
                    break;
                }
                
                if (!(device->bitmap[byte_idx] & (1 << bit_idx))) {
                    device->bitmap[byte_idx] |= (1 << bit_idx);
                    device->search_hint = page_idx + 1;
                    device->free_pages--;
                    device->used_pages++;
                    return page_idx;
                }
            }
        }
    }
    
    return -1; /* Pas de page libre */
}

/**
 * @brief Libère une page dans le bitmap
 * @param device Device de swap
 * @param page_offset Offset de la page
 */
static void free_swap_page(swap_device_t *device, uint32_t page_offset) {
    if (!device || !device->bitmap || page_offset >= device->total_pages) {
        return;
    }
    
    uint32_t byte_idx = page_offset / 8;
    uint32_t bit_idx = page_offset % 8;
    
    if (device->bitmap[byte_idx] & (1 << bit_idx)) {
        device->bitmap[byte_idx] &= ~(1 << bit_idx);
        device->free_pages++;
        device->used_pages--;
        
        if (page_offset < device->search_hint) {
            device->search_hint = page_offset;
        }
    }
}

/**
 * @brief Vérifie si une page est libre
 * @param device Device de swap
 * @param page_offset Offset de la page
 * @return true si libre
 */
static bool is_swap_page_free(swap_device_t *device, uint32_t page_offset) {
    if (!device || !device->bitmap || page_offset >= device->total_pages) {
        return false;
    }
    
    uint32_t byte_idx = page_offset / 8;
    uint32_t bit_idx = page_offset % 8;
    
    return !(device->bitmap[byte_idx] & (1 << bit_idx));
}

/* ========================================================================
 * DEVICE MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise un device de swap
 * @param device Device à initialiser
 * @param name Nom du device
 * @param type Type de device
 * @param size_pages Taille en pages
 * @return 0 en cas de succès
 */
static int init_swap_device(swap_device_t *device, const char *name, 
                           uint32_t type, uint64_t size_pages) {
    if (!device || !name || size_pages == 0) {
        return -1;
    }
    
    /* Initialiser la structure */
    memset(device, 0, sizeof(swap_device_t));
    strncpy(device->name, name, sizeof(device->name) - 1);
    device->type = type;
    device->total_pages = size_pages;
    device->free_pages = size_pages;
    device->used_pages = 0;
    device->bad_pages = 0;
    device->priority = SWAP_PRIORITY_DEFAULT;
    device->active = false;
    device->cluster_size = swap_cluster_default_size;
    device->readahead_size = swap_readahead_default_size;
    device->search_hint = 0;
    
    /* Allouer le bitmap */
    device->bitmap_size = (size_pages + 7) / 8;
    device->bitmap = (uint8_t *)kmalloc(device->bitmap_size, GFP_KERNEL);
    if (!device->bitmap) {
        printk(KERN_ERR "Failed to allocate swap bitmap for %s\n", name);
        return -1;
    }
    
    /* Initialiser le bitmap (toutes les pages libres) */
    memset(device->bitmap, 0, device->bitmap_size);
    
    printk(KERN_INFO "Initialized swap device: %s (%llu pages, %llu MB)\n",
           name, size_pages, (size_pages * PAGE_SIZE) / (1024 * 1024));
    
    return 0;
}

/**
 * @brief Active un device de swap
 * @param device Device à activer
 * @return 0 en cas de succès
 */
static int activate_swap_device(swap_device_t *device) {
    if (!device || device->active) {
        return -1;
    }
    
    /* TODO: Vérifier l'intégrité du device */
    /* TODO: Initialiser l'interface I/O */
    
    device->active = true;
    swap_mgr.total_swap_pages += device->total_pages;
    swap_mgr.free_swap_pages += device->free_pages;
    
    printk(KERN_INFO "Activated swap device: %s (priority %d)\n", 
           device->name, device->priority);
    
    return 0;
}

/**
 * @brief Désactive un device de swap
 * @param device Device à désactiver
 * @return 0 en cas de succès
 */
static int deactivate_swap_device(swap_device_t *device) {
    if (!device || !device->active) {
        return -1;
    }
    
    /* Vérifier qu'aucune page n'est en cours d'utilisation */
    if (device->used_pages > 0) {
        printk(KERN_WARNING "Cannot deactivate swap device %s: %llu pages still in use\n",
               device->name, device->used_pages);
        return -1;
    }
    
    device->active = false;
    swap_mgr.total_swap_pages -= device->total_pages;
    swap_mgr.free_swap_pages -= device->free_pages;
    
    printk(KERN_INFO "Deactivated swap device: %s\n", device->name);
    
    return 0;
}

/**
 * @brief Trouve le meilleur device pour allocation
 * @return Pointeur vers device ou NULL
 */
static swap_device_t *select_swap_device(void) {
    swap_device_t *best_device = NULL;
    int best_priority = SWAP_PRIORITY_MIN - 1;
    uint64_t most_free_pages = 0;
    
    /* Rechercher le device avec la plus haute priorité et le plus d'espace libre */
    for (uint32_t i = 0; i < swap_mgr.num_devices; i++) {
        swap_device_t *device = &swap_mgr.devices[i];
        
        if (!device->active || device->free_pages == 0) {
            continue;
        }
        
        /* Priorité plus élevée */
        if (device->priority > best_priority) {
            best_device = device;
            best_priority = device->priority;
            most_free_pages = device->free_pages;
        }
        /* Même priorité, plus d'espace libre */
        else if (device->priority == best_priority && device->free_pages > most_free_pages) {
            best_device = device;
            most_free_pages = device->free_pages;
        }
    }
    
    return best_device;
}

/* ========================================================================
 * SWAP ALLOCATION AND DEALLOCATION
 * ======================================================================== */

/**
 * @brief Alloue un emplacement de swap pour une page
 * @param page_info Informations de la page à swapper
 * @return 0 en cas de succès, -1 en cas d'erreur
 */
int swap_alloc_page(page_swap_info_t *page_info) {
    if (!swap_mgr_initialized || !page_info) {
        return -1;
    }
    
    SWAP_LOCK();
    
    if (swap_mgr.free_swap_pages == 0) {
        SWAP_UNLOCK();
        printk(KERN_WARNING "No free swap space available\n");
        return -1;
    }
    
    /* Sélectionner le device */
    swap_device_t *device = select_swap_device();
    if (!device) {
        SWAP_UNLOCK();
        printk(KERN_ERR "No suitable swap device found\n");
        return -1;
    }
    
    /* Allouer une page dans le device */
    int page_offset = find_free_swap_page(device);
    if (page_offset < 0) {
        SWAP_UNLOCK();
        printk(KERN_ERR "Failed to allocate page in swap device %s\n", device->name);
        return -1;
    }
    
    /* Remplir les informations */
    page_info->device = device;
    page_info->offset = page_offset;
    page_info->cluster_offset = page_offset % device->cluster_size;
    page_info->valid = true;
    page_info->timestamp = get_timestamp();
    
    /* Mettre à jour les statistiques globales */
    swap_mgr.free_swap_pages--;
    swap_mgr.used_swap_pages++;
    
    SWAP_UNLOCK();
    
    if (debug_swap) {
        printk(KERN_DEBUG "Allocated swap page: device=%s, offset=%u\n",
               device->name, page_offset);
    }
    
    return 0;
}

/**
 * @brief Libère un emplacement de swap
 * @param page_info Informations de la page à libérer
 * @return 0 en cas de succès
 */
int swap_free_page(page_swap_info_t *page_info) {
    if (!swap_mgr_initialized || !page_info || !page_info->valid) {
        return -1;
    }
    
    SWAP_LOCK();
    
    swap_device_t *device = page_info->device;
    if (!device || !device->active) {
        SWAP_UNLOCK();
        return -1;
    }
    
    /* Libérer la page dans le device */
    free_swap_page(device, page_info->offset);
    
    /* Optionnel: DISCARD/TRIM si supporté */
    if ((device->flags & SWAP_FLAG_DISCARD) && device->discard_page) {
        device->discard_page(device, page_info->offset);
        device->discards++;
    }
    
    /* Mettre à jour les statistiques globales */
    swap_mgr.free_swap_pages++;
    swap_mgr.used_swap_pages--;
    
    /* Invalider les informations */
    page_info->valid = false;
    page_info->device = NULL;
    
    SWAP_UNLOCK();
    
    if (debug_swap) {
        printk(KERN_DEBUG "Freed swap page: device=%s, offset=%u\n",
               device->name, page_info->offset);
    }
    
    return 0;
}

/* ========================================================================
 * SWAP I/O OPERATIONS
 * ======================================================================== */

/**
 * @brief Écrit une page vers le swap
 * @param page_info Informations de swap
 * @param page_data Données de la page
 * @return 0 en cas de succès
 */
int swap_write_page(page_swap_info_t *page_info, const void *page_data) {
    if (!swap_mgr_initialized || !page_info || !page_info->valid || !page_data) {
        return -1;
    }
    
    swap_device_t *device = page_info->device;
    if (!device || !device->active || !device->write_page) {
        return -1;
    }
    
    uint64_t start_time = get_timestamp();
    
    /* Écrire la page */
    int result = device->write_page(device, page_info->offset, page_data);
    
    uint64_t end_time = get_timestamp();
    
    SWAP_LOCK();
    
    if (result == 0) {
        device->writes++;
        device->total_write_time += (end_time - start_time);
        swap_stats.pages_swapped_out++;
        swap_stats.swap_write_operations++;
    } else {
        device->errors++;
        swap_stats.swap_errors++;
        printk(KERN_ERR "Swap write error: device=%s, offset=%u\n",
               device->name, page_info->offset);
    }
    
    swap_stats.swap_operations++;
    swap_stats.total_swap_time += (end_time - start_time);
    
    SWAP_UNLOCK();
    
    if (debug_swap) {
        printk(KERN_DEBUG "Swap write: device=%s, offset=%u, result=%d, time=%llu\n",
               device->name, page_info->offset, result, end_time - start_time);
    }
    
    return result;
}

/**
 * @brief Lit une page depuis le swap
 * @param page_info Informations de swap
 * @param page_data Buffer pour les données
 * @return 0 en cas de succès
 */
int swap_read_page(page_swap_info_t *page_info, void *page_data) {
    if (!swap_mgr_initialized || !page_info || !page_info->valid || !page_data) {
        return -1;
    }
    
    swap_device_t *device = page_info->device;
    if (!device || !device->active || !device->read_page) {
        return -1;
    }
    
    uint64_t start_time = get_timestamp();
    
    /* Lire la page */
    int result = device->read_page(device, page_info->offset, page_data);
    
    uint64_t end_time = get_timestamp();
    
    SWAP_LOCK();
    
    if (result == 0) {
        device->reads++;
        device->total_read_time += (end_time - start_time);
        swap_stats.pages_swapped_in++;
        swap_stats.swap_read_operations++;
    } else {
        device->errors++;
        swap_stats.swap_errors++;
        printk(KERN_ERR "Swap read error: device=%s, offset=%u\n",
               device->name, page_info->offset);
    }
    
    swap_stats.swap_operations++;
    swap_stats.total_swap_time += (end_time - start_time);
    
    SWAP_UNLOCK();
    
    if (debug_swap) {
        printk(KERN_DEBUG "Swap read: device=%s, offset=%u, result=%d, time=%llu\n",
               device->name, page_info->offset, result, end_time - start_time);
    }
    
    return result;
}

/* ========================================================================
 * SYSTEM INTERFACE
 * ======================================================================== */

/**
 * @brief Ajoute un device de swap au système
 * @param name Nom du device
 * @param type Type de device
 * @param size_pages Taille en pages
 * @param priority Priorité du device
 * @return ID du device ou -1
 */
int swap_add_device(const char *name, uint32_t type, uint64_t size_pages, int16_t priority) {
    if (!swap_mgr_initialized || !name || size_pages < (MIN_SWAP_SIZE / PAGE_SIZE)) {
        return -1;
    }
    
    SWAP_LOCK();
    
    if (swap_mgr.num_devices >= MAX_SWAP_DEVICES) {
        SWAP_UNLOCK();
        printk(KERN_ERR "Maximum number of swap devices reached\n");
        return -1;
    }
    
    /* Vérifier que le nom n'existe pas déjà */
    for (uint32_t i = 0; i < swap_mgr.num_devices; i++) {
        if (strcmp(swap_mgr.devices[i].name, name) == 0) {
            SWAP_UNLOCK();
            printk(KERN_ERR "Swap device %s already exists\n", name);
            return -1;
        }
    }
    
    /* Initialiser le nouveau device */
    uint32_t device_id = swap_mgr.num_devices;
    swap_device_t *device = &swap_mgr.devices[device_id];
    
    if (init_swap_device(device, name, type, size_pages) != 0) {
        SWAP_UNLOCK();
        return -1;
    }
    
    device->priority = priority;
    
    /* Activer le device */
    if (activate_swap_device(device) != 0) {
        kfree(device->bitmap);
        SWAP_UNLOCK();
        return -1;
    }
    
    swap_mgr.num_devices++;
    
    SWAP_UNLOCK();
    
    printk(KERN_INFO "Added swap device: %s (ID %u, priority %d, %llu MB)\n",
           name, device_id, priority, (size_pages * PAGE_SIZE) / (1024 * 1024));
    
    return device_id;
}

/**
 * @brief Retire un device de swap du système
 * @param device_id ID du device
 * @return 0 en cas de succès
 */
int swap_remove_device(uint32_t device_id) {
    if (!swap_mgr_initialized || device_id >= swap_mgr.num_devices) {
        return -1;
    }
    
    SWAP_LOCK();
    
    swap_device_t *device = &swap_mgr.devices[device_id];
    
    /* Désactiver le device */
    if (deactivate_swap_device(device) != 0) {
        SWAP_UNLOCK();
        return -1;
    }
    
    /* Libérer le bitmap */
    if (device->bitmap) {
        kfree(device->bitmap);
        device->bitmap = NULL;
    }
    
    /* Décaler les devices suivants */
    for (uint32_t i = device_id; i < swap_mgr.num_devices - 1; i++) {
        swap_mgr.devices[i] = swap_mgr.devices[i + 1];
    }
    
    swap_mgr.num_devices--;
    
    SWAP_UNLOCK();
    
    printk(KERN_INFO "Removed swap device: %s\n", device->name);
    
    return 0;
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise le gestionnaire de swap
 * @return 0 en cas de succès
 */
int swap_init(void) {
    if (swap_mgr_initialized) {
        printk(KERN_WARNING "Swap manager already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing swap manager\n");
    
    /* Initialiser le gestionnaire */
    memset(&swap_mgr, 0, sizeof(swap_mgr));
    memset(&swap_stats, 0, sizeof(swap_stats));
    
    swap_mgr.swapping_enabled = true;
    swap_mgr.emergency_mode = false;
    swap_mgr.allocation_policy = 0; /* Round-robin par défaut */
    swap_mgr.reclaim_policy = 0;    /* LRU par défaut */
    
    /* Seuils par défaut (en pourcentage) */
    swap_mgr.low_watermark = 20;        /* 20% */
    swap_mgr.high_watermark = 80;       /* 80% */
    swap_mgr.emergency_watermark = 95;  /* 95% */
    
    swap_mgr_initialized = true;
    
    printk(KERN_INFO "Swap manager initialized\n");
    printk(KERN_INFO "  Max devices: %d\n", MAX_SWAP_DEVICES);
    printk(KERN_INFO "  Default cluster size: %u pages\n", swap_cluster_default_size);
    printk(KERN_INFO "  Default readahead: %u pages\n", swap_readahead_default_size);
    
    return 0;
}

/**
 * @brief Obtient les statistiques de swap
 * @param stats Pointeur vers structure de statistiques
 */
void swap_get_stats(swap_stats_t *stats) {
    if (!stats || !swap_mgr_initialized) {
        return;
    }
    
    SWAP_LOCK();
    memcpy(stats, &swap_stats, sizeof(swap_stats_t));
    stats->current_swap_pressure = swap_mgr.swap_pressure;
    SWAP_UNLOCK();
}

/**
 * @brief Affiche les statistiques de swap
 */
void swap_print_stats(void) {
    if (!swap_mgr_initialized) {
        printk(KERN_INFO "Swap manager not initialized\n");
        return;
    }
    
    printk(KERN_INFO "Swap Manager Statistics:\n");
    printk(KERN_INFO "  Active devices:       %u\n", swap_mgr.num_devices);
    printk(KERN_INFO "  Total swap space:     %llu MB\n", 
           (swap_mgr.total_swap_pages * PAGE_SIZE) / (1024 * 1024));
    printk(KERN_INFO "  Free swap space:      %llu MB\n", 
           (swap_mgr.free_swap_pages * PAGE_SIZE) / (1024 * 1024));
    printk(KERN_INFO "  Used swap space:      %llu MB\n", 
           (swap_mgr.used_swap_pages * PAGE_SIZE) / (1024 * 1024));
    printk(KERN_INFO "  Pages swapped out:    %llu\n", swap_stats.pages_swapped_out);
    printk(KERN_INFO "  Pages swapped in:     %llu\n", swap_stats.pages_swapped_in);
    printk(KERN_INFO "  Swap operations:      %llu\n", swap_stats.swap_operations);
    printk(KERN_INFO "  Swap errors:          %llu\n", swap_stats.swap_errors);
    printk(KERN_INFO "  Current pressure:     %u%%\n", swap_mgr.swap_pressure);
    printk(KERN_INFO "  Emergency mode:       %s\n", swap_mgr.emergency_mode ? "Yes" : "No");
}

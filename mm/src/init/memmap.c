/**
 * @file memmap.c
 * @brief Carte mémoire système - Gestion de la carte mémoire du système
 * 
 * Ce fichier gère l'analyse et l'interprétation de la carte mémoire fournie
 * par le bootloader (BIOS E820, UEFI memory map, etc.) pour identifier les
 * zones de mémoire disponibles, réservées et spéciales du système. Il fournit:
 * 
 * - Parsing des cartes mémoire multi-format (E820, UEFI, etc.)
 * - Classification des régions mémoire par type et usage
 * - Interface d'interrogation des zones mémoire disponibles
 * - Gestion des régions réservées et protection
 * - Statistiques et métriques mémoire système
 * - Validation et vérification de cohérence
 * 
 * Le gestionnaire de carte mémoire est l'un des premiers composants initialisés
 * et sert de base pour tous les autres allocateurs de mémoire.
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
#include "mm_setup.h"

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

#define MAX_MEMORY_REGIONS      128             /* Maximum memory regions */
#define MIN_REGION_SIZE         PAGE_SIZE       /* Minimum region size */
#define MAX_REGION_SIZE         (1ULL << 40)    /* Maximum region size (1TB) */
#define MEMMAP_ALIGNMENT        4096            /* Memory alignment */
#define MEMMAP_GUARD_SIZE       4096            /* Guard size around regions */

/* Memory map signature validation */
#define E820_SIGNATURE          0x534D4150      /* "SMAP" */
#define UEFI_SIGNATURE          0x55454649      /* "UEFI" */
#define MEMMAP_MAGIC            0x4D454D4D      /* "MEMM" */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Types de régions mémoire (standards E820/UEFI)
 */
typedef enum {
    MEMORY_TYPE_AVAILABLE = 1,          /* Mémoire disponible */
    MEMORY_TYPE_RESERVED = 2,           /* Mémoire réservée */
    MEMORY_TYPE_ACPI_RECLAIMABLE = 3,   /* ACPI récupérable */
    MEMORY_TYPE_ACPI_NVS = 4,           /* ACPI Non-Volatile Storage */
    MEMORY_TYPE_BAD = 5,                /* Mémoire défectueuse */
    MEMORY_TYPE_BOOTLOADER = 6,         /* Utilisée par bootloader */
    MEMORY_TYPE_KERNEL = 7,             /* Utilisée par kernel */
    MEMORY_TYPE_INITRD = 8,             /* Initial RAM disk */
    MEMORY_TYPE_FRAMEBUFFER = 9,        /* Framebuffer vidéo */
    MEMORY_TYPE_DEVICE = 10,            /* Mapped devices */
    MEMORY_TYPE_COUNT
} memory_region_type_t;

/**
 * @brief Flags pour les régions mémoire
 */
typedef enum {
    MEMORY_FLAG_NONE        = 0x00,
    MEMORY_FLAG_CACHED      = 0x01,     /* Mémoire cacheable */
    MEMORY_FLAG_BUFFERED    = 0x02,     /* Mémoire bufferable */
    MEMORY_FLAG_EXECUTABLE  = 0x04,     /* Exécution autorisée */
    MEMORY_FLAG_WRITABLE    = 0x08,     /* Écriture autorisée */
    MEMORY_FLAG_DMA_CAPABLE = 0x10,     /* Compatible DMA */
    MEMORY_FLAG_PERSISTENT  = 0x20,     /* Mémoire persistante */
    MEMORY_FLAG_VOLATILE    = 0x40,     /* Mémoire volatile */
    MEMORY_FLAG_PROTECTED   = 0x80      /* Région protégée */
} memory_region_flags_t;

/**
 * @brief Structure représentant une région mémoire
 */
typedef struct memory_region {
    uint64_t base_addr;                 /* Adresse de base */
    uint64_t length;                    /* Taille de la région */
    uint32_t type;                      /* Type de région */
    uint32_t flags;                     /* Flags de la région */
    uint32_t attributes;                /* Attributs étendus */
    uint32_t numa_node;                 /* Nœud NUMA */
    const char *name;                   /* Nom descriptif */
    struct memory_region *next;         /* Région suivante */
    struct memory_region *parent;       /* Région parente */
} memory_region_t;

/**
 * @brief Format E820 (BIOS legacy)
 */
typedef struct {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t acpi_attributes;
} __attribute__((packed)) e820_entry_t;

/**
 * @brief Format UEFI Memory Descriptor
 */
typedef struct {
    uint32_t type;
    uint64_t physical_start;
    uint64_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} __attribute__((packed)) uefi_memory_descriptor_t;

/**
 * @brief Statistiques de carte mémoire
 */
typedef struct {
    size_t total_regions;               /* Nombre total de régions */
    size_t available_regions;           /* Régions disponibles */
    size_t reserved_regions;            /* Régions réservées */
    uint64_t total_memory;              /* Mémoire totale */
    uint64_t available_memory;          /* Mémoire disponible */
    uint64_t reserved_memory;           /* Mémoire réservée */
    uint64_t largest_free_region;       /* Plus grande région libre */
    uint64_t fragmentation_ratio;       /* Ratio de fragmentation */
} memmap_stats_t;

/**
 * @brief État du gestionnaire de carte mémoire
 */
typedef struct {
    memory_region_t regions[MAX_MEMORY_REGIONS];
    size_t region_count;
    memmap_stats_t stats;
    bool initialized;
    uint32_t checksum;
    void *raw_map;
    size_t raw_map_size;
    uint32_t map_format;
} memmap_state_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

static memmap_state_t g_memmap = {
    .region_count = 0,
    .stats = {0},
    .initialized = false,
    .checksum = 0,
    .raw_map = NULL,
    .raw_map_size = 0,
    .map_format = 0
};

/* Noms des types de régions pour affichage */
static const char *memory_type_names[MEMORY_TYPE_COUNT] = {
    [MEMORY_TYPE_AVAILABLE] = "Available",
    [MEMORY_TYPE_RESERVED] = "Reserved",
    [MEMORY_TYPE_ACPI_RECLAIMABLE] = "ACPI Reclaimable",
    [MEMORY_TYPE_ACPI_NVS] = "ACPI NVS",
    [MEMORY_TYPE_BAD] = "Bad Memory",
    [MEMORY_TYPE_BOOTLOADER] = "Bootloader",
    [MEMORY_TYPE_KERNEL] = "Kernel",
    [MEMORY_TYPE_INITRD] = "InitRD",
    [MEMORY_TYPE_FRAMEBUFFER] = "Framebuffer",
    [MEMORY_TYPE_DEVICE] = "Device"
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
static spinlock_t memmap_lock = SPINLOCK_INIT;
#define MEMMAP_LOCK() spin_lock(&memmap_lock)
#define MEMMAP_UNLOCK() spin_unlock(&memmap_lock)
#else
#define MEMMAP_LOCK() do {} while(0)
#define MEMMAP_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * @brief Calcule un checksum simple
 * @param data Données à traiter
 * @param size Taille des données
 * @return Checksum calculé
 */
static uint32_t calculate_checksum(const void *data, size_t size) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t checksum = 0;
    
    for (size_t i = 0; i < size; i++) {
        checksum += bytes[i];
        checksum = (checksum << 1) | (checksum >> 31); /* Rotation */
    }
    
    return checksum;
}

/**
 * @brief Aligne une adresse
 * @param addr Adresse à aligner
 * @param alignment Alignement requis
 * @return Adresse alignée
 */
static inline uint64_t align_address(uint64_t addr, uint64_t alignment) {
    return (addr + alignment - 1) & ~(alignment - 1);
}

/**
 * @brief Vérifie si deux régions se chevauchent
 * @param r1 Première région
 * @param r2 Seconde région
 * @return true si chevauchement
 */
static bool regions_overlap(const memory_region_t *r1, const memory_region_t *r2) {
    uint64_t r1_end = r1->base_addr + r1->length;
    uint64_t r2_end = r2->base_addr + r2->length;
    
    return (r1->base_addr < r2_end) && (r2->base_addr < r1_end);
}

/**
 * @brief Valide une région mémoire
 * @param region Région à valider
 * @return true si valide
 */
static bool validate_memory_region(const memory_region_t *region) {
    if (!region) return false;
    
    /* Vérifications de base */
    if (region->length == 0) return false;
    if (region->length > MAX_REGION_SIZE) return false;
    if (region->base_addr + region->length < region->base_addr) return false; /* Overflow */
    if (region->type >= MEMORY_TYPE_COUNT) return false;
    
    /* Vérification d'alignement */
    if (region->base_addr & (MEMMAP_ALIGNMENT - 1)) return false;
    
    return true;
}

/**
 * @brief Convertit un type E820 vers notre format
 * @param e820_type Type E820
 * @return Notre type de région
 */
static memory_region_type_t convert_e820_type(uint32_t e820_type) {
    switch (e820_type) {
        case 1: return MEMORY_TYPE_AVAILABLE;
        case 2: return MEMORY_TYPE_RESERVED;
        case 3: return MEMORY_TYPE_ACPI_RECLAIMABLE;
        case 4: return MEMORY_TYPE_ACPI_NVS;
        case 5: return MEMORY_TYPE_BAD;
        default: return MEMORY_TYPE_RESERVED;
    }
}

/**
 * @brief Convertit un type UEFI vers notre format
 * @param uefi_type Type UEFI
 * @return Notre type de région
 */
static memory_region_type_t convert_uefi_type(uint32_t uefi_type) {
    switch (uefi_type) {
        case 3:  /* EfiBootServicesCode */
        case 4:  /* EfiBootServicesData */
        case 7:  /* EfiConventionalMemory */
            return MEMORY_TYPE_AVAILABLE;
        case 0:  /* EfiReservedMemoryType */
        case 1:  /* EfiLoaderCode */
        case 2:  /* EfiLoaderData */
        case 5:  /* EfiRuntimeServicesCode */
        case 6:  /* EfiRuntimeServicesData */
        case 8:  /* EfiUnusableMemory */
        case 11: /* EfiPalCode */
            return MEMORY_TYPE_RESERVED;
        case 9:  /* EfiACPIReclaimMemory */
            return MEMORY_TYPE_ACPI_RECLAIMABLE;
        case 10: /* EfiACPIMemoryNVS */
            return MEMORY_TYPE_ACPI_NVS;
        default:
            return MEMORY_TYPE_RESERVED;
    }
}

/* ========================================================================
 * MEMORY MAP PARSING
 * ======================================================================== */

/**
 * @brief Parse une carte mémoire E820
 * @param e820_map Pointeur vers la carte E820
 * @param entry_count Nombre d'entrées
 * @return 0 en cas de succès
 */
static int parse_e820_map(const e820_entry_t *e820_map, size_t entry_count) {
    if (!e820_map || entry_count == 0) return -1;
    
    printk(KERN_INFO "Parsing E820 memory map (%zu entries)\n", entry_count);
    
    for (size_t i = 0; i < entry_count && g_memmap.region_count < MAX_MEMORY_REGIONS; i++) {
        const e820_entry_t *entry = &e820_map[i];
        
        /* Valider l'entrée */
        if (entry->length == 0) continue;
        if (entry->base > UINT64_MAX - entry->length) continue; /* Overflow check */
        
        memory_region_t *region = &g_memmap.regions[g_memmap.region_count];
        
        region->base_addr = entry->base;
        region->length = entry->length;
        region->type = convert_e820_type(entry->type);
        region->flags = MEMORY_FLAG_CACHED;
        region->attributes = entry->acpi_attributes;
        region->numa_node = 0; /* Default NUMA node */
        region->name = memory_type_names[region->type];
        region->next = NULL;
        region->parent = NULL;
        
        if (validate_memory_region(region)) {
            g_memmap.region_count++;
            printk(KERN_DEBUG "E820[%zu]: 0x%016llx - 0x%016llx (%s)\n",
                   i, region->base_addr, region->base_addr + region->length - 1,
                   region->name);
        } else {
            printk(KERN_WARNING "Invalid E820 entry %zu: 0x%llx + 0x%llx\n",
                   i, entry->base, entry->length);
        }
    }
    
    return 0;
}

/**
 * @brief Parse une carte mémoire UEFI
 * @param uefi_map Pointeur vers la carte UEFI
 * @param map_size Taille de la carte
 * @param descriptor_size Taille d'un descripteur
 * @return 0 en cas de succès
 */
static int parse_uefi_map(const void *uefi_map, size_t map_size, size_t descriptor_size) {
    if (!uefi_map || map_size == 0 || descriptor_size == 0) return -1;
    
    size_t entry_count = map_size / descriptor_size;
    printk(KERN_INFO "Parsing UEFI memory map (%zu entries)\n", entry_count);
    
    const uint8_t *map_ptr = (const uint8_t *)uefi_map;
    
    for (size_t i = 0; i < entry_count && g_memmap.region_count < MAX_MEMORY_REGIONS; i++) {
        const uefi_memory_descriptor_t *entry = 
            (const uefi_memory_descriptor_t *)(map_ptr + i * descriptor_size);
        
        /* Valider l'entrée */
        if (entry->number_of_pages == 0) continue;
        
        memory_region_t *region = &g_memmap.regions[g_memmap.region_count];
        
        region->base_addr = entry->physical_start;
        region->length = entry->number_of_pages * PAGE_SIZE;
        region->type = convert_uefi_type(entry->type);
        region->flags = MEMORY_FLAG_CACHED;
        region->attributes = (uint32_t)entry->attribute;
        region->numa_node = 0;
        region->name = memory_type_names[region->type];
        region->next = NULL;
        region->parent = NULL;
        
        if (validate_memory_region(region)) {
            g_memmap.region_count++;
            printk(KERN_DEBUG "UEFI[%zu]: 0x%016llx - 0x%016llx (%s)\n",
                   i, region->base_addr, region->base_addr + region->length - 1,
                   region->name);
        } else {
            printk(KERN_WARNING "Invalid UEFI entry %zu: 0x%llx + %llu pages\n",
                   i, entry->physical_start, entry->number_of_pages);
        }
    }
    
    return 0;
}

/**
 * @brief Détecte le format de carte mémoire
 * @param map Pointeur vers la carte
 * @param size Taille de la carte
 * @return Format détecté
 */
static uint32_t detect_memory_map_format(const void *map, size_t size) {
    if (!map || size < 4) return 0;
    
    const uint32_t *signature = (const uint32_t *)map;
    
    /* Vérifier signature E820 */
    if (*signature == E820_SIGNATURE) {
        return E820_SIGNATURE;
    }
    
    /* Vérifier signature UEFI */
    if (*signature == UEFI_SIGNATURE) {
        return UEFI_SIGNATURE;
    }
    
    /* Heuristique: si la taille est multiple de sizeof(e820_entry_t) */
    if (size % sizeof(e820_entry_t) == 0) {
        return E820_SIGNATURE;
    }
    
    /* Heuristique: si la taille suggère des descripteurs UEFI */
    if (size % sizeof(uefi_memory_descriptor_t) == 0) {
        return UEFI_SIGNATURE;
    }
    
    return 0; /* Format inconnu */
}

/* ========================================================================
 * MEMORY MAP PROCESSING
 * ======================================================================== */

/**
 * @brief Trie les régions par adresse de base
 */
static void sort_memory_regions(void) {
    /* Tri à bulles simple - suffisant pour le nombre limité de régions */
    for (size_t i = 0; i < g_memmap.region_count - 1; i++) {
        for (size_t j = 0; j < g_memmap.region_count - 1 - i; j++) {
            if (g_memmap.regions[j].base_addr > g_memmap.regions[j + 1].base_addr) {
                memory_region_t temp = g_memmap.regions[j];
                g_memmap.regions[j] = g_memmap.regions[j + 1];
                g_memmap.regions[j + 1] = temp;
            }
        }
    }
}

/**
 * @brief Fusionne les régions adjacentes de même type
 */
static void merge_adjacent_regions(void) {
    if (g_memmap.region_count <= 1) return;
    
    size_t write_idx = 0;
    
    for (size_t read_idx = 0; read_idx < g_memmap.region_count; read_idx++) {
        memory_region_t *current = &g_memmap.regions[read_idx];
        
        /* Si cette région peut être fusionnée avec la précédente */
        if (write_idx > 0) {
            memory_region_t *prev = &g_memmap.regions[write_idx - 1];
            
            if (prev->type == current->type &&
                prev->flags == current->flags &&
                prev->base_addr + prev->length == current->base_addr) {
                
                /* Fusionner avec la région précédente */
                prev->length += current->length;
                printk(KERN_DEBUG "Merged region: 0x%llx + 0x%llx -> 0x%llx\n",
                       prev->base_addr, prev->length - current->length, prev->length);
                continue;
            }
        }
        
        /* Copier la région si nécessaire */
        if (write_idx != read_idx) {
            g_memmap.regions[write_idx] = *current;
        }
        write_idx++;
    }
    
    g_memmap.region_count = write_idx;
}

/**
 * @brief Calcule les statistiques de carte mémoire
 */
static void calculate_memory_stats(void) {
    memset(&g_memmap.stats, 0, sizeof(memmap_stats_t));
    
    g_memmap.stats.total_regions = g_memmap.region_count;
    
    for (size_t i = 0; i < g_memmap.region_count; i++) {
        const memory_region_t *region = &g_memmap.regions[i];
        
        g_memmap.stats.total_memory += region->length;
        
        switch (region->type) {
            case MEMORY_TYPE_AVAILABLE:
                g_memmap.stats.available_regions++;
                g_memmap.stats.available_memory += region->length;
                if (region->length > g_memmap.stats.largest_free_region) {
                    g_memmap.stats.largest_free_region = region->length;
                }
                break;
                
            default:
                g_memmap.stats.reserved_regions++;
                g_memmap.stats.reserved_memory += region->length;
                break;
        }
    }
    
    /* Calcul du ratio de fragmentation */
    if (g_memmap.stats.available_memory > 0) {
        g_memmap.stats.fragmentation_ratio = 
            (g_memmap.stats.available_regions * 100) / 
            (g_memmap.stats.available_memory / (1024 * 1024)); /* Régions par MB */
    }
}

/* ========================================================================
 * PUBLIC API FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialise la carte mémoire système
 * @param map Pointeur vers la carte mémoire du bootloader
 * @param map_size Taille de la carte en octets
 * @return 0 en cas de succès, code d'erreur négatif sinon
 */
int memmap_init(void *map, size_t map_size) {
    if (g_memmap.initialized) {
        printk(KERN_WARNING "Memory map already initialized\n");
        return 0;
    }
    
    if (!map || map_size == 0) {
        printk(KERN_ERR "Invalid memory map parameters\n");
        return -1;
    }
    
    printk(KERN_INFO "Initializing memory map (%zu bytes)\n", map_size);
    
    MEMMAP_LOCK();
    
    /* Réinitialiser l'état */
    memset(&g_memmap.regions, 0, sizeof(g_memmap.regions));
    g_memmap.region_count = 0;
    g_memmap.raw_map = map;
    g_memmap.raw_map_size = map_size;
    
    /* Détecter le format de carte mémoire */
    g_memmap.map_format = detect_memory_map_format(map, map_size);
    
    int result = -1;
    
    switch (g_memmap.map_format) {
        case E820_SIGNATURE:
            printk(KERN_INFO "Detected E820 memory map format\n");
            result = parse_e820_map((const e820_entry_t *)map, 
                                   map_size / sizeof(e820_entry_t));
            break;
            
        case UEFI_SIGNATURE:
            printk(KERN_INFO "Detected UEFI memory map format\n");
            result = parse_uefi_map((const uint8_t *)map + 4, map_size - 4,
                                   sizeof(uefi_memory_descriptor_t));
            break;
            
        default:
            printk(KERN_ERR "Unknown memory map format\n");
            result = -1;
            break;
    }
    
    if (result == 0) {
        /* Traitement post-parsing */
        sort_memory_regions();
        merge_adjacent_regions();
        calculate_memory_stats();
        
        /* Calcul du checksum pour validation */
        g_memmap.checksum = calculate_checksum(g_memmap.regions,
                                              g_memmap.region_count * sizeof(memory_region_t));
        
        g_memmap.initialized = true;
        
        printk(KERN_INFO "Memory map initialized: %zu regions, %llu MB total\n",
               g_memmap.region_count, g_memmap.stats.total_memory / (1024 * 1024));
    }
    
    MEMMAP_UNLOCK();
    
    return result;
}

/**
 * @brief Obtient la taille totale de mémoire
 * @return Taille totale en octets
 */
uint64_t memmap_get_total_memory(void) {
    return g_memmap.initialized ? g_memmap.stats.total_memory : 0;
}

/**
 * @brief Obtient la taille de mémoire disponible
 * @return Taille disponible en octets
 */
uint64_t memmap_get_available_memory(void) {
    return g_memmap.initialized ? g_memmap.stats.available_memory : 0;
}

/**
 * @brief Trouve la plus grande région de mémoire disponible
 * @param base_addr Pointeur pour stocker l'adresse de base
 * @param length Pointeur pour stocker la taille
 * @return 0 en cas de succès, -1 si aucune région trouvée
 */
int memmap_find_largest_region(uint64_t *base_addr, uint64_t *length) {
    if (!g_memmap.initialized || !base_addr || !length) {
        return -1;
    }
    
    *base_addr = 0;
    *length = 0;
    
    MEMMAP_LOCK();
    
    for (size_t i = 0; i < g_memmap.region_count; i++) {
        const memory_region_t *region = &g_memmap.regions[i];
        
        if (region->type == MEMORY_TYPE_AVAILABLE && region->length > *length) {
            *base_addr = region->base_addr;
            *length = region->length;
        }
    }
    
    MEMMAP_UNLOCK();
    
    return (*length > 0) ? 0 : -1;
}

/**
 * @brief Trouve une région de mémoire libre d'une taille minimale
 * @param min_size Taille minimale requise
 * @param alignment Alignement requis
 * @param base_addr Pointeur pour stocker l'adresse de base
 * @param length Pointeur pour stocker la taille
 * @return 0 en cas de succès, -1 si aucune région trouvée
 */
int memmap_find_free_region(uint64_t min_size, uint64_t alignment,
                           uint64_t *base_addr, uint64_t *length) {
    if (!g_memmap.initialized || min_size == 0 || !base_addr || !length) {
        return -1;
    }
    
    *base_addr = 0;
    *length = 0;
    
    MEMMAP_LOCK();
    
    for (size_t i = 0; i < g_memmap.region_count; i++) {
        const memory_region_t *region = &g_memmap.regions[i];
        
        if (region->type != MEMORY_TYPE_AVAILABLE) continue;
        
        uint64_t aligned_base = align_address(region->base_addr, alignment);
        uint64_t aligned_end = region->base_addr + region->length;
        
        if (aligned_base >= aligned_end) continue;
        if (aligned_end - aligned_base < min_size) continue;
        
        *base_addr = aligned_base;
        *length = aligned_end - aligned_base;
        
        MEMMAP_UNLOCK();
        return 0;
    }
    
    MEMMAP_UNLOCK();
    return -1;
}

/**
 * @brief Obtient les statistiques de carte mémoire
 * @param stats Pointeur vers structure de statistiques
 */
void memmap_get_stats(memmap_stats_t *stats) {
    if (!stats || !g_memmap.initialized) return;
    
    MEMMAP_LOCK();
    memcpy(stats, &g_memmap.stats, sizeof(memmap_stats_t));
    MEMMAP_UNLOCK();
}

/**
 * @brief Affiche la carte mémoire
 */
void memmap_print(void) {
    if (!g_memmap.initialized) {
        printk(KERN_INFO "Memory map not initialized\n");
        return;
    }
    
    printk(KERN_INFO "System Memory Map (%zu regions):\n", g_memmap.region_count);
    printk(KERN_INFO "Address Range          Size        Type\n");
    printk(KERN_INFO "================================================\n");
    
    for (size_t i = 0; i < g_memmap.region_count; i++) {
        const memory_region_t *region = &g_memmap.regions[i];
        uint64_t end_addr = region->base_addr + region->length - 1;
        
        printk(KERN_INFO "0x%016llx-0x%016llx %8llu KB %s\n",
               region->base_addr, end_addr,
               region->length / 1024,
               region->name);
    }
    
    printk(KERN_INFO "================================================\n");
    printk(KERN_INFO "Total Memory:     %llu MB\n", g_memmap.stats.total_memory / (1024 * 1024));
    printk(KERN_INFO "Available Memory: %llu MB\n", g_memmap.stats.available_memory / (1024 * 1024));
    printk(KERN_INFO "Reserved Memory:  %llu MB\n", g_memmap.stats.reserved_memory / (1024 * 1024));
    printk(KERN_INFO "Largest Region:   %llu KB\n", g_memmap.stats.largest_free_region / 1024);
}

/**
 * @brief Vérifie l'intégrité de la carte mémoire
 * @return true si intègre, false si corruption détectée
 */
bool memmap_check_integrity(void) {
    if (!g_memmap.initialized) return false;
    
    uint32_t current_checksum = calculate_checksum(g_memmap.regions,
                                                  g_memmap.region_count * sizeof(memory_region_t));
    
    return current_checksum == g_memmap.checksum;
}

/**
 * @brief Marque une région comme réservée
 * @param base_addr Adresse de base
 * @param length Taille de la région
 * @param name Nom de la région
 * @return 0 en cas de succès
 */
int memmap_reserve_region(uint64_t base_addr, uint64_t length, const char *name) {
    if (!g_memmap.initialized || length == 0) return -1;
    
    MEMMAP_LOCK();
    
    /* Chercher une région disponible qui contient cette zone */
    for (size_t i = 0; i < g_memmap.region_count; i++) {
        memory_region_t *region = &g_memmap.regions[i];
        
        if (region->type != MEMORY_TYPE_AVAILABLE) continue;
        
        uint64_t region_end = region->base_addr + region->length;
        uint64_t reserve_end = base_addr + length;
        
        /* Vérifier si la réservation est dans cette région */
        if (base_addr >= region->base_addr && reserve_end <= region_end) {
            /* TODO: Subdiviser la région disponible */
            printk(KERN_INFO "Reserved region '%s': 0x%llx - 0x%llx (%llu KB)\n",
                   name ? name : "unnamed", base_addr, reserve_end - 1, length / 1024);
            
            MEMMAP_UNLOCK();
            return 0;
        }
    }
    
    MEMMAP_UNLOCK();
    return -1;
}

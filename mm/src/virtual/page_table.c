/**
 * @file page_table.c
 * @brief Gestion des tables de pages - Interface bas niveau pour la MMU
 * 
 * Ce fichier implémente la gestion détaillée des tables de pages pour LeaxOS.
 * Il fournit une interface bas niveau pour manipuler les structures de données
 * de la MMU (Memory Management Unit) incluant:
 * 
 * - Création et destruction de tables de pages
 * - Mapping et unmapping de pages individuelles
 * - Gestion des permissions et attributs de pages
 * - Support multi-niveau (PGD, PUD, PMD, PTE)
 * - Optimisations pour différentes architectures
 * - Cache et invalidation TLB
 * - Support pour pages de différentes tailles
 * - Mécanismes de protection et sécurité
 * 
 * Le gestionnaire de tables de pages travaille en étroite collaboration
 * avec le VMM pour fournir les services de mémoire virtuelle.
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
#include "../physical/phys_page.h"

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
 * ARCHITECTURE-SPECIFIC DEFINITIONS (x86 32-bit)
 * ======================================================================== */

/* Layout des tables de pages x86 32-bit */
#define PGDIR_SHIFT         22              /* Décalage répertoire pages */
#define PTABLE_SHIFT        12              /* Décalage table pages */
#define PGDIR_SIZE          (1UL << PGDIR_SHIFT)    /* 4MB par entrée PGD */
#define PTABLE_SIZE         (1UL << PTABLE_SHIFT)   /* 4KB par entrée PTE */

#define PGDIR_MASK          (~(PGDIR_SIZE - 1))
#define PTABLE_MASK         (~(PTABLE_SIZE - 1))

#define PTRS_PER_PGD        1024            /* Entrées par PGD */
#define PTRS_PER_PTE        1024            /* Entrées par PTE */

/* Flags de pages x86 */
#define _PAGE_PRESENT       (1 << 0)        /* Page présente */
#define _PAGE_RW            (1 << 1)        /* Read/Write */
#define _PAGE_USER          (1 << 2)        /* User/Supervisor */
#define _PAGE_PWT           (1 << 3)        /* Page Write Through */
#define _PAGE_PCD           (1 << 4)        /* Page Cache Disable */
#define _PAGE_ACCESSED      (1 << 5)        /* Page Accessed */
#define _PAGE_DIRTY         (1 << 6)        /* Page Dirty */
#define _PAGE_PSE           (1 << 7)        /* Page Size Extension (4MB) */
#define _PAGE_GLOBAL        (1 << 8)        /* Global page */
#define _PAGE_UNUSED1       (1 << 9)        /* Disponible pour l'OS */
#define _PAGE_UNUSED2       (1 << 10)       /* Disponible pour l'OS */
#define _PAGE_UNUSED3       (1 << 11)       /* Disponible pour l'OS */

/* Masques pour extraction d'adresses */
#define PAGE_MASK           (~((1 << PAGE_SHIFT) - 1))
#define PTE_ADDR_MASK       0xFFFFF000UL    /* Masque adresse dans PTE */
#define PGD_ADDR_MASK       0xFFFFF000UL    /* Masque adresse dans PGD */

/* Macros d'index */
#define pgd_index(addr)     (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pte_index(addr)     (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Entrée de table de pages (Page Table Entry)
 */
typedef struct {
    uint32_t val;                   /* Valeur brute de l'entrée */
} pte_t;

/**
 * @brief Entrée de répertoire de pages (Page Global Directory)
 */
typedef struct {
    uint32_t val;                   /* Valeur brute de l'entrée */
} pgd_t;

/**
 * @brief Table de pages complète
 */
typedef struct page_table {
    pte_t entries[PTRS_PER_PTE];    /* Entrées PTE */
    struct page_table *next;        /* Table suivante (pour cache) */
    uint32_t ref_count;             /* Compteur de références */
    uint32_t flags;                 /* Flags de la table */
    void *virt_addr;                /* Adresse virtuelle de la table */
    phys_addr_t phys_addr;          /* Adresse physique de la table */
} page_table_t;

/**
 * @brief Répertoire de pages complet
 */
typedef struct page_directory {
    pgd_t entries[PTRS_PER_PGD];    /* Entrées PGD */
    page_table_t *page_tables[PTRS_PER_PGD]; /* Pointeurs vers tables */
    uint32_t ref_count;             /* Compteur de références */
    uint32_t asid;                  /* Address Space ID */
    void *virt_addr;                /* Adresse virtuelle */
    phys_addr_t phys_addr;          /* Adresse physique */
    struct page_directory *next;    /* Cache de répertoires */
} page_directory_t;

/**
 * @brief Informations de mapping
 */
typedef struct {
    virt_addr_t virt_start;         /* Début virtuel */
    virt_addr_t virt_end;           /* Fin virtuelle */
    phys_addr_t phys_start;         /* Début physique */
    uint32_t flags;                 /* Flags de protection */
    size_t page_count;              /* Nombre de pages */
    bool mapped;                    /* Mapping actif */
} page_mapping_t;

/**
 * @brief Statistiques des tables de pages
 */
typedef struct {
    uint64_t total_page_tables;     /* Tables de pages totales */
    uint64_t active_page_tables;    /* Tables actives */
    uint64_t total_page_dirs;       /* Répertoires totaux */
    uint64_t active_page_dirs;      /* Répertoires actifs */
    uint64_t memory_used;           /* Mémoire utilisée par tables */
    uint64_t tlb_flushes;           /* Invalidations TLB */
    uint64_t page_faults;           /* Page faults gérés */
    uint64_t mappings_created;      /* Mappings créés */
    uint64_t mappings_destroyed;    /* Mappings détruits */
    uint64_t large_pages_used;      /* Pages 4MB utilisées */
} page_table_stats_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* État global du gestionnaire de tables */
static bool page_table_mgr_initialized = false;
static page_table_stats_t pt_stats;
static page_directory_t *kernel_pgd = NULL;
static page_directory_t *current_pgd = NULL;

/* Cache de tables de pages */
#define PAGE_TABLE_CACHE_SIZE 64
static page_table_t *page_table_cache[PAGE_TABLE_CACHE_SIZE];
static int pt_cache_head = 0;
static int pt_cache_count = 0;

/* Cache de répertoires de pages */
#define PAGE_DIR_CACHE_SIZE 16
static page_directory_t *page_dir_cache[PAGE_DIR_CACHE_SIZE];
static int pd_cache_head = 0;
static int pd_cache_count = 0;

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
static spinlock_t pt_lock = SPINLOCK_INIT;
#define PT_LOCK() spin_lock(&pt_lock)
#define PT_UNLOCK() spin_unlock(&pt_lock)
#else
#define PT_LOCK() do {} while(0)
#define PT_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * LOW-LEVEL PTE/PGD OPERATIONS
 * ======================================================================== */

/**
 * @brief Crée une entrée PTE
 * @param phys_addr Adresse physique
 * @param flags Flags de protection
 * @return Entrée PTE
 */
static inline pte_t make_pte(phys_addr_t phys_addr, uint32_t flags) {
    pte_t pte;
    pte.val = (phys_addr & PTE_ADDR_MASK) | (flags & ~PTE_ADDR_MASK);
    return pte;
}

/**
 * @brief Crée une entrée PGD
 * @param phys_addr Adresse physique de la table
 * @param flags Flags
 * @return Entrée PGD
 */
static inline pgd_t make_pgd(phys_addr_t phys_addr, uint32_t flags) {
    pgd_t pgd;
    pgd.val = (phys_addr & PGD_ADDR_MASK) | (flags & ~PGD_ADDR_MASK);
    return pgd;
}

/**
 * @brief Vérifie si une entrée PTE est présente
 * @param pte Entrée PTE
 * @return true si présente
 */
static inline bool pte_present(pte_t pte) {
    return (pte.val & _PAGE_PRESENT) != 0;
}

/**
 * @brief Vérifie si une entrée PGD est présente
 * @param pgd Entrée PGD
 * @return true si présente
 */
static inline bool pgd_present(pgd_t pgd) {
    return (pgd.val & _PAGE_PRESENT) != 0;
}

/**
 * @brief Extrait l'adresse physique d'une PTE
 * @param pte Entrée PTE
 * @return Adresse physique
 */
static inline phys_addr_t pte_phys(pte_t pte) {
    return pte.val & PTE_ADDR_MASK;
}

/**
 * @brief Extrait l'adresse physique d'une PGD
 * @param pgd Entrée PGD
 * @return Adresse physique
 */
static inline phys_addr_t pgd_phys(pgd_t pgd) {
    return pgd.val & PGD_ADDR_MASK;
}

/**
 * @brief Convertit les flags VM en flags de page
 * @param vm_flags Flags VM
 * @return Flags de page
 */
static uint32_t vm_flags_to_page_flags(uint32_t vm_flags) {
    uint32_t page_flags = _PAGE_PRESENT;
    
    if (vm_flags & VM_WRITE) {
        page_flags |= _PAGE_RW;
    }
    
    if (vm_flags & VM_USER) {
        page_flags |= _PAGE_USER;
    }
    
    if (vm_flags & VM_IO) {
        page_flags |= _PAGE_PCD | _PAGE_PWT;
    }
    
    return page_flags;
}

/* ========================================================================
 * PAGE TABLE CACHE MANAGEMENT
 * ======================================================================== */

/**
 * @brief Alloue une nouvelle table de pages
 * @return Pointeur vers la table ou NULL
 */
static page_table_t *alloc_page_table(void) {
    page_table_t *pt = NULL;
    
    PT_LOCK();
    
    /* Vérifier le cache d'abord */
    if (pt_cache_count > 0) {
        pt = page_table_cache[pt_cache_head];
        pt_cache_head = (pt_cache_head + 1) % PAGE_TABLE_CACHE_SIZE;
        pt_cache_count--;
    }
    
    PT_UNLOCK();
    
    if (!pt) {
        /* Allouer une nouvelle page physique */
        phys_addr_t phys_addr = pmm_alloc_page();
        if (phys_addr == 0) {
            return NULL;
        }
        
        /* Mapper temporairement pour initialiser */
        pt = (page_table_t *)phys_to_virt(phys_addr);
        pt->phys_addr = phys_addr;
        pt->virt_addr = pt;
    }
    
    /* Initialiser la table */
    memset(pt->entries, 0, sizeof(pt->entries));
    pt->ref_count = 1;
    pt->flags = 0;
    pt->next = NULL;
    
    pt_stats.total_page_tables++;
    pt_stats.active_page_tables++;
    pt_stats.memory_used += PAGE_SIZE;
    
    return pt;
}

/**
 * @brief Libère une table de pages
 * @param pt Pointeur vers la table
 */
static void free_page_table(page_table_t *pt) {
    if (!pt) return;
    
    PT_LOCK();
    
    pt->ref_count--;
    if (pt->ref_count > 0) {
        PT_UNLOCK();
        return;
    }
    
    /* Essayer d'ajouter au cache */
    if (pt_cache_count < PAGE_TABLE_CACHE_SIZE) {
        int cache_index = (pt_cache_head + pt_cache_count) % PAGE_TABLE_CACHE_SIZE;
        page_table_cache[cache_index] = pt;
        pt_cache_count++;
        PT_UNLOCK();
        return;
    }
    
    PT_UNLOCK();
    
    /* Libérer la page physique */
    pmm_free_page(pt->phys_addr);
    
    pt_stats.active_page_tables--;
    pt_stats.memory_used -= PAGE_SIZE;
}

/**
 * @brief Alloue un nouveau répertoire de pages
 * @return Pointeur vers le répertoire ou NULL
 */
static page_directory_t *alloc_page_directory(void) {
    page_directory_t *pd = NULL;
    
    PT_LOCK();
    
    /* Vérifier le cache */
    if (pd_cache_count > 0) {
        pd = page_dir_cache[pd_cache_head];
        pd_cache_head = (pd_cache_head + 1) % PAGE_DIR_CACHE_SIZE;
        pd_cache_count--;
    }
    
    PT_UNLOCK();
    
    if (!pd) {
        /* Allouer une nouvelle page */
        phys_addr_t phys_addr = pmm_alloc_page();
        if (phys_addr == 0) {
            return NULL;
        }
        
        pd = (page_directory_t *)phys_to_virt(phys_addr);
        pd->phys_addr = phys_addr;
        pd->virt_addr = pd;
    }
    
    /* Initialiser le répertoire */
    memset(pd->entries, 0, sizeof(pd->entries));
    memset(pd->page_tables, 0, sizeof(pd->page_tables));
    pd->ref_count = 1;
    pd->asid = 0;
    pd->next = NULL;
    
    pt_stats.total_page_dirs++;
    pt_stats.active_page_dirs++;
    pt_stats.memory_used += PAGE_SIZE;
    
    return pd;
}

/**
 * @brief Libère un répertoire de pages
 * @param pd Pointeur vers le répertoire
 */
static void free_page_directory(page_directory_t *pd) {
    if (!pd) return;
    
    PT_LOCK();
    
    pd->ref_count--;
    if (pd->ref_count > 0) {
        PT_UNLOCK();
        return;
    }
    
    /* Libérer toutes les tables de pages */
    for (int i = 0; i < PTRS_PER_PGD; i++) {
        if (pd->page_tables[i]) {
            free_page_table(pd->page_tables[i]);
            pd->page_tables[i] = NULL;
        }
    }
    
    /* Essayer d'ajouter au cache */
    if (pd_cache_count < PAGE_DIR_CACHE_SIZE) {
        int cache_index = (pd_cache_head + pd_cache_count) % PAGE_DIR_CACHE_SIZE;
        page_dir_cache[cache_index] = pd;
        pd_cache_count++;
        PT_UNLOCK();
        return;
    }
    
    PT_UNLOCK();
    
    /* Libérer la page physique */
    pmm_free_page(pd->phys_addr);
    
    pt_stats.active_page_dirs--;
    pt_stats.memory_used -= PAGE_SIZE;
}

/* ========================================================================
 * PAGE MAPPING OPERATIONS
 * ======================================================================== */

/**
 * @brief Obtient ou crée une table de pages dans un répertoire
 * @param pd Répertoire de pages
 * @param virt_addr Adresse virtuelle
 * @param create Créer si n'existe pas
 * @return Pointeur vers la table ou NULL
 */
static page_table_t *get_page_table(page_directory_t *pd, virt_addr_t virt_addr, bool create) {
    if (!pd) return NULL;
    
    unsigned int pgd_idx = pgd_index(virt_addr);
    
    /* Vérifier si la table existe déjà */
    if (pd->page_tables[pgd_idx]) {
        return pd->page_tables[pgd_idx];
    }
    
    /* Vérifier l'entrée PGD */
    if (!pgd_present(pd->entries[pgd_idx])) {
        if (!create) {
            return NULL;
        }
        
        /* Créer nouvelle table */
        page_table_t *new_table = alloc_page_table();
        if (!new_table) {
            return NULL;
        }
        
        /* Configurer l'entrée PGD */
        uint32_t flags = _PAGE_PRESENT | _PAGE_RW | _PAGE_USER;
        pd->entries[pgd_idx] = make_pgd(new_table->phys_addr, flags);
        pd->page_tables[pgd_idx] = new_table;
        
        return new_table;
    } else {
        /* Récupérer la table existante */
        phys_addr_t table_phys = pgd_phys(pd->entries[pgd_idx]);
        page_table_t *table = (page_table_t *)phys_to_virt(table_phys);
        pd->page_tables[pgd_idx] = table;
        return table;
    }
}

/**
 * @brief Mappe une page virtuelle vers une page physique
 * @param pd Répertoire de pages
 * @param virt_addr Adresse virtuelle (alignée sur page)
 * @param phys_addr Adresse physique (alignée sur page)
 * @param flags Flags de protection
 * @return 0 en cas de succès, -1 en cas d'erreur
 */
int map_page_in_directory(page_directory_t *pd, virt_addr_t virt_addr, 
                         phys_addr_t phys_addr, uint32_t flags) {
    if (!pd || (virt_addr & ~PAGE_MASK) || (phys_addr & ~PAGE_MASK)) {
        return -1;
    }
    
    /* Obtenir la table de pages */
    page_table_t *pt = get_page_table(pd, virt_addr, true);
    if (!pt) {
        return -1;
    }
    
    /* Calculer l'index PTE */
    unsigned int pte_idx = pte_index(virt_addr);
    
    /* Vérifier si déjà mappé */
    if (pte_present(pt->entries[pte_idx])) {
        printk(KERN_WARNING "Page already mapped: 0x%lx -> 0x%llx\n", 
               virt_addr, phys_addr);
        return -1;
    }
    
    /* Créer l'entrée PTE */
    pt->entries[pte_idx] = make_pte(phys_addr, flags | _PAGE_PRESENT);
    
    pt_stats.mappings_created++;
    
    printk(KERN_DEBUG "Mapped page: 0x%lx -> 0x%llx (flags=0x%x)\n", 
           virt_addr, phys_addr, flags);
    
    return 0;
}

/**
 * @brief Démonte une page virtuelle
 * @param pd Répertoire de pages
 * @param virt_addr Adresse virtuelle
 * @return Adresse physique de la page démontée, ou 0
 */
phys_addr_t unmap_page_in_directory(page_directory_t *pd, virt_addr_t virt_addr) {
    if (!pd || (virt_addr & ~PAGE_MASK)) {
        return 0;
    }
    
    /* Obtenir la table de pages */
    page_table_t *pt = get_page_table(pd, virt_addr, false);
    if (!pt) {
        return 0;
    }
    
    /* Calculer l'index PTE */
    unsigned int pte_idx = pte_index(virt_addr);
    
    if (!pte_present(pt->entries[pte_idx])) {
        return 0;
    }
    
    /* Extraire l'adresse physique */
    phys_addr_t phys_addr = pte_phys(pt->entries[pte_idx]);
    
    /* Effacer l'entrée */
    pt->entries[pte_idx].val = 0;
    
    pt_stats.mappings_destroyed++;
    
    printk(KERN_DEBUG "Unmapped page: 0x%lx (was -> 0x%llx)\n", virt_addr, phys_addr);
    
    return phys_addr;
}

/**
 * @brief Résout une adresse virtuelle en adresse physique
 * @param pd Répertoire de pages
 * @param virt_addr Adresse virtuelle
 * @return Adresse physique ou 0 si non mappée
 */
phys_addr_t resolve_address(page_directory_t *pd, virt_addr_t virt_addr) {
    if (!pd) return 0;
    
    /* Obtenir la table de pages */
    page_table_t *pt = get_page_table(pd, virt_addr, false);
    if (!pt) {
        return 0;
    }
    
    /* Obtenir l'entrée PTE */
    unsigned int pte_idx = pte_index(virt_addr);
    pte_t pte = pt->entries[pte_idx];
    
    if (!pte_present(pte)) {
        return 0;
    }
    
    /* Calculer l'adresse physique finale */
    phys_addr_t page_base = pte_phys(pte);
    unsigned int offset = virt_addr & ~PAGE_MASK;
    
    return page_base + offset;
}

/* ========================================================================
 * BULK OPERATIONS
 * ======================================================================== */

/**
 * @brief Mappe une région de mémoire contiguë
 * @param pd Répertoire de pages
 * @param virt_start Adresse virtuelle de début
 * @param phys_start Adresse physique de début
 * @param size Taille de la région
 * @param flags Flags de protection
 * @return 0 en cas de succès
 */
int map_region(page_directory_t *pd, virt_addr_t virt_start, phys_addr_t phys_start,
               size_t size, uint32_t flags) {
    if (!pd || size == 0) {
        return -1;
    }
    
    /* Aligner sur les pages */
    virt_addr_t virt_aligned = virt_start & PAGE_MASK;
    phys_addr_t phys_aligned = phys_start & PAGE_MASK;
    size_t aligned_size = PAGE_ALIGN(size + (virt_start - virt_aligned));
    
    size_t page_count = aligned_size / PAGE_SIZE;
    
    printk(KERN_DEBUG "Mapping region: 0x%lx -> 0x%llx (%zu pages)\n",
           virt_aligned, phys_aligned, page_count);
    
    /* Mapper page par page */
    for (size_t i = 0; i < page_count; i++) {
        virt_addr_t virt_addr = virt_aligned + (i * PAGE_SIZE);
        phys_addr_t phys_addr = phys_aligned + (i * PAGE_SIZE);
        
        if (map_page_in_directory(pd, virt_addr, phys_addr, flags) != 0) {
            /* Échec - défaire les mappings précédents */
            for (size_t j = 0; j < i; j++) {
                virt_addr_t unmap_virt = virt_aligned + (j * PAGE_SIZE);
                unmap_page_in_directory(pd, unmap_virt);
            }
            return -1;
        }
    }
    
    return 0;
}

/**
 * @brief Démonte une région de mémoire
 * @param pd Répertoire de pages
 * @param virt_start Adresse virtuelle de début
 * @param size Taille de la région
 * @return Nombre de pages démontées
 */
size_t unmap_region(page_directory_t *pd, virt_addr_t virt_start, size_t size) {
    if (!pd || size == 0) {
        return 0;
    }
    
    /* Aligner sur les pages */
    virt_addr_t virt_aligned = virt_start & PAGE_MASK;
    size_t aligned_size = PAGE_ALIGN(size + (virt_start - virt_aligned));
    size_t page_count = aligned_size / PAGE_SIZE;
    size_t unmapped_count = 0;
    
    printk(KERN_DEBUG "Unmapping region: 0x%lx (%zu pages)\n", virt_aligned, page_count);
    
    /* Démonter page par page */
    for (size_t i = 0; i < page_count; i++) {
        virt_addr_t virt_addr = virt_aligned + (i * PAGE_SIZE);
        
        if (unmap_page_in_directory(pd, virt_addr) != 0) {
            unmapped_count++;
        }
    }
    
    return unmapped_count;
}

/* ========================================================================
 * TLB MANAGEMENT
 * ======================================================================== */

/**
 * @brief Invalide une page dans le TLB
 * @param virt_addr Adresse virtuelle à invalider
 */
void flush_tlb_page(virt_addr_t virt_addr) {
    /* TODO: Architecture-specific implementation */
    /* x86: invlpg instruction */
    pt_stats.tlb_flushes++;
    printk(KERN_DEBUG "TLB flush page: 0x%lx\n", virt_addr);
}

/**
 * @brief Invalide toutes les entrées TLB
 */
void flush_tlb_all(void) {
    /* TODO: Architecture-specific implementation */  
    /* x86: reload CR3 */
    pt_stats.tlb_flushes++;
    printk(KERN_DEBUG "TLB flush all\n");
}

/**
 * @brief Invalide le TLB pour une région
 * @param virt_start Début de la région
 * @param size Taille de la région
 */
void flush_tlb_range(virt_addr_t virt_start, size_t size) {
    virt_addr_t virt_end = virt_start + size;
    
    /* Si la région est petite, invalider page par page */
    if (size <= PAGE_SIZE * 16) {
        for (virt_addr_t addr = virt_start & PAGE_MASK; 
             addr < virt_end; 
             addr += PAGE_SIZE) {
            flush_tlb_page(addr);
        }
    } else {
        /* Région grande - invalider tout le TLB */
        flush_tlb_all();
    }
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise le gestionnaire de tables de pages
 * @return 0 en cas de succès
 */
int page_table_init(void) {
    if (page_table_mgr_initialized) {
        printk(KERN_WARNING "Page table manager already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing page table manager\n");
    
    /* Réinitialiser les statistiques */
    memset(&pt_stats, 0, sizeof(pt_stats));
    
    /* Initialiser les caches */
    memset(page_table_cache, 0, sizeof(page_table_cache));
    memset(page_dir_cache, 0, sizeof(page_dir_cache));
    pt_cache_head = 0;
    pt_cache_count = 0;
    pd_cache_head = 0;
    pd_cache_count = 0;
    
    /* Créer le répertoire de pages du kernel */
    kernel_pgd = alloc_page_directory();
    if (!kernel_pgd) {
        printk(KERN_ERR "Failed to allocate kernel page directory\n");
        return -1;
    }
    
    current_pgd = kernel_pgd;
    
    page_table_mgr_initialized = true;
    
    printk(KERN_INFO "Page table manager initialized\n");
    printk(KERN_INFO "  Architecture: x86 32-bit\n");
    printk(KERN_INFO "  Page size: %d KB\n", PAGE_SIZE / 1024);
    printk(KERN_INFO "  Entries per PGD: %d\n", PTRS_PER_PGD);
    printk(KERN_INFO "  Entries per PTE: %d\n", PTRS_PER_PTE);
    printk(KERN_INFO "  Kernel PGD at: %p (phys: 0x%llx)\n", 
           kernel_pgd, kernel_pgd->phys_addr);
    
    return 0;
}

/**
 * @brief Obtient le répertoire de pages du kernel
 * @return Pointeur vers le PGD kernel
 */
page_directory_t *get_kernel_pgd(void) {
    return kernel_pgd;
}

/**
 * @brief Obtient le répertoire de pages actuel
 * @return Pointeur vers le PGD actuel
 */
page_directory_t *get_current_pgd(void) {
    return current_pgd;
}

/**
 * @brief Change le répertoire de pages actuel
 * @param new_pgd Nouveau répertoire
 * @return 0 en cas de succès
 */
int switch_page_directory(page_directory_t *new_pgd) {
    if (!new_pgd || !page_table_mgr_initialized) {
        return -1;
    }
    
    current_pgd = new_pgd;
    
    /* TODO: Architecture-specific CR3 loading */
    
    flush_tlb_all();
    
    printk(KERN_DEBUG "Switched to page directory %p (phys: 0x%llx)\n",
           new_pgd, new_pgd->phys_addr);
    
    return 0;
}

/* ========================================================================
 * STATISTICS AND DEBUGGING
 * ======================================================================== */

/**
 * @brief Obtient les statistiques des tables de pages
 * @param stats Pointeur vers structure de statistiques
 */
void page_table_get_stats(page_table_stats_t *stats) {
    if (!stats || !page_table_mgr_initialized) {
        return;
    }
    
    PT_LOCK();
    memcpy(stats, &pt_stats, sizeof(page_table_stats_t));
    PT_UNLOCK();
}

/**
 * @brief Affiche les statistiques des tables de pages
 */
void page_table_print_stats(void) {
    if (!page_table_mgr_initialized) {
        printk(KERN_INFO "Page table manager not initialized\n");
        return;
    }
    
    printk(KERN_INFO "Page Table Statistics:\n");
    printk(KERN_INFO "  Total page tables:    %llu\n", pt_stats.total_page_tables);
    printk(KERN_INFO "  Active page tables:   %llu\n", pt_stats.active_page_tables);
    printk(KERN_INFO "  Total page dirs:      %llu\n", pt_stats.total_page_dirs);
    printk(KERN_INFO "  Active page dirs:     %llu\n", pt_stats.active_page_dirs);
    printk(KERN_INFO "  Memory used:          %llu KB\n", pt_stats.memory_used / 1024);
    printk(KERN_INFO "  TLB flushes:          %llu\n", pt_stats.tlb_flushes);
    printk(KERN_INFO "  Page faults handled:  %llu\n", pt_stats.page_faults);
    printk(KERN_INFO "  Mappings created:     %llu\n", pt_stats.mappings_created);
    printk(KERN_INFO "  Mappings destroyed:   %llu\n", pt_stats.mappings_destroyed);
    printk(KERN_INFO "  Large pages used:     %llu\n", pt_stats.large_pages_used);
    printk(KERN_INFO "  Cache status:\n");
    printk(KERN_INFO "    Page table cache:   %d/%d\n", pt_cache_count, PAGE_TABLE_CACHE_SIZE);
    printk(KERN_INFO "    Page dir cache:     %d/%d\n", pd_cache_count, PAGE_DIR_CACHE_SIZE);
}

/**
 * @brief Vérifie l'intégrité des tables de pages
 * @param pd Répertoire à vérifier (NULL pour le courant)
 * @return true si intègre
 */
bool page_table_check_integrity(page_directory_t *pd) {
    if (!page_table_mgr_initialized) {
        return false;
    }
    
    if (!pd) {
        pd = current_pgd;
    }
    
    if (!pd) {
        return false;
    }
    
    bool integrity_ok = true;
    
    /* Vérifier la cohérence du répertoire */
    for (int i = 0; i < PTRS_PER_PGD; i++) {
        if (pgd_present(pd->entries[i])) {
            /* Vérifier que la table correspondante existe */
            if (!pd->page_tables[i]) {
                printk(KERN_ERR "PGD entry %d present but no page table pointer\n", i);
                integrity_ok = false;
                continue;
            }
            
            /* Vérifier l'adresse physique */
            phys_addr_t expected_phys = pd->page_tables[i]->phys_addr;
            phys_addr_t actual_phys = pgd_phys(pd->entries[i]);
            
            if (expected_phys != actual_phys) {
                printk(KERN_ERR "PGD entry %d: phys mismatch (expected 0x%llx, got 0x%llx)\n",
                       i, expected_phys, actual_phys);
                integrity_ok = false;
            }
        } else {
            /* Vérifier qu'il n'y a pas de table fantôme */
            if (pd->page_tables[i]) {
                printk(KERN_ERR "PGD entry %d not present but page table pointer exists\n", i);
                integrity_ok = false;
            }
        }
    }
    
    return integrity_ok;
}

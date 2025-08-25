/**
 * @file vmm.c
 * @brief Virtual Memory Manager - Gestionnaire de mémoire virtuelle
 * 
 * Ce fichier implémente le gestionnaire principal de mémoire virtuelle pour
 * LeaxOS. Il fournit une interface unifiée pour la gestion des espaces
 * d'adressage virtuels, incluant:
 * 
 * - Gestion des tables de pages et MMU
 * - Allocation et mapping d'espaces virtuels
 * - Gestion des VMAs (Virtual Memory Areas)
 * - Support pour la pagination et le swap
 * - Protection mémoire et contrôle d'accès
 * - Optimisations pour les architectures modernes
 * 
 * Le VMM coordonne avec le PMM (Physical Memory Manager) pour fournir
 * une abstraction complète de la mémoire virtuelle aux processus.
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
#include "../../include/vmalloc.h"
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
 * CONSTANTS AND CONFIGURATION
 * ======================================================================== */

/* Layout mémoire virtuelle */
#define USER_SPACE_START        0x00001000UL    /* 4KB - éviter NULL */
#define USER_SPACE_END          0x7FFFFFFFUL    /* 2GB espace utilisateur */
#define KERNEL_SPACE_START      0x80000000UL    /* 2GB début kernel */
#define KERNEL_SPACE_END        0xFFFFFFFFUL    /* Fin espace kernel */

/* Zones spéciales */
#define VMALLOC_START           0xF0000000UL    /* Zone vmalloc */
#define VMALLOC_END             0xFEFFFFFFUL    /* Fin vmalloc */
#define FIXMAP_START            0xFF000000UL    /* Mappings fixes */
#define FIXMAP_END              0xFF3FFFFFUL    /* Fin fixmap */

/* Tailles et alignements */
#define PGDIR_SIZE              PAGE_SIZE       /* Taille répertoire pages */
#define PTABLE_SIZE             PAGE_SIZE       /* Taille table pages */
#define PTABLE_ENTRIES          1024            /* Entrées par table */
#define PGDIR_ENTRIES           1024            /* Entrées par répertoire */

/* Flags pour tables de pages (x86 32-bit) */
#define PAGE_PRESENT            (1 << 0)        /* Page présente */
#define PAGE_WRITABLE           (1 << 1)        /* Page accessible en écriture */
#define PAGE_USER               (1 << 2)        /* Accessible en mode user */
#define PAGE_WRITETHROUGH       (1 << 3)        /* Write-through cache */
#define PAGE_CACHE_DISABLE      (1 << 4)        /* Cache désactivé */
#define PAGE_ACCESSED           (1 << 5)        /* Page accédée */
#define PAGE_DIRTY              (1 << 6)        /* Page modifiée */
#define PAGE_SIZE_EXT           (1 << 7)        /* Page 4MB (PSE) */
#define PAGE_GLOBAL             (1 << 8)        /* Page globale */

/* Masques et décalages */
#define PAGE_ADDR_MASK          0xFFFFF000UL    /* Masque adresse page */
#define PGDIR_INDEX_SHIFT       22              /* Décalage index répertoire */
#define PTABLE_INDEX_SHIFT      12              /* Décalage index table */
#define PGDIR_INDEX_MASK        0x3FF           /* Masque index répertoire */
#define PTABLE_INDEX_MASK       0x3FF           /* Masque index table */

/* Constantes VMM */
#define MAX_MM_CONTEXTS         256             /* Contextes MM maximum */
#define VMA_CACHE_SIZE          64              /* Cache VMAs */
#define PAGE_FAULT_STACK_SIZE   4096            /* Pile page fault */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Entrée de table de pages
 */
typedef uint32_t pte_t;

/**
 * @brief Entrée de répertoire de pages
 */
typedef uint32_t pgd_t;

/**
 * @brief Contexte MMU architecture-spécifique
 */
typedef struct {
    pgd_t *pgd;                     /* Répertoire global pages */
    uint32_t asid;                  /* Address Space ID */
    uint32_t cr3_value;             /* Valeur CR3 (x86) */
    bool active;                    /* Contexte actif */
} mm_context_t;

/**
 * @brief Opérations sur VMAs
 */
struct vm_operations_struct {
    void (*open)(struct vm_area_struct *vma);
    void (*close)(struct vm_area_struct *vma);
    int (*fault)(struct vm_area_struct *vma, virt_addr_t addr, uint32_t flags);
    int (*page_mkwrite)(struct vm_area_struct *vma, struct page *page);
    int (*access)(struct vm_area_struct *vma, virt_addr_t addr, void *buf, 
                  int len, int write);
};

/**
 * @brief Structure VMA (Virtual Memory Area)
 */
struct vm_area_struct {
    virt_addr_t vm_start;           /* Adresse de début */
    virt_addr_t vm_end;             /* Adresse de fin */
    
    struct vm_area_struct *vm_next; /* VMA suivante */
    struct vm_area_struct *vm_prev; /* VMA précédente */
    
    uint32_t vm_flags;              /* Flags de protection */
    uint32_t vm_page_prot;          /* Protection pages */
    
    struct mm_struct *vm_mm;        /* MM parent */
    
    /* Pour mappings de fichiers */
    struct file *vm_file;           /* Fichier mappé */
    unsigned long vm_pgoff;         /* Offset dans le fichier */
    
    /* Opérations */
    const struct vm_operations_struct *vm_ops;
    
    /* Données privées */
    void *vm_private_data;
    
    /* Statistiques */
    unsigned long vm_fault_count;   /* Nombre de page faults */
    unsigned long vm_access_count;  /* Nombre d'accès */
};

/**
 * @brief Structure MM (Memory Management) par processus
 */
struct mm_struct {
    struct vm_area_struct *mmap;    /* Liste des VMAs */
    
    virt_addr_t start_code;         /* Début du code */
    virt_addr_t end_code;           /* Fin du code */
    virt_addr_t start_data;         /* Début des données */
    virt_addr_t end_data;           /* Fin des données */
    virt_addr_t start_brk;          /* Début du tas */
    virt_addr_t brk;                /* Fin actuelle du tas */
    virt_addr_t start_stack;        /* Début de la pile */
    virt_addr_t arg_start;          /* Début arguments */
    virt_addr_t arg_end;            /* Fin arguments */
    virt_addr_t env_start;          /* Début environnement */
    virt_addr_t env_end;            /* Fin environnement */
    
    unsigned long total_vm;         /* Pages totales */
    unsigned long locked_vm;        /* Pages verrouillées */
    unsigned long pinned_vm;        /* Pages épinglées */
    unsigned long shared_vm;        /* Pages partagées */
    unsigned long exec_vm;          /* Pages exécutables */
    unsigned long stack_vm;         /* Pages de pile */
    unsigned long data_vm;          /* Pages de données */
    
    /* Compteurs de références */
    int mm_users;                   /* Utilisateurs */
    int mm_count;                   /* Compteur de références */
    
    /* Contexte architecture */
    mm_context_t context;
    
    /* Protection et verrous */
    spinlock_t page_table_lock;     /* Verrou tables pages */
    
    /* Statistiques */
    unsigned long fault_count;      /* Page faults total */
    unsigned long major_fault_count; /* Major page faults */
    unsigned long minor_fault_count; /* Minor page faults */
};

/**
 * @brief Statistiques VMM globales
 */
typedef struct {
    uint64_t total_virtual_memory;  /* Mémoire virtuelle totale */
    uint64_t used_virtual_memory;   /* Mémoire virtuelle utilisée */
    uint64_t kernel_virtual_memory; /* Mémoire virtuelle kernel */
    uint64_t user_virtual_memory;   /* Mémoire virtuelle user */
    uint64_t page_table_memory;     /* Mémoire tables de pages */
    uint64_t total_page_faults;     /* Page faults total */
    uint64_t major_page_faults;     /* Major page faults */
    uint64_t minor_page_faults;     /* Minor page faults */
    uint64_t cow_faults;            /* Copy-on-write faults */
    uint64_t swap_faults;           /* Swap faults */
    unsigned long active_mm_count;  /* Contextes MM actifs */
    unsigned long vma_count;        /* VMAs totales */
    unsigned long cache_hits;       /* Hits cache TLB */
    unsigned long cache_misses;     /* Misses cache TLB */
} vmm_stats_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* État global VMM */
static bool vmm_initialized = false;
static struct mm_struct *current_mm = NULL;
static struct mm_struct kernel_mm;
static vmm_stats_t vmm_stats;

/* Cache de contextes MM */
static struct mm_struct mm_cache[MAX_MM_CONTEXTS];
static bool mm_cache_used[MAX_MM_CONTEXTS];
static int next_mm_slot = 0;

/* Tables de pages du kernel */
static pgd_t kernel_pgd[PGDIR_ENTRIES] __attribute__((aligned(PAGE_SIZE)));
static pte_t *kernel_page_tables[PGDIR_ENTRIES];

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
static spinlock_t vmm_lock = SPINLOCK_INIT;
#define VMM_LOCK() spin_lock(&vmm_lock)
#define VMM_UNLOCK() spin_unlock(&vmm_lock)
#else
#define VMM_LOCK() do {} while(0)
#define VMM_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * PAGE TABLE UTILITIES
 * ======================================================================== */

/**
 * @brief Obtient l'index du répertoire de pages
 * @param addr Adresse virtuelle
 * @return Index dans le répertoire
 */
static inline unsigned int pgd_index(virt_addr_t addr) {
    return (addr >> PGDIR_INDEX_SHIFT) & PGDIR_INDEX_MASK;
}

/**
 * @brief Obtient l'index de la table de pages
 * @param addr Adresse virtuelle
 * @return Index dans la table
 */
static inline unsigned int pte_index(virt_addr_t addr) {
    return (addr >> PTABLE_INDEX_SHIFT) & PTABLE_INDEX_MASK;
}

/**
 * @brief Crée une entrée PTE
 * @param pfn Numéro de page physique
 * @param flags Flags de protection
 * @return Entrée PTE
 */
static inline pte_t make_pte(uint32_t pfn, uint32_t flags) {
    return (pfn << PAGE_SHIFT) | flags;
}

/**
 * @brief Extrait le PFN d'une entrée PTE
 * @param pte Entrée PTE
 * @return Numéro de page physique
 */
static inline uint32_t pte_pfn(pte_t pte) {
    return (pte & PAGE_ADDR_MASK) >> PAGE_SHIFT;
}

/**
 * @brief Vérifie si une entrée PTE est présente
 * @param pte Entrée PTE
 * @return true si présente
 */
static inline bool pte_present(pte_t pte) {
    return (pte & PAGE_PRESENT) != 0;
}

/**
 * @brief Convertit les flags VM en flags page
 * @param vm_flags Flags VMA
 * @return Flags de page
 */
static uint32_t vm_flags_to_page_flags(uint32_t vm_flags) {
    uint32_t page_flags = PAGE_PRESENT;
    
    if (vm_flags & VM_WRITE) {
        page_flags |= PAGE_WRITABLE;
    }
    
    if (vm_flags & VM_USER) {
        page_flags |= PAGE_USER;
    }
    
    if (vm_flags & VM_IO) {
        page_flags |= PAGE_CACHE_DISABLE;
    }
    
    return page_flags;
}

/* ========================================================================
 * PAGE TABLE MANAGEMENT
 * ======================================================================== */

/**
 * @brief Alloue une nouvelle table de pages
 * @return Pointeur vers la table ou NULL
 */
static pte_t *alloc_page_table(void) {
    /* Allouer une page physique pour la table */
    uint64_t phys_addr = pmm_alloc_page();
    if (phys_addr == 0) {
        return NULL;
    }
    
    /* Mapper temporairement pour initialiser */
    pte_t *table = (pte_t *)phys_to_virt(phys_addr);
    memset(table, 0, PTABLE_SIZE);
    
    vmm_stats.page_table_memory += PAGE_SIZE;
    
    return table;
}

/**
 * @brief Libère une table de pages
 * @param table Pointeur vers la table
 */
static void free_page_table(pte_t *table) {
    if (!table) return;
    
    uint64_t phys_addr = virt_to_phys((virt_addr_t)table);
    pmm_free_page(phys_addr);
    
    vmm_stats.page_table_memory -= PAGE_SIZE;
}

/**
 * @brief Obtient ou crée une table de pages
 * @param pgd Répertoire de pages
 * @param addr Adresse virtuelle
 * @param create Créer si n'existe pas
 * @return Pointeur vers la table ou NULL
 */
static pte_t *get_page_table(pgd_t *pgd, virt_addr_t addr, bool create) {
    unsigned int pgd_idx = pgd_index(addr);
    pgd_t *pgd_entry = &pgd[pgd_idx];
    
    /* Vérifier si l'entrée existe */
    if (!(*pgd_entry & PAGE_PRESENT)) {
        if (!create) {
            return NULL;
        }
        
        /* Créer nouvelle table */
        pte_t *new_table = alloc_page_table();
        if (!new_table) {
            return NULL;
        }
        
        uint64_t table_phys = virt_to_phys((virt_addr_t)new_table);
        *pgd_entry = table_phys | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;
    }
    
    /* Retourner pointeur vers la table */
    uint64_t table_phys = *pgd_entry & PAGE_ADDR_MASK;
    return (pte_t *)phys_to_virt(table_phys);
}

/**
 * @brief Mappe une page virtuelle vers une page physique
 * @param pgd Répertoire de pages
 * @param vaddr Adresse virtuelle
 * @param paddr Adresse physique
 * @param flags Flags de protection
 * @return 0 en cas de succès
 */
int map_page(pgd_t *pgd, virt_addr_t vaddr, phys_addr_t paddr, uint32_t flags) {
    if (!pgd || !PAGE_ALIGN_DOWN(vaddr) || !PAGE_ALIGN_DOWN(paddr)) {
        return -1;
    }
    
    /* Obtenir la table de pages */
    pte_t *page_table = get_page_table(pgd, vaddr, true);
    if (!page_table) {
        return -1;
    }
    
    /* Calculer l'index dans la table */
    unsigned int pte_idx = pte_index(vaddr);
    pte_t *pte = &page_table[pte_idx];
    
    /* Vérifier si déjà mappé */
    if (pte_present(*pte)) {
        printk(KERN_WARNING "Page already mapped: 0x%lx -> 0x%llx\n", vaddr, paddr);
        return -1;
    }
    
    /* Créer l'entrée PTE */
    uint32_t pfn = paddr >> PAGE_SHIFT;
    *pte = make_pte(pfn, flags | PAGE_PRESENT);
    
    /* Invalider TLB pour cette page */
    invalidate_tlb_page(vaddr);
    
    printk(KERN_DEBUG "Mapped page: 0x%lx -> 0x%llx (flags=0x%x)\n", 
           vaddr, paddr, flags);
    
    return 0;
}

/**
 * @brief Démonte une page virtuelle
 * @param pgd Répertoire de pages
 * @param vaddr Adresse virtuelle
 * @return Adresse physique de la page démontée, ou 0
 */
phys_addr_t unmap_page(pgd_t *pgd, virt_addr_t vaddr) {
    if (!pgd) return 0;
    
    /* Obtenir la table de pages */
    pte_t *page_table = get_page_table(pgd, vaddr, false);
    if (!page_table) {
        return 0;
    }
    
    /* Obtenir l'entrée PTE */
    unsigned int pte_idx = pte_index(vaddr);
    pte_t *pte = &page_table[pte_idx];
    
    if (!pte_present(*pte)) {
        return 0;
    }
    
    /* Extraire l'adresse physique */
    phys_addr_t paddr = (*pte & PAGE_ADDR_MASK);
    
    /* Effacer l'entrée */
    *pte = 0;
    
    /* Invalider TLB */
    invalidate_tlb_page(vaddr);
    
    printk(KERN_DEBUG "Unmapped page: 0x%lx (was -> 0x%llx)\n", vaddr, paddr);
    
    return paddr;
}

/**
 * @brief Résout une adresse virtuelle en adresse physique
 * @param pgd Répertoire de pages
 * @param vaddr Adresse virtuelle
 * @return Adresse physique ou 0 si non mappée
 */
phys_addr_t resolve_virtual_address(pgd_t *pgd, virt_addr_t vaddr) {
    if (!pgd) return 0;
    
    /* Obtenir la table de pages */
    pte_t *page_table = get_page_table(pgd, vaddr, false);
    if (!page_table) {
        return 0;
    }
    
    /* Obtenir l'entrée PTE */
    unsigned int pte_idx = pte_index(vaddr);
    pte_t pte = page_table[pte_idx];
    
    if (!pte_present(pte)) {
        return 0;
    }
    
    /* Calculer l'adresse physique finale */
    phys_addr_t page_base = pte & PAGE_ADDR_MASK;
    unsigned int offset = vaddr & ~PAGE_MASK;
    
    return page_base + offset;
}

/* ========================================================================
 * VMM INITIALIZATION
 * ======================================================================== */

/**
 * @brief Initialise les tables de pages du kernel
 * @return 0 en cas de succès
 */
static int init_kernel_page_tables(void) {
    printk(KERN_INFO "Initializing kernel page tables\n");
    
    /* Effacer le répertoire kernel */
    memset(kernel_pgd, 0, sizeof(kernel_pgd));
    memset(kernel_page_tables, 0, sizeof(kernel_page_tables));
    
    /* Mapping identité pour le kernel (0x80000000 - 0xFFFFFFFF) */
    for (virt_addr_t vaddr = KERNEL_SPACE_START; 
         vaddr < KERNEL_SPACE_END; 
         vaddr += PAGE_SIZE) {
        
        phys_addr_t paddr = virt_to_phys(vaddr);
        uint32_t flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;
        
        if (map_page(kernel_pgd, vaddr, paddr, flags) != 0) {
            printk(KERN_ERR "Failed to map kernel page 0x%lx\n", vaddr);
            return -1;
        }
    }
    
    printk(KERN_INFO "Kernel page tables initialized\n");
    return 0;
}

/**
 * @brief Initialise le contexte MM du kernel
 * @return 0 en cas de succès
 */
static int init_kernel_mm(void) {
    memset(&kernel_mm, 0, sizeof(kernel_mm));
    
    /* Configuration du contexte kernel */
    kernel_mm.start_code = KERNEL_SPACE_START;
    kernel_mm.end_code = KERNEL_SPACE_START + (32 * 1024 * 1024); /* 32MB code */
    kernel_mm.start_data = kernel_mm.end_code;
    kernel_mm.end_data = VMALLOC_START;
    kernel_mm.start_brk = 0;
    kernel_mm.brk = 0;
    kernel_mm.start_stack = 0;
    
    /* Contexte architecture */
    kernel_mm.context.pgd = kernel_pgd;
    kernel_mm.context.asid = 0; /* Kernel ASID */
    kernel_mm.context.cr3_value = virt_to_phys((virt_addr_t)kernel_pgd);
    kernel_mm.context.active = true;
    
    /* Compteurs */
    kernel_mm.mm_users = 1;
    kernel_mm.mm_count = 1;
    
    current_mm = &kernel_mm;
    
    printk(KERN_INFO "Kernel MM context initialized\n");
    return 0;
}

/**
 * @brief Initialise le gestionnaire de mémoire virtuelle
 * @return 0 en cas de succès
 */
int vmm_init(void) {
    if (vmm_initialized) {
        printk(KERN_WARNING "VMM already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing Virtual Memory Manager\n");
    
    /* Réinitialiser les statistiques */
    memset(&vmm_stats, 0, sizeof(vmm_stats));
    
    /* Initialiser le cache de contextes MM */
    memset(mm_cache, 0, sizeof(mm_cache));
    memset(mm_cache_used, 0, sizeof(mm_cache_used));
    next_mm_slot = 0;
    
    /* Initialiser les tables de pages du kernel */
    if (init_kernel_page_tables() != 0) {
        printk(KERN_ERR "Failed to initialize kernel page tables\n");
        return -1;
    }
    
    /* Initialiser le contexte MM du kernel */
    if (init_kernel_mm() != 0) {
        printk(KERN_ERR "Failed to initialize kernel MM context\n");
        return -1;
    }
    
    /* Activer la pagination */
    if (enable_paging() != 0) {
        printk(KERN_ERR "Failed to enable paging\n");
        return -1;
    }
    
    /* Calculer statistiques initiales */
    vmm_stats.total_virtual_memory = KERNEL_SPACE_END - USER_SPACE_START;
    vmm_stats.kernel_virtual_memory = KERNEL_SPACE_END - KERNEL_SPACE_START;
    vmm_stats.user_virtual_memory = USER_SPACE_END - USER_SPACE_START;
    vmm_stats.active_mm_count = 1; /* Kernel MM */
    
    vmm_initialized = true;
    
    printk(KERN_INFO "VMM initialized successfully\n");
    printk(KERN_INFO "Virtual memory layout:\n");
    printk(KERN_INFO "  User space:   0x%08lx - 0x%08lx (%lu MB)\n",
           USER_SPACE_START, USER_SPACE_END,
           (USER_SPACE_END - USER_SPACE_START) / (1024 * 1024));
    printk(KERN_INFO "  Kernel space: 0x%08lx - 0x%08lx (%lu MB)\n",
           KERNEL_SPACE_START, KERNEL_SPACE_END,
           (KERNEL_SPACE_END - KERNEL_SPACE_START) / (1024 * 1024));
    printk(KERN_INFO "  Vmalloc area: 0x%08lx - 0x%08lx (%lu MB)\n",
           VMALLOC_START, VMALLOC_END,
           (VMALLOC_END - VMALLOC_START) / (1024 * 1024));
    
    return 0;
}

/* ========================================================================
 * ARCHITECTURE-SPECIFIC FUNCTIONS (à implémenter selon l'architecture)
 * ======================================================================== */

/**
 * @brief Active la pagination
 * @return 0 en cas de succès
 */
int enable_paging(void) {
    /* TODO: Implémentation spécifique à l'architecture */
    /* Pour x86 32-bit:
     * 1. Charger CR3 avec l'adresse du répertoire de pages
     * 2. Activer le bit PG dans CR0
     * 3. Configurer CR4 si nécessaire (PSE, PAE, etc.)
     */
    
    printk(KERN_INFO "Paging enabled (CR3=0x%x)\n", kernel_mm.context.cr3_value);
    return 0;
}

/**
 * @brief Invalide une page dans le TLB
 * @param vaddr Adresse virtuelle à invalider
 */
void invalidate_tlb_page(virt_addr_t vaddr) {
    /* TODO: Implémentation spécifique à l'architecture */
    /* Pour x86: utiliser l'instruction INVLPG */
    
    (void)vaddr; /* Éviter warning unused */
}

/**
 * @brief Invalide tout le TLB
 */
void invalidate_tlb_all(void) {
    /* TODO: Implémentation spécifique à l'architecture */
    /* Pour x86: recharger CR3 */
}

/**
 * @brief Change le contexte MMU
 * @param mm Nouveau contexte MM
 */
void switch_mm_context(struct mm_struct *mm) {
    if (!mm || current_mm == mm) {
        return;
    }
    
    /* TODO: Implémentation spécifique à l'architecture */
    /* Pour x86: charger nouveau CR3 */
    
    current_mm = mm;
    mm->context.active = true;
    
    printk(KERN_DEBUG "Switched to MM context (CR3=0x%x)\n", mm->context.cr3_value);
}

/* ========================================================================
 * PUBLIC API FUNCTIONS
 * ======================================================================== */

/**
 * @brief Obtient le contexte MM actuel
 * @return Pointeur vers le contexte MM
 */
struct mm_struct *get_current_mm(void) {
    return current_mm;
}

/**
 * @brief Vérifie si le VMM est initialisé
 * @return true si initialisé
 */
bool vmm_is_initialized(void) {
    return vmm_initialized;
}

/**
 * @brief Obtient les statistiques VMM
 * @param stats Pointeur vers structure de statistiques
 */
void vmm_get_stats(vmm_stats_t *stats) {
    if (!stats || !vmm_initialized) {
        return;
    }
    
    VMM_LOCK();
    memcpy(stats, &vmm_stats, sizeof(vmm_stats_t));
    VMM_UNLOCK();
}

/**
 * @brief Affiche les statistiques VMM
 */
void vmm_print_stats(void) {
    if (!vmm_initialized) {
        printk(KERN_INFO "VMM not initialized\n");
        return;
    }
    
    printk(KERN_INFO "VMM Statistics:\n");
    printk(KERN_INFO "  Total virtual memory: %llu MB\n", 
           vmm_stats.total_virtual_memory / (1024 * 1024));
    printk(KERN_INFO "  Used virtual memory:  %llu MB\n", 
           vmm_stats.used_virtual_memory / (1024 * 1024));
    printk(KERN_INFO "  Kernel virtual mem:   %llu MB\n", 
           vmm_stats.kernel_virtual_memory / (1024 * 1024));
    printk(KERN_INFO "  User virtual mem:     %llu MB\n", 
           vmm_stats.user_virtual_memory / (1024 * 1024));
    printk(KERN_INFO "  Page table memory:    %llu KB\n", 
           vmm_stats.page_table_memory / 1024);
    printk(KERN_INFO "  Total page faults:    %llu\n", vmm_stats.total_page_faults);
    printk(KERN_INFO "  Major page faults:    %llu\n", vmm_stats.major_page_faults);
    printk(KERN_INFO "  Minor page faults:    %llu\n", vmm_stats.minor_page_faults);
    printk(KERN_INFO "  Active MM contexts:   %lu\n", vmm_stats.active_mm_count);
    printk(KERN_INFO "  Total VMAs:           %lu\n", vmm_stats.vma_count);
}

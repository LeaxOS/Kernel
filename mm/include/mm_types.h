/**
 * @file mm_types.h
 * @brief Memory management types and structures
 * 
 * @author LeaxOS Team
 * @version 1.0
 */

#ifndef MM_TYPES_H
#define MM_TYPES_H

#include "stdint.h"
#include "stddef.h"
#include "stdbool.h"
#include "mm_common.h"

/* ========================================================================
 * BASIC DATA STRUCTURES
 * ======================================================================== */

/* Double linked list */
struct list_head {
    struct list_head *next, *prev;
};

/* Red-black tree node */
struct rb_node {
    unsigned long rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
};

/* Red-black tree root */
struct rb_root {
    struct rb_node *rb_node;
};

/* Atomic counter */
typedef struct {
    volatile int counter;
} atomic_t;

/* GFP (Get Free Pages) flags type */
typedef unsigned int gfp_flags_t;

/* GFP flag constants */
#define GFP_KERNEL          0x00
#define GFP_ATOMIC          0x01
#define GFP_USER            0x02
#define GFP_HIGHUSER        0x04
#define GFP_DMA             0x08
#define GFP_DMA32           0x10
#define GFP_ZERO            0x20
#define GFP_COLD            0x40
#define GFP_REPEAT          0x80
#define GFP_NOFAIL          0x100
#define GFP_NORETRY         0x200

/* Kernel logging levels */
#define KERN_EMERG    "<0>"
#define KERN_ALERT    "<1>"
#define KERN_CRIT     "<2>"
#define KERN_ERR      "<3>"
#define KERN_WARNING  "<4>"
#define KERN_NOTICE   "<5>"
#define KERN_INFO     "<6>"
#define KERN_DEBUG    "<7>"
#define KERN_CONT     "<c>"

/* KMalloc size constants */
#define KMALLOC_HUGE_THRESHOLD  (4 * 1024 * 1024)  /* 4MB */

/* Page type */
typedef struct page {
    unsigned long flags;
    atomic_t ref_count;
    void *virtual_addr;
    struct list_head lru;
} page_t;

/* ========================================================================
 * FORWARD DECLARATIONS
 * ======================================================================== */

/* Forward declarations for complex types */
typedef struct pgd pgd_t;
typedef struct mm_context mm_context_t;

/* ========================================================================
 * BASIC TYPES AND CONSTANTS
 * ======================================================================== */

/* Note: PAGE_SIZE and related constants are defined in mm_common.h */

#define LARGE_PAGE_SIZE (2 * 1024 * 1024)  /* 2MB large page */
#define HUGE_PAGE_SIZE  (1024 * 1024 * 1024) /* 1GB huge page */

/* Macros d'alignement */
#define PAGE_ALIGN(addr)        (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define PAGE_ALIGN_DOWN(addr)   ((addr) & PAGE_MASK)
#define IS_PAGE_ALIGNED(addr)   (((addr) & ~PAGE_MASK) == 0)

/* Types d'adresses */
typedef uint64_t phys_addr_t;   /* Adresse physique */
typedef uint64_t virt_addr_t;   /* Adresse virtuelle */
typedef uint64_t dma_addr_t;    /* Adresse DMA */

/* Identifiants et index */
typedef uint32_t page_idx_t;    /* Index de page */
typedef uint32_t zone_id_t;     /* Identifiant de zone */
typedef uint32_t numa_node_t;   /* Nœud NUMA */

/* ========================================================================
 * MEMORY ZONES
 * ======================================================================== */

/**
 * @brief Types de zones mémoire
 */
typedef enum {
    MM_ZONE_DMA = 0,        /* Zone DMA (< 16MB) */
    MM_ZONE_NORMAL,         /* Zone normale (16MB - 896MB) */
    MM_ZONE_HIGHMEM,        /* Zone haute (> 896MB) */
    MM_ZONE_MOVABLE,        /* Zone mobile (pages déplaçables) */
    MM_ZONE_DEVICE,         /* Zone device (mémoire spéciale) */
    MM_ZONE_COUNT
} mm_zone_type_t;

/**
 * @brief Informations sur une zone mémoire
 */
typedef struct {
    mm_zone_type_t type;        /* Type de zone */
    phys_addr_t start_pfn;      /* Première page de la zone */
    phys_addr_t end_pfn;        /* Dernière page + 1 */
    size_t total_pages;         /* Nombre total de pages */
    size_t free_pages;          /* Pages libres */
    size_t min_free_pages;      /* Minimum de pages libres */
    size_t low_watermark;       /* Seuil bas */
    size_t high_watermark;      /* Seuil haut */
    bool initialized;           /* Zone initialisée */
} mm_zone_info_t;

/* ========================================================================
 * PAGE STRUCTURES
 * ======================================================================== */

/**
 * @brief Flags pour les pages
 */
typedef enum {
    PAGE_FLAG_LOCKED        = (1 << 0),   /* Page verrouillée */
    PAGE_FLAG_ERROR         = (1 << 1),   /* Erreur sur la page */
    PAGE_FLAG_REFERENCED    = (1 << 2),   /* Page référencée */
    PAGE_FLAG_UPTODATE      = (1 << 3),   /* Page à jour */
    PAGE_FLAG_DIRTY         = (1 << 4),   /* Page modifiée */
    PAGE_FLAG_LRU           = (1 << 5),   /* Page dans LRU */
    PAGE_FLAG_ACTIVE        = (1 << 6),   /* Page active */
    PAGE_FLAG_SLAB          = (1 << 7),   /* Page slab */
    PAGE_FLAG_OWNER_PRIV_1  = (1 << 8),   /* Privé propriétaire */
    PAGE_FLAG_ARCH_1        = (1 << 9),   /* Spécifique architecture */
    PAGE_FLAG_RESERVED      = (1 << 10),  /* Page réservée */
    PAGE_FLAG_COMPOUND      = (1 << 11),  /* Page composée */
    PAGE_FLAG_SWAPCACHE     = (1 << 12),  /* Page dans swap cache */
    PAGE_FLAG_MAPPEDTODISK  = (1 << 13),  /* Page mappée sur disque */
    PAGE_FLAG_RECLAIM       = (1 << 14),  /* Page à récupérer */
    PAGE_FLAG_BUDDY         = (1 << 15)   /* Page dans buddy system */
} page_flags_t;

/**
 * @brief Structure de page physique
 */
typedef struct page {
    uint32_t flags;                 /* Flags de la page */
    atomic_t ref_count;             /* Compteur de références */
    atomic_t map_count;             /* Compteur de mappings */
    
    union {
        /* Pour pages normales */
        struct {
            struct list_head lru;   /* Liste LRU */
            void *mapping;          /* Mapping de la page */
            unsigned long index;    /* Index dans le mapping */
        };
        
        /* Pour pages slab */
        struct {
            struct kmem_cache *slab_cache;  /* Cache slab */
            void *freelist;                 /* Liste des objets libres */
            unsigned int active;            /* Objets actifs */
        };
        
        /* Pour pages buddy */
        struct {
            unsigned int order;     /* Ordre buddy */
            struct list_head buddy_list; /* Liste buddy */
        };
        
        /* Pour pages composées */
        struct {
            struct page *first_page;    /* Première page */
            unsigned char compound_order;
        };
    };
    
    /* Métadonnées */
    zone_id_t zone_id;              /* Zone de la page */
    numa_node_t nid;                /* Nœud NUMA */
    void *virt_addr;                /* Adresse virtuelle */
} page_t;

/* ========================================================================
 * MEMORY ALLOCATION FLAGS
 * ======================================================================== */

/**
 * @brief Flags d'allocation (style GFP)
 */
/* Note: GFP flags are now defined in mm_common.h to avoid conflicts */

/* ========================================================================
 * VIRTUAL MEMORY STRUCTURES
 * ======================================================================== */

/**
 * @brief Types de VMA (Virtual Memory Area)
 */
typedef enum {
    VMA_TYPE_ANONYMOUS = 0,     /* Mémoire anonyme */
    VMA_TYPE_FILE,              /* Fichier mappé */
    VMA_TYPE_SHARED,            /* Mémoire partagée */
    VMA_TYPE_STACK,             /* Pile */
    VMA_TYPE_HEAP,              /* Tas */
    VMA_TYPE_VDSO,              /* VDSO */
    VMA_TYPE_VSYSCALL,          /* Vsyscall */
    VMA_TYPE_DEVICE,            /* Device mapping */
    VMA_TYPE_COUNT
} vma_type_t;

/**
 * @brief Flags de protection mémoire
 */
typedef enum {
    VM_READ         = (1 << 0),     /* Lecture autorisée */
    VM_WRITE        = (1 << 1),     /* Écriture autorisée */
    VM_EXEC         = (1 << 2),     /* Exécution autorisée */
    VM_SHARED       = (1 << 3),     /* Mapping partagé */
    VM_MAYREAD      = (1 << 4),     /* Peut être lisible */
    VM_MAYWRITE     = (1 << 5),     /* Peut être accessible en écriture */
    VM_MAYEXEC      = (1 << 6),     /* Peut être exécutable */
    VM_MAYSHARE     = (1 << 7),     /* Peut être partagé */
    VM_GROWSDOWN    = (1 << 8),     /* Grandit vers le bas */
    VM_GROWSUP      = (1 << 9),     /* Grandit vers le haut */
    VM_PFNMAP       = (1 << 10),    /* Page frame number mapping */
    VM_DENYWRITE    = (1 << 11),    /* Interdire écriture sur fichier */
    VM_LOCKED       = (1 << 12),    /* Pages verrouillées */
    VM_IO           = (1 << 13),    /* Zone d'I/O */
    VM_SEQ_READ     = (1 << 14),    /* Lecture séquentielle */
    VM_RAND_READ    = (1 << 15),    /* Lecture aléatoire */
    VM_DONTCOPY     = (1 << 16),    /* Ne pas copier sur fork */
    VM_DONTEXPAND   = (1 << 17),    /* Ne peut pas être étendu */
    VM_ACCOUNT      = (1 << 18),    /* Compter dans les quotas */
    VM_NORESERVE    = (1 << 19),    /* Pas de réservation swap */
    VM_HUGETLB      = (1 << 20),    /* Pages énormes */
    VM_NONLINEAR    = (1 << 21)     /* Mapping non-linéaire */
} vm_flags_t;

/* VMA-specific flags (used by mmap.c) */
#define VMA_FLAG_MERGEABLE   (1U << 0)
#define VMA_FLAG_GROWSDOWN   (1U << 1)
#define VMA_FLAG_LOCKED      (1U << 2)
#define VMA_FLAG_HUGEPAGE    (1U << 3)

/**
 * @brief Structure VMA (Virtual Memory Area)
 */
typedef struct vm_area_struct {
    virt_addr_t vm_start;           /* Adresse de début */
    virt_addr_t vm_end;             /* Adresse de fin */
    
    struct vm_area_struct *vm_next; /* VMA suivante */
    struct vm_area_struct *vm_prev; /* VMA précédente */
    
    struct rb_node vm_rb;           /* Nœud dans l'arbre rouge-noir */
    
    vm_flags_t vm_flags;            /* Flags de protection */
    uint32_t vm_prot;               /* Protection converted to VM_* flags */
    vma_type_t vm_type;             /* Type de VMA */
    
    struct mm_struct *vm_mm;        /* MM parent */
    
    /* Pour mappings de fichiers */
    struct file *vm_file;           /* Fichier mappé */
    unsigned long vm_pgoff;         /* Offset dans le fichier */
    
    /* Opérations */
    const struct vm_operations_struct *vm_ops;
    
    /* Données privées */
    void *vm_private_data;
} vm_area_struct_t;

/* ========================================================================
 * MEMORY MANAGEMENT STRUCTURES
 * ======================================================================== */

/**
 * @brief Structure de contexte mémoire (processus)
 */
typedef struct mm_struct {
    struct vm_area_struct *mmap;    /* Liste des VMAs */
    struct rb_root mm_rb;           /* Arbre rouge-noir des VMAs */
    
    virt_addr_t start_code;         /* Début du code */
    virt_addr_t end_code;           /* Fin du code */
    virt_addr_t start_data;         /* Début des données */
    virt_addr_t end_data;           /* Fin des données */
    virt_addr_t start_brk;          /* Début du tas */
    virt_addr_t brk;                /* Fin actuelle du tas */
    virt_addr_t start_stack;        /* Début de la pile */
    
    unsigned long total_vm;         /* Pages totales */
    unsigned long locked_vm;        /* Pages verrouillées */
    unsigned long pinned_vm;        /* Pages épinglées */
    unsigned long shared_vm;        /* Pages partagées */
    unsigned long exec_vm;          /* Pages exécutables */
    unsigned long stack_vm;         /* Pages de pile */
    
    atomic_t mm_users;              /* Utilisateurs */
    atomic_t mm_count;              /* Compteur de références */
    
    /* Table des pages */
    pgd_t *pgd;                     /* Répertoire global des pages */
} mm_struct_t;

/* ========================================================================
 * ALLOCATOR STRUCTURES
 * ======================================================================== */

/**
 * @brief Types d'allocateurs
 */
typedef enum {
    ALLOCATOR_TYPE_BUDDY = 0,       /* Buddy system */
    ALLOCATOR_TYPE_SLAB,            /* SLAB allocator */
    ALLOCATOR_TYPE_SLUB,            /* SLUB allocator */
    ALLOCATOR_TYPE_VMALLOC,         /* Virtual allocator */
    ALLOCATOR_TYPE_KMALLOC,         /* Kernel malloc */
    ALLOCATOR_TYPE_PERCPU,          /* Per-CPU allocator */
    ALLOCATOR_TYPE_CMA,             /* Contiguous Memory Allocator */
    ALLOCATOR_TYPE_COUNT
} allocator_type_t;

/**
 * @brief Configuration d'allocateur
 */
typedef struct {
    allocator_type_t type;          /* Type d'allocateur */
    const char *name;               /* Nom de l'allocateur */
    size_t min_size;                /* Taille minimale */
    size_t max_size;                /* Taille maximale */
    size_t alignment;               /* Alignement requis */
    uint32_t flags;                 /* Flags de configuration */
    void *private_data;             /* Données privées */
} allocator_config_t;

/**
 * @brief Statistiques d'allocateur
 */
typedef struct {
    uint64_t alloc_count;           /* Nombre d'allocations */
    uint64_t free_count;            /* Nombre de libérations */
    uint64_t bytes_allocated;       /* Octets alloués */
    uint64_t bytes_freed;           /* Octets libérés */
    uint64_t peak_usage;            /* Pic d'utilisation */
    uint64_t current_usage;         /* Utilisation actuelle */
    uint64_t failed_allocs;         /* Allocations échouées */
    uint64_t cache_hits;            /* Hits de cache */
    uint64_t cache_misses;          /* Misses de cache */
} allocator_stats_t;

/* ========================================================================
 * MEMORY BARRIERS AND SYNCHRONIZATION
 * ======================================================================== */

/**
 * @brief Types de barrières mémoire
 */
typedef enum {
    MEMORY_BARRIER_FULL = 0,        /* Barrière complète */
    MEMORY_BARRIER_READ,            /* Barrière lecture */
    MEMORY_BARRIER_WRITE,           /* Barrière écriture */
    MEMORY_BARRIER_ACQUIRE,         /* Barrière acquisition */
    MEMORY_BARRIER_RELEASE,         /* Barrière relâchement */
    MEMORY_BARRIER_COUNT
} memory_barrier_type_t;

/**
 * @brief Types atomiques
 */
typedef struct {
    volatile int counter;
} atomic_t;

typedef struct {
    volatile long counter;
} atomic64_t;

/* ========================================================================
 * SWAP AND RECLAIM
 * ======================================================================== */

/**
 * @brief Types de stockage swap
 */
typedef enum {
    SWAP_TYPE_FILE = 0,             /* Fichier swap */
    SWAP_TYPE_PARTITION,            /* Partition swap */
    SWAP_TYPE_NETWORK,              /* Swap réseau */
    SWAP_TYPE_COMPRESSED,           /* Swap compressé */
    SWAP_TYPE_COUNT
} swap_type_t;

/**
 * @brief Entrée swap
 */
typedef struct {
    unsigned long val;              /* Valeur de l'entrée */
} swp_entry_t;

/**
 * @brief Information sur zone de swap
 */
typedef struct swap_info_struct {
    unsigned long flags;            /* Flags */
    short prio;                     /* Priorité */
    struct file *swap_file;         /* Fichier swap */
    unsigned int max;               /* Pages maximum */
    unsigned char *swap_map;        /* Carte d'utilisation */
    unsigned int lowest_bit;        /* Plus bas bit libre */
    unsigned int highest_bit;       /* Plus haut bit utilisé */
    unsigned int pages;             /* Nombre de pages */
    unsigned int inuse_pages;       /* Pages utilisées */
    unsigned int cluster_nr;        /* Numéro de cluster */
} swap_info_t;

/* ========================================================================
 * ERROR CODES
 * ======================================================================== */

/**
 * @brief Codes d'erreur MM
 */
typedef enum {
    MM_SUCCESS = 0,                 /* Succès */
    MM_ERROR_NOMEM = -1,            /* Pas assez de mémoire */
    MM_ERROR_INVALID = -2,          /* Paramètre invalide */
    MM_ERROR_BUSY = -3,             /* Ressource occupée */
    MM_ERROR_EXISTS = -4,           /* Existe déjà */
    MM_ERROR_NOTFOUND = -5,         /* Non trouvé */
    MM_ERROR_CORRUPT = -6,          /* Corruption détectée */
    MM_ERROR_DEADLOCK = -7,         /* Interblocage détecté */
    MM_ERROR_TIMEOUT = -8,          /* Timeout */
    MM_ERROR_IO = -9,               /* Erreur I/O */
    MM_ERROR_QUOTA = -10            /* Quota dépassé */
} mm_error_t;

/* ========================================================================
 * UTILITY MACROS
 * ======================================================================== */

/* Conversion d'adresses */
#define virt_to_phys(x)     ((phys_addr_t)(x) - KERNEL_VIRT_BASE)
#define phys_to_virt(x)     ((virt_addr_t)(x) + KERNEL_VIRT_BASE)

/* Opérations sur pages */
#define page_to_pfn(page)   ((page) - mem_map)
#define pfn_to_page(pfn)    (mem_map + (pfn))
#define page_address(page)  ((void *)((page)->virtual))

/* Tests d'alignement */
#define IS_ALIGNED(x, a)    (((x) & ((a) - 1)) == 0)
#define ALIGN(x, a)         (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a)    ((x) & ~((a) - 1))

/* Tailles en unités */
#define SIZE_KB(x)          ((x) * 1024UL)
#define SIZE_MB(x)          ((x) * 1024UL * 1024UL)
#define SIZE_GB(x)          ((x) * 1024UL * 1024UL * 1024UL)

/* Limites architecture */
#ifndef KERNEL_VIRT_BASE
#define KERNEL_VIRT_BASE    0xC0000000UL    /* Base virtuelle kernel */
#endif

#ifndef VMALLOC_START
#define VMALLOC_START       0xF0000000UL    /* Début zone vmalloc */
#endif

#ifndef VMALLOC_END
#define VMALLOC_END         0xFF000000UL    /* Fin zone vmalloc */
#endif

#endif /* MM_TYPES_H */

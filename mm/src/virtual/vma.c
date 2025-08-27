/**
 * @file vma.c
 * @brief Virtual Memory Area management
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
#include "vmalloc.h"

/* Définition du GFP_KERNEL si non défini */
#ifndef GFP_KERNEL
#define GFP_KERNEL 0
#endif


/* ========================================================================
 * CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/* Types de VMA */
#define VMA_TYPE_ANONYMOUS      0x0001  /* Mémoire anonyme */
#define VMA_TYPE_FILE           0x0002  /* Mapping de fichier */
#define VMA_TYPE_DEVICE         0x0004  /* Mapping de device */
#define VMA_TYPE_SHARED         0x0008  /* Mémoire partagée */
#define VMA_TYPE_STACK          0x0010  /* Pile de thread */
#define VMA_TYPE_HEAP           0x0020  /* Tas dynamique */
#define VMA_TYPE_VDSO           0x0040  /* VDSO (Virtual DSO) */
#define VMA_TYPE_VSYSCALL       0x0080  /* Vsyscall page */

/* Permissions de VMA */
#define VM_READ   0x1
#define VM_WRITE  0x2
#define VM_EXEC   0x4

/* Flags spéciaux de VMA */
#define VMA_FLAG_GROWSDOWN      0x0100  /* Croît vers le bas (pile) */
#define VMA_FLAG_GROWSUP        0x0200  /* Croît vers le haut */
#define VMA_FLAG_DONTEXPAND     0x0400  /* Ne pas étendre automatiquement */
#define VMA_FLAG_DONTDUMP       0x0800  /* Exclure des core dumps */
#define VMA_FLAG_LOCKED         0x1000  /* Pages verrouillées en mémoire */
#define VMA_FLAG_HUGEPAGE       0x2000  /* Utilise des huge pages */
#define VMA_FLAG_MERGEABLE      0x4000  /* Peut être fusionné */
#define VMA_FLAG_SPECIAL        0x8000  /* VMA spéciale (pas de swap) */

/* Tailles par défaut */
#define VMA_CACHE_SIZE          64      /* Cache de VMA */
#define VMA_MERGE_THRESHOLD     8       /* Seuil de fusion */
#define MAX_VMA_PER_MM          65536   /* VMA max par espace mémoire */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Structure représentant une zone de mémoire virtuelle
 */
typedef struct vm_area_struct {
    /* Limites de la région */
    virt_addr_t vm_start;               /* Début de la région (inclus) */
    virt_addr_t vm_end;                 /* Fin de la région (exclus) */
    
    /* Propriétés de la région */
    uint32_t vm_prot;                   /* Permissions (VM_READ, VM_WRITE, etc.) */
    uint32_t vm_flags;                  /* Flags spéciaux */
    uint32_t vm_type;                   /* Type de VMA */
    
    /* Offset dans le fichier (pour mappings de fichiers) */
    uint64_t vm_pgoff;                  /* Offset en pages */
    
    /* Liens dans l'arbre et la liste */
    struct vm_area_struct *vm_next;     /* VMA suivant dans la liste */
    struct vm_area_struct *vm_prev;     /* VMA précédent dans la liste */
    struct vm_area_struct *vm_left;     /* Enfant gauche dans l'arbre RB */
    struct vm_area_struct *vm_right;    /* Enfant droit dans l'arbre RB */
    struct vm_area_struct *vm_parent;   /* Parent dans l'arbre RB */
    int vm_color;                       /* Couleur RB (0=noir, 1=rouge) */
    
    /* Gestion mémoire */
    struct mm_struct *vm_mm;            /* Espace mémoire parent */
    
    /* Fichier mappé (si applicable) */
    void *vm_file;                      /* Pointeur vers structure de fichier */
    void *vm_private_data;              /* Données privées */
    
    /* Opérations spécialisées */
    struct vm_operations_struct *vm_ops; /* Opérations sur cette VMA */
    
    /* Statistiques et gestion */
    uint32_t vm_ref_count;              /* Compteur de références */
    uint64_t vm_access_count;           /* Compteur d'accès */
    uint64_t vm_fault_count;            /* Compteur de page faults */
    
    /* Données temporaires */
    void *vm_temp_data;                 /* Données temporaires */
} vma_t;

/**
 * @brief Operations sur VMA
 */
typedef struct vm_operations_struct {
    void (*open)(vma_t *vma);
    void (*close)(vma_t *vma);
    int (*fault)(vma_t *vma, virt_addr_t address);
    int (*page_mkwrite)(vma_t *vma, virt_addr_t address);
    int (*access)(vma_t *vma, virt_addr_t address, void *buf, int len, int write);
} vm_ops_t;

/**
 * @brief Espace d'adressage d'un processus
 */
typedef struct mm_struct {
    /* Arbre des VMA */
    vma_t *mmap;                        /* Liste des VMA */
    vma_t *mmap_rb_root;                /* Racine de l'arbre RB */
    uint32_t map_count;                 /* Nombre de VMA */
    
    /* Régions spéciales */
    virt_addr_t start_code;             /* Début du code */
    virt_addr_t end_code;               /* Fin du code */
    virt_addr_t start_data;             /* Début des données */
    virt_addr_t end_data;               /* Fin des données */
    virt_addr_t start_brk;              /* Début du heap */
    virt_addr_t brk;                    /* Fin actuelle du heap */
    virt_addr_t start_stack;            /* Début de la pile */
    virt_addr_t env_start;              /* Début des variables d'env */
    virt_addr_t env_end;                /* Fin des variables d'env */
    virt_addr_t arg_start;              /* Début des arguments */
    virt_addr_t arg_end;                /* Fin des arguments */
    
    /* Gestion mémoire */
    uint64_t total_vm;                  /* Pages virtuelles totales */
    uint64_t locked_vm;                 /* Pages verrouillées */
    uint64_t shared_vm;                 /* Pages partagées */
    uint64_t exec_vm;                   /* Pages exécutables */
    uint64_t stack_vm;                  /* Pages de pile */
    uint64_t data_vm;                   /* Pages de données */
    
    /* Synchronisation */
    uint32_t mm_users;                  /* Utilisateurs de cette mm */
    uint32_t mm_count;                  /* Compteur de références */
    
    /* Répertoire de pages */
    void *pgd;                          /* Page Global Directory */
    
    /* Cache de la dernière VMA trouvée */
    vma_t *mmap_cache;                  /* Cache VMA */
    
} mm_struct_t;

/**
 * @brief Statistiques des VMA
 */
typedef struct {
    uint64_t total_vma;                 /* VMA totales créées */
    uint64_t active_vma;                /* VMA actuellement actives */
    uint64_t vma_splits;                /* Divisions de VMA */
    uint64_t vma_merges;                /* Fusions de VMA */
    uint64_t cache_hits;                /* Hits du cache */
    uint64_t cache_misses;              /* Misses du cache */
    uint64_t rb_searches;               /* Recherches dans l'arbre RB */
    uint64_t linear_searches;           /* Recherches linéaires */
    uint64_t memory_used;               /* Mémoire utilisée par VMA */
    uint64_t max_vma_size;              /* Taille VMA maximale */
    uint64_t avg_vma_size;              /* Taille VMA moyenne */
    uint64_t page_faults_handled;       /* Page faults gérés */
} vma_stats_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* État global du gestionnaire VMA */
static bool vma_mgr_initialized = false;
static vma_stats_t vma_stats;

/* Cache de VMA */
static vma_t *vma_cache[VMA_CACHE_SIZE];
static int vma_cache_head = 0;
static int vma_cache_count = 0;

/* Liste des espaces mémoire actifs */
static mm_struct_t *mm_list_head = NULL;
static uint32_t mm_count = 0;

/* Synchronization */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
static mm_spinlock_t vma_lock = MM_SPINLOCK_INIT("unknown");
#define VMA_LOCK() mm_spin_lock(&vma_lock)
#define VMA_UNLOCK() mm_spin_unlock(&vma_lock)
#else
#define VMA_LOCK() do {} while(0)
#define VMA_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * VMA ALLOCATION AND DEALLOCATION
 * ======================================================================== */

/**
 * @brief Alloue une nouvelle structure VMA
 * @return Pointeur vers VMA ou NULL
 */
static vma_t *alloc_vma(void) {
    vma_t *vma = NULL;
    
    VMA_LOCK();
    
    /* Vérifier le cache */
    if (vma_cache_count > 0) {
        vma = vma_cache[vma_cache_head];
        vma_cache_head = (vma_cache_head + 1) % VMA_CACHE_SIZE;
        vma_cache_count--;
    }
    
    VMA_UNLOCK();
    
    if (!vma) {
        /* Allouer depuis le gestionnaire de mémoire kernel */
        vma = (vma_t *)kmalloc(sizeof(vma_t));
        if (!vma) {
            return NULL;
        }
    }
    
    /* Initialiser la VMA */
    memset(vma, 0, sizeof(vma_t));
    vma->vm_ref_count = 1;
    
    vma_stats.total_vma++;
    vma_stats.active_vma++;
    vma_stats.memory_used += sizeof(vma_t);
    
    return vma;
}

/**
 * @brief Libère une structure VMA
 * @param vma VMA à libérer
 */
static void free_vma(vma_t *vma) {
    if (!vma) return;
    
    VMA_LOCK();
    
    vma->vm_ref_count--;
    if (vma->vm_ref_count > 0) {
        VMA_UNLOCK();
        return;
    }
    
    /* Appeler les opérations de fermeture si nécessaire */
    if (vma->vm_ops && vma->vm_ops->close) {
        vma->vm_ops->close(vma);
    }
    
    /* Essayer d'ajouter au cache */
    if (vma_cache_count < VMA_CACHE_SIZE) {
        int cache_index = (vma_cache_head + vma_cache_count) % VMA_CACHE_SIZE;
        vma_cache[cache_index] = vma;
        vma_cache_count++;
        VMA_UNLOCK();
        return;
    }
    
    VMA_UNLOCK();
    
    /* Libérer la mémoire */
    kfree(vma);
    
    vma_stats.active_vma--;
    vma_stats.memory_used -= sizeof(vma_t);
}

/* ========================================================================
 * RED-BLACK TREE OPERATIONS
 * ======================================================================== */

/**
 * @brief Rotation gauche dans l'arbre RB
 * @param mm Espace mémoire
 * @param node Nœud à faire tourner
 */
static void rb_rotate_left(mm_struct_t *mm, vma_t *node) {
    vma_t *right = node->vm_right;
    
    node->vm_right = right->vm_left;
    if (right->vm_left) {
        right->vm_left->vm_parent = node;
    }
    
    right->vm_parent = node->vm_parent;
    if (!node->vm_parent) {
        mm->mmap_rb_root = right;
    } else if (node == node->vm_parent->vm_left) {
        node->vm_parent->vm_left = right;
    } else {
        node->vm_parent->vm_right = right;
    }
    
    right->vm_left = node;
    node->vm_parent = right;
}

/**
 * @brief Rotation droite dans l'arbre RB
 * @param mm Espace mémoire
 * @param node Nœud à faire tourner
 */
static void rb_rotate_right(mm_struct_t *mm, vma_t *node) {
    vma_t *left = node->vm_left;
    
    node->vm_left = left->vm_right;
    if (left->vm_right) {
        left->vm_right->vm_parent = node;
    }
    
    left->vm_parent = node->vm_parent;
    if (!node->vm_parent) {
        mm->mmap_rb_root = left;
    } else if (node == node->vm_parent->vm_right) {
        node->vm_parent->vm_right = left;
    } else {
        node->vm_parent->vm_left = left;
    }
    
    left->vm_right = node;
    node->vm_parent = left;
}

/**
 * @brief Fixe l'arbre après insertion
 * @param mm Espace mémoire
 * @param vma VMA insérée
 */
static void rb_insert_fixup(mm_struct_t *mm, vma_t *vma) {
    while (vma->vm_parent && vma->vm_parent->vm_color == 1) { /* Rouge */
        if (vma->vm_parent == vma->vm_parent->vm_parent->vm_left) {
            vma_t *uncle = vma->vm_parent->vm_parent->vm_right;
            
            if (uncle && uncle->vm_color == 1) { /* Uncle rouge */
                vma->vm_parent->vm_color = 0; /* Noir */
                uncle->vm_color = 0; /* Noir */
                vma->vm_parent->vm_parent->vm_color = 1; /* Rouge */
                vma = vma->vm_parent->vm_parent;
            } else {
                if (vma == vma->vm_parent->vm_right) {
                    vma = vma->vm_parent;
                    rb_rotate_left(mm, vma);
                }
                vma->vm_parent->vm_color = 0; /* Noir */
                vma->vm_parent->vm_parent->vm_color = 1; /* Rouge */
                rb_rotate_right(mm, vma->vm_parent->vm_parent);
            }
        } else {
            vma_t *uncle = vma->vm_parent->vm_parent->vm_left;
            
            if (uncle && uncle->vm_color == 1) { /* Uncle rouge */
                vma->vm_parent->vm_color = 0; /* Noir */
                uncle->vm_color = 0; /* Noir */
                vma->vm_parent->vm_parent->vm_color = 1; /* Rouge */
                vma = vma->vm_parent->vm_parent;
            } else {
                if (vma == vma->vm_parent->vm_left) {
                    vma = vma->vm_parent;
                    rb_rotate_right(mm, vma);
                }
                vma->vm_parent->vm_color = 0; /* Noir */
                vma->vm_parent->vm_parent->vm_color = 1; /* Rouge */
                rb_rotate_left(mm, vma->vm_parent->vm_parent);
            }
        }
    }
    
    mm->mmap_rb_root->vm_color = 0; /* Racine noire */
}

/**
 * @brief Insère une VMA dans l'arbre RB
 * @param mm Espace mémoire
 * @param vma VMA à insérer
 */
static void rb_insert_vma(mm_struct_t *mm, vma_t *vma) {
    vma_t **node = &mm->mmap_rb_root;
    vma_t *parent = NULL;
    
    /* Recherche de la position d'insertion */
    while (*node) {
        parent = *node;
        
        if (vma->vm_start < (*node)->vm_start) {
            node = &(*node)->vm_left;
        } else {
            node = &(*node)->vm_right;
        }
    }
    
    /* Insertion */
    *node = vma;
    vma->vm_parent = parent;
    vma->vm_left = NULL;
    vma->vm_right = NULL;
    vma->vm_color = 1; /* Rouge */
    
    /* Rééquilibrage */
    rb_insert_fixup(mm, vma);
    
    vma_stats.rb_searches++;
}

/* ========================================================================
 * VMA SEARCH OPERATIONS
 * ======================================================================== */

/**
 * @brief Recherche une VMA contenant une adresse donnée
 * @param mm Espace mémoire
 * @param addr Adresse à rechercher
 * @return VMA trouvée ou NULL
 */
vma_t *find_vma(mm_struct_t *mm, virt_addr_t addr) {
    if (!mm || !mm->mmap_rb_root) {
        return NULL;
    }
    
    /* Vérifier le cache en premier */
    if (mm->mmap_cache && 
        addr >= mm->mmap_cache->vm_start && 
        addr < mm->mmap_cache->vm_end) {
        vma_stats.cache_hits++;
        mm->mmap_cache->vm_access_count++;
        return mm->mmap_cache;
    }
    
    vma_stats.cache_misses++;
    
    /* Recherche dans l'arbre RB */
    vma_t *vma = mm->mmap_rb_root;
    vma_t *result = NULL;
    
    while (vma) {
        vma_stats.rb_searches++;
        
        if (addr < vma->vm_start) {
            vma = vma->vm_left;
        } else if (addr >= vma->vm_end) {
            vma = vma->vm_right;
        } else {
            /* Trouvé */
            result = vma;
            break;
        }
    }
    
    /* Mettre à jour le cache */
    if (result) {
        mm->mmap_cache = result;
        result->vm_access_count++;
    }
    
    return result;
}

/**
 * @brief Recherche la première VMA après une adresse donnée
 * @param mm Espace mémoire
 * @param addr Adresse de référence
 * @return VMA trouvée ou NULL
 */
vma_t *find_vma_next(mm_struct_t *mm, virt_addr_t addr) {
    if (!mm || !mm->mmap_rb_root) {
        return NULL;
    }
    
    vma_t *vma = mm->mmap_rb_root;
    vma_t *result = NULL;
    
    while (vma) {
        if (vma->vm_start > addr) {
            result = vma;
            vma = vma->vm_left;
        } else {
            vma = vma->vm_right;
        }
    }
    
    return result;
}

/**
 * @brief Recherche une VMA par intervalle
 * @param mm Espace mémoire
 * @param start_addr Début de l'intervalle
 * @param end_addr Fin de l'intervalle
 * @return VMA qui se chevauche ou NULL
 */
vma_t *find_vma_intersection(mm_struct_t *mm, virt_addr_t start_addr, virt_addr_t end_addr) {
    if (!mm || start_addr >= end_addr) {
        return NULL;
    }
    
    /* Recherche linéaire dans la liste (plus efficace pour cette opération) */
    vma_t *vma = mm->mmap;
    
    while (vma) {
        vma_stats.linear_searches++;
        
        /* Vérifier chevauchement */
        if (!(end_addr <= vma->vm_start || start_addr >= vma->vm_end)) {
            return vma;
        }
        
        vma = vma->vm_next;
    }
    
    return NULL;
}

/* ========================================================================
 * VMA MANIPULATION OPERATIONS
 * ======================================================================== */

/**
 * @brief Teste si deux VMA peuvent être fusionnées
 * @param vma1 Première VMA
 * @param vma2 Deuxième VMA
 * @return true si fusionnables
 */
static bool can_merge_vma(vma_t *vma1, vma_t *vma2) {
    if (!vma1 || !vma2) {
        return false;
    }
    
    /* Vérifier si adjacentes */
    if (vma1->vm_end != vma2->vm_start) {
        return false;
    }
    
    /* Vérifier les propriétés */
    if (vma1->vm_prot != vma2->vm_prot ||
        vma1->vm_flags != vma2->vm_flags ||
        vma1->vm_type != vma2->vm_type ||
        vma1->vm_file != vma2->vm_file ||
        vma1->vm_ops != vma2->vm_ops) {
        return false;
    }
    
    /* Vérifier les flags de fusion */
    if (!(vma1->vm_flags & VMA_FLAG_MERGEABLE) ||
        !(vma2->vm_flags & VMA_FLAG_MERGEABLE)) {
        return false;
    }
    
    /* Pour les fichiers mappés, vérifier l'offset */
    if (vma1->vm_file && 
        vma1->vm_pgoff + ((vma1->vm_end - vma1->vm_start) >> PAGE_SHIFT) != vma2->vm_pgoff) {
        return false;
    }
    
    return true;
}

/**
 * @brief Fusionne deux VMA adjacentes
 * @param mm Espace mémoire
 * @param prev VMA précédente
 * @param next VMA suivante
 * @return VMA fusionnée ou NULL
 */
static vma_t *merge_vma(mm_struct_t *mm, vma_t *prev, vma_t *next) {
    if (!can_merge_vma(prev, next)) {
        return NULL;
    }
    
    /* Étendre la VMA précédente */
    prev->vm_end = next->vm_end;
    
    /* Fusionner les statistiques */
    prev->vm_access_count += next->vm_access_count;
    prev->vm_fault_count += next->vm_fault_count;
    
    /* Retirer next de la liste */
    if (next->vm_next) {
        next->vm_next->vm_prev = prev;
    }
    prev->vm_next = next->vm_next;
    
    /* Retirer next de l'arbre RB */
    // TODO: Implémentation de rb_erase
    
    /* Mettre à jour le cache si nécessaire */
    if (mm->mmap_cache == next) {
        mm->mmap_cache = prev;
    }
    
    /* Libérer next */
    free_vma(next);
    
    mm->map_count--;
    vma_stats.vma_merges++;
    
    printk(KERN_DEBUG "Merged VMA: 0x%lx-0x%lx\n", prev->vm_start, prev->vm_end);
    
    return prev;
}

/**
 * @brief Divise une VMA en deux à une adresse donnée
 * @param mm Espace mémoire
 * @param vma VMA à diviser
 * @param addr Adresse de division
 * @return Nouvelle VMA (partie haute) ou NULL
 */
vma_t *split_vma(mm_struct_t *mm, vma_t *vma, virt_addr_t addr) {
    if (!mm || !vma || addr <= vma->vm_start || addr >= vma->vm_end) {
        return NULL;
    }
    
    /* Allouer nouvelle VMA pour la partie haute */
    vma_t *new_vma = alloc_vma();
    if (!new_vma) {
        return NULL;
    }
    
    /* Copier les propriétés */
    *new_vma = *vma;
    new_vma->vm_ref_count = 1;
    
    /* Ajuster les limites */
    new_vma->vm_start = addr;
    vma->vm_end = addr;
    
    /* Ajuster l'offset pour fichiers mappés */
    if (vma->vm_file) {
        size_t offset_pages = (addr - vma->vm_start) >> PAGE_SHIFT;
        new_vma->vm_pgoff += offset_pages;
    }
    
    /* Insérer dans la liste */
    new_vma->vm_next = vma->vm_next;
    new_vma->vm_prev = vma;
    if (vma->vm_next) {
        vma->vm_next->vm_prev = new_vma;
    }
    vma->vm_next = new_vma;
    
    /* Insérer dans l'arbre RB */
    rb_insert_vma(mm, new_vma);
    
    /* Appeler les opérations d'ouverture */
    if (new_vma->vm_ops && new_vma->vm_ops->open) {
        new_vma->vm_ops->open(new_vma);
    }
    
    mm->map_count++;
    vma_stats.vma_splits++;
    
    printk(KERN_DEBUG "Split VMA: 0x%lx-0x%lx -> 0x%lx-0x%lx + 0x%lx-0x%lx\n",
           vma->vm_start, new_vma->vm_end,
           vma->vm_start, vma->vm_end,
           new_vma->vm_start, new_vma->vm_end);
    
    return new_vma;
}

/* ========================================================================
 * VMA CREATION AND INSERTION
 * ======================================================================== */

/**
 * @brief Crée et insère une nouvelle VMA
 * @param mm Espace mémoire
 * @param start Adresse de début
 * @param end Adresse de fin
 * @param prot Permissions
 * @param flags Flags
 * @param type Type de VMA
 * @return VMA créée ou NULL
 */
vma_t *create_vma(mm_struct_t *mm, virt_addr_t start, virt_addr_t end,
                  uint32_t prot, uint32_t flags, uint32_t type) {
    if (!mm || start >= end || start & ~PAGE_MASK || end & ~PAGE_MASK) {
        return NULL;
    }
    
    /* Vérifier les limites */
    if (mm->map_count >= MAX_VMA_PER_MM) {
        printk(KERN_ERR "Too many VMA in mm_struct\n");
        return NULL;
    }
    
    /* Vérifier les chevauchements */
    vma_t *conflict = find_vma_intersection(mm, start, end);
    if (conflict) {
        printk(KERN_ERR "VMA conflict: 0x%lx-0x%lx overlaps with 0x%lx-0x%lx\n",
               start, end, conflict->vm_start, conflict->vm_end);
        return NULL;
    }
    
    /* Allouer nouvelle VMA */
    vma_t *vma = alloc_vma();
    if (!vma) {
        return NULL;
    }
    
    /* Initialiser les propriétés */
    vma->vm_start = start;
    vma->vm_end = end;
    vma->vm_prot = prot;
    vma->vm_flags = flags;
    vma->vm_type = type;
    vma->vm_mm = mm;
    vma->vm_pgoff = 0;
    vma->vm_file = NULL;
    vma->vm_ops = NULL;
    vma->vm_private_data = NULL;
    
    /* Insérer dans la liste triée */
    vma_t *prev = NULL;
    vma_t *curr = mm->mmap;
    
    while (curr && curr->vm_start < start) {
        prev = curr;
        curr = curr->vm_next;
    }
    
    vma->vm_prev = prev;
    vma->vm_next = curr;
    
    if (prev) {
        prev->vm_next = vma;
    } else {
        mm->mmap = vma;
    }
    
    if (curr) {
        curr->vm_prev = vma;
    }
    
    /* Insérer dans l'arbre RB */
    rb_insert_vma(mm, vma);
    
    mm->map_count++;
    
    /* Mettre à jour les statistiques de l'espace mémoire */
    size_t vma_size = end - start;
    mm->total_vm += vma_size >> PAGE_SHIFT;
    
    switch (type) {
        case VMA_TYPE_STACK:
            mm->stack_vm += vma_size >> PAGE_SHIFT;
            break;
        case VMA_TYPE_HEAP:
            mm->data_vm += vma_size >> PAGE_SHIFT;
            break;
        default:
            if (prot & VM_EXEC) {
                mm->exec_vm += vma_size >> PAGE_SHIFT;
            } else {
                mm->data_vm += vma_size >> PAGE_SHIFT;
            }
            break;
    }
    
    /* Mettre à jour les statistiques globales */
    if (vma_size > vma_stats.max_vma_size) {
        vma_stats.max_vma_size = vma_size;
    }
    
    vma_stats.avg_vma_size = (vma_stats.avg_vma_size * (vma_stats.active_vma - 1) + vma_size) / vma_stats.active_vma;
    
    printk(KERN_DEBUG "Created VMA: 0x%lx-0x%lx (prot=0x%x, flags=0x%x, type=0x%x)\n",
           start, end, prot, flags, type);
    
    /* Essayer de fusionner avec les VMA adjacentes */
    if (prev && can_merge_vma(prev, vma)) {
        vma = merge_vma(mm, prev, vma);
    }
    
    if (vma && vma->vm_next && can_merge_vma(vma, vma->vm_next)) {
        merge_vma(mm, vma, vma->vm_next);
    }
    
    return vma;
}

/* ========================================================================
 * MM_STRUCT MANAGEMENT
 * ======================================================================== */

/**
 * @brief Crée un nouvel espace d'adressage
 * @return Pointeur vers mm_struct ou NULL
 */
mm_struct_t *create_mm_struct(void) {
    mm_struct_t *mm = (mm_struct_t *)kmalloc(sizeof(mm_struct_t));
    if (!mm) {
        return NULL;
    }
    
    /* Initialiser la structure */
    memset(mm, 0, sizeof(mm_struct_t));
    
    mm->mm_users = 1;
    mm->mm_count = 1;
    
    /* Valeurs par défaut pour les régions */
    mm->start_code = 0x08048000;     /* Adresse standard ELF */
    mm->end_code = 0x08048000;
    mm->start_data = 0x08048000;
    mm->end_data = 0x08048000;
    mm->start_brk = 0x08048000;
    mm->brk = 0x08048000;
    mm->start_stack = 0xC0000000;    /* Pile en haut de l'espace user */
    
    /* Ajouter à la liste globale */
    VMA_LOCK();
    mm->pgd = mm_list_head;  /* Réutiliser le champ pgd comme next temporairement */
    mm_list_head = mm;
    mm_count++;
    VMA_UNLOCK();
    
    printk(KERN_DEBUG "Created mm_struct: %p\n", mm);
    
    return mm;
}

/**
 * @brief Libère un espace d'adressage
 * @param mm Espace à libérer
 */
void free_mm_struct(mm_struct_t *mm) {
    if (!mm) return;
    
    VMA_LOCK();
    mm->mm_count--;
    if (mm->mm_count > 0) {
        VMA_UNLOCK();
        return;
    }
    VMA_UNLOCK();
    
    /* Libérer toutes les VMA */
    vma_t *vma = mm->mmap;
    while (vma) {
        vma_t *next = vma->vm_next;
        free_vma(vma);
        vma = next;
    }
    
    /* Retirer de la liste globale */
    VMA_LOCK();
    // TODO: Implémentation de la suppression de liste
    mm_count--;
    VMA_UNLOCK();
    
    /* Libérer la structure */
    kfree(mm);
    
    printk(KERN_DEBUG "Freed mm_struct: %p\n", mm);
}

/* ========================================================================
 * INITIALIZATION AND STATISTICS
 * ======================================================================== */

/**
 * @brief Initialise le gestionnaire VMA
 * @return 0 en cas de succès
 */
int vma_init(void) {
    if (vma_mgr_initialized) {
        printk(KERN_WARNING "VMA manager already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing VMA manager\n");
    
    /* Réinitialiser les statistiques */
    memset(&vma_stats, 0, sizeof(vma_stats));
    
    /* Initialiser les caches */
    memset(vma_cache, 0, sizeof(vma_cache));
    vma_cache_head = 0;
    vma_cache_count = 0;
    
    /* Initialiser la liste des mm_struct */
    mm_list_head = NULL;
    mm_count = 0;
    
    vma_mgr_initialized = true;
    
    printk(KERN_INFO "VMA manager initialized\n");
    printk(KERN_INFO "  VMA structure size: %zu bytes\n", sizeof(vma_t));
    printk(KERN_INFO "  MM structure size: %zu bytes\n", sizeof(mm_struct_t));
    printk(KERN_INFO "  Cache size: %d VMA\n", VMA_CACHE_SIZE);
    printk(KERN_INFO "  Max VMA per MM: %d\n", MAX_VMA_PER_MM);
    
    return 0;
}

/**
 * @brief Obtient les statistiques VMA
 * @param stats Pointeur vers structure de statistiques
 */
void vma_get_stats(vma_stats_t *stats) {
    if (!stats || !vma_mgr_initialized) {
        return;
    }
    
    VMA_LOCK();
    memcpy(stats, &vma_stats, sizeof(vma_stats_t));
    VMA_UNLOCK();
}

/**
 * @brief Affiche les statistiques VMA
 */
void vma_print_stats(void) {
    if (!vma_mgr_initialized) {
        printk(KERN_INFO "VMA manager not initialized\n");
        return;
    }
    
    printk(KERN_INFO "VMA Statistics:\n");
    printk(KERN_INFO "  Total VMA created:    %llu\n", vma_stats.total_vma);
    printk(KERN_INFO "  Active VMA:           %llu\n", vma_stats.active_vma);
    printk(KERN_INFO "  VMA splits:           %llu\n", vma_stats.vma_splits);
    printk(KERN_INFO "  VMA merges:           %llu\n", vma_stats.vma_merges);
    printk(KERN_INFO "  Cache hits:           %llu\n", vma_stats.cache_hits);
    printk(KERN_INFO "  Cache misses:         %llu\n", vma_stats.cache_misses);
    printk(KERN_INFO "  RB tree searches:     %llu\n", vma_stats.rb_searches);
    printk(KERN_INFO "  Linear searches:      %llu\n", vma_stats.linear_searches);
    printk(KERN_INFO "  Memory used:          %llu KB\n", vma_stats.memory_used / 1024);
    printk(KERN_INFO "  Max VMA size:         %llu KB\n", vma_stats.max_vma_size / 1024);
    printk(KERN_INFO "  Avg VMA size:         %llu KB\n", vma_stats.avg_vma_size / 1024);
    printk(KERN_INFO "  Page faults handled:  %llu\n", vma_stats.page_faults_handled);
    printk(KERN_INFO "  Active mm_struct:     %u\n", mm_count);
    printk(KERN_INFO "  VMA cache:            %d/%d\n", vma_cache_count, VMA_CACHE_SIZE);
}

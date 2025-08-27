/**
 * @file swap_policy.c
 * @brief Swap policy management
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
#include "mm_types.h"
#include "mm.h"
#include "page_alloc.h"

/* ========================================================================
 * CONSTANTS AND CONFIGURATION
 * ======================================================================== */

/** Types de politiques de swap disponibles */
typedef enum {
    SWAP_POLICY_LRU = 0,            /**< Least Recently Used */
    SWAP_POLICY_CLOCK,              /**< Clock algorithm */
    SWAP_POLICY_WORKING_SET,        /**< Working Set Model */
    SWAP_POLICY_AGING,              /**< Aging algorithm */
    SWAP_POLICY_RANDOM,             /**< Random selection */
    SWAP_POLICY_FIFO,               /**< First In First Out */
    SWAP_POLICY_LFU,                /**< Least Frequently Used */
    SWAP_POLICY_ADAPTIVE,           /**< Adaptive hybrid policy */
    SWAP_POLICY_COUNT
} swap_policy_type_t;

/** Niveaux de priorité des pages */
typedef enum {
    PAGE_PRIORITY_CRITICAL = 0, /**< Pages critiques (kernel core) */
    PAGE_PRIORITY_HIGH,         /**< Pages importantes (drivers) */
    PAGE_PRIORITY_NORMAL,       /**< Pages normales (user apps) */
    PAGE_PRIORITY_LOW,          /**< Pages peu importantes (cache) */
    PAGE_PRIORITY_BACKGROUND,   /**< Pages background (logs, temp) */
    PAGE_PRIORITY_COUNT
} page_priority_t;
#define PAGE_PRIORITY_IDLE      4       /* Pages inactives */

/* États des pages pour les politiques */
#define PAGE_STATE_ACTIVE       0x01    /* Page active */
#define PAGE_STATE_INACTIVE     0x02    /* Page inactive */
#define PAGE_STATE_REFERENCED   0x04    /* Page référencée */
#define PAGE_STATE_DIRTY        0x08    /* Page modifiée */
#define PAGE_STATE_LOCKED       0x10    /* Page verrouillée */
#define PAGE_STATE_PINNED       0x20    /* Page épinglée */
#define PAGE_STATE_SHARED       0x40    /* Page partagée */
#define PAGE_STATE_EXECUTABLE   0x80    /* Page exécutable */

/* Constantes de configuration */
#define MAX_WORKING_SET_SIZE    1024    /* Taille max du working set */
#define AGING_SHIFT_COUNT       3       /* Décalages pour aging */
#define CLOCK_HAND_MAX_SCAN     4096    /* Scan max pour clock */
#define PREDICTION_WINDOW       100     /* Fenêtre de prédiction */
#define ADAPTATION_INTERVAL     1000    /* Intervalle d'adaptation */

/* Métriques de performance */
#define METRIC_SWAP_RATE        0x01    /* Taux de swap */
#define METRIC_PAGE_FAULT_RATE  0x02    /* Taux de page faults */
#define METRIC_CACHE_HIT_RATE   0x04    /* Taux de cache hits */
#define METRIC_IO_BANDWIDTH     0x08    /* Bande passante I/O */
#define METRIC_MEMORY_PRESSURE  0x10    /* Pression mémoire */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Métadonnées d'une page pour les politiques
 */
typedef struct page_policy_info {
    /* Identification */
    uint64_t page_frame;                /* Numéro de frame physique */
    uint32_t virt_addr;                 /* Adresse virtuelle */
    uint32_t process_id;                /* ID du processus */
    
    /* État et attributs */
    uint8_t state;                      /* État de la page */
    uint8_t priority;                   /* Priorité */
    uint8_t ref_count;                  /* Compteur de références */
    uint8_t age;                        /* Âge pour algorithme aging */
    
    /* Historique d'accès */
    uint64_t last_access_time;          /* Dernier accès */
    uint64_t creation_time;             /* Temps de création */
    uint32_t access_count;              /* Nombre d'accès */
    uint32_t access_frequency;          /* Fréquence d'accès */
    
    /* Prédiction */
    float prediction_score;             /* Score de prédiction */
    uint32_t predicted_next_access;     /* Prochain accès prédit */
    
    /* Chaînage pour listes */
    struct page_policy_info *next;      /* Suivant dans la liste */
    struct page_policy_info *prev;      /* Précédent dans la liste */
    
    /* Working set */
    bool in_working_set;                /* Dans le working set */
    uint32_t working_set_index;         /* Index dans working set */
    
} page_policy_info_t;

/**
 * @brief Liste LRU pour gestion des pages
 */
typedef struct lru_list {
    page_policy_info_t *head;           /* Tête (plus récent) */
    page_policy_info_t *tail;           /* Queue (plus ancien) */
    uint32_t count;                     /* Nombre d'éléments */
    uint32_t max_count;                 /* Nombre max d'éléments */
} lru_list_t;

/**
 * @brief Clock algorithm state
 */
typedef struct clock_state {
    page_policy_info_t **pages;         /* Tableau circulaire de pages */
    uint32_t hand;                      /* Position de l'aiguille */
    uint32_t size;                      /* Taille du tableau */
    uint32_t count;                     /* Nombre de pages */
} clock_state_t;

/**
 * @brief Working set information
 */
typedef struct working_set {
    page_policy_info_t *pages[MAX_WORKING_SET_SIZE];  /* Pages du working set */
    uint32_t size;                      /* Taille actuelle */
    uint32_t max_size;                  /* Taille maximale */
    uint64_t window_start;              /* Début de la fenêtre */
    uint64_t window_size;               /* Taille de la fenêtre */
    uint32_t access_count;              /* Accès dans la fenêtre */
} working_set_t;

/**
 * @brief Statistiques de performance des politiques
 */
typedef struct policy_stats {
    uint64_t pages_swapped_out;         /* Pages swappées out */
    uint64_t pages_swapped_in;          /* Pages swappées in */
    uint64_t page_faults;               /* Page faults */
    uint64_t cache_hits;                /* Cache hits */
    uint64_t cache_misses;              /* Cache misses */
    uint64_t policy_changes;            /* Changements de politique */
    uint64_t prediction_hits;           /* Prédictions correctes */
    uint64_t prediction_misses;         /* Prédictions incorrectes */
    float avg_swap_latency;             /* Latence moyenne de swap */
    float memory_pressure;              /* Pression mémoire actuelle */
    float efficiency_score;             /* Score d'efficacité */
} policy_stats_t;

/**
 * @brief Interface de politique de swap
 */
typedef struct swap_policy_interface {
    /* Identification */
    char name[64];                      /* Nom de la politique */
    uint32_t type;                      /* Type de politique */
    uint32_t version;                   /* Version */
    
    /* Méthodes principales */
    page_policy_info_t* (*select_victim)(void);
    int (*add_page)(page_policy_info_t *page);
    int (*remove_page)(page_policy_info_t *page);
    int (*update_access)(page_policy_info_t *page);
    int (*update_state)(page_policy_info_t *page, uint8_t new_state);
    
    /* Méthodes de configuration */
    int (*configure)(const char *param, uint32_t value);
    int (*reset)(void);
    void (*get_stats)(policy_stats_t *stats);
    
    /* Données privées */
    void *private_data;                 /* Données spécifiques à la politique */
    uint32_t data_size;                 /* Taille des données privées */
    
} swap_policy_interface_t;

/**
 * @brief Gestionnaire principal des politiques
 */
typedef struct swap_policy_manager {
    /* Politique active */
    swap_policy_interface_t *active_policy;    /* Politique actuellement active */
    uint32_t active_policy_type;        /* Type de politique active */
    
    /* Politiques disponibles */
    swap_policy_interface_t *policies[8];      /* Politiques enregistrées */
    uint32_t policy_count;              /* Nombre de politiques */
    
    /* Pool de pages */
    page_policy_info_t *page_pool;      /* Pool de métadonnées */
    uint32_t pool_size;                 /* Taille du pool */
    
    /* Hash table pour lookup rapide */
    page_policy_info_t **page_hash;     /* Table de hash des pages */
    uint32_t hash_size;                 /* Taille de la table */
    
    /* Configuration */
    bool adaptive_mode;                 /* Mode adaptatif activé */
    uint32_t adaptation_threshold;      /* Seuil d'adaptation */
    uint64_t last_adaptation;           /* Dernière adaptation */
    
    /* Prédiction */
    bool prediction_enabled;            /* Prédiction activée */
    uint32_t prediction_accuracy;       /* Précision de prédiction */
    
} swap_policy_manager_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Gestionnaire principal */
static swap_policy_manager_t policy_mgr;
static bool swap_policy_initialized = false;
static policy_stats_t global_stats;

/* Configuration */
static bool debug_policy = false;
static uint32_t default_policy = SWAP_POLICY_LRU;
static uint32_t adaptation_interval = ADAPTATION_INTERVAL;

/* Timestamp functions */
static uint64_t policy_timestamp_counter = 0;
static inline uint64_t get_policy_timestamp(void) {
    return ++policy_timestamp_counter;
}

/* Synchronization */
#ifdef CONFIG_SMP
/* Spinlock definitions moved to mm_common.h */
static mm_spinlock_t policy_lock = MM_SPINLOCK_INIT("unknown");
#define POLICY_LOCK() mm_spin_lock(&policy_lock)
#define POLICY_UNLOCK() mm_spin_unlock(&policy_lock)
#else
#define POLICY_LOCK() do {} while(0)
#define POLICY_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * PAGE POOL MANAGEMENT
 * ======================================================================== */

/**
 * @brief Alloue une structure de métadonnées de page
 * @return Pointeur vers métadonnées ou NULL
 */
static page_policy_info_t *alloc_page_info(void) {
    page_policy_info_t *info = NULL;
    
    POLICY_LOCK();
    
    if (policy_mgr.page_pool) {
        info = policy_mgr.page_pool;
        policy_mgr.page_pool = info->next;
        policy_mgr.pool_size--;
    }
    
    POLICY_UNLOCK();
    
    if (!info) {
        info = (page_policy_info_t *)kmalloc(sizeof(page_policy_info_t));
    }
    
    if (info) {
        memset(info, 0, sizeof(page_policy_info_t));
        info->creation_time = get_policy_timestamp();
        info->last_access_time = info->creation_time;
        info->priority = PAGE_PRIORITY_NORMAL;
        info->state = PAGE_STATE_ACTIVE;
    }
    
    return info;
}

/**
 * @brief Libère une structure de métadonnées de page
 * @param info Métadonnées à libérer
 */
static void free_page_info(page_policy_info_t *info) {
    if (!info) return;
    
    POLICY_LOCK();
    
    /* Retourner au pool si pas trop gros */
    if (policy_mgr.pool_size < 128) {
        info->next = policy_mgr.page_pool;
        policy_mgr.page_pool = info;
        policy_mgr.pool_size++;
    } else {
        kfree(info);
    }
    
    POLICY_UNLOCK();
}

/**
 * @brief Hash function pour la table de pages
 * @param page_frame Numéro de frame
 * @return Hash value
 */
static uint32_t hash_page_frame(uint64_t page_frame) {
    return (uint32_t)(page_frame % policy_mgr.hash_size);
}

/**
 * @brief Trouve les métadonnées d'une page
 * @param page_frame Numéro de frame
 * @return Pointeur vers métadonnées ou NULL
 */
static page_policy_info_t *find_page_info(uint64_t page_frame) {
    if (!policy_mgr.page_hash) {
        return NULL;
    }
    
    uint32_t hash = hash_page_frame(page_frame);
    page_policy_info_t *info = policy_mgr.page_hash[hash];
    
    while (info) {
        if (info->page_frame == page_frame) {
            return info;
        }
        info = info->next;
    }
    
    return NULL;
}

/**
 * @brief Ajoute une page à la hash table
 * @param info Métadonnées de la page
 */
static void add_page_to_hash(page_policy_info_t *info) {
    if (!info || !policy_mgr.page_hash) {
        return;
    }
    
    uint32_t hash = hash_page_frame(info->page_frame);
    info->next = policy_mgr.page_hash[hash];
    policy_mgr.page_hash[hash] = info;
}

/**
 * @brief Retire une page de la hash table
 * @param info Métadonnées de la page
 */
static void remove_page_from_hash(page_policy_info_t *info) {
    if (!info || !policy_mgr.page_hash) {
        return;
    }
    
    uint32_t hash = hash_page_frame(info->page_frame);
    page_policy_info_t **current = &policy_mgr.page_hash[hash];
    
    while (*current) {
        if (*current == info) {
            *current = info->next;
            info->next = NULL;
            break;
        }
        current = &(*current)->next;
    }
}

/* ========================================================================
 * LRU POLICY IMPLEMENTATION
 * ======================================================================== */

/* Données privées pour LRU */
typedef struct lru_private_data {
    lru_list_t active_list;             /* Liste des pages actives */
    lru_list_t inactive_list;           /* Liste des pages inactives */
    uint32_t max_active;                /* Max pages actives */
    uint32_t max_inactive;              /* Max pages inactives */
} lru_private_data_t;

/**
 * @brief Ajoute une page à une liste LRU
 * @param list Liste cible
 * @param page Page à ajouter
 */
static void lru_add_page_to_list(lru_list_t *list, page_policy_info_t *page) {
    if (!list || !page || list->count >= list->max_count) {
        return;
    }
    
    page->next = list->head;
    page->prev = NULL;
    
    if (list->head) {
        list->head->prev = page;
    } else {
        list->tail = page;
    }
    
    list->head = page;
    list->count++;
}

/**
 * @brief Retire une page d'une liste LRU
 * @param list Liste source
 * @param page Page à retirer
 */
static void lru_remove_page_from_list(lru_list_t *list, page_policy_info_t *page) {
    if (!list || !page) {
        return;
    }
    
    if (page->prev) {
        page->prev->next = page->next;
    } else {
        list->head = page->next;
    }
    
    if (page->next) {
        page->next->prev = page->prev;
    } else {
        list->tail = page->prev;
    }
    
    page->next = NULL;
    page->prev = NULL;
    list->count--;
}

/**
 * @brief Sélectionne une victime avec l'algorithme LRU
 * @return Pointeur vers page victime ou NULL
 */
static page_policy_info_t *lru_select_victim(void) {
    if (!policy_mgr.active_policy || !policy_mgr.active_policy->private_data) {
        return NULL;
    }
    
    lru_private_data_t *lru_data = (lru_private_data_t *)policy_mgr.active_policy->private_data;
    
    /* Chercher d'abord dans la liste inactive */
    if (lru_data->inactive_list.tail) {
        page_policy_info_t *victim = lru_data->inactive_list.tail;
        
        /* Vérifier que la page peut être swappée */
        if (!(victim->state & (PAGE_STATE_LOCKED | PAGE_STATE_PINNED))) {
            return victim;
        }
    }
    
    /* Si pas de victime inactive, prendre de la liste active */
    if (lru_data->active_list.tail) {
        page_policy_info_t *victim = lru_data->active_list.tail;
        
        if (!(victim->state & (PAGE_STATE_LOCKED | PAGE_STATE_PINNED))) {
            return victim;
        }
    }
    
    return NULL;
}

/**
 * @brief Ajoute une page avec l'algorithme LRU
 * @param page Page à ajouter
 * @return 0 en cas de succès
 */
static int lru_add_page(page_policy_info_t *page) {
    if (!page || !policy_mgr.active_policy || !policy_mgr.active_policy->private_data) {
        return -1;
    }
    
    lru_private_data_t *lru_data = (lru_private_data_t *)policy_mgr.active_policy->private_data;
    
    /* Ajouter à la liste active */
    lru_add_page_to_list(&lru_data->active_list, page);
    page->state |= PAGE_STATE_ACTIVE;
    
    return 0;
}

/**
 * @brief Met à jour l'accès d'une page avec LRU
 * @param page Page accédée
 * @return 0 en cas de succès
 */
static int lru_update_access(page_policy_info_t *page) {
    if (!page || !policy_mgr.active_policy || !policy_mgr.active_policy->private_data) {
        return -1;
    }
    
    lru_private_data_t *lru_data = (lru_private_data_t *)policy_mgr.active_policy->private_data;
    
    page->last_access_time = get_policy_timestamp();
    page->access_count++;
    page->state |= PAGE_STATE_REFERENCED;
    
    /* Déplacer vers la tête de la liste appropriée */
    if (page->state & PAGE_STATE_ACTIVE) {
        lru_remove_page_from_list(&lru_data->active_list, page);
        lru_add_page_to_list(&lru_data->active_list, page);
    } else {
        /* Promouvoir de inactive à active */
        lru_remove_page_from_list(&lru_data->inactive_list, page);
        lru_add_page_to_list(&lru_data->active_list, page);
        page->state |= PAGE_STATE_ACTIVE;
        page->state &= ~PAGE_STATE_INACTIVE;
    }
    
    return 0;
}

/* ========================================================================
 * CLOCK POLICY IMPLEMENTATION
 * ======================================================================== */

/* Données privées pour Clock */
typedef struct clock_private_data {
    clock_state_t clock;                /* État de l'algorithme clock */
    uint32_t scan_limit;                /* Limite de scan */
} clock_private_data_t;

/**
 * @brief Sélectionne une victime avec l'algorithme Clock
 * @return Pointeur vers page victime ou NULL
 */
static page_policy_info_t *clock_select_victim(void) {
    if (!policy_mgr.active_policy || !policy_mgr.active_policy->private_data) {
        return NULL;
    }
    
    clock_private_data_t *clock_data = (clock_private_data_t *)policy_mgr.active_policy->private_data;
    clock_state_t *clock = &clock_data->clock;
    
    uint32_t scanned = 0;
    uint32_t start_hand = clock->hand;
    
    do {
        if (clock->pages[clock->hand]) {
            page_policy_info_t *page = clock->pages[clock->hand];
            
            /* Vérifier le bit de référence */
            if (page->state & PAGE_STATE_REFERENCED) {
                /* Donner une seconde chance */
                page->state &= ~PAGE_STATE_REFERENCED;
            } else if (!(page->state & (PAGE_STATE_LOCKED | PAGE_STATE_PINNED))) {
                /* Page victime trouvée */
                return page;
            }
        }
        
        /* Avancer l'aiguille */
        clock->hand = (clock->hand + 1) % clock->size;
        scanned++;
        
    } while (scanned < clock_data->scan_limit && clock->hand != start_hand);
    
    return NULL;
}

/* ========================================================================
 * WORKING SET POLICY IMPLEMENTATION
 * ======================================================================== */

/* Données privées pour Working Set */
typedef struct ws_private_data {
    working_set_t working_set;          /* Working set actuel */
    uint64_t window_size;               /* Taille de la fenêtre */
    uint32_t theta;                     /* Paramètre theta */
} ws_private_data_t;

/**
 * @brief Met à jour le working set
 * @param ws_data Données working set
 */
static void update_working_set(ws_private_data_t *ws_data) {
    working_set_t *ws = &ws_data->working_set;
    uint64_t current_time = get_policy_timestamp();
    
    /* Retirer les pages trop anciennes */
    for (uint32_t i = 0; i < ws->size; i++) {
        page_policy_info_t *page = ws->pages[i];
        
        if (page && (current_time - page->last_access_time) > ws_data->window_size) {
            /* Retirer du working set */
            ws->pages[i] = ws->pages[ws->size - 1];
            ws->pages[ws->size - 1] = NULL;
            ws->size--;
            page->in_working_set = false;
            i--; /* Réexaminer cette position */
        }
    }
    
    ws->window_start = current_time - ws_data->window_size;
}

/**
 * @brief Sélectionne une victime avec Working Set
 * @return Pointeur vers page victime ou NULL
 */
static page_policy_info_t *ws_select_victim(void) {
    if (!policy_mgr.active_policy || !policy_mgr.active_policy->private_data) {
        return NULL;
    }
    
    ws_private_data_t *ws_data = (ws_private_data_t *)policy_mgr.active_policy->private_data;
    
    /* Mettre à jour le working set */
    update_working_set(ws_data);
    
    /* Chercher une page hors du working set */
    for (uint32_t i = 0; i < policy_mgr.hash_size; i++) {
        page_policy_info_t *page = policy_mgr.page_hash[i];
        
        while (page) {
            if (!page->in_working_set && 
                !(page->state & (PAGE_STATE_LOCKED | PAGE_STATE_PINNED))) {
                return page;
            }
            page = page->next;
        }
    }
    
    return NULL;
}

/* ========================================================================
 * ADAPTIVE POLICY SELECTION
 * ======================================================================== */

/**
 * @brief Évalue la performance d'une politique
 * @param policy Politique à évaluer
 * @return Score de performance
 */
static float evaluate_policy_performance(swap_policy_interface_t *policy) {
    if (!policy) {
        return 0.0f;
    }
    
    policy_stats_t stats;
    policy->get_stats(&stats);
    
    /* Calculer un score basé sur plusieurs métriques */
    float hit_rate = 0.0f;
    if (stats.cache_hits + stats.cache_misses > 0) {
        hit_rate = (float)stats.cache_hits / (stats.cache_hits + stats.cache_misses);
    }
    
    float fault_rate = (float)stats.page_faults / (stats.pages_swapped_in + stats.pages_swapped_out + 1);
    float efficiency = stats.efficiency_score;
    
    /* Score composite */
    float score = (hit_rate * 0.4f) + ((1.0f - fault_rate) * 0.3f) + (efficiency * 0.3f);
    
    return score;
}

/**
 * @brief Sélectionne la meilleure politique adaptative
 * @return Type de politique recommandée
 */
static uint32_t select_adaptive_policy(void) {
    float best_score = 0.0f;
    uint32_t best_policy = SWAP_POLICY_LRU;
    
    /* Évaluer toutes les politiques disponibles */
    for (uint32_t i = 0; i < policy_mgr.policy_count; i++) {
        if (policy_mgr.policies[i]) {
            float score = evaluate_policy_performance(policy_mgr.policies[i]);
            
            if (score > best_score) {
                best_score = score;
                best_policy = policy_mgr.policies[i]->type;
            }
        }
    }
    
    /* Prendre en compte la pression mémoire */
    if (global_stats.memory_pressure > 0.8f) {
        /* Haute pression - favoriser LRU strict */
        best_policy = SWAP_POLICY_LRU;
    } else if (global_stats.memory_pressure < 0.3f) {
        /* Faible pression - working set peut être plus efficace */
        best_policy = SWAP_POLICY_WORKING_SET;
    }
    
    return best_policy;
}

/**
 * @brief Adapte la politique selon les conditions actuelles
 */
static void adapt_policy(void) {
    if (!policy_mgr.adaptive_mode) {
        return;
    }
    
    uint64_t current_time = get_policy_timestamp();
    
    if (current_time - policy_mgr.last_adaptation < adaptation_interval) {
        return;
    }
    
    uint32_t recommended_policy = select_adaptive_policy();
    
    if (recommended_policy != policy_mgr.active_policy_type) {
        if (debug_policy) {
            printk(KERN_INFO "Adapting swap policy from %u to %u\n",
                   policy_mgr.active_policy_type, recommended_policy);
        }
        
        swap_policy_set_active(recommended_policy);
        global_stats.policy_changes++;
    }
    
    policy_mgr.last_adaptation = current_time;
}

/* ========================================================================
 * HIGH-LEVEL POLICY INTERFACE
 * ======================================================================== */

/**
 * @brief Sélectionne une page victime selon la politique active
 * @return Pointeur vers page victime ou NULL
 */
page_policy_info_t *swap_policy_select_victim(void) {
    if (!swap_policy_initialized || !policy_mgr.active_policy) {
        return NULL;
    }
    
    /* Adaptation si nécessaire */
    adapt_policy();
    
    POLICY_LOCK();
    page_policy_info_t *victim = policy_mgr.active_policy->select_victim();
    POLICY_UNLOCK();
    
    if (victim && debug_policy) {
        printk(KERN_DEBUG "Selected victim page: frame=%llu, age=%u, access_count=%u\n",
               victim->page_frame, victim->age, victim->access_count);
    }
    
    return victim;
}

/**
 * @brief Ajoute une page au gestionnaire de politique
 * @param page_frame Numéro de frame physique
 * @param virt_addr Adresse virtuelle
 * @param process_id ID du processus
 * @return 0 en cas de succès
 */
int swap_policy_add_page(uint64_t page_frame, uint32_t virt_addr, uint32_t process_id) {
    if (!swap_policy_initialized || !policy_mgr.active_policy) {
        return -1;
    }
    
    /* Vérifier si la page existe déjà */
    POLICY_LOCK();
    page_policy_info_t *existing = find_page_info(page_frame);
    POLICY_UNLOCK();
    
    if (existing) {
        return 0; /* Déjà présente */
    }
    
    /* Allouer nouvelles métadonnées */
    page_policy_info_t *info = alloc_page_info();
    if (!info) {
        return -1;
    }
    
    /* Initialiser */
    info->page_frame = page_frame;
    info->virt_addr = virt_addr;
    info->process_id = process_id;
    
    POLICY_LOCK();
    
    /* Ajouter à la hash table */
    add_page_to_hash(info);
    
    /* Ajouter à la politique active */
    int result = policy_mgr.active_policy->add_page(info);
    
    POLICY_UNLOCK();
    
    if (result != 0) {
        remove_page_from_hash(info);
        free_page_info(info);
        return result;
    }
    
    if (debug_policy) {
        printk(KERN_DEBUG "Added page to policy: frame=%llu, virt=%x, pid=%u\n",
               page_frame, virt_addr, process_id);
    }
    
    return 0;
}

/**
 * @brief Met à jour l'accès à une page
 * @param page_frame Numéro de frame physique
 * @return 0 en cas de succès
 */
int swap_policy_update_access(uint64_t page_frame) {
    if (!swap_policy_initialized || !policy_mgr.active_policy) {
        return -1;
    }
    
    POLICY_LOCK();
    page_policy_info_t *info = find_page_info(page_frame);
    POLICY_UNLOCK();
    
    if (!info) {
        return -1;
    }
    
    POLICY_LOCK();
    int result = policy_mgr.active_policy->update_access(info);
    POLICY_UNLOCK();
    
    return result;
}

/**
 * @brief Retire une page du gestionnaire de politique
 * @param page_frame Numéro de frame physique
 * @return 0 en cas de succès
 */
int swap_policy_remove_page(uint64_t page_frame) {
    if (!swap_policy_initialized || !policy_mgr.active_policy) {
        return -1;
    }
    
    POLICY_LOCK();
    page_policy_info_t *info = find_page_info(page_frame);
    
    if (info) {
        policy_mgr.active_policy->remove_page(info);
        remove_page_from_hash(info);
        free_page_info(info);
    }
    
    POLICY_UNLOCK();
    
    return info ? 0 : -1;
}

/* ========================================================================
 * POLICY REGISTRATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise la politique LRU
 * @return Interface de politique ou NULL
 */
static swap_policy_interface_t *init_lru_policy(void) {
    swap_policy_interface_t *policy = (swap_policy_interface_t *)
        kmalloc(sizeof(swap_policy_interface_t));
    
    if (!policy) {
        return NULL;
    }
    
    /* Allouer données privées */
    lru_private_data_t *lru_data = (lru_private_data_t *)
        kmalloc(sizeof(lru_private_data_t));
    
    if (!lru_data) {
        kfree(policy);
        return NULL;
    }
    
    memset(policy, 0, sizeof(swap_policy_interface_t));
    memset(lru_data, 0, sizeof(lru_private_data_t));
    
    /* Configuration de la politique */
    strcpy(policy->name, "LRU");
    policy->type = SWAP_POLICY_LRU;
    policy->version = 1;
    
    /* Méthodes */
    policy->select_victim = lru_select_victim;
    policy->add_page = lru_add_page;
    policy->update_access = lru_update_access;
    
    /* Données privées */
    lru_data->active_list.max_count = 1024;
    lru_data->inactive_list.max_count = 2048;
    lru_data->max_active = 1024;
    lru_data->max_inactive = 2048;
    
    policy->private_data = lru_data;
    policy->data_size = sizeof(lru_private_data_t);
    
    return policy;
}

/**
 * @brief Définit la politique active
 * @param policy_type Type de politique
 * @return 0 en cas de succès
 */
int swap_policy_set_active(uint32_t policy_type) {
    if (!swap_policy_initialized) {
        return -1;
    }
    
    /* Chercher la politique */
    swap_policy_interface_t *policy = NULL;
    for (uint32_t i = 0; i < policy_mgr.policy_count; i++) {
        if (policy_mgr.policies[i] && policy_mgr.policies[i]->type == policy_type) {
            policy = policy_mgr.policies[i];
            break;
        }
    }
    
    if (!policy) {
        return -1;
    }
    
    POLICY_LOCK();
    policy_mgr.active_policy = policy;
    policy_mgr.active_policy_type = policy_type;
    POLICY_UNLOCK();
    
    printk(KERN_INFO "Switched to swap policy: %s\n", policy->name);
    
    return 0;
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise le gestionnaire de politiques de swap
 * @return 0 en cas de succès
 */
int swap_policy_init(void) {
    if (swap_policy_initialized) {
        printk(KERN_WARNING "Swap policy manager already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing swap policy manager\n");
    
    /* Initialiser la structure principale */
    memset(&policy_mgr, 0, sizeof(policy_mgr));
    memset(&global_stats, 0, sizeof(global_stats));
    
    /* Allouer la hash table */
    policy_mgr.hash_size = 1024;
    policy_mgr.page_hash = (page_policy_info_t **)
        kmalloc(policy_mgr.hash_size * sizeof(page_policy_info_t *));
    
    if (!policy_mgr.page_hash) {
        printk(KERN_ERR "Failed to allocate page hash table\n");
        return -1;
    }
    
    memset(policy_mgr.page_hash, 0, policy_mgr.hash_size * sizeof(page_policy_info_t *));
    
    /* Configuration par défaut */
    policy_mgr.adaptive_mode = true;
    policy_mgr.adaptation_threshold = 100;
    policy_mgr.prediction_enabled = true;
    
    /* Initialiser la politique LRU par défaut */
    swap_policy_interface_t *lru_policy = init_lru_policy();
    if (!lru_policy) {
        printk(KERN_ERR "Failed to initialize LRU policy\n");
        kfree(policy_mgr.page_hash);
        return -1;
    }
    
    /* Enregistrer LRU */
    policy_mgr.policies[0] = lru_policy;
    policy_mgr.policy_count = 1;
    policy_mgr.active_policy = lru_policy;
    policy_mgr.active_policy_type = SWAP_POLICY_LRU;
    
    swap_policy_initialized = true;
    
    printk(KERN_INFO "Swap policy manager initialized\n");
    printk(KERN_INFO "  Default policy: %s\n", lru_policy->name);
    printk(KERN_INFO "  Hash table size: %u\n", policy_mgr.hash_size);
    printk(KERN_INFO "  Adaptive mode: %s\n", policy_mgr.adaptive_mode ? "enabled" : "disabled");
    printk(KERN_INFO "  Prediction: %s\n", policy_mgr.prediction_enabled ? "enabled" : "disabled");
    
    return 0;
}

/**
 * @brief Obtient les statistiques des politiques
 * @param stats Pointeur vers structure de statistiques
 */
void swap_policy_get_stats(policy_stats_t *stats) {
    if (!stats || !swap_policy_initialized) {
        return;
    }
    
    POLICY_LOCK();
    memcpy(stats, &global_stats, sizeof(policy_stats_t));
    POLICY_UNLOCK();
}

/**
 * @brief Affiche les statistiques des politiques
 */
void swap_policy_print_stats(void) {
    if (!swap_policy_initialized) {
        printk(KERN_INFO "Swap policy manager not initialized\n");
        return;
    }
    
    printk(KERN_INFO "Swap Policy Statistics:\n");
    printk(KERN_INFO "  Active policy:        %s\n", 
           policy_mgr.active_policy ? policy_mgr.active_policy->name : "None");
    printk(KERN_INFO "  Pages swapped out:    %llu\n", global_stats.pages_swapped_out);
    printk(KERN_INFO "  Pages swapped in:     %llu\n", global_stats.pages_swapped_in);
    printk(KERN_INFO "  Page faults:          %llu\n", global_stats.page_faults);
    printk(KERN_INFO "  Cache hits:           %llu\n", global_stats.cache_hits);
    printk(KERN_INFO "  Cache misses:         %llu\n", global_stats.cache_misses);
    printk(KERN_INFO "  Policy changes:       %llu\n", global_stats.policy_changes);
    printk(KERN_INFO "  Prediction hits:      %llu\n", global_stats.prediction_hits);
    printk(KERN_INFO "  Prediction misses:    %llu\n", global_stats.prediction_misses);
    printk(KERN_INFO "  Avg swap latency:     %.2f\n", global_stats.avg_swap_latency);
    printk(KERN_INFO "  Memory pressure:      %.2f\n", global_stats.memory_pressure);
    printk(KERN_INFO "  Efficiency score:     %.2f\n", global_stats.efficiency_score);
}

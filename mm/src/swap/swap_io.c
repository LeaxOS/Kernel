/**
 * @file swap_io.c
 * @brief Gestionnaire d'I/O pour le système de swap de LeaxOS
 * 
 * Ce fichier implémente les opérations d'entrée/sortie pour le système
 * de swap, incluant la communication avec les drivers de stockage,
 * l'optimisation des accès disque, et la gestion des erreurs I/O.
 * 
 * Fonctionnalités principales:
 * - Interface avec les drivers de stockage bloc
 * - Gestion asynchrone des I/O
 * - Optimisation des accès séquentiels et clustering
 * - Gestion des erreurs et retry automatique
 * - Support pour différents types de stockage
 * - Statistiques détaillées des performances I/O
 * - Mécanismes de priorité et QoS
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
 * SWAP I/O CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/* Constantes d'I/O */
#define MAX_SWAP_IO_REQUESTS    256     /* Requêtes I/O max en cours */
#define SWAP_IO_TIMEOUT         30000   /* Timeout I/O en ms */
#define MAX_RETRY_COUNT         3       /* Tentatives max en cas d'erreur */
#define CLUSTER_SIZE_MAX        32      /* Taille max d'un cluster */
#define IO_QUEUE_SIZE           128     /* Taille des queues I/O */

/* Types de requêtes I/O */
#define IO_TYPE_READ            0x01    /* Lecture */
#define IO_TYPE_WRITE           0x02    /* Écriture */
#define IO_TYPE_DISCARD         0x04    /* Discard/TRIM */
#define IO_TYPE_SYNC            0x08    /* Synchronisation */
#define IO_TYPE_READAHEAD       0x10    /* Lecture anticipée */

/* États des requêtes I/O */
#define IO_STATE_PENDING        0x01    /* En attente */
#define IO_STATE_SUBMITTED      0x02    /* Soumise au driver */
#define IO_STATE_COMPLETED      0x04    /* Complétée */
#define IO_STATE_ERROR          0x08    /* Erreur */
#define IO_STATE_TIMEOUT        0x10    /* Timeout */
#define IO_STATE_CANCELLED      0x20    /* Annulée */

/* Priorités I/O */
#define IO_PRIORITY_CRITICAL    0       /* Critique (page fault) */
#define IO_PRIORITY_HIGH        1       /* Haute */
#define IO_PRIORITY_NORMAL      2       /* Normale */
#define IO_PRIORITY_LOW         3       /* Basse (readahead) */
#define IO_PRIORITY_IDLE        4       /* Idle */

/* Flags de configuration */
#define IO_FLAG_ASYNC           0x01    /* I/O asynchrone */
#define IO_FLAG_SYNC            0x02    /* I/O synchrone */
#define IO_FLAG_ORDERED         0x04    /* Ordre garanti */
#define IO_FLAG_BARRIER         0x08    /* Barrière I/O */
#define IO_FLAG_DIRECT          0x10    /* Accès direct (bypass cache) */

/* ========================================================================
 * DATA STRUCTURES
 * ======================================================================== */

/**
 * @brief Requête d'I/O swap
 */
typedef struct swap_io_request {
    /* Identification */
    uint32_t request_id;                /* ID unique de la requête */
    uint32_t device_id;                 /* ID du device cible */
    
    /* Type et flags */
    uint8_t io_type;                    /* Type d'I/O */
    uint8_t priority;                   /* Priorité */
    uint16_t flags;                     /* Flags de configuration */
    
    /* Paramètres I/O */
    uint64_t offset;                    /* Offset dans le device (en secteurs) */
    uint32_t page_count;                /* Nombre de pages */
    void **page_buffers;                /* Buffers des pages */
    
    /* État et timing */
    uint8_t state;                      /* État actuel */
    uint8_t retry_count;                /* Nombre de tentatives */
    uint64_t submit_time;               /* Temps de soumission */
    uint64_t complete_time;             /* Temps de completion */
    
    /* Résultat */
    int result;                         /* Code de résultat */
    uint32_t bytes_transferred;         /* Octets transférés */
    
    /* Callback et contexte */
    void (*callback)(struct swap_io_request *req);  /* Callback de completion */
    void *private_data;                 /* Données privées */
    
    /* Chaînage */
    struct swap_io_request *next;       /* Suivant dans la queue */
    struct swap_io_request *prev;       /* Précédent dans la queue */
    
    /* Clustering */
    struct swap_io_request *cluster_head;   /* Tête du cluster */
    uint32_t cluster_size;              /* Taille du cluster */
    
} swap_io_request_t;

/**
 * @brief Interface driver de swap
 */
typedef struct swap_driver_interface {
    /* Identification */
    char name[64];                      /* Nom du driver */
    uint32_t version;                   /* Version */
    uint32_t capabilities;              /* Capacités supportées */
    
    /* Méthodes I/O */
    int (*submit_io)(swap_io_request_t *req);
    int (*cancel_io)(uint32_t request_id);
    int (*sync_device)(uint32_t device_id);
    int (*get_status)(uint32_t device_id);
    
    /* Configuration */
    uint32_t max_request_size;          /* Taille max d'une requête */
    uint32_t max_concurrent_ios;        /* I/O concurrentes max */
    uint32_t sector_size;               /* Taille d'un secteur */
    bool supports_discard;              /* Support DISCARD/TRIM */
    bool supports_barrier;              /* Support barrières I/O */
    
    /* Statistiques driver */
    uint64_t requests_submitted;        /* Requêtes soumises */
    uint64_t requests_completed;        /* Requêtes complétées */
    uint64_t requests_failed;           /* Requêtes échouées */
    uint64_t bytes_read;                /* Octets lus */
    uint64_t bytes_written;             /* Octets écrits */
    
} swap_driver_interface_t;

/**
 * @brief Queue d'I/O avec priorités
 */
typedef struct io_queue {
    swap_io_request_t *head;            /* Tête de la queue */
    swap_io_request_t *tail;            /* Queue de la queue */
    uint32_t count;                     /* Nombre de requêtes */
    uint32_t max_count;                 /* Nombre max de requêtes */
    uint8_t priority;                   /* Priorité de la queue */
} io_queue_t;

/**
 * @brief Gestionnaire d'I/O swap
 */
typedef struct swap_io_manager {
    /* Queues par priorité */
    io_queue_t priority_queues[5];      /* Queues par priorité */
    uint32_t total_pending;             /* Total des requêtes en attente */
    
    /* Pool de requêtes */
    swap_io_request_t *request_pool;    /* Pool de requêtes */
    uint32_t pool_size;                 /* Taille du pool */
    uint32_t next_request_id;           /* Prochain ID de requête */
    
    /* Interface driver */
    swap_driver_interface_t *driver;    /* Interface driver actuelle */
    
    /* Configuration */
    bool async_io_enabled;              /* I/O asynchrone activé */
    bool clustering_enabled;            /* Clustering activé */
    uint32_t max_cluster_size;          /* Taille max des clusters */
    uint32_t io_timeout;                /* Timeout I/O */
    
    /* Thread de traitement */
    bool io_thread_running;             /* Thread I/O actif */
    
} swap_io_manager_t;

/**
 * @brief Statistiques d'I/O swap
 */
typedef struct {
    uint64_t total_ios;                 /* I/O totales */
    uint64_t read_ios;                  /* I/O de lecture */
    uint64_t write_ios;                 /* I/O d'écriture */
    uint64_t discard_ios;               /* I/O de discard */
    uint64_t sync_ios;                  /* I/O de sync */
    uint64_t bytes_read;                /* Octets lus */
    uint64_t bytes_written;             /* Octets écrits */
    uint64_t io_errors;                 /* Erreurs I/O */
    uint64_t io_timeouts;               /* Timeouts I/O */
    uint64_t io_retries;                /* Tentatives de retry */
    uint64_t clustered_ios;             /* I/O clusterisées */
    uint64_t total_io_time;             /* Temps total I/O */
    uint64_t avg_io_latency;            /* Latence moyenne */
    uint64_t max_io_latency;            /* Latence max */
    uint32_t current_queue_depth;       /* Profondeur de queue actuelle */
    uint32_t max_queue_depth;           /* Profondeur de queue max */
} swap_io_stats_t;

/* ========================================================================
 * GLOBAL VARIABLES
 * ======================================================================== */

/* Gestionnaire principal */
static swap_io_manager_t io_mgr;
static bool swap_io_initialized = false;
static swap_io_stats_t io_stats;

/* Configuration */
static bool debug_io = false;
static uint32_t default_io_timeout = SWAP_IO_TIMEOUT;
static uint32_t default_cluster_size = 8;

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
static spinlock_t io_lock = SPINLOCK_INIT;
#define IO_LOCK() spin_lock(&io_lock)
#define IO_UNLOCK() spin_unlock(&io_lock)
#else
#define IO_LOCK() do {} while(0)
#define IO_UNLOCK() do {} while(0)
#endif

/* ========================================================================
 * REQUEST POOL MANAGEMENT
 * ======================================================================== */

/**
 * @brief Alloue une requête I/O depuis le pool
 * @return Pointeur vers requête ou NULL
 */
static swap_io_request_t *alloc_io_request(void) {
    swap_io_request_t *req = NULL;
    
    IO_LOCK();
    
    if (io_mgr.request_pool) {
        req = io_mgr.request_pool;
        io_mgr.request_pool = req->next;
        io_mgr.pool_size--;
    }
    
    IO_UNLOCK();
    
    if (!req) {
        /* Allouer dynamiquement si pool vide */
        req = (swap_io_request_t *)kmalloc(sizeof(swap_io_request_t), GFP_KERNEL);
    }
    
    if (req) {
        memset(req, 0, sizeof(swap_io_request_t));
        req->request_id = __sync_fetch_and_add(&io_mgr.next_request_id, 1);
        req->submit_time = get_timestamp();
        req->state = IO_STATE_PENDING;
    }
    
    return req;
}

/**
 * @brief Libère une requête I/O vers le pool
 * @param req Requête à libérer
 */
static void free_io_request(swap_io_request_t *req) {
    if (!req) return;
    
    /* Libérer les buffers de pages si alloués */
    if (req->page_buffers) {
        kfree(req->page_buffers);
    }
    
    IO_LOCK();
    
    /* Retourner au pool si pas trop gros */
    if (io_mgr.pool_size < 64) {
        req->next = io_mgr.request_pool;
        io_mgr.request_pool = req;
        io_mgr.pool_size++;
    } else {
        kfree(req);
    }
    
    IO_UNLOCK();
}

/* ========================================================================
 * QUEUE MANAGEMENT
 * ======================================================================== */

/**
 * @brief Ajoute une requête à une queue de priorité
 * @param queue Queue cible
 * @param req Requête à ajouter
 */
static void enqueue_io_request(io_queue_t *queue, swap_io_request_t *req) {
    if (!queue || !req) return;
    
    req->next = NULL;
    req->prev = queue->tail;
    
    if (queue->tail) {
        queue->tail->next = req;
    } else {
        queue->head = req;
    }
    
    queue->tail = req;
    queue->count++;
    io_mgr.total_pending++;
    
    if (queue->count > io_stats.max_queue_depth) {
        io_stats.max_queue_depth = queue->count;
    }
}

/**
 * @brief Retire une requête d'une queue
 * @param queue Queue source
 * @return Pointeur vers requête ou NULL
 */
static swap_io_request_t *dequeue_io_request(io_queue_t *queue) {
    if (!queue || !queue->head) {
        return NULL;
    }
    
    swap_io_request_t *req = queue->head;
    
    queue->head = req->next;
    if (queue->head) {
        queue->head->prev = NULL;
    } else {
        queue->tail = NULL;
    }
    
    queue->count--;
    io_mgr.total_pending--;
    
    req->next = NULL;
    req->prev = NULL;
    
    return req;
}

/**
 * @brief Trouve la queue avec la plus haute priorité non vide
 * @return Pointeur vers queue ou NULL
 */
static io_queue_t *get_next_priority_queue(void) {
    for (int i = 0; i < 5; i++) {
        if (io_mgr.priority_queues[i].count > 0) {
            return &io_mgr.priority_queues[i];
        }
    }
    return NULL;
}

/* ========================================================================
 * CLUSTERING OPERATIONS
 * ======================================================================== */

/**
 * @brief Vérifie si deux requêtes peuvent être clusterisées
 * @param req1 Première requête
 * @param req2 Deuxième requête
 * @return true si clusterisables
 */
static bool can_cluster_requests(swap_io_request_t *req1, swap_io_request_t *req2) {
    if (!req1 || !req2) {
        return false;
    }
    
    /* Même device et type d'I/O */
    if (req1->device_id != req2->device_id || req1->io_type != req2->io_type) {
        return false;
    }
    
    /* Même priorité */
    if (req1->priority != req2->priority) {
        return false;
    }
    
    /* Offsets adjacents */
    uint64_t pages_per_sector = PAGE_SIZE / 512; /* Assumer secteurs de 512 bytes */
    if (req1->offset + (req1->page_count * pages_per_sector) != req2->offset) {
        return false;
    }
    
    /* Taille totale acceptable */
    if (req1->page_count + req2->page_count > io_mgr.max_cluster_size) {
        return false;
    }
    
    return true;
}

/**
 * @brief Essaie de clusteriser les requêtes dans une queue
 * @param queue Queue à optimiser
 * @return Nombre de clusters créés
 */
static uint32_t cluster_queue_requests(io_queue_t *queue) {
    if (!io_mgr.clustering_enabled || !queue || queue->count < 2) {
        return 0;
    }
    
    uint32_t clusters_created = 0;
    swap_io_request_t *current = queue->head;
    
    while (current && current->next) {
        swap_io_request_t *next = current->next;
        
        if (can_cluster_requests(current, next)) {
            /* Créer un cluster */
            
            /* Allouer nouveau buffer combiné */
            void **combined_buffers = (void **)kmalloc(
                (current->page_count + next->page_count) * sizeof(void *), 
                GFP_KERNEL);
                
            if (combined_buffers) {
                /* Copier les pointeurs de buffers */
                memcpy(combined_buffers, current->page_buffers, 
                       current->page_count * sizeof(void *));
                memcpy(combined_buffers + current->page_count, next->page_buffers,
                       next->page_count * sizeof(void *));
                
                /* Mettre à jour la requête courante */
                kfree(current->page_buffers);
                current->page_buffers = combined_buffers;
                current->page_count += next->page_count;
                current->cluster_size = current->page_count;
                
                /* Retirer la requête suivante */
                current->next = next->next;
                if (next->next) {
                    next->next->prev = current;
                } else {
                    queue->tail = current;
                }
                
                queue->count--;
                io_mgr.total_pending--;
                
                free_io_request(next);
                clusters_created++;
                
                io_stats.clustered_ios++;
                
                if (debug_io) {
                    printk(KERN_DEBUG "Clustered I/O requests: size=%u pages\n",
                           current->page_count);
                }
            }
        } else {
            current = current->next;
        }
    }
    
    return clusters_created;
}

/* ========================================================================
 * DRIVER INTERFACE
 * ======================================================================== */

/**
 * @brief Soumet une requête au driver
 * @param req Requête à soumettre
 * @return 0 en cas de succès
 */
static int submit_request_to_driver(swap_io_request_t *req) {
    if (!req || !io_mgr.driver || !io_mgr.driver->submit_io) {
        return -1;
    }
    
    req->state = IO_STATE_SUBMITTED;
    req->submit_time = get_timestamp();
    
    int result = io_mgr.driver->submit_io(req);
    
    if (result != 0) {
        req->state = IO_STATE_ERROR;
        req->result = result;
        
        if (debug_io) {
            printk(KERN_ERR "Failed to submit I/O request %u: error=%d\n",
                   req->request_id, result);
        }
        
        io_stats.io_errors++;
    }
    
    return result;
}

/**
 * @brief Callback de completion d'I/O
 * @param req Requête complétée
 */
static void io_completion_callback(swap_io_request_t *req) {
    if (!req) return;
    
    req->complete_time = get_timestamp();
    req->state = IO_STATE_COMPLETED;
    
    /* Calculer latence */
    uint64_t latency = req->complete_time - req->submit_time;
    io_stats.total_io_time += latency;
    io_stats.avg_io_latency = io_stats.total_io_time / io_stats.total_ios;
    
    if (latency > io_stats.max_io_latency) {
        io_stats.max_io_latency = latency;
    }
    
    /* Mettre à jour statistiques par type */
    switch (req->io_type) {
        case IO_TYPE_READ:
            io_stats.read_ios++;
            io_stats.bytes_read += req->bytes_transferred;
            break;
        case IO_TYPE_WRITE:
            io_stats.write_ios++;
            io_stats.bytes_written += req->bytes_transferred;
            break;
        case IO_TYPE_DISCARD:
            io_stats.discard_ios++;
            break;
        case IO_TYPE_SYNC:
            io_stats.sync_ios++;
            break;
    }
    
    io_stats.total_ios++;
    
    if (debug_io) {
        printk(KERN_DEBUG "I/O completed: req=%u, type=%u, latency=%llu, bytes=%u\n",
               req->request_id, req->io_type, latency, req->bytes_transferred);
    }
    
    /* Appeler le callback utilisateur si présent */
    if (req->callback) {
        req->callback(req);
    }
}

/* ========================================================================
 * HIGH-LEVEL I/O OPERATIONS
 * ======================================================================== */

/**
 * @brief Lit une ou plusieurs pages depuis le swap
 * @param device_id ID du device
 * @param offset Offset en pages
 * @param page_count Nombre de pages
 * @param buffers Buffers de destination
 * @param callback Callback de completion (peut être NULL)
 * @param private_data Données privées pour le callback
 * @return ID de la requête ou -1
 */
int swap_io_read_pages(uint32_t device_id, uint64_t offset, uint32_t page_count,
                       void **buffers, void (*callback)(swap_io_request_t *),
                       void *private_data) {
    if (!swap_io_initialized || !buffers || page_count == 0) {
        return -1;
    }
    
    /* Allouer une requête */
    swap_io_request_t *req = alloc_io_request();
    if (!req) {
        return -1;
    }
    
    /* Configurer la requête */
    req->device_id = device_id;
    req->io_type = IO_TYPE_READ;
    req->priority = IO_PRIORITY_NORMAL;
    req->flags = io_mgr.async_io_enabled ? IO_FLAG_ASYNC : IO_FLAG_SYNC;
    req->offset = offset * (PAGE_SIZE / 512); /* Convertir en secteurs */
    req->page_count = page_count;
    req->callback = callback;
    req->private_data = private_data;
    
    /* Allouer et copier les pointeurs de buffers */
    req->page_buffers = (void **)kmalloc(page_count * sizeof(void *), GFP_KERNEL);
    if (!req->page_buffers) {
        free_io_request(req);
        return -1;
    }
    memcpy(req->page_buffers, buffers, page_count * sizeof(void *));
    
    IO_LOCK();
    
    /* Ajouter à la queue appropriée */
    enqueue_io_request(&io_mgr.priority_queues[req->priority], req);
    
    /* Essayer de clusteriser */
    if (io_mgr.clustering_enabled) {
        cluster_queue_requests(&io_mgr.priority_queues[req->priority]);
    }
    
    IO_UNLOCK();
    
    if (debug_io) {
        printk(KERN_DEBUG "Queued read request: req=%u, device=%u, offset=%llu, pages=%u\n",
               req->request_id, device_id, offset, page_count);
    }
    
    return req->request_id;
}

/**
 * @brief Écrit une ou plusieurs pages vers le swap
 * @param device_id ID du device
 * @param offset Offset en pages
 * @param page_count Nombre de pages
 * @param buffers Buffers source
 * @param callback Callback de completion (peut être NULL)
 * @param private_data Données privées pour le callback
 * @return ID de la requête ou -1
 */
int swap_io_write_pages(uint32_t device_id, uint64_t offset, uint32_t page_count,
                        void **buffers, void (*callback)(swap_io_request_t *),
                        void *private_data) {
    if (!swap_io_initialized || !buffers || page_count == 0) {
        return -1;
    }
    
    /* Allouer une requête */
    swap_io_request_t *req = alloc_io_request();
    if (!req) {
        return -1;
    }
    
    /* Configurer la requête */
    req->device_id = device_id;
    req->io_type = IO_TYPE_WRITE;
    req->priority = IO_PRIORITY_NORMAL;
    req->flags = io_mgr.async_io_enabled ? IO_FLAG_ASYNC : IO_FLAG_SYNC;
    req->offset = offset * (PAGE_SIZE / 512); /* Convertir en secteurs */
    req->page_count = page_count;
    req->callback = callback;
    req->private_data = private_data;
    
    /* Allouer et copier les pointeurs de buffers */
    req->page_buffers = (void **)kmalloc(page_count * sizeof(void *), GFP_KERNEL);
    if (!req->page_buffers) {
        free_io_request(req);
        return -1;
    }
    memcpy(req->page_buffers, buffers, page_count * sizeof(void *));
    
    IO_LOCK();
    
    /* Ajouter à la queue appropriée */
    enqueue_io_request(&io_mgr.priority_queues[req->priority], req);
    
    /* Essayer de clusteriser */
    if (io_mgr.clustering_enabled) {
        cluster_queue_requests(&io_mgr.priority_queues[req->priority]);
    }
    
    IO_UNLOCK();
    
    if (debug_io) {
        printk(KERN_DEBUG "Queued write request: req=%u, device=%u, offset=%llu, pages=%u\n",
               req->request_id, device_id, offset, page_count);
    }
    
    return req->request_id;
}

/**
 * @brief Synchronise un device de swap
 * @param device_id ID du device
 * @return 0 en cas de succès
 */
int swap_io_sync_device(uint32_t device_id) {
    if (!swap_io_initialized || !io_mgr.driver || !io_mgr.driver->sync_device) {
        return -1;
    }
    
    return io_mgr.driver->sync_device(device_id);
}

/* ========================================================================
 * I/O THREAD AND PROCESSING
 * ======================================================================== */

/**
 * @brief Thread principal de traitement des I/O
 * Cette fonction simule un thread qui traite les requêtes I/O
 */
static void io_processing_thread(void) {
    while (io_mgr.io_thread_running) {
        IO_LOCK();
        
        /* Traiter les requêtes par ordre de priorité */
        io_queue_t *queue = get_next_priority_queue();
        
        if (queue) {
            swap_io_request_t *req = dequeue_io_request(queue);
            
            if (req) {
                IO_UNLOCK();
                
                /* Soumettre la requête */
                int result = submit_request_to_driver(req);
                
                if (result == 0) {
                    /* Simulation de completion immédiate */
                    req->result = 0;
                    req->bytes_transferred = req->page_count * PAGE_SIZE;
                    io_completion_callback(req);
                } else {
                    /* Gestion d'erreur */
                    req->retry_count++;
                    
                    if (req->retry_count < MAX_RETRY_COUNT) {
                        /* Remettre en queue pour retry */
                        IO_LOCK();
                        enqueue_io_request(queue, req);
                        IO_UNLOCK();
                        io_stats.io_retries++;
                    } else {
                        /* Échec définitif */
                        req->state = IO_STATE_ERROR;
                        io_completion_callback(req);
                        io_stats.io_errors++;
                    }
                }
                
                free_io_request(req);
            } else {
                IO_UNLOCK();
            }
        } else {
            IO_UNLOCK();
            /* Pas de requête - pause courte */
            /* TODO: Utiliser un mécanisme de réveil approprié */
        }
    }
}

/* ========================================================================
 * INITIALIZATION AND MANAGEMENT
 * ======================================================================== */

/**
 * @brief Initialise le gestionnaire d'I/O swap
 * @return 0 en cas de succès
 */
int swap_io_init(void) {
    if (swap_io_initialized) {
        printk(KERN_WARNING "Swap I/O manager already initialized\n");
        return 0;
    }
    
    printk(KERN_INFO "Initializing swap I/O manager\n");
    
    /* Initialiser la structure principale */
    memset(&io_mgr, 0, sizeof(io_mgr));
    memset(&io_stats, 0, sizeof(io_stats));
    
    /* Initialiser les queues de priorité */
    for (int i = 0; i < 5; i++) {
        io_mgr.priority_queues[i].priority = i;
        io_mgr.priority_queues[i].max_count = IO_QUEUE_SIZE;
    }
    
    /* Configuration par défaut */
    io_mgr.async_io_enabled = true;
    io_mgr.clustering_enabled = true;
    io_mgr.max_cluster_size = default_cluster_size;
    io_mgr.io_timeout = default_io_timeout;
    io_mgr.next_request_id = 1;
    
    /* Démarrer le thread de traitement */
    io_mgr.io_thread_running = true;
    
    swap_io_initialized = true;
    
    printk(KERN_INFO "Swap I/O manager initialized\n");
    printk(KERN_INFO "  Max requests: %d\n", MAX_SWAP_IO_REQUESTS);
    printk(KERN_INFO "  Queue size: %d per priority\n", IO_QUEUE_SIZE);
    printk(KERN_INFO "  Async I/O: %s\n", io_mgr.async_io_enabled ? "enabled" : "disabled");
    printk(KERN_INFO "  Clustering: %s\n", io_mgr.clustering_enabled ? "enabled" : "disabled");
    printk(KERN_INFO "  Max cluster size: %u pages\n", io_mgr.max_cluster_size);
    
    return 0;
}

/**
 * @brief Enregistre une interface driver
 * @param driver Interface driver à enregistrer
 * @return 0 en cas de succès
 */
int swap_io_register_driver(swap_driver_interface_t *driver) {
    if (!swap_io_initialized || !driver) {
        return -1;
    }
    
    /* Validation de l'interface */
    if (!driver->submit_io || !driver->name[0]) {
        return -1;
    }
    
    IO_LOCK();
    io_mgr.driver = driver;
    IO_UNLOCK();
    
    printk(KERN_INFO "Registered swap I/O driver: %s v%u\n", 
           driver->name, driver->version);
    
    return 0;
}

/**
 * @brief Obtient les statistiques d'I/O
 * @param stats Pointeur vers structure de statistiques
 */
void swap_io_get_stats(swap_io_stats_t *stats) {
    if (!stats || !swap_io_initialized) {
        return;
    }
    
    IO_LOCK();
    memcpy(stats, &io_stats, sizeof(swap_io_stats_t));
    stats->current_queue_depth = io_mgr.total_pending;
    IO_UNLOCK();
}

/**
 * @brief Affiche les statistiques d'I/O
 */
void swap_io_print_stats(void) {
    if (!swap_io_initialized) {
        printk(KERN_INFO "Swap I/O manager not initialized\n");
        return;
    }
    
    printk(KERN_INFO "Swap I/O Statistics:\n");
    printk(KERN_INFO "  Total I/Os:           %llu\n", io_stats.total_ios);
    printk(KERN_INFO "  Read I/Os:            %llu\n", io_stats.read_ios);
    printk(KERN_INFO "  Write I/Os:           %llu\n", io_stats.write_ios);
    printk(KERN_INFO "  Discard I/Os:         %llu\n", io_stats.discard_ios);
    printk(KERN_INFO "  Sync I/Os:            %llu\n", io_stats.sync_ios);
    printk(KERN_INFO "  Bytes read:           %llu\n", io_stats.bytes_read);
    printk(KERN_INFO "  Bytes written:        %llu\n", io_stats.bytes_written);
    printk(KERN_INFO "  I/O errors:           %llu\n", io_stats.io_errors);
    printk(KERN_INFO "  I/O timeouts:         %llu\n", io_stats.io_timeouts);
    printk(KERN_INFO "  I/O retries:          %llu\n", io_stats.io_retries);
    printk(KERN_INFO "  Clustered I/Os:       %llu\n", io_stats.clustered_ios);
    printk(KERN_INFO "  Avg latency:          %llu units\n", io_stats.avg_io_latency);
    printk(KERN_INFO "  Max latency:          %llu units\n", io_stats.max_io_latency);
    printk(KERN_INFO "  Current queue depth:  %u\n", io_mgr.total_pending);
    printk(KERN_INFO "  Max queue depth:      %u\n", io_stats.max_queue_depth);
}

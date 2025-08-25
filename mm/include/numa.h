/**
 * @file numa.h
 * @brief Interface NUMA (Non-Uniform Memory Access) pour LeaxOS
 * 
 * Ce header définit l'interface pour la gestion NUMA du noyau LeaxOS.
 * Le support NUMA optimise l'accès mémoire en tenant compte de la 
 * topologie physique et des latences entre processeurs et bancs mémoire.
 * 
 * Fonctionnalités :
 * - Détection automatique de la topologie NUMA
 * - Allocation mémoire locale au nœud
 * - Migration automatique de pages
 * - Équilibrage de charge NUMA
 * - Statistiques et monitoring
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_NUMA_H
#define LEAX_KERNEL_MM_NUMA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mm_common.h"

/* ========================================================================
 * NUMA CONSTANTS AND DEFINITIONS
 * ======================================================================== */

/** Maximum number of NUMA nodes supported */
#define MAX_NUMA_NODES          64

/** NUMA node ID type */
typedef int numa_node_t;
#define NUMA_NO_NODE            (-1)

/** NUMA distance values */
#define NUMA_LOCAL_DISTANCE     10      /**< Local node distance */
#define NUMA_REMOTE_DISTANCE    20      /**< Remote node distance */
#define NUMA_VERY_REMOTE_DISTANCE 40    /**< Very remote node distance */

/** NUMA allocation policies */
typedef enum {
    NUMA_POLICY_DEFAULT = 0,    /**< System default policy */
    NUMA_POLICY_BIND,           /**< Bind to specific nodes */
    NUMA_POLICY_INTERLEAVE,     /**< Interleave across nodes */
    NUMA_POLICY_PREFERRED,      /**< Prefer specific node */
    NUMA_POLICY_LOCAL,          /**< Local node only */
    NUMA_POLICY_COUNT
} numa_policy_t;

/** NUMA node states */
typedef enum {
    NUMA_NODE_ONLINE = 0,       /**< Node is online and available */
    NUMA_NODE_OFFLINE,          /**< Node is offline */
    NUMA_NODE_GOING_DOWN,       /**< Node is being taken offline */
    NUMA_NODE_COMING_UP,        /**< Node is coming online */
    NUMA_NODE_UNKNOWN           /**< Node state unknown */
} numa_node_state_t;

/* ========================================================================
 * NUMA DATA STRUCTURES
 * ======================================================================== */

/** NUMA node information */
typedef struct numa_node_info {
    numa_node_t node_id;                /**< Node ID */
    numa_node_state_t state;            /**< Node state */
    
    /* Memory information */
    size_t total_memory;                /**< Total memory in bytes */
    size_t free_memory;                 /**< Free memory in bytes */
    size_t used_memory;                 /**< Used memory in bytes */
    
    /* CPU information */
    uint32_t cpu_count;                 /**< CPUs on this node */
    uint32_t *cpu_list;                 /**< List of CPU IDs */
    
    /* Distance information */
    uint8_t distances[MAX_NUMA_NODES];  /**< Distance to other nodes */
    
    /* Statistics */
    uint64_t alloc_count;               /**< Local allocations */
    uint64_t alloc_miss;                /**< Remote allocations */
    uint64_t free_count;                /**< Local frees */
    uint64_t migration_in;              /**< Pages migrated in */
    uint64_t migration_out;             /**< Pages migrated out */
} numa_node_info_t;

/** NUMA policy structure */
typedef struct numa_policy {
    numa_policy_t policy;               /**< Policy type */
    uint64_t allowed_nodes;             /**< Bitmask of allowed nodes */
    numa_node_t preferred_node;         /**< Preferred node */
    uint32_t flags;                     /**< Policy flags */
} numa_policy_t;

/** NUMA topology information */
typedef struct numa_topology {
    uint32_t node_count;                /**< Number of NUMA nodes */
    numa_node_info_t nodes[MAX_NUMA_NODES]; /**< Node information */
    bool initialized;                   /**< Topology initialized */
    mm_spinlock_t lock;                 /**< Topology lock */
} numa_topology_t;

/* ========================================================================
 * NUMA INTERFACE FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize NUMA subsystem
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_init(void);

/**
 * @brief Shutdown NUMA subsystem
 */
void numa_shutdown(void);

/**
 * @brief Get current NUMA node for calling CPU
 * @return NUMA node ID or NUMA_NO_NODE if not available
 */
numa_node_t numa_node_id(void);

/**
 * @brief Get number of online NUMA nodes
 * @return Number of online nodes
 */
uint32_t numa_num_nodes(void);

/**
 * @brief Check if a NUMA node is online
 * @param node Node ID to check
 * @return true if online, false otherwise
 */
bool numa_node_online(numa_node_t node);

/**
 * @brief Get distance between two NUMA nodes
 * @param from Source node
 * @param to Destination node
 * @return Distance value or 0 if invalid
 */
uint8_t numa_distance(numa_node_t from, numa_node_t to);

/**
 * @brief Allocate memory on specific NUMA node
 * @param size Size in bytes
 * @param node Target node
 * @param flags Allocation flags
 * @return Pointer to allocated memory or NULL
 */
void *numa_alloc_onnode(size_t size, numa_node_t node, gfp_t flags);

/**
 * @brief Allocate memory with NUMA policy
 * @param size Size in bytes
 * @param policy NUMA policy
 * @param flags Allocation flags
 * @return Pointer to allocated memory or NULL
 */
void *numa_alloc_policy(size_t size, numa_policy_t *policy, gfp_t flags);

/**
 * @brief Free NUMA-allocated memory
 * @param ptr Pointer to memory
 */
void numa_free(void *ptr);

/**
 * @brief Set NUMA policy for current process
 * @param policy New policy
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_set_policy(numa_policy_t *policy);

/**
 * @brief Get current NUMA policy
 * @param policy Output policy structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_get_policy(numa_policy_t *policy);

/**
 * @brief Migrate pages to target node
 * @param addr Start address
 * @param size Size of region
 * @param target_node Target node
 * @return Number of pages migrated or negative error
 */
int numa_migrate_pages(void *addr, size_t size, numa_node_t target_node);

/**
 * @brief Get NUMA node for memory address
 * @param addr Memory address
 * @return NUMA node ID or NUMA_NO_NODE
 */
numa_node_t numa_node_of_addr(void *addr);

/* ========================================================================
 * NUMA STATISTICS AND MONITORING
 * ======================================================================== */

/**
 * @brief Get NUMA node information
 * @param node Node ID
 * @param info Output structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_get_node_info(numa_node_t node, numa_node_info_t *info);

/**
 * @brief Print NUMA topology information
 */
void numa_print_topology(void);

/**
 * @brief Print NUMA statistics
 */
void numa_print_stats(void);

/**
 * @brief Get NUMA memory usage by node
 * @param node Node ID
 * @param total Output total memory
 * @param free Output free memory
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_get_memory_info(numa_node_t node, size_t *total, size_t *free);

/* ========================================================================
 * NUMA BALANCING AND OPTIMIZATION
 * ======================================================================== */

/**
 * @brief Enable/disable automatic NUMA balancing
 * @param enable true to enable, false to disable
 */
void numa_set_balancing(bool enable);

/**
 * @brief Check if NUMA balancing is enabled
 * @return true if enabled, false otherwise
 */
bool numa_balancing_enabled(void);

/**
 * @brief Rebalance memory across NUMA nodes
 * @return Number of pages moved
 */
uint64_t numa_rebalance(void);

/**
 * @brief Get optimal NUMA node for allocation
 * @param size Allocation size
 * @param flags Allocation flags
 * @return Optimal node ID
 */
numa_node_t numa_get_optimal_node(size_t size, gfp_t flags);

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_NUMA_H */

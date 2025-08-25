/**
 * @file numa_core.c
 * @brief Implémentation principale du support NUMA pour LeaxOS
 * 
 * Ce fichier implémente la logique principale de gestion NUMA :
 * - Détection de la topologie NUMA
 * - Allocation mémoire locale aux nœuds
 * - Politiques d'allocation NUMA
 * - Migration automatique de pages
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
#include "../../include/numa.h"
#include "../../include/mm.h"
#include "../../include/page_alloc.h"

/* ========================================================================
 * NUMA GLOBAL STATE
 * ======================================================================== */

/** Global NUMA topology */
static numa_topology_t g_numa_topology = {
    .node_count = 0,
    .initialized = false,
    .lock = MM_SPINLOCK_INIT("numa_topology")
};

/** Current NUMA policy (per-process would be better but simplified here) */
static numa_policy_t g_current_policy = {
    .policy = NUMA_POLICY_DEFAULT,
    .allowed_nodes = ~0ULL,  /* All nodes allowed by default */
    .preferred_node = NUMA_NO_NODE,
    .flags = 0
};

/** NUMA statistics */
static struct {
    uint64_t total_allocs;
    uint64_t local_allocs;
    uint64_t remote_allocs;
    uint64_t migrations;
    uint64_t balancing_runs;
} g_numa_stats = {0};

/* NUMA balancing control */
static bool g_numa_balancing_enabled = true;

/* ========================================================================
 * INTERNAL HELPER FUNCTIONS
 * ======================================================================== */

/**
 * @brief Detect NUMA topology from hardware
 * @return MM_SUCCESS on success, error code on failure
 */
static mm_error_t detect_numa_topology(void) {
    /* In a real implementation, this would:
     * 1. Parse ACPI SRAT (System Resource Affinity Table)
     * 2. Read CPU topology from CPUID
     * 3. Detect memory controller configuration
     * 4. Build distance matrix
     * 
     * For now, we'll create a simple topology
     */
    
    mm_spin_lock(&g_numa_topology.lock);
    
    /* Simple topology: assume 2 nodes for demonstration */
    g_numa_topology.node_count = 2;
    
    /* Initialize node 0 */
    numa_node_info_t *node0 = &g_numa_topology.nodes[0];
    node0->node_id = 0;
    node0->state = NUMA_NODE_ONLINE;
    node0->total_memory = 1024 * 1024 * 1024; /* 1GB */
    node0->free_memory = 512 * 1024 * 1024;   /* 512MB */
    node0->used_memory = 512 * 1024 * 1024;   /* 512MB */
    node0->cpu_count = 2;
    node0->distances[0] = NUMA_LOCAL_DISTANCE;
    node0->distances[1] = NUMA_REMOTE_DISTANCE;
    
    /* Initialize node 1 */
    numa_node_info_t *node1 = &g_numa_topology.nodes[1];
    node1->node_id = 1;
    node1->state = NUMA_NODE_ONLINE;
    node1->total_memory = 1024 * 1024 * 1024; /* 1GB */
    node1->free_memory = 768 * 1024 * 1024;   /* 768MB */
    node1->used_memory = 256 * 1024 * 1024;   /* 256MB */
    node1->cpu_count = 2;
    node1->distances[0] = NUMA_REMOTE_DISTANCE;
    node1->distances[1] = NUMA_LOCAL_DISTANCE;
    
    g_numa_topology.initialized = true;
    
    mm_spin_unlock(&g_numa_topology.lock);
    
    printk(KERN_INFO "NUMA: Detected %u nodes\n", g_numa_topology.node_count);
    return MM_SUCCESS;
}

/**
 * @brief Get current CPU's NUMA node
 * @return NUMA node ID
 */
static numa_node_t get_current_cpu_node(void) {
    /* In a real implementation, this would:
     * 1. Get current CPU ID
     * 2. Look up CPU in NUMA topology
     * 3. Return associated node
     * 
     * For simplicity, we'll alternate based on a simple heuristic
     */
    static uint32_t cpu_counter = 0;
    return (cpu_counter++ % g_numa_topology.node_count);
}

/**
 * @brief Select best node for allocation
 * @param size Allocation size
 * @param policy Allocation policy
 * @return Selected node ID
 */
static numa_node_t select_allocation_node(size_t size, numa_policy_t *policy) {
    if (!g_numa_topology.initialized || g_numa_topology.node_count == 0) {
        return NUMA_NO_NODE;
    }
    
    switch (policy->policy) {
    case NUMA_POLICY_LOCAL: {
        numa_node_t current = get_current_cpu_node();
        if (numa_node_online(current)) {
            return current;
        }
        break;
    }
    
    case NUMA_POLICY_PREFERRED:
        if (policy->preferred_node != NUMA_NO_NODE &&
            numa_node_online(policy->preferred_node)) {
            return policy->preferred_node;
        }
        /* Fall through to default */
        
    case NUMA_POLICY_DEFAULT: {
        /* Find node with most free memory */
        numa_node_t best_node = NUMA_NO_NODE;
        size_t best_free = 0;
        
        for (uint32_t i = 0; i < g_numa_topology.node_count; i++) {
            numa_node_info_t *node = &g_numa_topology.nodes[i];
            if (node->state == NUMA_NODE_ONLINE && 
                node->free_memory > best_free &&
                node->free_memory >= size) {
                best_free = node->free_memory;
                best_node = i;
            }
        }
        return best_node;
    }
    
    case NUMA_POLICY_INTERLEAVE: {
        /* Simple round-robin interleaving */
        static uint32_t interleave_next = 0;
        for (uint32_t i = 0; i < g_numa_topology.node_count; i++) {
            numa_node_t node = (interleave_next + i) % g_numa_topology.node_count;
            if (numa_node_online(node)) {
                interleave_next = (node + 1) % g_numa_topology.node_count;
                return node;
            }
        }
        break;
    }
    
    case NUMA_POLICY_BIND:
        /* Check allowed nodes bitmask */
        for (uint32_t i = 0; i < g_numa_topology.node_count; i++) {
            if ((policy->allowed_nodes & (1ULL << i)) &&
                numa_node_online(i)) {
                return i;
            }
        }
        break;
    }
    
    return NUMA_NO_NODE;
}

/* ========================================================================
 * PUBLIC INTERFACE IMPLEMENTATION
 * ======================================================================== */

mm_error_t numa_init(void) {
    printk(KERN_INFO "NUMA: Initializing NUMA subsystem\n");
    
    /* Detect hardware topology */
    mm_error_t result = detect_numa_topology();
    if (result != MM_SUCCESS) {
        printk(KERN_ERR "NUMA: Failed to detect topology\n");
        return result;
    }
    
    /* Initialize per-node data structures */
    for (uint32_t i = 0; i < g_numa_topology.node_count; i++) {
        numa_node_info_t *node = &g_numa_topology.nodes[i];
        node->alloc_count = 0;
        node->alloc_miss = 0;
        node->free_count = 0;
        node->migration_in = 0;
        node->migration_out = 0;
    }
    
    printk(KERN_INFO "NUMA: Initialization complete\n");
    return MM_SUCCESS;
}

void numa_shutdown(void) {
    mm_spin_lock(&g_numa_topology.lock);
    g_numa_topology.initialized = false;
    g_numa_topology.node_count = 0;
    mm_spin_unlock(&g_numa_topology.lock);
    
    printk(KERN_INFO "NUMA: Subsystem shutdown\n");
}

numa_node_t numa_node_id(void) {
    if (!g_numa_topology.initialized) {
        return NUMA_NO_NODE;
    }
    return get_current_cpu_node();
}

uint32_t numa_num_nodes(void) {
    return g_numa_topology.node_count;
}

bool numa_node_online(numa_node_t node) {
    if (node < 0 || node >= (int)g_numa_topology.node_count) {
        return false;
    }
    return g_numa_topology.nodes[node].state == NUMA_NODE_ONLINE;
}

uint8_t numa_distance(numa_node_t from, numa_node_t to) {
    if (!numa_node_online(from) || !numa_node_online(to)) {
        return 0;
    }
    return g_numa_topology.nodes[from].distances[to];
}

void *numa_alloc_onnode(size_t size, numa_node_t node, gfp_t flags) {
    if (!numa_node_online(node)) {
        return NULL;
    }
    
    /* In a real implementation, this would:
     * 1. Call node-specific allocator
     * 2. Update node statistics
     * 3. Track allocation for migration
     */
    
    g_numa_stats.total_allocs++;
    
    numa_node_t current_node = numa_node_id();
    if (current_node == node) {
        g_numa_stats.local_allocs++;
        g_numa_topology.nodes[node].alloc_count++;
    } else {
        g_numa_stats.remote_allocs++;
        g_numa_topology.nodes[node].alloc_miss++;
    }
    
    /* For demonstration, use regular allocation */
    /* In reality, this would allocate from node-specific memory pool */
    void *ptr = kmalloc(size, flags);
    
    if (ptr) {
        g_numa_topology.nodes[node].free_memory -= size;
        g_numa_topology.nodes[node].used_memory += size;
    }
    
    return ptr;
}

void *numa_alloc_policy(size_t size, numa_policy_t *policy, gfp_t flags) {
    numa_policy_t *active_policy = policy ? policy : &g_current_policy;
    
    numa_node_t target_node = select_allocation_node(size, active_policy);
    if (target_node == NUMA_NO_NODE) {
        /* Fallback to any available node */
        for (uint32_t i = 0; i < g_numa_topology.node_count; i++) {
            if (numa_node_online(i)) {
                target_node = i;
                break;
            }
        }
    }
    
    if (target_node == NUMA_NO_NODE) {
        return NULL;
    }
    
    return numa_alloc_onnode(size, target_node, flags);
}

void numa_free(void *ptr) {
    if (!ptr) return;
    
    /* In a real implementation, we would:
     * 1. Determine which node owns this memory
     * 2. Update node statistics
     * 3. Return memory to node-specific pool
     */
    
    /* For now, use regular free */
    kfree(ptr);
}

mm_error_t numa_set_policy(numa_policy_t *policy) {
    if (!policy) {
        return MM_ERROR_INVALID;
    }
    
    g_current_policy = *policy;
    return MM_SUCCESS;
}

mm_error_t numa_get_policy(numa_policy_t *policy) {
    if (!policy) {
        return MM_ERROR_INVALID;
    }
    
    *policy = g_current_policy;
    return MM_SUCCESS;
}

int numa_migrate_pages(void *addr, size_t size, numa_node_t target_node) {
    if (!addr || !numa_node_online(target_node)) {
        return -1;
    }
    
    /* Migration would involve:
     * 1. Identify pages to migrate
     * 2. Allocate target memory on target node
     * 3. Copy page contents
     * 4. Update page tables
     * 5. Free source memory
     */
    
    size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    g_numa_stats.migrations += pages;
    
    /* For demonstration, just update statistics */
    numa_node_t current_node = numa_node_id();
    if (current_node != target_node) {
        g_numa_topology.nodes[current_node].migration_out += pages;
        g_numa_topology.nodes[target_node].migration_in += pages;
    }
    
    return (int)pages;
}

numa_node_t numa_node_of_addr(void *addr) {
    if (!addr) {
        return NUMA_NO_NODE;
    }
    
    /* In a real implementation:
     * 1. Look up physical address
     * 2. Determine which memory controller/node owns it
     * 3. Return node ID
     */
    
    /* For demonstration, simple hashing */
    uintptr_t ptr_val = (uintptr_t)addr;
    return (ptr_val / (1024 * 1024)) % g_numa_topology.node_count;
}

mm_error_t numa_get_node_info(numa_node_t node, numa_node_info_t *info) {
    if (!info || !numa_node_online(node)) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_numa_topology.lock);
    *info = g_numa_topology.nodes[node];
    mm_spin_unlock(&g_numa_topology.lock);
    
    return MM_SUCCESS;
}

void numa_print_topology(void) {
    if (!g_numa_topology.initialized) {
        printk(KERN_INFO "NUMA: Not initialized\n");
        return;
    }
    
    printk(KERN_INFO "NUMA Topology:\n");
    printk(KERN_INFO "  Nodes: %u\n", g_numa_topology.node_count);
    
    for (uint32_t i = 0; i < g_numa_topology.node_count; i++) {
        numa_node_info_t *node = &g_numa_topology.nodes[i];
        printk(KERN_INFO "  Node %d: %s, %zu MB total, %zu MB free\n",
               node->node_id,
               node->state == NUMA_NODE_ONLINE ? "online" : "offline",
               node->total_memory / (1024 * 1024),
               node->free_memory / (1024 * 1024));
    }
}

void numa_print_stats(void) {
    printk(KERN_INFO "NUMA Statistics:\n");
    printk(KERN_INFO "  Total allocations: %llu\n", g_numa_stats.total_allocs);
    printk(KERN_INFO "  Local allocations: %llu (%.1f%%)\n", 
           g_numa_stats.local_allocs,
           g_numa_stats.total_allocs ? 
           (100.0 * g_numa_stats.local_allocs / g_numa_stats.total_allocs) : 0.0);
    printk(KERN_INFO "  Remote allocations: %llu (%.1f%%)\n",
           g_numa_stats.remote_allocs,
           g_numa_stats.total_allocs ?
           (100.0 * g_numa_stats.remote_allocs / g_numa_stats.total_allocs) : 0.0);
    printk(KERN_INFO "  Page migrations: %llu\n", g_numa_stats.migrations);
    printk(KERN_INFO "  Balancing runs: %llu\n", g_numa_stats.balancing_runs);
}

mm_error_t numa_get_memory_info(numa_node_t node, size_t *total, size_t *free) {
    if (!total || !free || !numa_node_online(node)) {
        return MM_ERROR_INVALID;
    }
    
    numa_node_info_t *info = &g_numa_topology.nodes[node];
    *total = info->total_memory;
    *free = info->free_memory;
    
    return MM_SUCCESS;
}

void numa_set_balancing(bool enable) {
    g_numa_balancing_enabled = enable;
    printk(KERN_INFO "NUMA: Balancing %s\n", enable ? "enabled" : "disabled");
}

bool numa_balancing_enabled(void) {
    return g_numa_balancing_enabled;
}

uint64_t numa_rebalance(void) {
    if (!g_numa_balancing_enabled || !g_numa_topology.initialized) {
        return 0;
    }
    
    g_numa_stats.balancing_runs++;
    
    /* Balancing logic would:
     * 1. Identify imbalanced nodes
     * 2. Find pages to migrate
     * 3. Migrate pages to balance load
     * 4. Update statistics
     */
    
    uint64_t pages_moved = 0;
    
    /* Simple balancing: move from most used to least used */
    numa_node_t most_used = NUMA_NO_NODE;
    numa_node_t least_used = NUMA_NO_NODE;
    size_t max_usage = 0;
    size_t min_usage = SIZE_MAX;
    
    for (uint32_t i = 0; i < g_numa_topology.node_count; i++) {
        if (!numa_node_online(i)) continue;
        
        numa_node_info_t *node = &g_numa_topology.nodes[i];
        size_t usage = node->used_memory;
        
        if (usage > max_usage) {
            max_usage = usage;
            most_used = i;
        }
        if (usage < min_usage) {
            min_usage = usage;
            least_used = i;
        }
    }
    
    /* If imbalance is significant, simulate migration */
    if (most_used != NUMA_NO_NODE && least_used != NUMA_NO_NODE &&
        max_usage > min_usage + (64 * 1024 * 1024)) { /* 64MB threshold */
        
        size_t move_amount = (max_usage - min_usage) / 4; /* Move 25% of difference */
        pages_moved = move_amount / PAGE_SIZE;
        
        g_numa_topology.nodes[most_used].used_memory -= move_amount;
        g_numa_topology.nodes[most_used].free_memory += move_amount;
        g_numa_topology.nodes[most_used].migration_out += pages_moved;
        
        g_numa_topology.nodes[least_used].used_memory += move_amount;
        g_numa_topology.nodes[least_used].free_memory -= move_amount;
        g_numa_topology.nodes[least_used].migration_in += pages_moved;
        
        printk(KERN_DEBUG "NUMA: Balanced %llu pages from node %d to node %d\n",
               pages_moved, most_used, least_used);
    }
    
    return pages_moved;
}

numa_node_t numa_get_optimal_node(size_t size, gfp_t flags) {
    return select_allocation_node(size, &g_current_policy);
}

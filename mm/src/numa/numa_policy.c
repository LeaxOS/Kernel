/**
 * @file numa_policy.c
 * @brief NUMA policy management
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
#include "numa.h"
#include "mm.h"

/* ========================================================================
 * NUMA POLICY MANAGEMENT
 * ======================================================================== */

/** Maximum number of policy bindings */
#define MAX_POLICY_BINDINGS     256

/** Policy binding structure */
typedef struct numa_policy_binding {
    uint64_t start_addr;            /**< Start address */
    uint64_t end_addr;              /**< End address */
    numa_policy_t policy;           /**< Associated policy */
    bool active;                    /**< Binding is active */
} numa_policy_binding_t;

/** Global policy bindings */
static numa_policy_binding_t g_policy_bindings[MAX_POLICY_BINDINGS];
static uint32_t g_binding_count = 0;
static mm_spinlock_t g_policy_lock = MM_SPINLOCK_INIT("numa_policy");

/* ========================================================================
 * POLICY MANAGEMENT FUNCTIONS
 * ======================================================================== */

/**
 * @brief Find policy binding for address range
 * @param addr Address to check
 * @return Pointer to binding or NULL if not found
 */
static numa_policy_binding_t *find_policy_binding(uint64_t addr) {
    for (uint32_t i = 0; i < g_binding_count; i++) {
        numa_policy_binding_t *binding = &g_policy_bindings[i];
        if (binding->active &&
            addr >= binding->start_addr &&
            addr < binding->end_addr) {
            return binding;
        }
    }
    return NULL;
}

/**
 * @brief Add new policy binding
 * @param start_addr Start address
 * @param end_addr End address
 * @param policy Policy to bind
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_bind_policy(uint64_t start_addr, uint64_t end_addr, 
                           numa_policy_t *policy) {
    if (!policy || start_addr >= end_addr) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_policy_lock);
    
    if (g_binding_count >= MAX_POLICY_BINDINGS) {
        mm_spin_unlock(&g_policy_lock);
        return MM_ERROR_LIMIT;
    }
    
    /* Check for overlaps */
    for (uint32_t i = 0; i < g_binding_count; i++) {
        numa_policy_binding_t *existing = &g_policy_bindings[i];
        if (existing->active &&
            !((end_addr <= existing->start_addr) ||
              (start_addr >= existing->end_addr))) {
            mm_spin_unlock(&g_policy_lock);
            return MM_ERROR_EXISTS;
        }
    }
    
    /* Add new binding */
    numa_policy_binding_t *binding = &g_policy_bindings[g_binding_count++];
    binding->start_addr = start_addr;
    binding->end_addr = end_addr;
    binding->policy = *policy;
    binding->active = true;
    
    mm_spin_unlock(&g_policy_lock);
    
    printk(KERN_DEBUG "NUMA: Bound policy %d to range 0x%llx-0x%llx\n",
           policy->policy, start_addr, end_addr);
    
    return MM_SUCCESS;
}

/**
 * @brief Remove policy binding
 * @param start_addr Start address
 * @param end_addr End address
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_unbind_policy(uint64_t start_addr, uint64_t end_addr) {
    mm_spin_lock(&g_policy_lock);
    
    bool found = false;
    for (uint32_t i = 0; i < g_binding_count; i++) {
        numa_policy_binding_t *binding = &g_policy_bindings[i];
        if (binding->active &&
            binding->start_addr == start_addr &&
            binding->end_addr == end_addr) {
            binding->active = false;
            found = true;
            break;
        }
    }
    
    mm_spin_unlock(&g_policy_lock);
    
    return found ? MM_SUCCESS : MM_ERROR_NOTFOUND;
}

/**
 * @brief Get policy for specific address
 * @param addr Address to query
 * @param policy Output policy structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_get_addr_policy(uint64_t addr, numa_policy_t *policy) {
    if (!policy) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_policy_lock);
    
    numa_policy_binding_t *binding = find_policy_binding(addr);
    if (binding) {
        *policy = binding->policy;
        mm_spin_unlock(&g_policy_lock);
        return MM_SUCCESS;
    }
    
    mm_spin_unlock(&g_policy_lock);
    
    /* Return default policy if no binding found */
    return numa_get_policy(policy);
}

/**
 * @brief Create interleave policy
 * @param nodes Array of node IDs
 * @param node_count Number of nodes
 * @param policy Output policy structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_create_interleave_policy(numa_node_t *nodes, 
                                        uint32_t node_count,
                                        numa_policy_t *policy) {
    if (!nodes || !policy || node_count == 0) {
        return MM_ERROR_INVALID;
    }
    
    policy->policy = NUMA_POLICY_INTERLEAVE;
    policy->allowed_nodes = 0;
    policy->preferred_node = NUMA_NO_NODE;
    policy->flags = 0;
    
    /* Build node bitmask */
    for (uint32_t i = 0; i < node_count; i++) {
        if (nodes[i] >= 0 && nodes[i] < MAX_NUMA_NODES) {
            policy->allowed_nodes |= (1ULL << nodes[i]);
        }
    }
    
    return MM_SUCCESS;
}

/**
 * @brief Create bind policy
 * @param nodes Array of node IDs
 * @param node_count Number of nodes
 * @param policy Output policy structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_create_bind_policy(numa_node_t *nodes,
                                  uint32_t node_count,
                                  numa_policy_t *policy) {
    if (!nodes || !policy || node_count == 0) {
        return MM_ERROR_INVALID;
    }
    
    policy->policy = NUMA_POLICY_BIND;
    policy->allowed_nodes = 0;
    policy->preferred_node = NUMA_NO_NODE;
    policy->flags = 0;
    
    /* Build node bitmask */
    for (uint32_t i = 0; i < node_count; i++) {
        if (nodes[i] >= 0 && nodes[i] < MAX_NUMA_NODES) {
            policy->allowed_nodes |= (1ULL << nodes[i]);
        }
    }
    
    return MM_SUCCESS;
}

/**
 * @brief Create preferred policy
 * @param preferred_node Preferred node ID
 * @param policy Output policy structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t numa_create_preferred_policy(numa_node_t preferred_node,
                                       numa_policy_t *policy) {
    if (!policy || preferred_node < 0) {
        return MM_ERROR_INVALID;
    }
    
    policy->policy = NUMA_POLICY_PREFERRED;
    policy->allowed_nodes = ~0ULL; /* All nodes allowed as fallback */
    policy->preferred_node = preferred_node;
    policy->flags = 0;
    
    return MM_SUCCESS;
}

/* ========================================================================
 * POLICY-BASED ALLOCATION
 * ======================================================================== */

/**
 * @brief Allocate memory with address-specific policy
 * @param addr Allocation address hint
 * @param size Size in bytes
 * @param flags Allocation flags
 * @return Pointer to allocated memory or NULL
 */
void *numa_alloc_addr_policy(uint64_t addr, size_t size, gfp_t flags) {
    numa_policy_t policy;
    
    /* Get policy for this address */
    if (numa_get_addr_policy(addr, &policy) != MM_SUCCESS) {
        /* Fallback to default allocation */
        return kmalloc(size);
    }

    return numa_alloc_policy(size, &policy, flags);
}

/**
 * @brief Check if allocation should be migrated
 * @param addr Current address
 * @param size Size of allocation
 * @return Target node for migration or NUMA_NO_NODE
 */
numa_node_t numa_check_migration_target(void *addr, size_t size) {
    if (!addr) {
        return NUMA_NO_NODE;
    }
    
    uint64_t addr_val = (uint64_t)addr;
    numa_policy_t policy;
    
    /* Get current policy for this address */
    if (numa_get_addr_policy(addr_val, &policy) != MM_SUCCESS) {
        return NUMA_NO_NODE;
    }
    
    /* Current node of the allocation */
    numa_node_t current_node = numa_node_of_addr(addr);
    if (current_node == NUMA_NO_NODE) {
        return NUMA_NO_NODE;
    }
    
    /* Check if current placement is optimal */
    switch (policy.policy) {
    case NUMA_POLICY_LOCAL: {
        numa_node_t cpu_node = numa_node_id();
        if (cpu_node != current_node && numa_node_online(cpu_node)) {
            return cpu_node;
        }
        break;
    }
    
    case NUMA_POLICY_PREFERRED:
        if (policy.preferred_node != current_node &&
            numa_node_online(policy.preferred_node)) {
            return policy.preferred_node;
        }
        break;
        
    case NUMA_POLICY_BIND:
        /* Check if current node is in allowed set */
        if (!(policy.allowed_nodes & (1ULL << current_node))) {
            /* Find first allowed node */
            for (int i = 0; i < MAX_NUMA_NODES; i++) {
                if ((policy.allowed_nodes & (1ULL << i)) &&
                    numa_node_online(i)) {
                    return i;
                }
            }
        }
        break;
        
    default:
        break;
    }
    
    return NUMA_NO_NODE;
}

/* ========================================================================
 * POLICY STATISTICS AND MONITORING
 * ======================================================================== */

/**
 * @brief Print all active policy bindings
 */
void numa_print_policy_bindings(void) {
    mm_spin_lock(&g_policy_lock);
    
    printk(KERN_INFO "NUMA Policy Bindings:\n");
    
    uint32_t active_count = 0;
    for (uint32_t i = 0; i < g_binding_count; i++) {
        numa_policy_binding_t *binding = &g_policy_bindings[i];
        if (binding->active) {
            const char *policy_name;
            switch (binding->policy.policy) {
            case NUMA_POLICY_DEFAULT:    policy_name = "default"; break;
            case NUMA_POLICY_BIND:       policy_name = "bind"; break;
            case NUMA_POLICY_INTERLEAVE: policy_name = "interleave"; break;
            case NUMA_POLICY_PREFERRED:  policy_name = "preferred"; break;
            case NUMA_POLICY_LOCAL:      policy_name = "local"; break;
            default:                     policy_name = "unknown"; break;
            }
            
            printk(KERN_INFO "  0x%llx-0x%llx: %s (nodes=0x%llx, pref=%d)\n",
                   binding->start_addr, binding->end_addr, policy_name,
                   binding->policy.allowed_nodes, binding->policy.preferred_node);
            active_count++;
        }
    }
    
    if (active_count == 0) {
        printk(KERN_INFO "  No active bindings\n");
    }
    
    mm_spin_unlock(&g_policy_lock);
}

/**
 * @brief Get policy binding statistics
 * @param total_bindings Output total binding count
 * @param active_bindings Output active binding count
 * @return MM_SUCCESS on success
 */
mm_error_t numa_get_policy_stats(uint32_t *total_bindings, 
                                uint32_t *active_bindings) {
    if (!total_bindings || !active_bindings) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_policy_lock);
    
    *total_bindings = g_binding_count;
    *active_bindings = 0;
    
    for (uint32_t i = 0; i < g_binding_count; i++) {
        if (g_policy_bindings[i].active) {
            (*active_bindings)++;
        }
    }
    
    mm_spin_unlock(&g_policy_lock);
    
    return MM_SUCCESS;
}

/**
 * @brief Initialize policy subsystem
 * @return MM_SUCCESS on success
 */
mm_error_t numa_policy_init(void) {
    /* Clear all bindings */
    memset(g_policy_bindings, 0, sizeof(g_policy_bindings));
    g_binding_count = 0;
    
    printk(KERN_INFO "NUMA: Policy subsystem initialized\n");
    return MM_SUCCESS;
}

/**
 * @brief Cleanup policy subsystem
 */
void numa_policy_cleanup(void) {
    mm_spin_lock(&g_policy_lock);
    
    /* Mark all bindings as inactive */
    for (uint32_t i = 0; i < g_binding_count; i++) {
        g_policy_bindings[i].active = false;
    }
    g_binding_count = 0;
    
    mm_spin_unlock(&g_policy_lock);
    
    printk(KERN_INFO "NUMA: Policy subsystem cleaned up\n");
}

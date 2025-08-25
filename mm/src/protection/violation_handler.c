/**
 * @file violation_handler.c
 * @brief Implémentation du gestionnaire de violations de protection mémoire pour LeaxOS
 * 
 * Ce fichier implémente la gestion des violations de protection mémoire :
 * - Traitement des exceptions de page fault
 * - Classification des violations
 * - Actions correctives automatiques
 * - Logging et reporting
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
#include "../../include/memory_protection.h"
#include "../../include/mm.h"

/* ========================================================================
 * VIOLATION HANDLER STRUCTURES
 * ======================================================================== */

/** Violation context information */
typedef struct violation_context {
    uint64_t fault_address;        /**< Faulting address */
    uint64_t instruction_pointer;  /**< Instruction that caused fault */
    uint32_t error_code;           /**< Hardware error code */
    uint32_t cpu_id;               /**< CPU where fault occurred */
    uint64_t timestamp;            /**< Fault timestamp */
    uint32_t process_id;           /**< Process ID (if applicable) */
    uint32_t thread_id;            /**< Thread ID (if applicable) */
} violation_context_t;

/** Violation handling actions */
typedef enum {
    VIOLATION_ACTION_TERMINATE,    /**< Terminate process */
    VIOLATION_ACTION_SIGNAL,       /**< Send signal to process */
    VIOLATION_ACTION_RETRY,        /**< Retry after fixing */
    VIOLATION_ACTION_IGNORE,       /**< Ignore violation */
    VIOLATION_ACTION_CUSTOM        /**< Custom handler */
} violation_action_t;

/** Violation handler registration */
typedef struct violation_handler_entry {
    violation_type_t type;         /**< Violation type */
    protection_violation_handler_t handler; /**< Handler function */
    void *context;                 /**< Handler context */
    uint32_t priority;             /**< Handler priority */
    bool enabled;                  /**< Handler enabled */
    
    /* Statistics */
    uint64_t invocation_count;     /**< Times called */
    uint64_t success_count;        /**< Successful handlings */
    
    struct violation_handler_entry *next;
} violation_handler_entry_t;

/** Global violation management */
static violation_handler_entry_t *g_violation_handlers = NULL;
static mm_spinlock_t g_violation_lock = MM_SPINLOCK_INIT("violation_handler");
static bool g_violation_system_enabled = false;

/** Default violation action policy */
static violation_action_t g_default_actions[PROT_VIOLATION_MAX] = {
    [PROT_VIOLATION_READ] = VIOLATION_ACTION_TERMINATE,
    [PROT_VIOLATION_WRITE] = VIOLATION_ACTION_TERMINATE,
    [PROT_VIOLATION_EXEC] = VIOLATION_ACTION_TERMINATE,
    [PROT_VIOLATION_USER] = VIOLATION_ACTION_TERMINATE,
    [PROT_VIOLATION_STACK] = VIOLATION_ACTION_TERMINATE,
    [PROT_VIOLATION_HEAP] = VIOLATION_ACTION_TERMINATE,
    [PROT_VIOLATION_GUARD] = VIOLATION_ACTION_TERMINATE,
    [PROT_VIOLATION_DOMAIN] = VIOLATION_ACTION_TERMINATE
};

/** Violation statistics */
static struct {
    uint64_t total_violations;
    uint64_t handled_violations;
    uint64_t terminated_processes;
    uint64_t recovered_violations;
    uint64_t ignored_violations;
    uint64_t by_type[PROT_VIOLATION_MAX];
    uint64_t by_action[5];  /* VIOLATION_ACTION_* */
} g_violation_stats = {0};

/* ========================================================================
 * VIOLATION CLASSIFICATION
 * ======================================================================== */

/**
 * @brief Classify violation type from error code and address
 * @param addr Faulting address
 * @param error_code Hardware error code
 * @return Classified violation type
 */
static violation_type_t classify_violation(uint64_t addr, uint32_t error_code) {
    /* Check if it's a guard page violation first */
    if (is_guard_page((void *)addr)) {
        return PROT_VIOLATION_GUARD;
    }
    
    /* Analyze error code bits (x86-64 page fault error code) */
    bool present = (error_code & 0x1) != 0;      /* Page present */
    bool write = (error_code & 0x2) != 0;        /* Write access */
    bool user = (error_code & 0x4) != 0;         /* User mode */
    bool exec = (error_code & 0x10) != 0;        /* Instruction fetch */
    bool pkey = (error_code & 0x20) != 0;        /* Protection key */
    
    /* Protection key violation */
    if (pkey) {
        return PROT_VIOLATION_DOMAIN;
    }
    
    /* Privilege violation (user accessing kernel space) */
    if (user && addr >= 0xFFFF800000000000ULL) {
        return PROT_VIOLATION_USER;
    }
    
    /* Execution violation (NX bit) */
    if (exec && present) {
        return PROT_VIOLATION_EXEC;
    }
    
    /* Write protection violation */
    if (write && present) {
        return PROT_VIOLATION_WRITE;
    }
    
    /* Stack-related addresses (heuristic) */
    if (addr >= 0x7FFF00000000ULL && addr < 0x800000000000ULL) {
        return PROT_VIOLATION_STACK;
    }
    
    /* Heap-related addresses (heuristic) */
    if (addr >= 0x10000000ULL && addr < 0x80000000ULL) {
        return PROT_VIOLATION_HEAP;
    }
    
    /* Default to read violation */
    return PROT_VIOLATION_READ;
}

/**
 * @brief Get violation severity level
 * @param type Violation type
 * @return Severity level (0=low, 3=critical)
 */
static int get_violation_severity(violation_type_t type) {
    switch (type) {
    case PROT_VIOLATION_STACK:
    case PROT_VIOLATION_HEAP:
    case PROT_VIOLATION_GUARD:
        return 3;  /* Critical */
        
    case PROT_VIOLATION_EXEC:
    case PROT_VIOLATION_USER:
        return 2;  /* High */
        
    case PROT_VIOLATION_WRITE:
        return 1;  /* Medium */
        
    case PROT_VIOLATION_READ:
    default:
        return 0;  /* Low */
    }
}

/* ========================================================================
 * HANDLER MANAGEMENT
 * ======================================================================== */

/**
 * @brief Find violation handler for type
 * @param type Violation type
 * @return Handler entry or NULL
 */
static violation_handler_entry_t *find_violation_handler(violation_type_t type) {
    for (violation_handler_entry_t *entry = g_violation_handlers; entry; entry = entry->next) {
        if (entry->type == type && entry->enabled) {
            return entry;
        }
    }
    return NULL;
}

/**
 * @brief Add handler to list (sorted by priority)
 * @param entry Handler entry to add
 */
static void add_handler_to_list(violation_handler_entry_t *entry) {
    if (!g_violation_handlers || entry->priority > g_violation_handlers->priority) {
        entry->next = g_violation_handlers;
        g_violation_handlers = entry;
        return;
    }
    
    violation_handler_entry_t *curr = g_violation_handlers;
    while (curr->next && curr->next->priority >= entry->priority) {
        curr = curr->next;
    }
    
    entry->next = curr->next;
    curr->next = entry;
}

/**
 * @brief Remove handler from list
 * @param entry Handler entry to remove
 */
static void remove_handler_from_list(violation_handler_entry_t *entry) {
    if (g_violation_handlers == entry) {
        g_violation_handlers = entry->next;
        return;
    }
    
    for (violation_handler_entry_t *curr = g_violation_handlers; curr; curr = curr->next) {
        if (curr->next == entry) {
            curr->next = entry->next;
            break;
        }
    }
}

/* ========================================================================
 * VIOLATION RECOVERY
 * ======================================================================== */

/**
 * @brief Attempt automatic recovery from violation
 * @param violation Violation information
 * @return true if recovery successful
 */
static bool attempt_violation_recovery(protection_violation_t *violation) {
    switch (violation->type) {
    case PROT_VIOLATION_WRITE:
        /* Try to make page writable if it's a COW (Copy-On-Write) scenario */
        if (violation->error_code & 0x1) {  /* Page present */
            /* This would implement COW logic in a real kernel */
            printk(KERN_DEBUG "Violation: Attempting COW recovery for 0x%llx\n",
                   violation->address);
            return false;  /* Not implemented */
        }
        break;
        
    case PROT_VIOLATION_READ:
        /* Try to load page from swap or demand-page it */
        if (!(violation->error_code & 0x1)) {  /* Page not present */
            printk(KERN_DEBUG "Violation: Attempting demand paging for 0x%llx\n",
                   violation->address);
            return false;  /* Not implemented */
        }
        break;
        
    case PROT_VIOLATION_STACK:
        /* Try to expand stack if within limits */
        printk(KERN_DEBUG "Violation: Attempting stack expansion for 0x%llx\n",
               violation->address);
        return false;  /* Not implemented */
        
    default:
        /* No automatic recovery for other types */
        break;
    }
    
    return false;
}

/**
 * @brief Execute violation action
 * @param violation Violation information
 * @param action Action to execute
 * @return true if action successful
 */
static bool execute_violation_action(protection_violation_t *violation, violation_action_t action) {
    g_violation_stats.by_action[action]++;
    
    switch (action) {
    case VIOLATION_ACTION_TERMINATE:
        printk(KERN_ERROR "Violation: Terminating process due to %s violation at 0x%llx\n",
               (violation->type < PROT_VIOLATION_MAX) ? 
               "protection" : "unknown", violation->address);
        g_violation_stats.terminated_processes++;
        return false;  /* Process should be terminated */
        
    case VIOLATION_ACTION_SIGNAL:
        printk(KERN_WARNING "Violation: Sending signal for violation at 0x%llx\n",
               violation->address);
        /* Would send SIGSEGV or similar signal */
        return true;
        
    case VIOLATION_ACTION_RETRY:
        /* Attempt recovery first */
        if (attempt_violation_recovery(violation)) {
            printk(KERN_INFO "Violation: Recovery successful for 0x%llx\n",
                   violation->address);
            g_violation_stats.recovered_violations++;
            return true;
        } else {
            /* Recovery failed, fall back to terminate */
            return execute_violation_action(violation, VIOLATION_ACTION_TERMINATE);
        }
        
    case VIOLATION_ACTION_IGNORE:
        printk(KERN_DEBUG "Violation: Ignoring violation at 0x%llx\n",
               violation->address);
        g_violation_stats.ignored_violations++;
        return true;
        
    case VIOLATION_ACTION_CUSTOM:
        /* Custom actions handled by registered handlers */
        return true;
        
    default:
        return false;
    }
}

/* ========================================================================
 * PUBLIC INTERFACE IMPLEMENTATION
 * ======================================================================== */

mm_error_t violation_handler_init(void) {
    printk(KERN_INFO "Violation: Initializing violation handler system\n");
    
    /* Initialize statistics */
    memset(&g_violation_stats, 0, sizeof(g_violation_stats));
    
    /* Set default actions for less critical violations */
    g_default_actions[PROT_VIOLATION_READ] = VIOLATION_ACTION_RETRY;
    
    g_violation_system_enabled = true;
    
    printk(KERN_INFO "Violation: Handler system initialized\n");
    
    return MM_SUCCESS;
}

void violation_handler_shutdown(void) {
    if (!g_violation_system_enabled) {
        return;
    }
    
    mm_spin_lock(&g_violation_lock);
    
    /* Remove all registered handlers */
    while (g_violation_handlers) {
        violation_handler_entry_t *entry = g_violation_handlers;
        remove_handler_from_list(entry);
        kfree(entry);
    }
    
    g_violation_system_enabled = false;
    
    mm_spin_unlock(&g_violation_lock);
    
    printk(KERN_INFO "Violation: Handler system shutdown\n");
}

mm_error_t register_violation_handler(violation_type_t type, protection_violation_handler_t handler, 
                                    uint32_t priority) {
    if (!handler || type >= PROT_VIOLATION_MAX || !g_violation_system_enabled) {
        return MM_ERROR_INVALID;
    }
    
    /* Allocate handler entry */
    violation_handler_entry_t *entry = kmalloc(sizeof(violation_handler_entry_t), GFP_KERNEL);
    if (!entry) {
        return MM_ERROR_NO_MEMORY;
    }
    
    /* Initialize entry */
    memset(entry, 0, sizeof(*entry));
    entry->type = type;
    entry->handler = handler;
    entry->priority = priority;
    entry->enabled = true;
    
    mm_spin_lock(&g_violation_lock);
    
    /* Add to handler list */
    add_handler_to_list(entry);
    
    mm_spin_unlock(&g_violation_lock);
    
    printk(KERN_DEBUG "Violation: Registered handler for type %d (priority %u)\n",
           type, priority);
    
    return MM_SUCCESS;
}

mm_error_t unregister_violation_handler(violation_type_t type, protection_violation_handler_t handler) {
    if (!handler || type >= PROT_VIOLATION_MAX || !g_violation_system_enabled) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_violation_lock);
    
    /* Find and remove handler */
    for (violation_handler_entry_t *entry = g_violation_handlers; entry; entry = entry->next) {
        if (entry->type == type && entry->handler == handler) {
            remove_handler_from_list(entry);
            mm_spin_unlock(&g_violation_lock);
            
            kfree(entry);
            
            printk(KERN_DEBUG "Violation: Unregistered handler for type %d\n", type);
            return MM_SUCCESS;
        }
    }
    
    mm_spin_unlock(&g_violation_lock);
    
    return MM_ERROR_INVALID;
}

bool handle_memory_violation(uint64_t fault_addr, uint64_t ip, uint32_t error_code) {
    if (!g_violation_system_enabled) {
        return false;
    }
    
    /* Create violation structure */
    protection_violation_t violation = {0};
    violation.address = fault_addr;
    violation.ip = ip;
    violation.error_code = error_code;
    violation.type = classify_violation(fault_addr, error_code);
    violation.severity = get_violation_severity(violation.type);
    violation.timestamp = 0;  /* Would be real timestamp */
    
    mm_spin_lock(&g_violation_lock);
    
    /* Update statistics */
    g_violation_stats.total_violations++;
    if (violation.type < PROT_VIOLATION_MAX) {
        g_violation_stats.by_type[violation.type]++;
    }
    
    mm_spin_unlock(&g_violation_lock);
    
    /* Log the violation */
    printk(KERN_WARNING "Memory violation: type=%d, addr=0x%llx, ip=0x%llx, error=0x%x\n",
           violation.type, fault_addr, ip, error_code);
    
    /* Check for guard page violation first */
    if (violation.type == PROT_VIOLATION_GUARD) {
        bool handled = handle_guard_page_violation((void *)fault_addr, error_code);
        if (handled) {
            mm_spin_lock(&g_violation_lock);
            g_violation_stats.handled_violations++;
            mm_spin_unlock(&g_violation_lock);
        }
        return handled;
    }
    
    /* Look for registered handler */
    mm_spin_lock(&g_violation_lock);
    violation_handler_entry_t *handler_entry = find_violation_handler(violation.type);
    if (handler_entry) {
        handler_entry->invocation_count++;
        mm_spin_unlock(&g_violation_lock);
        
        /* Call registered handler */
        bool handled = handler_entry->handler(&violation);
        
        mm_spin_lock(&g_violation_lock);
        if (handled) {
            handler_entry->success_count++;
            g_violation_stats.handled_violations++;
        }
        mm_spin_unlock(&g_violation_lock);
        
        return handled;
    }
    mm_spin_unlock(&g_violation_lock);
    
    /* Use default action */
    violation_action_t action = g_default_actions[violation.type];
    bool handled = execute_violation_action(&violation, action);
    
    if (handled) {
        mm_spin_lock(&g_violation_lock);
        g_violation_stats.handled_violations++;
        mm_spin_unlock(&g_violation_lock);
    }
    
    return handled;
}

mm_error_t set_violation_action(violation_type_t type, violation_action_t action) {
    if (type >= PROT_VIOLATION_MAX || action > VIOLATION_ACTION_CUSTOM) {
        return MM_ERROR_INVALID;
    }
    
    g_default_actions[type] = action;
    
    printk(KERN_DEBUG "Violation: Set action %d for type %d\n", action, type);
    
    return MM_SUCCESS;
}

violation_action_t get_violation_action(violation_type_t type) {
    if (type >= PROT_VIOLATION_MAX) {
        return VIOLATION_ACTION_TERMINATE;
    }
    
    return g_default_actions[type];
}

mm_error_t get_violation_statistics(violation_stats_t *stats) {
    if (!stats) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_violation_lock);
    
    stats->total_violations = g_violation_stats.total_violations;
    stats->handled_violations = g_violation_stats.handled_violations;
    stats->terminated_processes = g_violation_stats.terminated_processes;
    stats->recovered_violations = g_violation_stats.recovered_violations;
    stats->ignored_violations = g_violation_stats.ignored_violations;
    
    memcpy(stats->by_type, g_violation_stats.by_type, sizeof(stats->by_type));
    
    mm_spin_unlock(&g_violation_lock);
    
    return MM_SUCCESS;
}

void print_violation_stats(void) {
    printk(KERN_INFO "Memory Violation Statistics:\n");
    printk(KERN_INFO "  Total violations: %llu\n", g_violation_stats.total_violations);
    printk(KERN_INFO "  Handled violations: %llu\n", g_violation_stats.handled_violations);
    printk(KERN_INFO "  Terminated processes: %llu\n", g_violation_stats.terminated_processes);
    printk(KERN_INFO "  Recovered violations: %llu\n", g_violation_stats.recovered_violations);
    printk(KERN_INFO "  Ignored violations: %llu\n", g_violation_stats.ignored_violations);
    
    printk(KERN_INFO "  By type:\n");
    printk(KERN_INFO "    Read: %llu\n", g_violation_stats.by_type[PROT_VIOLATION_READ]);
    printk(KERN_INFO "    Write: %llu\n", g_violation_stats.by_type[PROT_VIOLATION_WRITE]);
    printk(KERN_INFO "    Execute: %llu\n", g_violation_stats.by_type[PROT_VIOLATION_EXEC]);
    printk(KERN_INFO "    User: %llu\n", g_violation_stats.by_type[PROT_VIOLATION_USER]);
    printk(KERN_INFO "    Stack: %llu\n", g_violation_stats.by_type[PROT_VIOLATION_STACK]);
    printk(KERN_INFO "    Heap: %llu\n", g_violation_stats.by_type[PROT_VIOLATION_HEAP]);
    printk(KERN_INFO "    Guard: %llu\n", g_violation_stats.by_type[PROT_VIOLATION_GUARD]);
    printk(KERN_INFO "    Domain: %llu\n", g_violation_stats.by_type[PROT_VIOLATION_DOMAIN]);
}

void print_violation_handlers(void) {
    printk(KERN_INFO "Registered Violation Handlers:\n");
    
    mm_spin_lock(&g_violation_lock);
    
    for (violation_handler_entry_t *entry = g_violation_handlers; entry; entry = entry->next) {
        printk(KERN_INFO "  Type %d: priority=%u, enabled=%s, calls=%llu, success=%llu\n",
               entry->type, entry->priority, entry->enabled ? "yes" : "no",
               entry->invocation_count, entry->success_count);
    }
    
    mm_spin_unlock(&g_violation_lock);
}

void reset_violation_stats(void) {
    mm_spin_lock(&g_violation_lock);
    memset(&g_violation_stats, 0, sizeof(g_violation_stats));
    mm_spin_unlock(&g_violation_lock);
    
    printk(KERN_INFO "Violation: Statistics reset\n");
}

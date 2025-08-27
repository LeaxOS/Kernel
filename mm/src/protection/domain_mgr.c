/**
 * @file domain_mgr.c
 * @brief Implémentation de la gestion des domaines de protection pour LeaxOS
 * 
 * Ce fichier implémente la gestion des domaines de protection mémoire :
 * - Création et destruction des domaines
 * - Assignation de pages aux domaines
 * - Protection Keys (PKU) sur x86-64
 * - Isolation entre domaines
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

/* Define protection_domain_info_t if not defined in included headers */
#ifndef PROTECTION_DOMAIN_INFO_T_DEFINED
typedef struct protection_domain_info {
    domain_id_t id;
    char name[32];
    uint32_t flags;
    uint32_t protection_key;
    uint64_t page_count;
    uint64_t total_size;
    uint64_t creation_time;
    uint64_t access_count;
    uint64_t violation_count;
} protection_domain_info_t;
#define PROTECTION_DOMAIN_INFO_T_DEFINED
#endif

/* Define missing error code if not present in headers */
#ifndef MM_ERROR_NO_MEMORY
#define MM_ERROR_NO_MEMORY 5
#endif

/* Define kernel log level macros if not already defined */
#ifndef KERN_ERROR
#define KERN_ERROR   "<3>"
#endif
#ifndef KERN_WARNING
#define KERN_WARNING "<4>"
#endif
#ifndef KERN_INFO
#define KERN_INFO    "<6>"
#endif
#ifndef KERN_DEBUG
#define KERN_DEBUG   "<7>"
#endif

/* Define domain_id_t if not defined in included headers */
#ifndef DOMAIN_ID_T_DEFINED
typedef uint32_t domain_id_t;
#define DOMAIN_ID_T_DEFINED
#endif

/* Define missing domain flag for disabling PKU if not present */
#ifndef DOMAIN_FLAG_NO_PKU
#define DOMAIN_FLAG_NO_PKU 0x2
#endif

/* ========================================================================
 * DOMAIN MANAGEMENT STRUCTURES
 * ======================================================================== */

/** Maximum number of protection domains */
#define MAX_PROTECTION_DOMAINS  256

#define DOMAIN_FLAG_DEFAULT     0x1

/** Domain structure */
typedef struct protection_domain {
    domain_id_t id;                    /**< Domain identifier */
    char name[32];                     /**< Domain name */
    uint32_t flags;                    /**< Domain flags */
    uint32_t protection_key;           /**< Protection key (PKU) */
    uint64_t page_count;               /**< Number of pages in domain */
    uint64_t total_size;               /**< Total size in bytes */
    uint64_t creation_time;            /**< Creation timestamp */
    bool in_use;                       /**< Domain is active */
    
    /* Statistics */
    uint64_t access_count;             /**< Access counter */
    uint64_t violation_count;          /**< Violation counter */
    
    /* Linked list for active domains */
    struct protection_domain *next;
} protection_domain_t;

/** Global domain management */
static protection_domain_t g_domains[MAX_PROTECTION_DOMAINS];
static protection_domain_t *g_active_domains = NULL;
static mm_spinlock_t g_domain_lock = MM_SPINLOCK_INIT("domain_mgr");
static domain_id_t g_next_domain_id = 1;
static uint32_t g_active_domain_count = 0;

/** Protection key management (x86-64 PKU) */
static uint32_t g_used_protection_keys = 0;  /* Bitmask of used keys */
static bool g_pku_enabled = false;

/* ========================================================================
 * PROTECTION KEY MANAGEMENT
 * ======================================================================== */

/**
 * @brief Allocate a protection key
 * @return Protection key number, or -1 if none available
 */
static int allocate_protection_key(void) {
    if (!g_pku_enabled) {
        return -1;
    }
    
    mm_spin_lock(&g_domain_lock);
    
    /* Find first available key (0 and 1 are usually reserved) */
    for (int key = 2; key < 16; key++) {
        if (!(g_used_protection_keys & (1U << key))) {
            g_used_protection_keys |= (1U << key);
            mm_spin_unlock(&g_domain_lock);
            return key;
        }
    }
    
    mm_spin_unlock(&g_domain_lock);
    return -1;  /* No keys available */
}

/**
 * @brief Free a protection key
 * @param key Protection key to free
 */
static void free_protection_key(uint32_t key) {
    if (!g_pku_enabled || key < 2 || key >= 16) {
        return;
    }
    
    mm_spin_lock(&g_domain_lock);
    g_used_protection_keys &= ~(1U << key);
    mm_spin_unlock(&g_domain_lock);
}

/**
 * @brief Set protection key permissions in PKRU register
 * @param key Protection key
 * @param permissions Permissions (PKEY_DISABLE_ACCESS, PKEY_DISABLE_WRITE)
 */
static void set_protection_key_permissions(uint32_t key, uint32_t permissions) {
    if (!g_pku_enabled || key >= 16) {
        return;
    }
    
    /* In a real implementation, this would:
     * 1. Read current PKRU register
     * 2. Update permissions for the specified key
     * 3. Write back to PKRU register using WRPKRU instruction
     */
    
    printk(KERN_DEBUG "Domain: Set protection key %u permissions to 0x%x\n",
           key, permissions);
}

/* ========================================================================
 * DOMAIN MANAGEMENT
 * ======================================================================== */

/**
 * @brief Find domain by ID
 * @param id Domain ID
 * @return Domain pointer or NULL if not found
 */
static protection_domain_t *find_domain(domain_id_t id) {
    for (protection_domain_t *domain = g_active_domains; domain; domain = domain->next) {
        if (domain->id == id) {
            return domain;
        }
    }
    return NULL;
}

/**
 * @brief Add domain to active list
 * @param domain Domain to add
 */
static void add_to_active_list(protection_domain_t *domain) {
    domain->next = g_active_domains;
    g_active_domains = domain;
    g_active_domain_count++;
}

/**
 * @brief Remove domain from active list
 * @param domain Domain to remove
 */
static void remove_from_active_list(protection_domain_t *domain) {
    if (g_active_domains == domain) {
        g_active_domains = domain->next;
    } else {
        for (protection_domain_t *curr = g_active_domains; curr; curr = curr->next) {
            if (curr->next == domain) {
                curr->next = domain->next;
                break;
            }
        }
    }
    domain->next = NULL;
    g_active_domain_count--;
}

/* ========================================================================
 * PUBLIC INTERFACE IMPLEMENTATION
 * ======================================================================== */

mm_error_t protection_domain_init(void) {
    printk(KERN_INFO "Domain: Initializing protection domain manager\n");
    
    /* Initialize domain array */
    memset(g_domains, 0, sizeof(g_domains));
    g_active_domains = NULL;
    g_next_domain_id = 1;
    g_active_domain_count = 0;
    
    /* Check if PKU is supported and enabled */
    hw_protection_caps_t caps;
    if (get_hw_protection_caps(&caps) == MM_SUCCESS && caps.pku_supported) {
        g_pku_enabled = is_protection_feature_enabled(MEM_PROT_PKU);
        if (g_pku_enabled) {
            printk(KERN_INFO "Domain: PKU (Protection Keys) enabled\n");
        }
    }
    
    /* Create default domain (domain 0) */
    domain_id_t default_domain;
    mm_error_t result = create_protection_domain("default", DOMAIN_FLAG_DEFAULT, &default_domain);
    if (result != MM_SUCCESS) {
        printk(KERN_ERROR "Domain: Failed to create default domain\n");
        return result;
    }
    
    printk(KERN_INFO "Domain: Manager initialized (PKU: %s)\n",
           g_pku_enabled ? "enabled" : "disabled");
    
    return MM_SUCCESS;
}

void protection_domain_shutdown(void) {
    mm_spin_lock(&g_domain_lock);
    
    /* Destroy all active domains */
    while (g_active_domains) {
        protection_domain_t *domain = g_active_domains;
        remove_from_active_list(domain);
        
        if (domain->protection_key != 0) {
            free_protection_key(domain->protection_key);
        }
        
        domain->in_use = false;
    }
    
    g_used_protection_keys = 0;
    g_next_domain_id = 1;
    g_active_domain_count = 0;
    
    mm_spin_unlock(&g_domain_lock);
    
    printk(KERN_INFO "Domain: Manager shutdown complete\n");
}

mm_error_t create_protection_domain(const char *name, uint32_t flags, domain_id_t *domain_id) {
    if (!name || !domain_id) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_domain_lock);
    
    /* Find free domain slot */
    protection_domain_t *domain = NULL;
    for (int i = 0; i < MAX_PROTECTION_DOMAINS; i++) {
        if (!g_domains[i].in_use) {
            domain = &g_domains[i];
            break;
        }
    }
    
    if (!domain) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_NO_MEMORY;
    }
    
    /* Initialize domain */
    memset(domain, 0, sizeof(*domain));
    domain->id = g_next_domain_id++;
    strncpy(domain->name, name, sizeof(domain->name) - 1);
    domain->name[sizeof(domain->name) - 1] = '\0';
    domain->flags = flags;
    domain->creation_time = 0;  /* Would be real timestamp */
    domain->in_use = true;
    
    /* Allocate protection key if PKU is enabled */
    if (g_pku_enabled && !(flags & DOMAIN_FLAG_NO_PKU)) {
        int key = allocate_protection_key();
        if (key >= 0) {
            domain->protection_key = key;
            
            /* Set initial permissions (allow all) */
            set_protection_key_permissions(key, 0);
        } else {
            printk(KERN_WARNING "Domain: No protection keys available for domain %s\n", name);
        }
    }
    
    /* Add to active list */
    add_to_active_list(domain);
    
    *domain_id = domain->id;
    
    mm_spin_unlock(&g_domain_lock);
    
    printk(KERN_INFO "Domain: Created domain '%s' (ID=%u, key=%u)\n",
           name, domain->id, domain->protection_key);
    
    return MM_SUCCESS;
}

mm_error_t destroy_protection_domain(domain_id_t domain_id) {
    mm_spin_lock(&g_domain_lock);
    
    protection_domain_t *domain = find_domain(domain_id);
    if (!domain) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_INVALID;
    }
    
    /* Cannot destroy default domain */
    if (domain->flags & DOMAIN_FLAG_DEFAULT) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_INVALID;
    }
    
    /* Free protection key */
    if (domain->protection_key != 0) {
        free_protection_key(domain->protection_key);
    }
    
    /* Remove from active list */
    remove_from_active_list(domain);
    
    /* Mark as free */
    domain->in_use = false;
    
    mm_spin_unlock(&g_domain_lock);
    
    printk(KERN_INFO "Domain: Destroyed domain '%s' (ID=%u)\n",
           domain->name, domain_id);
    
    return MM_SUCCESS;
}

mm_error_t get_domain_info(domain_id_t domain_id, protection_domain_info_t *info) {
    if (!info) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_domain_lock);
    
    protection_domain_t *domain = find_domain(domain_id);
    if (!domain) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_INVALID;
    }
    
    /* Fill info structure */
    info->id = domain->id;
    strncpy(info->name, domain->name, sizeof(info->name) - 1);
    info->name[sizeof(info->name) - 1] = '\0';
    info->flags = domain->flags;
    info->protection_key = domain->protection_key;
    info->page_count = domain->page_count;
    info->total_size = domain->total_size;
    info->creation_time = domain->creation_time;
    info->access_count = domain->access_count;
    info->violation_count = domain->violation_count;
    
    mm_spin_unlock(&g_domain_lock);
    
    return MM_SUCCESS;
}

mm_error_t assign_page_to_domain(void *addr, domain_id_t domain_id) {
    if (!addr) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_domain_lock);
    
    protection_domain_t *domain = find_domain(domain_id);
    if (!domain) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_INVALID;
    }
    
    /* In a real implementation, this would:
     * 1. Find the page table entry for the address
     * 2. Set the protection key bits in the PTE
     * 3. Flush TLB if necessary
     */
    
    uint64_t page_addr = (uint64_t)addr & PAGE_MASK;
    
    /* Update domain statistics */
    domain->page_count++;
    domain->total_size += PAGE_SIZE;
    
    mm_spin_unlock(&g_domain_lock);
    
    printk(KERN_DEBUG "Domain: Assigned page 0x%llx to domain %u (key=%u)\n",
           page_addr, domain_id, domain->protection_key);
    
    return MM_SUCCESS;
}

mm_error_t remove_page_from_domain(void *addr, domain_id_t domain_id) {
    if (!addr) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_domain_lock);
    
    protection_domain_t *domain = find_domain(domain_id);
    if (!domain) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_INVALID;
    }
    
    /* In a real implementation, this would clear protection key bits */
    
    uint64_t page_addr = (uint64_t)addr & PAGE_MASK;
    
    /* Update domain statistics */
    if (domain->page_count > 0) {
        domain->page_count--;
        domain->total_size -= PAGE_SIZE;
    }
    
    mm_spin_unlock(&g_domain_lock);
    
    printk(KERN_DEBUG "Domain: Removed page 0x%llx from domain %u\n",
           page_addr, domain_id);
    
    return MM_SUCCESS;
}

mm_error_t set_domain_permissions(domain_id_t domain_id, uint32_t permissions) {
    mm_spin_lock(&g_domain_lock);
    
    protection_domain_t *domain = find_domain(domain_id);
    if (!domain) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_INVALID;
    }
    
    /* Set protection key permissions */
    if (domain->protection_key != 0) {
        set_protection_key_permissions(domain->protection_key, permissions);
    }
    
    mm_spin_unlock(&g_domain_lock);
    
    printk(KERN_DEBUG "Domain: Set permissions 0x%x for domain %u\n",
           permissions, domain_id);
    
    return MM_SUCCESS;
}

mm_error_t get_domain_permissions(domain_id_t domain_id, uint32_t *permissions) {
    if (!permissions) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_domain_lock);
    
    protection_domain_t *domain = find_domain(domain_id);
    if (!domain) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_INVALID;
    }
    
    /* In a real implementation, this would read PKRU register */
    *permissions = 0;  /* Allow all by default */
    
    mm_spin_unlock(&g_domain_lock);
    
    return MM_SUCCESS;
}

mm_error_t switch_protection_domain(domain_id_t domain_id) {
    mm_spin_lock(&g_domain_lock);
    
    protection_domain_t *domain = find_domain(domain_id);
    if (!domain) {
        mm_spin_unlock(&g_domain_lock);
        return MM_ERROR_INVALID;
    }
    
    /* In a real implementation, this would:
     * 1. Save current PKRU state
     * 2. Load domain-specific PKRU configuration
     * 3. Update current domain tracking
     */
    
    domain->access_count++;
    
    mm_spin_unlock(&g_domain_lock);
    
    printk(KERN_DEBUG "Domain: Switched to domain %u ('%s')\n",
           domain_id, domain->name);
    
    return MM_SUCCESS;
}

mm_error_t enumerate_domains(domain_id_t *domains, size_t max_count, size_t *count) {
    if (!domains || !count || max_count == 0) {
        return MM_ERROR_INVALID;
    }
    
    mm_spin_lock(&g_domain_lock);
    
    size_t found = 0;
    for (protection_domain_t *domain = g_active_domains; 
         domain && found < max_count; 
         domain = domain->next) {
        domains[found++] = domain->id;
    }
    
    *count = found;
    
    mm_spin_unlock(&g_domain_lock);
    
    return MM_SUCCESS;
}

void print_domain_info(domain_id_t domain_id) {
    protection_domain_info_t info;
    
    if (get_domain_info(domain_id, &info) != MM_SUCCESS) {
        printk(KERN_ERROR "Domain: Invalid domain ID %u\n", domain_id);
        return;
    }
    
    printk(KERN_INFO "Domain %u ('%s'):\n", info.id, info.name);
    printk(KERN_INFO "  Flags: 0x%x\n", info.flags);
    printk(KERN_INFO "  Protection key: %u\n", info.protection_key);
    printk(KERN_INFO "  Pages: %llu (%llu bytes)\n", info.page_count, info.total_size);
    printk(KERN_INFO "  Access count: %llu\n", info.access_count);
    printk(KERN_INFO "  Violations: %llu\n", info.violation_count);
    printk(KERN_INFO "  Created: %llu\n", info.creation_time);
}

void print_all_domains(void) {
    printk(KERN_INFO "Protection Domains (%u active):\n", g_active_domain_count);
    
    mm_spin_lock(&g_domain_lock);
    
    for (protection_domain_t *domain = g_active_domains; domain; domain = domain->next) {
        printk(KERN_INFO "  %u: '%s' (key=%u, pages=%llu)\n",
               domain->id, domain->name, domain->protection_key, domain->page_count);
    }
    
    if (g_pku_enabled) {
        printk(KERN_INFO "Protection Keys: 0x%x used\n", g_used_protection_keys);
    }
    
    mm_spin_unlock(&g_domain_lock);
}

/**
 * @file memory_protection.h
 * @brief Memory protection interface
 * 
 * @author LeaxOS Team
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_MEMORY_PROTECTION_H
#define LEAX_KERNEL_MM_MEMORY_PROTECTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mm_common.h"

/* ========================================================================
 * MEMORY PROTECTION CONSTANTS
 * ======================================================================== */

/** Protection flags (extends vm_prot_t from mm_common.h) */
#define PROT_USER       0x08U       /**< User-accessible */
#define PROT_GLOBAL     0x10U       /**< Global page */
#define PROT_DIRTY      0x20U       /**< Dirty bit */
#define PROT_ACCESSED   0x40U       /**< Accessed bit */
#define PROT_CACHE_DIS  0x80U       /**< Cache disabled */

/** Protection domains */
typedef uint32_t protection_domain_t;
#define PROT_DOMAIN_KERNEL      0   /**< Kernel domain */
#define PROT_DOMAIN_USER        1   /**< User domain */
#define PROT_DOMAIN_DRIVER      2   /**< Driver domain */
#define PROT_DOMAIN_HYPERVISOR  3   /**< Hypervisor domain */
#define MAX_PROTECTION_DOMAINS  16  /**< Maximum domains */

/** Memory protection features */
typedef enum {
    MEM_PROT_NX         = (1 << 0), /**< No-Execute protection */
    MEM_PROT_SMEP       = (1 << 1), /**< Supervisor Mode Execution Prevention */
    MEM_PROT_SMAP       = (1 << 2), /**< Supervisor Mode Access Prevention */
    MEM_PROT_PKU        = (1 << 3), /**< Protection Key for Userspace */
    MEM_PROT_CET        = (1 << 4), /**< Control Flow Enforcement Technology */
    MEM_PROT_MPX        = (1 << 5), /**< Memory Protection Extensions */
    MEM_PROT_STACK_GUARD = (1 << 6), /**< Stack guard pages */
    MEM_PROT_HEAP_GUARD = (1 << 7)  /**< Heap guard pages */
} mem_prot_features_t;

/** Protection violation types */
typedef enum {
    PROT_VIOLATION_READ = 0,    /**< Read access violation */
    PROT_VIOLATION_WRITE,       /**< Write access violation */
    PROT_VIOLATION_EXEC,        /**< Execute access violation */
    PROT_VIOLATION_USER,        /**< User/kernel privilege violation */
    PROT_VIOLATION_RESERVED,    /**< Reserved bit violation */
    PROT_VIOLATION_STACK,       /**< Stack overflow/underflow */
    PROT_VIOLATION_HEAP,        /**< Heap corruption */
    PROT_VIOLATION_COUNT
} prot_violation_type_t;

/* ========================================================================
 * PROTECTION DATA STRUCTURES
 * ======================================================================== */

/** Protection domain descriptor */
typedef struct protection_domain {
    protection_domain_t id;         /**< Domain identifier */
    char name[32];                  /**< Domain name */
    uint32_t access_rights;         /**< Access rights mask */
    uint32_t flags;                 /**< Domain flags */
    
    /* Statistics */
    uint64_t access_count;          /**< Number of accesses */
    uint64_t violation_count;       /**< Number of violations */
    
    /* Policy */
    bool enforce_nx;                /**< Enforce NX bit */
    bool enforce_write_protect;     /**< Write protection */
    bool allow_user_access;         /**< Allow user access */
} protection_domain_t;

/** Protection violation information */
typedef struct protection_violation {
    prot_violation_type_t type;     /**< Violation type */
    uint64_t address;               /**< Faulting address */
    uint64_t ip;                    /**< Instruction pointer */
    uint32_t error_code;            /**< Hardware/error code (e.g., page fault error code) */
    int32_t severity;               /**< Severity level (0=low .. 3=critical) */
    protection_domain_t domain;     /**< Current domain */
    uint32_t attempted_access;      /**< Attempted access type */
    uint32_t allowed_access;        /**< Allowed access type */
    uint64_t timestamp;             /**< Violation timestamp */
} protection_violation_t;

/** Protection statistics */
typedef struct protection_stats {
    uint64_t total_pages;           /**< Total protected pages */
    uint64_t read_only_pages;       /**< Read-only pages */
    uint64_t no_exec_pages;         /**< Non-executable pages */
    uint64_t kernel_pages;          /**< Kernel-only pages */
    uint64_t user_pages;            /**< User-accessible pages */
    
    uint64_t total_violations;      /**< Total violations */
    uint64_t read_violations;       /**< Read violations */
    uint64_t write_violations;      /**< Write violations */
    uint64_t exec_violations;       /**< Execute violations */
    uint64_t privilege_violations;  /**< Privilege violations */
    
    uint64_t stack_violations;      /**< Stack violations */
    uint64_t heap_violations;       /**< Heap violations */
} protection_stats_t;

/** Hardware protection capabilities */
typedef struct hw_protection_caps {
    bool nx_supported;              /**< NX bit support */
    bool smep_supported;            /**< SMEP support */
    bool smap_supported;            /**< SMAP support */
    bool pku_supported;             /**< PKU support */
    bool cet_supported;             /**< CET support */
    bool mpx_supported;             /**< MPX support */
    
    uint32_t max_protection_keys;   /**< Maximum protection keys */
    uint32_t address_bits;          /**< Address bits */
    uint32_t physical_bits;         /**< Physical address bits */
} hw_protection_caps_t;

/* ========================================================================
 * PROTECTION INTERFACE FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize memory protection subsystem
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t memory_protection_init(void);

/**
 * @brief Shutdown memory protection subsystem
 */
void memory_protection_shutdown(void);

/**
 * @brief Get hardware protection capabilities
 * @param caps Output capabilities structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t get_hw_protection_caps(hw_protection_caps_t *caps);

/**
 * @brief Enable/disable protection feature
 * @param feature Feature to control
 * @param enable true to enable, false to disable
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t set_protection_feature(mem_prot_features_t feature, bool enable);

/**
 * @brief Check if protection feature is enabled
 * @param feature Feature to check
 * @return true if enabled, false otherwise
 */
bool is_protection_feature_enabled(mem_prot_features_t feature);

/* ========================================================================
 * PAGE PROTECTION FUNCTIONS
 * ======================================================================== */

/**
 * @brief Set protection for memory range
 * @param addr Start address (must be page-aligned)
 * @param size Size in bytes (will be rounded to pages)
 * @param prot Protection flags
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t set_memory_protection(void *addr, size_t size, uint32_t prot);

/**
 * @brief Get protection for memory address
 * @param addr Address to query
 * @param prot Output protection flags
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t get_memory_protection(void *addr, uint32_t *prot);

/**
 * @brief Make memory region read-only
 * @param addr Start address
 * @param size Size in bytes
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t make_readonly(void *addr, size_t size);

/**
 * @brief Make memory region writable
 * @param addr Start address
 * @param size Size in bytes
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t make_writable(void *addr, size_t size);

/**
 * @brief Make memory region non-executable
 * @param addr Start address
 * @param size Size in bytes
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t make_noexec(void *addr, size_t size);

/**
 * @brief Make memory region executable
 * @param addr Start address
 * @param size Size in bytes
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t make_executable(void *addr, size_t size);

/* ========================================================================
 * DOMAIN PROTECTION FUNCTIONS
 * ======================================================================== */

/**
 * @brief Create protection domain
 * @param name Domain name
 * @param flags Domain flags
 * @param domain_id Output domain ID
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t create_protection_domain(const char *name, uint32_t flags, protection_domain_t *domain_id);

/**
 * @brief Destroy protection domain
 * @param domain_id Domain ID
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t destroy_protection_domain(protection_domain_t domain_id);

/**
 * @brief Switch to protection domain
 * @param domain_id Target domain ID
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t switch_protection_domain(protection_domain_t domain_id);

/**
 * @brief Get current protection domain
 * @return Current domain ID
 */
protection_domain_t get_current_domain(void);

/**
 * @brief Assign memory to protection domain
 * @param addr Start address
 * @param size Size in bytes
 * @param domain_id Target domain
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t assign_memory_to_domain(void *addr, size_t size, protection_domain_t domain_id);

/* ========================================================================
 * GUARD PAGE TYPES AND CONSTANTS
 * ======================================================================== */

/** Guard page flags */
typedef uint32_t guard_page_flags_t;
#define GUARD_FLAG_STACK   0x01U    /**< Stack guard page */
#define GUARD_FLAG_HEAP    0x02U    /**< Heap guard page */
#define GUARD_FLAG_CANARY  0x04U    /**< Canary guard page */

/** Guard page types */
typedef enum {
    GUARD_TYPE_STACK_OVERFLOW,     /**< Stack overflow protection */
    GUARD_TYPE_STACK_UNDERFLOW,    /**< Stack underflow protection */
    GUARD_TYPE_HEAP_OVERFLOW,      /**< Heap overflow protection */
    GUARD_TYPE_HEAP_UNDERFLOW,     /**< Heap underflow protection */
    GUARD_TYPE_BUFFER_OVERFLOW,    /**< Buffer overflow protection */
    GUARD_TYPE_CANARY,             /**< Canary page */
    GUARD_TYPE_CUSTOM              /**< Custom guard page */
} guard_type_t;

/** Guard page information structure */
typedef struct guard_page_info {
    void *address;                 /**< Guard page address */
    size_t size;                   /**< Guard page size */
    guard_page_flags_t flags;      /**< Guard page flags */
    char description[64];          /**< Description */
    uint64_t creation_time;        /**< Creation timestamp */
    uint64_t access_count;         /**< Access attempts */
    uint64_t violation_count;      /**< Violations detected */
    bool active;                   /**< Guard is active */
} guard_page_info_t;

/** Guard page statistics structure */
typedef struct guard_page_stats {
    uint64_t total_guards;         /**< Total guard pages created */
    uint64_t active_guards;        /**< Active guard pages */
    uint64_t stack_guards;         /**< Stack guard pages */
    uint64_t heap_guards;          /**< Heap guard pages */
    uint64_t canary_guards;        /**< Canary guard pages */
    uint64_t total_violations;     /**< Total violations */
    uint64_t stack_violations;     /**< Stack violations */
    uint64_t heap_violations;      /**< Heap violations */
    uint64_t buffer_violations;    /**< Buffer violations */
} guard_page_stats_t;

/* ========================================================================
 * GUARD PAGE FUNCTIONS
 * ======================================================================== */

/**
 * @brief Initialize guard page system
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t guard_pages_init(void);

/**
 * @brief Shutdown guard page system
 */
void guard_pages_shutdown(void);

/**
 * @brief Create a guard page
 * @param addr Page address
 * @param size Page size
 * @param flags Guard flags
 * @param description Optional description
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t create_guard_page(void *addr, size_t size, guard_page_flags_t flags, const char *description);

/**
 * @brief Remove a guard page
 * @param addr Page address
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t remove_guard_page(void *addr);

/**
 * @brief Create stack guard page
 * @param stack_base Stack base address
 * @param stack_size Stack size
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t create_stack_guard(void *stack_base, size_t stack_size);

/**
 * @brief Create heap guard pages
 * @param heap_ptr Heap pointer
 * @param size Heap size
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t create_heap_guard(void *heap_ptr, size_t size);

/**
 * @brief Create canary page
 * @param addr Page address
 * @param description Description
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t create_canary_page(void *addr, const char *description);

/**
 * @brief Check if address is a guard page
 * @param addr Address to check
 * @return true if guard page, false otherwise
 */
bool is_guard_page(void *addr);

/**
 * @brief Handle guard page violation
 * @param addr Violation address
 * @param error_code Error code
 * @return true if handled, false if fatal
 */
bool handle_guard_page_violation(void *addr, uint32_t error_code);

/**
 * @brief Get guard page information
 * @param addr Page address
 * @param info Output information structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t get_guard_page_info(void *addr, guard_page_info_t *info);

/**
 * @brief Get guard page statistics
 * @param stats Output statistics structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t get_guard_stats(guard_page_stats_t *stats);

/**
 * @brief Print guard page information
 * @param addr Page address
 */
void print_guard_page_info(void *addr);

/**
 * @brief Print all guard pages
 */
void print_all_guard_pages(void);

/**
 * @brief Print guard page statistics
 */
void print_guard_stats(void);

/**
 * @brief Create guard pages around allocation
 * @param addr Allocation address
 * @param size Allocation size
 * @param guard_size Size of guard region
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t create_guard_pages(void *addr, size_t size, size_t guard_size);

/**
 * @brief Remove guard pages
 * @param addr Allocation address
 * @param size Allocation size
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t remove_guard_pages(void *addr, size_t size);

/**
 * @brief Enable stack guard protection
 * @param stack_base Stack base address
 * @param stack_size Stack size
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t enable_stack_guard(void *stack_base, size_t stack_size);

/**
 * @brief Enable heap guard protection
 * @param heap_base Heap base address
 * @param heap_size Heap size
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t enable_heap_guard(void *heap_base, size_t heap_size);

/* ========================================================================
 * VIOLATION HANDLING
 * ======================================================================== */

/**
 * @brief Register protection violation handler
 * @param handler Handler function
 * @return MM_SUCCESS on success, error code on failure
 */
typedef bool (*protection_violation_handler_t)(protection_violation_t *violation);
mm_error_t register_protection_handler(protection_violation_handler_t handler);

/**
 * @brief Handle protection violation
 * @param violation Violation information
 * @return true if handled, false to terminate process
 */
bool handle_protection_violation(protection_violation_t *violation);

/**
 * @brief Get violation history
 * @param violations Output array
 * @param max_count Maximum violations to return
 * @return Number of violations returned
 */
uint32_t get_violation_history(protection_violation_t *violations, uint32_t max_count);

/* ========================================================================
 * STATISTICS AND MONITORING
 * ======================================================================== */

/**
 * @brief Get protection statistics
 * @param stats Output statistics structure
 * @return MM_SUCCESS on success, error code on failure
 */
mm_error_t get_protection_stats(protection_stats_t *stats);

/**
 * @brief Print protection information
 */
void print_protection_info(void);

/**
 * @brief Print protection statistics
 */
void print_protection_stats(void);

/**
 * @brief Reset protection statistics
 */
void reset_protection_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_MEMORY_PROTECTION_H */

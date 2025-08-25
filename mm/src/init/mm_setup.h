/**
 * @file mm_setup.h
 * @brief Headers d'initialisation pour le système de gestion mémoire
 * 
 * Définit les prototypes et structures pour l'initialisation du MM
 */

#ifndef MM_SETUP_H
#define MM_SETUP_H

#include "../../../Include/stdint.h"
#include "../../../Include/stddef.h"

/**
 * @brief Structure de configuration pour l'initialisation MM
 */
typedef struct {
    uint64_t kernel_start;      ///< Adresse de début du kernel
    uint64_t kernel_end;        ///< Adresse de fin du kernel
    uint64_t initrd_start;      ///< Adresse de début de l'initrd
    uint64_t initrd_end;        ///< Adresse de fin de l'initrd
    void* memory_map;           ///< Carte mémoire du bootloader
    size_t memory_map_size;     ///< Taille de la carte mémoire
} mm_boot_info_t;

/* Fonctions d'initialisation de l'allocateur précoce */
void early_alloc_init(void);
void* early_alloc(size_t size);
void early_free(void* ptr);

/* Fonctions de gestion de la carte mémoire */
void memmap_init(void* map, size_t entries);
uint64_t memmap_get_total_memory(void);
uint64_t memmap_get_available_memory(void);
int memmap_find_largest_region(uint64_t* base_addr, uint64_t* length);

/* Fonction principale d'initialisation MM */
void mm_init(mm_boot_info_t* boot_info);

/* Fonctions d'initialisation des sous-systèmes */
void pmm_init(void);
void vmm_init(void);
void slab_init(void);
void vmalloc_init(void);

#endif /* MM_SETUP_H */

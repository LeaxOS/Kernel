# LeaxOS — Module de Gestion Mémoire

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-green.svg)]()
[![Version](https://img.shields.io/badge/Version-1.0-orange.svg)]()

## 📋 Table des Matières

- [Présentation](#présentation)
- [Architecture](#architecture)
- [Fonctionnalités Clés](#fonctionnalités-clés)
- [Prérequis](#prérequis)
- [Installation & Compilation](#installation-et-compilation)
- [Utilisation](#utilisation)
- [Configuration](#configuration)
- [Performance](#performance)
- [Sécurité](#sécurité)
- [Tests & Qualité](#tests-et-qualité)
- [Documentation](#documentation)
- [Contribution](#contribution)
- [Licence](#licence)

## 📖 Présentation

Le module de gestion mémoire (`mm`) constitue le cœur du sous-système mémoire du noyau LeaxOS. Cette implémentation de pointe offre une architecture modulaire et robuste pour tous les aspects critiques de la gestion mémoire moderne.

### 🎯 Philosophie de Conception

- **Modularité** : Séparation claire des responsabilités avec interfaces bien définies
- **Performance** : Optimisé pour la vitesse et l'efficacité mémoire
- **Fiabilité** : Gestion d'erreurs complète et vérifications d'intégrité
- **Sécurité** : Mécanismes intégrés contre les vulnérabilités courantes
- **Évolutivité** : Conçu pour gérer de grandes configurations mémoire et systèmes SMP

### 🔍 Composants Principaux

Le module MM englobe plusieurs sous-systèmes critiques travaillant en harmonie :

- **Gestion Mémoire Physique** : Allocateur buddy pour une gestion efficace des pages
- **Mémoire Virtuelle** : Gestion complète de l'espace d'adressage virtuel avec support paging
- **Gestion du Tas** : Allocateurs multiples (SLAB/SLUB, kmalloc) pour différents cas d'usage
- **Protection Mémoire** : Isolation basée sur domaines et mécanismes de pages de garde
- **Support NUMA** : Allocation mémoire optimisée pour architectures Non-Uniform Memory Access

## 🏗️ Architecture

### Structure du Module

```
mm/
├── include/              # Interfaces publiques
│   ├── mm_common.h      # Types communs, erreurs, macros
│   ├── mm.h             # Interface principale gestionnaire mémoire
│   ├── memory_protection.h # Protection mémoire et domaines
│   ├── page_alloc.h     # Allocateur de pages physiques
│   ├── slab.h           # Allocateur SLAB/SLUB
│   ├── vmalloc.h        # Allocateur mémoire virtuelle
│   ├── mmap.h           # Memory mapping (mmap/munmap)
│   ├── numa.h           # Support NUMA
│   └── page_table.h     # Gestion tables de pages
├── src/                  # Implémentations
│   ├── init/            # Initialisation du sous-système
│   ├── physical/        # Gestion mémoire physique
│   ├── virtual/         # Gestion mémoire virtuelle
│   ├── heap/            # Allocateurs de tas
│   ├── protection/      # Protection mémoire et sécurité
│   ├── numa/            # Support NUMA
│   └── swap/            # Gestion du swap
└── docs/                # Documentation technique
```

### Organisation en Couches

Le code est structuré selon une approche en couches hiérarchiques :

- **`physical/`** : Gestion des pages physiques, allocateur buddy, PMM
- **`virtual/`** : Tables de pages, gestionnaire de défauts de page, mmap/VMA
- **`heap/`** : kmalloc, allocateurs SLAB/SLUB
- **`protection/`** : Pages de garde, domaines de protection, gestion des violations
- **`swap/`** : Gestionnaire de swap et I/O
- **`init/`** : Initialisation et configuration du sous-système

### Interfaces Publiques

Toutes les interfaces publiques sont exposées via le répertoire `include/`, permettant une intégration propre avec le reste du noyau sans dépendances internes.

## ✨ Fonctionnalités Clés

### 🔧 Allocateurs Mémoire

#### Allocateur de Pages Physiques
- **Buddy System** : Allocation/désallocation efficace de pages contiguës
- **Gestion des Zones** : DMA, Normal, High Memory avec politiques adaptées
- **Watermarks** : Contrôle automatique des niveaux de mémoire libre
- **Réclamation** : Récupération automatique de mémoire sous pression

#### Allocateurs de Tas
- **kmalloc/kfree** : Interface standard pour allocations kernel
- **SLAB/SLUB** : Allocation d'objets de taille fixe avec cache coloring
- **vmalloc** : Allocation de mémoire virtuelle contiguë (non physique)
- **Early Allocator** : Gestion mémoire durant les phases de boot

### 🛡️ Protection Mémoire

#### Domaines de Sécurité
- **Isolation par Domaines** : Séparation entre kernel, drivers, userspace
- **Contrôle d'Accès** : Permissions granulaires par domaine
- **Migration de Mémoire** : Déplacement sécurisé entre domaines

#### Mécanismes de Protection
- **Pages de Garde** : Détection d'overflows stack/heap
- **NX/XD Support** : Protection contre exécution de données
- **SMEP/SMAP** : Protection avancée contre accès kernel non autorisés
- **Memory Barriers** : Synchronisation SMP robuste

### 🌐 Gestion Mémoire Virtuelle

#### Memory Mapping
- **mmap/munmap** : Interface standard de mapping mémoire
- **VMA Management** : Gestion fine des régions mémoire virtuelles
- **Lazy Allocation** : Allocation à la demande avec demand-paging

#### Gestionnaire de Défauts de Page
- **Page Fault Handler** : Traitement complet des défauts de page
- **Copy-on-Write** : Optimisation des duplications de processus
- **Stack Growth** : Extension automatique de la pile
- **Demand Paging** : Chargement paresseux des pages

### ⚡ Optimisations Avancées

#### Support NUMA
- **Allocation Locale** : Préférence pour la proximité mémoire
- **Load Balancing** : Équilibrage automatique entre nœuds
- **Migration Intelligente** : Déplacement optimal des pages

#### Optimisations SMP
- **Per-CPU Caches** : Allocation rapide mono-processeur
- **Lock Contention** : Réduction des contentions sur les verrous
- **Scalabilité** : Performance maintenue avec augmentation CPU

### 📊 Monitoring et Diagnostic

#### Statistiques Exhaustives
- **Métriques Temps Réel** : Suivi des allocations/désallocations
- **Analyse de Fragmentation** : Mesure de l'efficacité mémoire
- **Détection de Fuites** : Outils de diagnostic des fuites mémoire

#### Debugging Avancé
- **Tracing** : Suivi détaillé des opérations mémoire
- **Integrity Checks** : Vérifications périodiques d'intégrité
- **Memory Dump** : Analyse post-mortem des états mémoire

## Installation et compilation

Prérequis
- Make, un compilateur C (gcc/clang) — sur Windows utilisez MSYS2/MinGW ou WSL

Compiler le module `mm` (depuis la racine du dépôt) :

```powershell
make -C "c:\Users\leaf_\Desktop\Projet\shard-1\Leax\Kernel\mm" check
make -C "c:\Users\leaf_\Desktop\Projet\shard-1\Leax\Kernel\mm"
```

- `check` : vérifie la présence du compilateur et affiche la version
- La compilation génère `libmm.a` et les objets intermédiaires dans `mm/build/`.

Conseils
- Sur Windows, préférez WSL ou MSYS2 pour un environnement Make / gcc compatible.
- Pour le développement en noyau, ajustez `CFLAGS`/`CC` selon la toolchain cible.

## Usage et API rapide

Exemples d'usage (API exposée dans `mm/include/`):

- Initialisation :

```c
mm_early_init();
mm_init(&config);
```

- Allocations :

```c
void *p = kmalloc(1024, GFP_KERNEL);
kfree(p);

void *v = vmalloc(4096);

```

- Mmap/munmap : exemples dans `src/virtual/mmap.c` (API simulée pour tests utilisateurspace)

Consultez `mm/include/` pour la liste complète des prototypes et structures.

## Tests et qualité

- Les composants ont des tests unitaires et d'intégration (emplacements dans `mm/tests/` si présent).
- Exécuter une compilation rapide et vérifier l'absence d'erreurs :

```powershell
make -C "c:\Users\leaf_\Desktop\Projet\shard-1\Leax\Kernel\mm" -j 6
```

- Utiliser l'outil d'analyse statique (IntelliSense/clang-tidy) pour repérer les problèmes de types et headers.

# Pour contribuer :

Contacts et reviewers : voir `CONTRIBUTORS.md` à la racine du dépôt.

## Style et bonnes pratiques

- Indentation : 4 espaces
- Longueur de ligne : ~100 caractères max
- Documentation publique : Doxygen
- Variables et types : suffixe `_t` pour types, `MM_`/`VM_` pour constantes globales

## Licence et auteurs

Ce module reprend la licence du dépôt racine — consultez `LICENSE` à la racine.

Maintenu par l'équipe LeaxOS. Pour questions et contributions, voir `CONTRIBUTORS.md`.

---

Fichier maintenu : `mm/README.md` — conçu pour être clair, professionnel et facilement utilisable par un contributeur ou intégrateur.
buddy_print_stats();

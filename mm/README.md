# LeaxOS Memory Management Module

## Overview

The LeaxOS Memory Management (MM) module provides a comprehensive and robust memory management system for the LeaxOS kernel. This module implements all critical aspects of memory management including physical and virtual memory allocation, memory protection, and virtual memory operations.

## Architecture

### Module Structure

```
mm/
├── include/              # Public interfaces
│   ├── mm_common.h      # Common types, errors, macros
│   ├── mm.h             # Main memory manager interface
│   ├── memory_protection.h # Memory protection and domains
│   ├── page_alloc.h     # Physical page allocator
│   ├── slab.h           # SLAB/SLUB allocator
│   ├── vmalloc.h        # Virtual memory allocator
│   ├── mmap.h           # Memory mapping interface
│   ├── numa.h           # NUMA support
│   └── page_table.h     # Page table management
├── src/                  # Implementation files
│   ├── init/            # Subsystem initialization
│   ├── physical/        # Physical memory management
│   ├── virtual/         # Virtual memory management
│   ├── heap/            # Heap allocators
│   ├── protection/      # Memory protection and security
│   ├── numa/            # NUMA support
│   └── swap/            # Swap management
└── docs/                # Technical documentation
```

### Layered Architecture

The code is organized in hierarchical layers:

```
+-------------------+
|   User Space      |
+-------------------+
         |
+-------------------+
|   Virtual Memory  |  <- mmap, VMA, page faults
+-------------------+
         |
+-------------------+
|   Heap Management |  <- kmalloc, SLAB/SLUB, vmalloc
+-------------------+
         |
+-------------------+
| Physical Memory   |  <- Buddy allocator, zones, PMM
+-------------------+
         |
+-------------------+
|   Hardware        |
+-------------------+
```

### Memory Zones Architecture

```
Physical Memory Layout:
+-------------------+  <- ZONE_HIGH start
|   High Memory     |     (896MB - end)
|   (ZONE_HIGH)     |
+-------------------+
|   Normal Memory   |     (16MB - 896MB)
|   (ZONE_NORMAL)   |
+-------------------+
|   DMA Memory      |     (0 - 16MB)
|   (ZONE_DMA)      |
+-------------------+
```

## Core Features

### Memory Allocators

#### Physical Page Allocator
- Buddy system for efficient contiguous page allocation
- Zone-based management (DMA, Normal, High Memory)
- Automatic reclamation under memory pressure
- Watermark-based memory level control

#### Heap Allocators
- kmalloc/kfree: Standard kernel memory allocation
- SLAB/SLUB: Fixed-size object allocation with cache coloring
- vmalloc: Contiguous virtual memory allocation
- Early allocator: Memory management during boot phases

### Memory Protection

#### Security Domains
- Domain-based isolation between kernel, drivers, userspace
- Granular access control per domain
- Secure memory migration between domains

#### Protection Mechanisms
- Guard pages for stack/heap overflow detection
- NX/XD bit support for data execution prevention
- SMEP/SMAP for advanced kernel protection
- Memory barriers for SMP synchronization

### Virtual Memory Management

#### Memory Mapping
- mmap/munmap: Standard memory mapping interface
- VMA management: Fine-grained virtual memory region handling
- Lazy allocation with demand paging

#### Page Fault Handling
- Comprehensive page fault processing
- Copy-on-Write optimization for process duplication
- Automatic stack growth
- Demand paging for file-backed memory

### Advanced Optimizations

#### NUMA Support
- Local memory allocation preference
- Automatic load balancing between nodes
- Intelligent page migration

#### SMP Optimizations
- Per-CPU allocation caches
- Reduced lock contention
- Maintained performance scaling with CPU count

### Monitoring and Diagnostics

#### Comprehensive Statistics
- Real-time allocation/deallocation tracking
- Memory fragmentation analysis
- Memory leak detection tools

#### Advanced Debugging
- Detailed operation tracing
- Periodic integrity verification
- Post-mortem memory state analysis

## Prerequisites

- Make build system
- C compiler (GCC/Clang) - on Windows use MSYS2/MinGW or WSL
- Standard C library headers

## Installation and Compilation

Compile the mm module (from repository root):

```powershell
make -C "c:\Users\leaf_\Desktop\Projet\shard-1\Leax\Kernel\mm" check
make -C "c:\Users\leaf_\Desktop\Projet\shard-1\Leax\Kernel\mm"
```

- `check`: Verifies compiler presence and displays version
- Compilation generates `libmm.a` and intermediate objects in `mm/build/`

### Recommendations
- On Windows, prefer WSL or MSYS2 for Make/GCC compatible environment
- For kernel development, adjust `CFLAGS`/`CC` according to target toolchain

## Usage and API

### Initialization

```c
mm_early_init();
mm_init(&config);
```

### Memory Allocation

```c
void *p = kmalloc(1024, GFP_KERNEL);
kfree(p);

void *v = vmalloc(4096);
```

### Memory Mapping

See `src/virtual/mmap.c` for mmap/munmap examples (simulated API for userspace testing)

Refer to `mm/include/` for complete list of prototypes and structures.

## Testing and Quality

- Components include unit and integration tests
- Perform quick compilation and verify no errors:

```powershell
make -C "c:\Users\leaf_\Desktop\Projet\shard-1\Leax\Kernel\mm" -j 6
```

- Use static analysis tools (IntelliSense/clang-tidy) to identify type and header issues

## Contributing

See `CONTRIBUTORS.md` at repository root for contacts and reviewers.

### Code Style and Best Practices

- Indentation: 4 spaces
- Line length: ~100 characters maximum
- Public documentation: Doxygen format
- Variables and types: `_t` suffix for types, `MM_`/`VM_` prefix for global constants

## License and Authors

This module follows the repository root license - see `LICENSE` at root.

Maintained by LeaxOS team. For questions and contributions, see `CONTRIBUTORS.md`.

---

File maintained: `mm/README.md` - designed to be clear, professional and easily usable by contributors or integrators.

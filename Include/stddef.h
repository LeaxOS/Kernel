/* stddef.h - minimal kernel stddef for LeaxOS */

#ifndef LEAX_KERNEL_STDDEF_H
#define LEAX_KERNEL_STDDEF_H

#include "stdint.h"

typedef uintptr_t size_t;    /* size in bytes */
typedef intptr_t ptrdiff_t;  /* signed pointer difference */

#ifndef NULL
#define NULL ((void *)0)
#endif

#define offsetof(type, member) ((size_t)(&(((type *)0)->member)))

#define container_of(ptr, type, member) \
        ((type *)((char *)(ptr) - offsetof(type, member)))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define ROUND_UP(value, alignment) \
        (((value) + ((alignment) - 1)) & ~((alignment) - 1))

#define ROUND_DOWN(value, alignment) \
        ((value) & ~((alignment) - 1))

#define IS_POWER_OF_2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

#endif /* LEAX_KERNEL_STDDEF_H */
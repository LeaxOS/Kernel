
#ifndef LEAX_KERNEL_INCLUDE_STRING_H
#define LEAX_KERNEL_INCLUDE_STRING_H

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal, portable string.h for the kernel.
 * This header only declares common string/memory functions used across
 * the kernel. Implementations should live in the corresponding C files.
 */

#ifndef NULL
#define NULL ((void*)0)
#endif

/* Provide size_t if not already defined by other headers. Keep the
 * same macro used in the project's stdio.h to avoid redefinition.
 */
#ifndef _SIZE_T_DEFINED
#define _SIZE_T_DEFINED
typedef unsigned long size_t;
#endif

/* Memory functions */
void *memchr(const void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);

/* String functions */
size_t strlen(const char *s);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
char *strcat(char *dest, const char *src);
char *strncat(char *dest, const char *src, size_t n);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);

/* Convenience utility (optional to implement). Use only if your C
 * runtime provides allocation or the kernel has its allocator. Left
 * declared here for convenience.
 */
char *strdup(const char *s);

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_INCLUDE_STRING_H */
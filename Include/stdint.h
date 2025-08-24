/**
 * stdint.h
 * Minimal fixed-width integer types for the Leax kernel.
 *
 * This header intentionally provides a small, portable set of exact-width
 * integer typedefs and their limit macros so the kernel doesn't depend on
 * the hosted C library. Do not assume pointer width from this header.
 */

#ifndef LEAX_KERNEL_INCLUDE_STDINT_H
#define LEAX_KERNEL_INCLUDE_STDINT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Exact-width unsigned integer types */
typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long long  uint64_t;

/* Exact-width signed integer types */
typedef signed char         int8_t;
typedef signed short        int16_t;
typedef signed int          int32_t;
typedef signed long long    int64_t;

/* Limits for exact-width types */
#define INT8_MIN   (-128)
#define INT8_MAX   127
#define UINT8_MAX  255U

#define INT16_MIN  (-32768)
#define INT16_MAX  32767
#define UINT16_MAX 65535U

#define INT32_MIN  (-2147483647 - 1)
#define INT32_MAX  2147483647
#define UINT32_MAX 4294967295U

#define INT64_MIN  (-9223372036854775807LL - 1)
#define INT64_MAX  9223372036854775807LL
#define UINT64_MAX 18446744073709551615ULL

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_INCLUDE_STDINT_H */
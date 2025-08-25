/* minimal stdbool for LeaxOS */

#ifndef LEAX_KERNEL_STDBOOL_H
#define LEAX_KERNEL_STDBOOL_H

#ifdef __cplusplus
/* In C++ these are keywords; do not redefine */
#else

#ifndef __bool_true_false_are_defined
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
typedef _Bool bool;
#else
typedef unsigned char bool;
#endif
#define true 1
#define false 0
#define __bool_true_false_are_defined 1
#endif /* __bool_true_false_are_defined */

#endif /* __cplusplus */

#endif /* LEAX_KERNEL_STDBOOL_H */
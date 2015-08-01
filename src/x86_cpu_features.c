/*
 * x86_cpu_features.c
 *
 * Feature detection for x86 processors.
 *
 * Author:	Eric Biggers
 * Year:	2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#include "wimlib/x86_cpu_features.h"

#if defined(__i386__) || defined(__x86_64__)

#define DEBUG 0

#if DEBUG
#  include <stdio.h>
#endif

u32 _x86_cpu_features = 0;

static void
cpuid(u32 leaf, u32 subleaf, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	__asm__ ("cpuid\n\t"
		 : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		 : "a" (leaf), "c" (subleaf));
}

/* Read an extended control register.  */
static u64
read_xcr(u32 index)
{
	u32 edx, eax;

	__asm__ ("xgetbv\n\t" : "=d" (edx), "=a" (eax) : "c" (index));

	return ((u64)edx << 32) | eax;
}

#define IS_SET(reg, bit) ((reg) & ((u32)1 << (bit)))

void
x86_setup_cpu_features(void)
{
	u32 features = 0;
	u32 dummy1, dummy2, dummy3, dummy4;
	u32 max_function;
	u32 features_1, features_2, features_3, features_4;
	bool os_saves_ymm_regs = false;

	/* Get maximum supported function  */
	cpuid(0, 0, &max_function, &dummy2, &dummy3, &dummy4);
	if (max_function < 1)
		goto out;

	/* Standard feature flags  */
	cpuid(1, 0, &dummy1, &dummy2, &features_2, &features_1);

	if (IS_SET(features_1, 25))
		features |= X86_CPU_FEATURE_SSE;

	if (IS_SET(features_1, 26))
		features |= X86_CPU_FEATURE_SSE2;

	if (IS_SET(features_2, 9))
		features |= X86_CPU_FEATURE_SSSE3;

	if (IS_SET(features_2, 19))
		features |= X86_CPU_FEATURE_SSE4_1;

	if (IS_SET(features_2, 20))
		features |= X86_CPU_FEATURE_SSE4_2;

	if (IS_SET(features_2, 27)) /* OSXSAVE set?  */
		if (read_xcr(0) & 0x2)
			os_saves_ymm_regs = true;

	if (os_saves_ymm_regs && IS_SET(features_2, 28))
		features |= X86_CPU_FEATURE_AVX;

	if (max_function < 7)
		goto out;

	/* Extended feature flags  */

	cpuid(7, 0, &dummy1, &features_3, &features_4, &dummy4);

	if (IS_SET(features_3, 3))
		features |= X86_CPU_FEATURE_BMI;

	if (os_saves_ymm_regs && IS_SET(features_3, 5))
		features |= X86_CPU_FEATURE_AVX2;

	if (IS_SET(features_3, 8))
		features |= X86_CPU_FEATURE_BMI2;

#if DEBUG
	printf("Detected x86 CPU features: ");
	if (features & X86_CPU_FEATURE_SSE)
		printf("SSE ");
	if (features & X86_CPU_FEATURE_SSE2)
		printf("SSE2 ");
	if (features & X86_CPU_FEATURE_SSSE3)
		printf("SSSE3 ");
	if (features & X86_CPU_FEATURE_SSE4_1)
		printf("SSE4.1 ");
	if (features & X86_CPU_FEATURE_SSE4_2)
		printf("SSE4.2 ");
	if (features & X86_CPU_FEATURE_BMI)
		printf("BMI ");
	if (features & X86_CPU_FEATURE_AVX)
		printf("AVX ");
	if (features & X86_CPU_FEATURE_BMI2)
		printf("BMI2 ");
	if (features & X86_CPU_FEATURE_AVX2)
		printf("AVX2 ");
	printf("\n");
#endif

out:
	_x86_cpu_features = features | X86_CPU_FEATURES_KNOWN;
}

#endif /* __i386__ || __x86_64__ */

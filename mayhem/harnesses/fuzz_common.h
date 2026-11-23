/*
 * Shared byte-reader + tables for the libseccomp fuzz harnesses.
 * Every harness takes its whole input from the fuzzer; nothing is read from disk.
 */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct reader {
	const uint8_t *d;
	size_t n, i;
};

static inline int rd_left(const struct reader *r) { return r->i < r->n; }

static inline uint8_t rd_u8(struct reader *r)
{
	return r->i < r->n ? r->d[r->i++] : 0;
}

static inline uint16_t rd_u16(struct reader *r)
{
	return (uint16_t)(rd_u8(r) | (rd_u8(r) << 8));
}

static inline uint64_t rd_u64(struct reader *r)
{
	uint64_t v = 0;
	for (int k = 0; k < 8; k++)
		v |= (uint64_t)rd_u8(r) << (8 * k);
	return v;
}

static const uint32_t fz_archs[] = {
	SCMP_ARCH_NATIVE, SCMP_ARCH_X86, SCMP_ARCH_X86_64, SCMP_ARCH_X32,
	SCMP_ARCH_ARM, SCMP_ARCH_AARCH64, SCMP_ARCH_LOONGARCH64, SCMP_ARCH_M68K,
	SCMP_ARCH_MIPS, SCMP_ARCH_MIPS64, SCMP_ARCH_MIPS64N32, SCMP_ARCH_MIPSEL,
	SCMP_ARCH_MIPSEL64, SCMP_ARCH_MIPSEL64N32, SCMP_ARCH_PPC, SCMP_ARCH_PPC64,
	SCMP_ARCH_PPC64LE, SCMP_ARCH_S390, SCMP_ARCH_S390X, SCMP_ARCH_PARISC,
	SCMP_ARCH_PARISC64, SCMP_ARCH_RISCV64, SCMP_ARCH_SHEB, SCMP_ARCH_SH,
};
#define FZ_NARCHS (sizeof(fz_archs) / sizeof(fz_archs[0]))

static inline uint32_t rd_arch(struct reader *r)
{
	return fz_archs[rd_u8(r) % FZ_NARCHS];
}

/* actions, including the parameterised ones; the low bits come from the input */
static inline uint32_t rd_action(struct reader *r)
{
	uint8_t b = rd_u8(r);
	switch (b % 9) {
	case 0: return SCMP_ACT_KILL_PROCESS;
	case 1: return SCMP_ACT_KILL_THREAD;
	case 2: return SCMP_ACT_TRAPX(rd_u8(r));
	case 3: return SCMP_ACT_ERRNO(rd_u16(r));
	case 4: return SCMP_ACT_TRACE(rd_u16(r));
	case 5: return SCMP_ACT_LOG;
	case 6: return SCMP_ACT_ALLOW;
	case 7: return SCMP_ACT_NOTIFY;
	default: return (uint32_t)rd_u16(r) << 16 | rd_u16(r); /* raw/invalid */
	}
}

/*
 * Syscall numbers: a small window of real numbers so rules collide and build
 * chains, the libseccomp pseudo-syscalls (__PNR_*, -10000..-10250), and -1.
 */
static inline int rd_syscall(struct reader *r)
{
	uint16_t v = rd_u16(r);
	switch (v >> 14) {
	case 0: return (int)(v % 64);
	case 1: return (int)(v % 600);
	case 2: return -10000 - (int)(v % 256);
	default: return (v & 1) ? -1 : (int)(int16_t)v;
	}
}

/* 0..6 argument comparisons; returns the count */
static inline unsigned rd_args(struct reader *r, struct scmp_arg_cmp *a)
{
	unsigned cnt = rd_u8(r) % 7, k;
	for (k = 0; k < cnt; k++) {
		uint8_t b = rd_u8(r);
		a[k].arg = b % 7;            /* 6 is out of range on purpose */
		a[k].op = (b >> 3) % 9;      /* 0 and 8 are invalid on purpose */
		a[k].datum_a = rd_u64(r);
		a[k].datum_b = rd_u64(r);
	}
	return cnt;
}

#endif

/*
 * fuzz_filter: build a seccomp filter from a fuzzer-chosen rule set through the
 * public API, then generate it with every exporter (BPF to an fd, BPF into a
 * caller buffer of several sizes, PFC text).
 *
 * Reaches src/api.c, src/db.c (rule tree, argument chains, per-arch syscall
 * rewriting), src/gen_bpf.c (both optimize levels) and src/gen_pfc.c.
 * seccomp_load() is never called: it would install the filter on the fuzzer.
 *
 * Process-global state: the API level (seccomp_api_set) is set from every
 * input, so no input inherits the previous one's level.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "fuzz_common.h"

static int devnull = -1;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct reader r = { data, size, 0 };
	struct scmp_arg_cmp args[6];
	scmp_filter_ctx ctx;

	if (size < 3)
		return -1;
	if (devnull < 0)
		devnull = open("/dev/null", O_WRONLY);

	seccomp_api_set(1 + rd_u8(&r) % 7);
	ctx = seccomp_init(rd_action(&r));
	if (ctx == NULL)
		return 0;

	uint8_t flags = rd_u8(&r);
	seccomp_attr_set(ctx, SCMP_FLTATR_CTL_OPTIMIZE, 1 + (flags & 1));
	if (flags & 2)
		seccomp_attr_set(ctx, SCMP_FLTATR_API_TSKIP, 1);
	if (flags & 4)
		seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, rd_action(&r));
	if (flags & 8)
		seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);
	if (flags & 16)
		seccomp_attr_set(ctx, SCMP_FLTATR_CTL_SSB, 1);
	if (flags & 32)
		seccomp_attr_set(ctx, SCMP_FLTATR_API_SYSRAWRC, 1);

	while (rd_left(&r)) {
		uint8_t op = rd_u8(&r);
		switch (op % 6) {
		case 0:
			seccomp_arch_add(ctx, rd_arch(&r));
			break;
		case 1:
			seccomp_arch_remove(ctx, rd_arch(&r));
			break;
		case 2: {
			int sc = rd_syscall(&r);
			seccomp_syscall_priority(ctx, sc, rd_u8(&r));
			break;
		}
		case 3:
		case 4: {
			uint32_t act = rd_action(&r);
			int sc = rd_syscall(&r);
			unsigned cnt = rd_args(&r, args);
			seccomp_rule_add_array(ctx, act, sc, cnt, args);
			break;
		}
		default: {
			uint32_t act = rd_action(&r);
			int sc = rd_syscall(&r);
			unsigned cnt = rd_args(&r, args);
			seccomp_rule_add_exact_array(ctx, act, sc, cnt, args);
			break;
		}
		}
	}

	seccomp_export_pfc(ctx, devnull);
	seccomp_export_bpf(ctx, devnull);

	/* size query, then exact, short and oversized caller buffers */
	size_t len = 0;
	if (seccomp_export_bpf_mem(ctx, NULL, &len) == 0 && len > 0) {
		size_t sizes[3] = { len, len / 2, len + 64 };
		for (int k = 0; k < 3; k++) {
			size_t l = sizes[k];
			void *buf = malloc(l ? l : 1);
			if (buf == NULL)
				break;
			seccomp_export_bpf_mem(ctx, buf, &l);
			free(buf);
		}
	}

	seccomp_release(ctx);
	return 0;
}

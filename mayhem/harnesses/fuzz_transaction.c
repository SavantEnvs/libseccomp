/*
 * fuzz_transaction: a stateful interpreter over two filter contexts that drives
 * the filter-lifecycle API: nested transactions (start/commit/reject), merge,
 * reset, precompute, syscall priorities and attributes, interleaved with rule
 * and arch changes, then exports the result.
 *
 * Reaches the db.c snapshot/rollback and duplication code, db_col_merge, the
 * precompute cache in api.c/gen_bpf.c and attribute handling.
 * seccomp_load() is never called. The API level is set from every input.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "fuzz_common.h"

static int devnull = -1;

static void export_all(scmp_filter_ctx ctx)
{
	size_t len = 0;

	seccomp_export_pfc(ctx, devnull);
	if (seccomp_export_bpf_mem(ctx, NULL, &len) == 0 && len > 0) {
		size_t l = len + 32;
		void *buf = malloc(l);
		if (buf != NULL) {
			seccomp_export_bpf_mem(ctx, buf, &l);
			free(buf);
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct reader r = { data, size, 0 };
	struct scmp_arg_cmp args[6];
	scmp_filter_ctx ctx[2];
	uint32_t def;
	unsigned steps = 0;

	if (size < 3)
		return -1;
	if (devnull < 0)
		devnull = open("/dev/null", O_WRONLY);

	seccomp_api_set(1 + rd_u8(&r) % 7);
	def = rd_action(&r);
	ctx[0] = seccomp_init(def);
	ctx[1] = seccomp_init(def);

	while (rd_left(&r) && steps++ < 4096) {
		uint8_t op = rd_u8(&r);
		scmp_filter_ctx c = ctx[op >> 7];
		if (c == NULL) {
			ctx[op >> 7] = seccomp_init(def);
			continue;
		}
		switch (op % 16) {
		case 0:
			seccomp_arch_add(c, rd_arch(&r));
			break;
		case 1:
			seccomp_arch_remove(c, rd_arch(&r));
			break;
		case 2:
		case 3: {
			uint32_t act = rd_action(&r);
			int sc = rd_syscall(&r);
			unsigned cnt = rd_args(&r, args);
			if (op & 0x40)
				seccomp_rule_add_exact_array(c, act, sc, cnt, args);
			else
				seccomp_rule_add_array(c, act, sc, cnt, args);
			break;
		}
		case 4:
			seccomp_transaction_start(c);
			break;
		case 5:
			seccomp_transaction_commit(c);
			break;
		case 6:
			seccomp_transaction_reject(c);
			break;
		case 7: {
			int sc = rd_syscall(&r);
			seccomp_syscall_priority(c, sc, rd_u8(&r));
			break;
		}
		case 8: {
			uint8_t a = rd_u8(&r);
			enum scmp_filter_attr attr = (enum scmp_filter_attr)(a % 12);
			uint32_t val;
			if (attr == SCMP_FLTATR_ACT_DEFAULT ||
			    attr == SCMP_FLTATR_ACT_BADARCH)
				val = rd_action(&r);
			else
				val = rd_u8(&r) % 4;
			seccomp_attr_set(c, attr, val);
			uint32_t got;
			seccomp_attr_get(c, attr, &got);
			break;
		}
		case 9:
			seccomp_precompute(c);
			break;
		case 10:
			/* on success the source context is consumed */
			if (ctx[0] != NULL && ctx[1] != NULL &&
			    seccomp_merge(ctx[0], ctx[1]) == 0)
				ctx[1] = NULL;
			break;
		case 11:
			seccomp_reset(c, rd_action(&r));
			break;
		case 12:
			seccomp_reset(NULL, rd_action(&r));
			break;
		case 13:
			seccomp_arch_exist(c, rd_arch(&r));
			break;
		case 14:
			export_all(c);
			break;
		default:
			seccomp_export_bpf(c, devnull);
			break;
		}
	}

	for (int k = 0; k < 2; k++) {
		if (ctx[k] == NULL)
			continue;
		export_all(ctx[k]);
		seccomp_release(ctx[k]);
	}
	return 0;
}

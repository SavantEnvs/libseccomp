/*
 * fuzz_resolve: the public name/number resolvers.
 *   byte 0      selects the architecture (from the arch table, or native)
 *   bytes 1..4  a syscall number for seccomp_syscall_resolve_num_arch()
 *   rest        a NUL-terminated syscall/arch name for
 *               seccomp_syscall_resolve_name{,_arch,_rewrite}() and
 *               seccomp_arch_resolve_name()
 * Reaches src/syscalls.c, the gperf table (syscalls.perf.c) and the per-arch
 * resolvers/rewriters in src/arch*.c. Stateless.
 */
#include <stdlib.h>
#include <string.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct reader r = { data, size, 0 };
	uint32_t arch;
	int32_t num;
	char *name, *s;

	if (size < 5)
		return -1;

	arch = rd_arch(&r);
	num = (int32_t)(rd_u16(&r) | ((uint32_t)rd_u16(&r) << 16));

	s = seccomp_syscall_resolve_num_arch(arch, num);
	if (s != NULL) {
		/* round trip the resolved name */
		seccomp_syscall_resolve_name_arch(arch, s);
		free(s);
	}

	name = malloc(size - r.i + 1);
	if (name == NULL)
		return 0;
	memcpy(name, data + r.i, size - r.i);
	name[size - r.i] = '\0';

	seccomp_syscall_resolve_name(name);
	num = seccomp_syscall_resolve_name_arch(arch, name);
	seccomp_syscall_resolve_name_rewrite(arch, name);
	if (num != __NR_SCMP_ERROR) {
		s = seccomp_syscall_resolve_num_arch(arch, num);
		free(s);
	}
	seccomp_arch_resolve_name(name);

	free(name);
	return 0;
}

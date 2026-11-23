/*
 * fuzz_bpf_disasm: the scmp_bpf_disasm tool's decoder over an untrusted raw
 * classic-BPF program (an array of struct sock_filter records).
 *
 * The tool's main() only parses argv (-a ARCH, -d) and hands a FILE* (stdin)
 * to bpf_decode() or bpf_dot_decode(); upstream's file-argument handling uses
 * argv[optind - 1], so with an option the file is never opened as given. This
 * harness compiles the tool's own source with its main() renamed and drives
 * the same two decoders over an in-memory FILE*, choosing the options from
 * the first byte:
 *   byte 0  bit 0: -d (dot output), bits 1..: -a ARCH from the tool's list
 *   rest    the BPF program, exactly as the tool reads it from stdin
 * The decoders write to stdout; it is redirected to /dev/null once.
 * Per-input state: the tool's global `arch` is set from every input.
 */
#define main scmp_bpf_disasm_main
#include "../../tools/scmp_bpf_disasm.c"
#undef main

/* the architectures main() accepts for -a */
static const uint32_t tool_archs[] = {
	AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, AUDIT_ARCH_ARM, AUDIT_ARCH_AARCH64,
	AUDIT_ARCH_LOONGARCH64, AUDIT_ARCH_MIPS, AUDIT_ARCH_MIPSEL,
	AUDIT_ARCH_MIPS64, AUDIT_ARCH_MIPSEL64, AUDIT_ARCH_MIPS64N32,
	AUDIT_ARCH_MIPSEL64N32, AUDIT_ARCH_PPC64, AUDIT_ARCH_PPC64LE,
	AUDIT_ARCH_PPC, AUDIT_ARCH_S390, AUDIT_ARCH_S390X, AUDIT_ARCH_RISCV64,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	if (freopen("/dev/null", "w", stdout) == NULL)
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FILE *f;

	if (size < 1)
		return -1;

	arch = tool_archs[(data[0] >> 1) %
			  (sizeof(tool_archs) / sizeof(tool_archs[0]))];

	f = fmemopen((void *)(data + 1), size - 1 ? size - 1 : 1, "r");
	if (f == NULL)
		return 0;
	if (size == 1)
		fseek(f, 0, SEEK_END);
	if (data[0] & 1)
		bpf_dot_decode(f);
	else
		bpf_decode(f);
	fclose(f);
	return 0;
}

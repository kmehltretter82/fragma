#!/bin/sh
# Rebuild the project-only RV32 guard-page reproducer before and after the fix.
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "usage: $0 SOURCE_KERNEL_TREE NEW_WORK_DIRECTORY [JOBS]" >&2
	exit 2
fi

source_tree=$1
work=$2
jobs=${3:-4}
project=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
base=df2908090cda368b01ff43709f51890076c56157
next=af5f12805e5cefa4fe68d6127c7e1fb78cd5535c
diagnostic_patch=$project/riscv/rv32-zeropad/reproducer/0001-DO-NOT-SUBMIT-riscv-Add-RV32-unaligned-zeropad-repro.patch
fix_patch=$project/riscv/rv32-zeropad/patches/0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch
fragment=$project/riscv/rv32-zeropad/repro.config

case $jobs in
	''|*[!0-9]*|0)
		echo "JOBS must be a positive integer" >&2
		exit 2
		;;
esac

for tool in git make riscv64-linux-gnu-gcc qemu-system-riscv32 timeout cmp grep; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "missing required tool: $tool" >&2
		exit 2
	fi
done
if ! git -C "$source_tree" rev-parse --git-dir >/dev/null 2>&1; then
	echo "not a Git kernel source tree: $source_tree" >&2
	exit 2
fi
if [ -e "$work" ] || [ -L "$work" ]; then
	echo "refusing to overwrite existing work path: $work" >&2
	exit 2
fi
for commit in "$base" "$next"; do
	if ! git -C "$source_tree" cat-file -e "$commit^{commit}"; then
		echo "source tree lacks required commit: $commit" >&2
		exit 2
	fi
done

mkdir -p "$(dirname -- "$work")"
mkdir "$work"
git clone --shared --no-checkout "$source_tree" "$work/linux"
linux=$work/linux
build=$work/build-rv32
build_rv64=$work/build-rv64
evidence=$work/evidence
mkdir "$evidence"

git -C "$linux" checkout --detach "$base"
git -C "$linux" am "$diagnostic_patch"

make -C "$linux" O="$build" ARCH=riscv \
	CROSS_COMPILE=riscv64-linux-gnu- defconfig
"$linux/scripts/kconfig/merge_config.sh" -m -O "$build" \
	"$build/.config" "$fragment"
make -C "$linux" O="$build" ARCH=riscv \
	CROSS_COMPILE=riscv64-linux-gnu- olddefconfig
for setting in \
	CONFIG_32BIT=y \
	CONFIG_MMU=y \
	CONFIG_RISCV_EFFICIENT_UNALIGNED_ACCESS=y \
	CONFIG_DCACHE_WORD_ACCESS=y \
	CONFIG_KUNIT=y \
	CONFIG_KUNIT_AUTORUN_ENABLED=y; do
	grep -qx "$setting" "$build/.config"
done
make -C "$linux" O="$build" ARCH=riscv \
	CROSS_COMPILE=riscv64-linux-gnu- -j"$jobs" Image
cp "$build/.config" "$evidence/config.before"
cp "$build/arch/riscv/boot/Image" "$evidence/Image.before"

set +e
timeout 90s qemu-system-riscv32 -machine virt -m 256M -smp 1 \
	-nographic -no-reboot -bios default \
	-kernel "$evidence/Image.before" \
	-append 'console=ttyS0 earlycon=sbi kunit.enable=1 kunit.autorun=1 kunit.filter_glob=riscv-load-unaligned-zeropad panic=-1' \
	>"$evidence/qemu-before.log" 2>&1
before_qemu_status=$?
set -e
if [ "$before_qemu_status" -ne 0 ] && [ "$before_qemu_status" -ne 124 ]; then
	echo "unpatched QEMU terminated unexpectedly: $before_qemu_status" >&2
	exit 1
fi

grep -Fq 'got == 165 (0xa5)' "$evidence/qemu-before.log"
grep -Fq 'got == 42405 (0xa5a5)' "$evidence/qemu-before.log"
grep -Fq 'got == 10855845 (0xa5a5a5)' "$evidence/qemu-before.log"
grep -Fq 'expected == 68 (0x44)' "$evidence/qemu-before.log"
grep -Fq 'expected == 17459 (0x4433)' "$evidence/qemu-before.log"
grep -Fq 'expected == 4469538 (0x443322)' "$evidence/qemu-before.log"
grep -Fq 'not ok 1 riscv-load-unaligned-zeropad' "$evidence/qemu-before.log"

git -C "$linux" am "$fix_patch"
make -C "$linux" O="$build" ARCH=riscv \
	CROSS_COMPILE=riscv64-linux-gnu- -j"$jobs" Image
cp "$build/.config" "$evidence/config.after"
cp "$build/arch/riscv/boot/Image" "$evidence/Image.after"

set +e
timeout 90s qemu-system-riscv32 -machine virt -m 256M -smp 1 \
	-nographic -no-reboot -bios default \
	-kernel "$evidence/Image.after" \
	-append 'console=ttyS0 earlycon=sbi kunit.enable=1 kunit.autorun=1 kunit.filter_glob=riscv-load-unaligned-zeropad panic=-1' \
	>"$evidence/qemu-after.log" 2>&1
after_qemu_status=$?
set -e
if [ "$after_qemu_status" -ne 0 ] && [ "$after_qemu_status" -ne 124 ]; then
	echo "patched QEMU terminated unexpectedly: $after_qemu_status" >&2
	exit 1
fi

grep -Fq 'ok 1 riscv_load_unaligned_zeropad_guard_test' "$evidence/qemu-after.log"
grep -Fq '] ok 1 riscv-load-unaligned-zeropad' "$evidence/qemu-after.log"
if grep -Fq 'EXPECTATION FAILED' "$evidence/qemu-after.log"; then
	echo "patched KUnit log still contains an expectation failure" >&2
	exit 1
fi
cmp "$evidence/config.before" "$evidence/config.after"

make -C "$linux" O="$build_rv64" ARCH=riscv \
	CROSS_COMPILE=riscv64-linux-gnu- defconfig
make -C "$linux" O="$build_rv64" ARCH=riscv \
	CROSS_COMPILE=riscv64-linux-gnu- -j"$jobs" arch/riscv/mm/extable.o

(cd "$linux" && scripts/checkpatch.pl --strict --no-tree "$fix_patch")
(cd "$linux" && scripts/get_maintainer.pl --no-rolestats "$fix_patch") \
	>"$evidence/maintainers.txt"

echo "PASS: unpatched RV32 fails, patched RV32 passes, configs match"
echo "Evidence: $evidence"

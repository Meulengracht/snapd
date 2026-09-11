#!/bin/sh
set -eu

# Replace snap-bootstrap inside the UC26 kernel snap's unified kernel image
# (UKI) with the binary built from this checkout. A UKI is a PE executable whose
# .linux and .initrd sections are loaded by the EFI stub, so changing the initrd
# requires rebuilding the section layout rather than editing the squashfs alone.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
input_snap=${1:?usage: repack-kernel.sh INPUT-KERNEL OUTPUT-KERNEL}
output_snap=${2:?usage: repack-kernel.sh INPUT-KERNEL OUTPUT-KERNEL}
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/kernel-poc.XXXXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

# Fail before unpacking the large kernel snap if any archive, PE, compression,
# build, or snap-validation tool required by the reconstruction is unavailable.
for command in cpio go objcopy objdump snap unsquashfs zstd zstdcat; do
    if ! command -v "$command" >/dev/null; then
        echo "missing required command: $command" >&2
        exit 1
    fi
done

# Start from the distro's pristine EFI stub when rebuilding. Growing .initrd in
# the existing UKI can leave overlapping PE sections and an image firmware will
# reject even though objcopy itself succeeds.
efi_stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
if [ ! -f "$efi_stub" ]; then
    echo "missing required EFI stub: $efi_stub" >&2
    exit 1
fi

# Preserve the payload sections from the published UKI. The existing PE
# container is discarded later, but its kernel, release metadata, and uname
# remain the inputs to the reconstructed image.
echo "unpacking UC26 kernel snap"
unsquashfs -no-progress -f -d "$work_dir/kernel" "$input_snap"
objcopy -O binary -j .initrd "$work_dir/kernel/kernel.efi" "$work_dir/initrd"
objcopy -O binary -j .linux "$work_dir/kernel/kernel.efi" "$work_dir/linux"
objcopy -O binary -j .osrel "$work_dir/kernel/kernel.efi" "$work_dir/osrel"
objcopy -O binary -j .uname "$work_dir/kernel/kernel.efi" "$work_dir/uname"

# UC26 uses a concatenated initrd: an uncompressed early cpio archive followed
# by a zstd-compressed main cpio archive. cpio stops at the end of the first
# archive, leaving the shared input stream positioned for zstdcat to consume
# the main archive.
echo "extracting UC26 UKI initrd"
mkdir "$work_dir/early" "$work_dir/main"
(
    cd "$work_dir/early"
    cpio -id --quiet
    cd "$work_dir/main"
    zstdcat | cpio -id --quiet
) < "$work_dir/initrd"

# Build the same initramfs-oriented snap-bootstrap variant used by snapd's test
# snap. withtestkeys accepts the repository model, nomanagers avoids daemon-only
# dependencies, and netgo keeps name resolution self-contained in the initrd.
(
    cd "$repo_root"
    echo "building snap-bootstrap for UC26 initramfs"
    CGO_ENABLED=1 go build -mod=readonly -tags withtestkeys,nomanagers,netgo \
        -o "$work_dir/main/usr/lib/snapd/snap-bootstrap.real" \
        ./cmd/snap-bootstrap
)

    # Keep stdout untouched for snap-bootstrap subcommands whose callers parse it.
    # Only initramfs-mounts is redirected to the serial console, where early-boot
    # failures remain visible even when the nested VM never reaches SSH or systemd.
cat > "$work_dir/main/usr/lib/snapd/snap-bootstrap" <<'EOF'
#!/bin/sh
if [ "${1-}" != initramfs-mounts ]; then
    exec /usr/lib/snapd/snap-bootstrap.real "$@"
fi
echo "boot-from-seed-poc: snap-bootstrap $*" > /dev/ttyS0
if /usr/lib/snapd/snap-bootstrap.real "$@" > /dev/ttyS0 2>&1; then
    exit 0
else
    status=$?
    echo "boot-from-seed-poc: snap-bootstrap failed status=$status" > /dev/ttyS0
    exit "$status"
fi
EOF
chmod 0755 "$work_dir/main/usr/lib/snapd/snap-bootstrap"

# Reproduce the original two-part initrd structure with deterministic root
# ownership. The compression level favors iteration speed for this PoC; kernel
# boot only requires a valid zstd stream, not the publisher's exact encoding.
echo "rebuilding UC26 UKI initrd"
(
    cd "$work_dir/early"
    find . | cpio --create --quiet --format=newc --owner=0:0
) > "$work_dir/new-initrd"
(
    cd "$work_dir/main"
    find . | cpio --create --quiet --format=newc --owner=0:0 | zstd -1 -T0
) >> "$work_dir/new-initrd"

# PE section VMAs are absolute addresses based on the stub's ImageBase. Keep
# small metadata sections near the stub's conventional offsets, place .linux
# well above the stub, and page-align .initrd immediately after the kernel so
# the two variable-sized payloads cannot overlap.
image_base_hex=$(objdump -p "$efi_stub" | awk '/ImageBase/ { print $2; exit }')
image_base=$((0x$image_base_hex))
osrel_vma=$(printf '0x%x' $((image_base + 0x30000)))
uname_vma=$(printf '0x%x' $((image_base + 0x31000)))
linux_vma=$((image_base + 0x2000000))
linux_size=$(stat -c %s "$work_dir/linux")
initrd_vma=$(( (linux_vma + linux_size + 0xfff) & ~0xfff ))
linux_vma=$(printf '0x%x' "$linux_vma")
initrd_vma=$(printf '0x%x' "$initrd_vma")

# Construct a fresh UKI from the stub and preserved payloads. This intentionally
# produces an unsigned kernel. The PoC disables Secure Boot rather than trying
# to preserve or forge the signature of the downloaded kernel snap.
objcopy \
    --add-section .osrel="$work_dir/osrel" --change-section-vma .osrel="$osrel_vma" \
    --add-section .uname="$work_dir/uname" --change-section-vma .uname="$uname_vma" \
    --add-section .linux="$work_dir/linux" --change-section-vma .linux="$linux_vma" \
    --add-section .initrd="$work_dir/new-initrd" --change-section-vma .initrd="$initrd_vma" \
    "$efi_stub" "$work_dir/kernel/kernel.efi"

# Validate snap structure, then force root ownership in the repacked squashfs.
# The latter is required even when this script runs from a normal user account.
echo "packing UC26 kernel snap"
snap pack --check-skeleton "$work_dir/kernel"
mksquashfs "$work_dir/kernel" "$output_snap" -noappend -comp xz -all-root -no-progress

# Verify the final UKI, not just the temporary initrd used to build it. Extract
# both cpio layers again, require an executable replacement, and compare its
# bytes with the locally built binary. The extraction may report trailing-data
# noise at the archive boundary, hence the guarded pipeline; the assertions
# below remain authoritative.
echo "verifying embedded snap-bootstrap"
objcopy -O binary -j .initrd "$work_dir/kernel/kernel.efi" "$work_dir/check-initrd"
mkdir "$work_dir/check-early" "$work_dir/check-main"
(
    cd "$work_dir/check-early"
    cpio -id --quiet
    cd "$work_dir/check-main"
    zstdcat 2>/dev/null | cpio -id --quiet
) < "$work_dir/check-initrd" || true
test -x "$work_dir/check-main/usr/lib/snapd/snap-bootstrap.real"
cmp "$work_dir/main/usr/lib/snapd/snap-bootstrap.real" \
    "$work_dir/check-main/usr/lib/snapd/snap-bootstrap.real"

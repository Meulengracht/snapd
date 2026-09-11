#!/bin/sh
set -eu

# Repack core26 with the guest-side pieces of the boot-from-seed PoC. Runtime
# logic that must exist on every boot goes into the immutable root filesystem;
# test state and mutable helpers are seeded through core26's factory writable
# tree and copied into ubuntu-data during first-boot initialization.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
input_snap=${1:?usage: repack-core26.sh INPUT-CORE26 OUTPUT-CORE26 TEST-SNAP-B}
output_snap=${2:?usage: repack-core26.sh INPUT-CORE26 OUTPUT-CORE26 TEST-SNAP-B}
test_snap_b=${3:?usage: repack-core26.sh INPUT-CORE26 OUTPUT-CORE26 TEST-SNAP-B}

# Re-enter under fakeroot when called by an unprivileged developer. Snap
# skeleton validation and the reconstructed squashfs must observe root-owned
# system files even though the extraction directory belongs to the caller.
if [ "$(id -u)" -ne 0 ] && [ -z "${FAKEROOTKEY-}" ]; then
    exec fakeroot "$0" "$input_snap" "$output_snap" "$test_snap_b"
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/core26-poc.XXXXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

# Work on a disposable expanded filesystem; the downloaded source snap remains
# byte-for-byte untouched and can be reused by later builds.
unsquashfs -no-progress -f -d "$work_dir/root" "$input_snap"

# The generator must live in /usr so systemd runs it before unit loading on
# every boot. It reads snap-bootstrap's volatile booted-run-seed marker and
# publishes only the units belonging to that selected seed.
install -D -m 0755 "$script_dir/generator/snapd-run-system-generator" \
    "$work_dir/root/usr/lib/systemd/system-generators/snapd-run-system-generator"

# Files below /usr/share/factory/writable/system-data are source templates, not
# directly writable runtime files. The matching tmpfiles C entries below copy
# them to /writable/system-data while preserving the initialized device's
# writable layout.
factory_data="$work_dir/root/usr/share/factory/writable/system-data"
install -D -m 0755 "$script_dir/helpers/finalize-run-system" \
    "$factory_data/var/lib/snapd/boot-from-seed-poc/finalize-run-system"
install -D -m 0755 "$script_dir/helpers/rollback-run-system" \
    "$factory_data/var/lib/snapd/boot-from-seed-poc/rollback-run-system"
install -D -m 0755 "$script_dir/run-ab-test.sh" \
    "$factory_data/var/lib/snapd/boot-from-seed-poc/run-ab-test.sh"
install -D -m 0644 "$test_snap_b" \
    "$factory_data/var/lib/snapd/boot-from-seed-poc/test-snap-b.snap"

# A tmpfiles C directive copies a factory file only when the destination does
# not already exist. This installs the helpers on first boot without replacing
# test progress or locally modified diagnostics on subsequent boots.
tmpfiles="$work_dir/root/usr/lib/tmpfiles.d/boot-from-seed-poc.conf"
cat > "$tmpfiles" <<'EOF'
C /writable/system-data/var/lib/snapd/boot-from-seed-poc/finalize-run-system
C /writable/system-data/var/lib/snapd/boot-from-seed-poc/rollback-run-system
C /writable/system-data/var/lib/snapd/boot-from-seed-poc/run-ab-test.sh
C /writable/system-data/var/lib/snapd/boot-from-seed-poc/test-snap-b.snap
EOF

# Autostart is optional because spread starts the test explicitly after device
# initialization, while a manually booted image may need to drive itself using
# serial output alone.
if [ "${POC_AUTOSTART-}" = 1 ]; then
    touch "$factory_data/var/lib/snapd/boot-from-seed-poc/autostart"
    printf 'C /writable/system-data/var/lib/snapd/boot-from-seed-poc/autostart\n' >> "$tmpfiles"
fi

# Seed the persistent systemd configuration into factory writable state. The
# rollback unit is activated through OnFailure by per-seed finalizer units; the
# test service resumes the phase machine after each reboot.
factory_systemd="$work_dir/root/usr/share/factory/writable/system-data/etc/systemd/system"
install -D -m 0644 "$script_dir/systemd/snapd-run-system-rollback.service" \
    "$factory_systemd/snapd-run-system-rollback.service"
install -D -m 0644 "$script_dir/systemd/boot-from-seed-poc-test.service" \
    "$factory_systemd/boot-from-seed-poc-test.service"
mkdir -p "$factory_systemd/multi-user.target.wants"
ln -sfn ../boot-from-seed-poc-test.service \
    "$factory_systemd/multi-user.target.wants/boot-from-seed-poc-test.service"

# Validate snap metadata and filesystem shape before packing. -all-root is
# required because ownership from the developer's extraction directory must
# never leak into the base snap used by ubuntu-image.
snap pack --check-skeleton "$work_dir/root"
mksquashfs "$work_dir/root" "$output_snap" -noappend -comp xz -all-root -no-progress

# Re-open the produced squashfs and check representative files from both the
# immutable generator path and factory writable tree. This catches a successful
# pack of the wrong directory or a silently omitted install destination.
for expected in \
    usr/lib/systemd/system-generators/snapd-run-system-generator \
    usr/share/factory/writable/system-data/var/lib/snapd/boot-from-seed-poc/run-ab-test.sh \
    usr/share/factory/writable/system-data/etc/systemd/system/boot-from-seed-poc-test.service; do
    unsquashfs -ll "$output_snap" "$expected" | grep -q "$expected"
done
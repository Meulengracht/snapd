#!/bin/sh
set -eu

# Boot a disposable copy of the local profile with UEFI and Secure Boot off.
# QEMU remains alive across the A/B reboots, while SSH is forwarded to port
# 8022 for manually starting and observing the guest-side state machine.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
image=${1:-"$script_dir/artifacts/local/uc26-boot-from-seed-poc.img"}

if [ ! -f "$image" ]; then
    echo "cannot find PoC image: $image" >&2
    exit 1
fi

ovmf_code=${POC_OVMF_CODE-}
ovmf_vars=${POC_OVMF_VARS-}
for candidate in \
    /usr/share/edk2/x64/OVMF_CODE.4m.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd; do
    if [ -z "$ovmf_code" ] && [ -f "$candidate" ]; then
        ovmf_code=$candidate
    fi
done
for candidate in \
    /usr/share/edk2/x64/OVMF_VARS.4m.fd \
    /usr/share/OVMF/OVMF_VARS_4M.fd \
    /usr/share/OVMF/OVMF_VARS.fd; do
    if [ -z "$ovmf_vars" ] && [ -f "$candidate" ]; then
        ovmf_vars=$candidate
    fi
done
if [ -z "$ovmf_code" ] || [ -z "$ovmf_vars" ]; then
    echo "cannot find OVMF firmware; set POC_OVMF_CODE and POC_OVMF_VARS" >&2
    exit 1
fi

run_dir=$(mktemp -d "${TMPDIR:-/tmp}/boot-from-seed-vm.XXXXXXXX")
cp --reflink=auto --sparse=always "$image" "$run_dir/disk.img"
cp "$ovmf_vars" "$run_dir/OVMF_VARS.fd"

echo "VM state: $run_dir"
echo "SSH after first boot: ssh -p 8022 philip@127.0.0.1"
echo "Start the test: sudo /var/lib/snapd/boot-from-seed-poc/run-ab-test.sh start"

exec qemu-system-x86_64 \
    -enable-kvm \
    -machine q35,accel=kvm \
    -cpu host \
    -smp 3 \
    -m 4096 \
    -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
    -drive if=pflash,format=raw,file="$run_dir/OVMF_VARS.fd" \
    -drive file="$run_dir/disk.img",cache=none,format=raw,id=disk1,if=none \
    -device virtio-blk-pci,drive=disk1,bootindex=1 \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:8022-:22 \
    -device virtio-net-pci,netdev=net0 \
    -nographic

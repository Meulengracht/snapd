#!/bin/sh
set -eu

# Repack the UC26 pc gadget with only the image-layout changes needed by this
# PoC. The boot assets remain those from the downloaded gadget; ubuntu-image
# consumes the modified gadget.yaml and optional cmdline.extra when laying out
# the disk and constructing the boot configuration.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
input_snap=${1:?usage: repack-gadget.sh INPUT-GADGET OUTPUT-GADGET SEED-SIZE [EXTRA-CMDLINE]}
output_snap=${2:?usage: repack-gadget.sh INPUT-GADGET OUTPUT-GADGET SEED-SIZE [EXTRA-CMDLINE]}
seed_size=${3:?usage: repack-gadget.sh INPUT-GADGET OUTPUT-GADGET SEED-SIZE [EXTRA-CMDLINE]}
extra_cmdline=${4:-}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/gadget-poc.XXXXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

# Expand into a temporary tree and use the repository helper to update the
# structured system-seed entry. A larger seed partition is necessary because
# it retains the original recovery seed alongside complete poc-a and poc-b
# run-system seeds and their private snap payloads.
unsquashfs -no-progress -f -d "$work_dir/root" "$input_snap"
python3 "$script_dir/../../../lib/manip_ubuntu_seed.py" \
	"$work_dir/root/meta/gadget.yaml" "$seed_size"

# cmdline.extra is the gadget-supported extension point for diagnostic kernel
# arguments. Omitting it entirely preserves the source gadget's normal command
# line rather than creating an empty override file.
if [ -n "$extra_cmdline" ]; then
	printf '%s\n' "$extra_cmdline" > "$work_dir/root/cmdline.extra"
fi

# Check the gadget schema before producing a root-owned squashfs suitable for
# inclusion in an image assembled by an unprivileged host process.
snap pack --check-skeleton "$work_dir/root"
mksquashfs "$work_dir/root" "$output_snap" -noappend -comp xz -all-root -no-progress

# Validate the packed artifact rather than trusting only the expanded work
# tree. Parse gadget.yaml as YAML so formatting or key ordering cannot affect
# the assertion, and verify the optional command line byte-for-byte.
test "$(unsquashfs -cat "$output_snap" meta/gadget.yaml | python3 -c 'import sys, yaml; print(next(s["size"] for s in yaml.safe_load(sys.stdin)["volumes"]["pc"]["structure"] if s.get("role") == "system-seed"))')" = "$seed_size"
if [ -n "$extra_cmdline" ]; then
	test "$(unsquashfs -cat "$output_snap" cmdline.extra)" = "$extra_cmdline"
fi

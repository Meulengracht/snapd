#!/bin/sh
set -eu

# Build a complete UC26 disk image for the boot-from-seed PoC. The image uses
# locally built PoC snaps and snapd code, but otherwise follows the normal
# ubuntu-image assembly path. Intermediate files live outside the checkout so
# interrupted builds cannot leave partially repacked snaps in the source tree.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
artifacts_dir=${1:-"$script_dir/artifacts"}
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/boot-from-seed-image.XXXXXXXX")

# KEEP_POC_WORK is useful when inspecting an ubuntu-image or snap repack
# failure. Normal runs remove the directory because it contains several
# unpacked snaps and a sparse disk image.
cleanup() {
    if [ "${KEEP_POC_WORK-}" = 1 ]; then
        echo "keeping work directory: $work_dir"
    else
        rm -rf "$work_dir"
    fi
}
trap cleanup EXIT HUP INT TERM

# Check the complete host-side tool set up front. This avoids discovering a
# missing squashfs or snap build tool after the expensive downloads begin.
for command in fakeroot git go mksquashfs snap snapcraft unsquashfs sha256sum; do
    if ! command -v "$command" >/dev/null; then
        echo "missing required command: $command" >&2
        exit 1
    fi
done

mkdir -p "$artifacts_dir" "$work_dir/downloads" "$work_dir/image"
artifacts_dir=$(realpath "$artifacts_dir")

# Build two revisions of the test snap. Revision A is included in the initial
# image; revision B is bundled into the modified core snap and later staged
# directly into the poc-b seed by the guest-side driver.
"$script_dir/build-test-snaps.sh" "$work_dir"

# The PoC exercises snap-bootstrap and userspace changes from this checkout, so
# use a caller-provided snapd snap or build one locally. Copying it into the work
# directory gives the rest of the build a stable name independent of version.
if [ -n "${POC_SNAPD_SNAP-}" ]; then
    snapd_snap=$POC_SNAPD_SNAP
else
    (cd "$repo_root" && ./tests/build-test-snapd-snap --clean-snapd-only)
    snapd_snap=$(find "$repo_root/built-snap" -maxdepth 1 -type f -name 'snapd_*.snap.keep' -printf '%T@ %p\n' |
        sort -nr | awk 'NR == 1 { print $2 }')
fi
if [ -z "$snapd_snap" ]; then
    echo "cannot find the locally built snapd snap" >&2
    exit 1
fi
if [ ! -f "$snapd_snap" ]; then
    echo "cannot use snapd snap: $snapd_snap" >&2
    exit 1
fi
cp "$snapd_snap" "$work_dir/snapd.snap"

# Download pristine UC26 components before applying narrowly scoped PoC
# modifications. Edge channels are used because core26, gadget 26, and kernel
# 26 are under active development.
(cd "$work_dir/downloads" && snap download core26 --channel=latest/edge --basename=core26)
(cd "$work_dir/downloads" && snap download pc --channel=26/edge --basename=pc)
(cd "$work_dir/downloads" && snap download pc-kernel --channel=26/edge --basename=pc-kernel)

# Rebuild the kernel UKI with snap-bootstrap from this checkout. Secure Boot
# must remain disabled because repacking invalidates the production signature.
"$script_dir/repack-kernel.sh" \
    "$work_dir/downloads/pc-kernel.snap" \
    "$work_dir/pc-kernel-poc.snap"

# Enlarge ubuntu-seed so the original seed and both run-system seeds fit. The
# gadget repack also provides an escape hatch for diagnostic kernel arguments.
gadget_snap="$work_dir/pc-poc.snap"
"$script_dir/repack-gadget.sh" \
    "$work_dir/downloads/pc.snap" \
    "$gadget_snap" \
    "${POC_SEED_SIZE:-3G}" \
    "${POC_EXTRA_CMDLINE-}"

# Install the early systemd generator, helper programs, service definitions,
# guest test driver, and B test snap into core26. These files are copied into
# writable state on first boot using the tmpfiles declarations in the repack.
"$script_dir/repack-core26.sh" \
    "$work_dir/downloads/core26.snap" \
    "$work_dir/core26-poc.snap" \
    "$work_dir/test-snap-B.snap"

# Use the repository's dangerous UC26 model so locally repacked and test-key
# snaps can be assembled without changing the host assertion database.
cp "$repo_root/tests/lib/assertions/ubuntu-core-26-amd64.model" \
    "$work_dir/model.assert"

# ubuntu-image must use this checkout's snapd packages because the PoC extends
# image/seed handling as well as runtime snapd. UBUNTU_IMAGE allows repeated
# runs to reuse an already built, withtestkeys-enabled binary.
if [ -n "${UBUNTU_IMAGE-}" ]; then
    ubuntu_image=$UBUNTU_IMAGE
else
    ubuntu_image="$work_dir/ubuntu-image"
    git clone --depth=1 https://github.com/canonical/ubuntu-image "$work_dir/ubuntu-image-src"
    (
        cd "$work_dir/ubuntu-image-src"
        go mod edit -replace="github.com/snapcore/snapd=$repo_root"
        go build -mod=mod -tags withtestkeys -o "$ubuntu_image" ./cmd/ubuntu-image
    )
fi

# Assemble the actual 10 GiB bootable image. The initial system contains A;
# the guest test later creates complete poc-a and poc-b run-system seeds from
# this installed state and selects them through the boot environment.
SNAPD_DEBUG=1 "$ubuntu_image" snap \
    --image-size 10G \
    --output-dir "$work_dir/image" \
    --snap "$gadget_snap" \
    --snap "$work_dir/pc-kernel-poc.snap" \
    --snap "$work_dir/core26-poc.snap" \
    --snap "$work_dir/snapd.snap" \
    --snap "$work_dir/test-snap-A.snap" \
    "$work_dir/model.assert"

image=$(find "$work_dir/image" -maxdepth 1 -type f -name '*.img' -print -quit)
if [ -z "$image" ]; then
    echo "ubuntu-image did not produce an image" >&2
    exit 1
fi

# Publish only the artifacts needed to boot, drive, and reproduce the test.
# Keeping the model beside the image also makes manual runs independent of the
# temporary work directory.
cp "$image" "$artifacts_dir/uc26-boot-from-seed-poc.img"
cp "$script_dir/run-ab-test.sh" "$artifacts_dir/run-ab-test.sh"
cp "$work_dir/model.assert" "$artifacts_dir/model.assert"

# Record content hashes and the source revision rather than relying on snap
# filenames, which may be reused across dirty local builds.
image_sha=$(sha256sum "$artifacts_dir/uc26-boot-from-seed-poc.img" | awk '{print $1}')
snapd_sha=$(sha256sum "$work_dir/snapd.snap" | awk '{print $1}')
core_sha=$(sha256sum "$work_dir/core26-poc.snap" | awk '{print $1}')
git_revision=$(git -C "$repo_root" rev-parse HEAD)
cat > "$artifacts_dir/build-manifest.json" <<EOF
{
  "git-revision": "$git_revision",
  "architecture": "amd64",
  "base": "core26",
  "gadget-channel": "26/edge",
  "kernel-channel": "26/edge",
  "base-channel": "latest/edge",
  "image-sha256": "$image_sha",
  "snapd-sha256": "$snapd_sha",
  "core26-sha256": "$core_sha"
}
EOF

echo "built $artifacts_dir/uc26-boot-from-seed-poc.img"

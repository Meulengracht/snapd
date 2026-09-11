#!/bin/sh
set -eu

# Build a complete UC26 disk image for the boot-from-seed PoC. The image uses
# locally built PoC snaps and snapd code, but otherwise follows the normal
# ubuntu-image assembly path. Intermediate files live outside the checkout so
# interrupted builds cannot leave partially repacked snaps in the source tree.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# Spread exports PROJECT_PATH for its transferred source tree, which does not
# contain .git. Standalone runs derive the same root from this script's fixed
# location under tests/nested/manual.
if [ -n "${PROJECT_PATH-}" ]; then
    repo_root=$PROJECT_PATH
else
    repo_root=$(CDPATH='' cd -- "$script_dir/../../../.." && pwd)
fi
artifacts_dir=${1:-"$script_dir/artifacts"}
core26_channel=${POC_CORE26_CHANNEL:-cloud-init/edge}
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/boot-from-seed-image.XXXXXXXX")
fakestore_pid=

# KEEP_POC_WORK is useful when inspecting an ubuntu-image or snap repack
# failure. Normal runs remove the directory because it contains several
# unpacked snaps and a sparse disk image.
cleanup() {
    if [ -n "$fakestore_pid" ]; then
        kill "$fakestore_pid" 2>/dev/null || true
        wait "$fakestore_pid" 2>/dev/null || true
    fi
    if [ "${KEEP_POC_WORK-}" = 1 ]; then
        echo "keeping work directory: $work_dir"
    else
        rm -rf "$work_dir"
    fi
}
trap cleanup EXIT HUP INT TERM

# Check the tools needed for every build up front. Snapcraft is checked below
# only when this script must build snapd instead of using POC_SNAPD_SNAP.
for command in curl fakeroot git go mksquashfs snap unsquashfs sha256sum; do
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

# Give both local test-snap revisions normal store identities. A is included in
# the image seed; B's assertion bundle is copied into the guest and acknowledged
# immediately before the local refresh. This exercises the asserted seed-refresh
# path without requiring a network store during the reboot sequence.
test_snap_id=v6fuBtBS2asZMPIHfzom0VhbHblwvQNy
fakestore="$work_dir/fakestore"
(cd "$repo_root" && go build -mod=readonly -o "$fakestore" ./tests/lib/fakestore/cmd/fakestore)
assertion_dir="$work_dir/fake-store"
mkdir -p "$assertion_dir/asserts"
cp "$repo_root/tests/lib/assertions/testrootorg-store.account-key" \
    "$repo_root/tests/lib/assertions/developer1.account" \
    "$repo_root/tests/lib/assertions/developer1.account-key" \
    "$assertion_dir/asserts/"
for revision in 1 2; do
    case "$revision" in
        1) snap_path="$work_dir/test-snap-A.snap" ;;
        2) snap_path="$work_dir/test-snap-B.snap" ;;
    esac
    cat > "$work_dir/snap-declaration-$revision.json" <<EOF
{"snap-id":"$test_snap_id","publisher-id":"developer1","snap-name":"test-snapd-sh-core26"}
EOF
    cat > "$work_dir/snap-revision-$revision.json" <<EOF
{"snap-id":"$test_snap_id","snap-revision":"$revision"}
EOF
    "$fakestore" new-snap-declaration --dir="$assertion_dir" \
        --snap-decl-json="$work_dir/snap-declaration-$revision.json" "$snap_path" >/dev/null
    "$fakestore" new-snap-revision --dir="$assertion_dir" \
        --snap-rev-json="$work_dir/snap-revision-$revision.json" "$snap_path" >/dev/null
    cp "$snap_path" "$assertion_dir/test-snapd-sh-core26_${revision}.snap"
done

: > "$work_dir/test-snap-B.assert"
for assertion in "$assertion_dir"/asserts/*; do
    cat "$assertion" >> "$work_dir/test-snap-B.assert"
    printf '\n' >> "$work_dir/test-snap-B.assert"
done

fakestore_addr=${POC_FAKESTORE_ADDR:-127.0.0.1:11028}
fakestore_url="http://$fakestore_addr"
"$fakestore" run --dir "$assertion_dir" --addr "$fakestore_addr" --assert-fallback &
fakestore_pid=$!
attempts=30
until curl -sS "$fakestore_url/" >/dev/null 2>&1; do
    if ! kill -0 "$fakestore_pid" 2>/dev/null || [ "$attempts" -eq 0 ]; then
        echo "cannot start fake store at $fakestore_url" >&2
        exit 1
    fi
    attempts=$((attempts - 1))
    sleep 1
done

# The PoC exercises snap-bootstrap and userspace changes from this checkout, so
# use a caller-provided snapd snap or build one locally. Copying it into the work
# directory gives the rest of the build a stable name independent of version.
if [ -n "${POC_SNAPD_SNAP-}" ]; then
    snapd_snap=$POC_SNAPD_SNAP
else
    if ! command -v snapcraft >/dev/null; then
        echo "missing required command: snapcraft (or set POC_SNAPD_SNAP)" >&2
        exit 1
    fi
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
# modifications. The cloud-init track is required for nested test user
# provisioning because the regular core26 snap does not ship cloud-init.
(cd "$work_dir/downloads" && snap download core26 --channel="$core26_channel" --basename=core26)
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
    "${POC_EXTRA_CMDLINE-}" \
    "${POC_GADGET_CLOUD_CONF-}"

# Install the early systemd generator, helper programs, service definitions,
# guest test driver, and B test snap into core26. These files are copied into
# writable state on first boot using the tmpfiles declarations in the repack.
"$script_dir/repack-core26.sh" \
    "$work_dir/downloads/core26.snap" \
    "$work_dir/core26-poc.snap" \
    "$work_dir/test-snap-B.snap" \
    "$work_dir/test-snap-B.assert"

# Sign the PoC's dangerous model with the repository test key. Declaring the
# test snap in the model makes normal seed-refresh policy classify its refresh
# as part of the A/B candidate instead of treating it as an unrelated snap.
(cd "$repo_root" && go run -mod=readonly ./tests/lib/gendeveloper1 sign-model --root-key \
    < "$script_dir/model.json" > "$work_dir/model.assert")

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
UBUNTU_STORE_URL="$fakestore_url" SNAPD_DEBUG=1 "$ubuntu_image" snap \
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
# A local checkout can identify its exact revision. Spread deliberately omits
# .git from the transferred project, so retain a valid manifest with an
# explicit unknown value there instead of failing an otherwise complete build.
git_revision=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown)
cat > "$artifacts_dir/build-manifest.json" <<EOF
{
  "git-revision": "$git_revision",
  "architecture": "amd64",
  "base": "core26",
  "gadget-channel": "26/edge",
  "kernel-channel": "26/edge",
  "base-channel": "$core26_channel",
  "image-sha256": "$image_sha",
  "snapd-sha256": "$snapd_sha",
  "core26-sha256": "$core_sha"
}
EOF

echo "built $artifacts_dir/uc26-boot-from-seed-poc.img"

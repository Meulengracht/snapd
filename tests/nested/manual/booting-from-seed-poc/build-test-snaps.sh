#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
output_dir=${1:?usage: build-test-snaps.sh OUTPUT-DIR}
mkdir -p "$output_dir"

for revision in A B; do
    work_dir=$(mktemp -d "${TMPDIR:-/tmp}/boot-from-seed-snap.XXXXXXXX")
    trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
    cp -a "$script_dir/test-snap/." "$work_dir/"
    printf '%s\n' "$revision" > "$work_dir/poc-revision"
    sed "s/version: \"A\"/version: \"$revision\"/" \
        "$work_dir/meta/snap.yaml" > "$work_dir/meta/snap.yaml.new"
    mv "$work_dir/meta/snap.yaml.new" "$work_dir/meta/snap.yaml"
    snap pack --check-skeleton "$work_dir"
    mksquashfs "$work_dir" "$output_dir/test-snap-${revision}.snap" \
        -noappend -comp xz -all-root -no-progress
    rm -rf "$work_dir"
    trap - EXIT HUP INT TERM
done

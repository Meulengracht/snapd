#!/bin/sh
set -eu

# Build the interactive local profile. It uses core26-cloud-init and embeds the
# developer SSH account in the gadget, but deliberately leaves A/B autostart
# disabled so the test begins only after run-ab-test.sh start is invoked.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../../.." && pwd)
output_dir=${1:-"$script_dir/artifacts/local"}

if [ -z "${POC_SNAPD_SNAP-}" ]; then
    POC_SNAPD_SNAP=$(find "$repo_root/built-snap" -maxdepth 1 -type f \
        -name 'snapd_*.snap.keep' -printf '%T@ %p\n' 2>/dev/null | \
        sort -nr | awk 'NR == 1 { print $2 }')
    if [ -n "$POC_SNAPD_SNAP" ]; then
        POC_SNAPD_SNAP=$(realpath "$POC_SNAPD_SNAP")
        export POC_SNAPD_SNAP
    fi
fi

POC_AUTOSTART=0 \
POC_CORE26_CHANNEL=${POC_CORE26_CHANNEL:-cloud-init/edge} \
POC_GADGET_CLOUD_CONF=${POC_GADGET_CLOUD_CONF:-"$script_dir/local-cloud.conf"} \
    "$script_dir/build-image.sh" "$output_dir"

#!/bin/sh
set -eu

# Exercise the generator without booting a VM or writing to the host's /run and
# /var. The copied generator has its two absolute input paths redirected into a
# temporary filesystem tree; its three output arguments retain systemd's real
# normal, early, and late generator ordering semantics.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(mktemp -d "${TMPDIR:-/tmp}/run-system-generator.XXXXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM

# Model a boot from poc-b and the set of units generated for that seed. The
# escaped mount filename matches systemd-escape output for the snap mount path,
# guarding against regressions where the generator only handles service names.
mkdir -p "$root/run/snapd" "$root/var/lib/snapd/systems/poc-b/systemd/system"
mkdir -p "$root/normal" "$root/early" "$root/early-try" "$root/early-verified" "$root/late" "$root/proc"
printf 'poc-b\n' > "$root/run/snapd/booted-run-seed"
printf 'snapd_recovery_mode=run snapd_run_system=poc-b snapd_run_system_status=trying\n' > "$root/proc/cmdline"
touch "$root/var/lib/snapd/systems/poc-b/systemd/system/snapd-run-system-finalize.service"
touch "$root/var/lib/snapd/systems/poc-b/systemd/system/snap.test-snapd-sh-core26.svc.service"
touch "$root/var/lib/snapd/systems/poc-b/systemd/system/snap-test\\x2dsnapd\\x2dsh\\x2dcore26-x2.mount"

# Rewrite only the test instance. The checked-in generator remains unchanged,
# and every path it can discover or publish is contained below $root.
sed \
    -e "s#MARKER_FILE=/run/#MARKER_FILE=$root/run/#" \
    -e "s#CMDLINE_FILE=/proc/#CMDLINE_FILE=$root/proc/#" \
    -e "s#UNITS_DIR=\"/var/#UNITS_DIR=\"$root/var/#" \
    -e "s#STATE_DIR=\"/var/#STATE_DIR=\"$root/var/#" \
    "$script_dir/generator/snapd-run-system-generator" > "$root/generator"
chmod +x "$root/generator"

# systemd invokes generators with normal, early, and late output directories.
# Run with that exact interface so choosing the wrong positional argument is
# observable below.
"$root/generator" "$root/normal" "$root/early" "$root/late"

# Run-system units must be emitted in generator.early. This lets them override
# units generated later from the installed snap state. The payload service must
# also be wanted by multi-user.target, while no duplicate appears in the normal
# generator directory.
test ! -e "$root/normal/snap.test-snapd-sh-core26.svc.service"
test -L "$root/early/snapd-run-system-finalize.service"
test -L "$root/early/snap.test-snapd-sh-core26.svc.service"
test -L "$root/early/snap-test\\x2dsnapd\\x2dsh\\x2dcore26-x2.mount"
test -L "$root/early/multi-user.target.wants/snap.test-snapd-sh-core26.svc.service"

# A seed-refresh candidate is not ready to run its payload yet. During its
# trying boot, activate only the finalizer; snapd resumes the refresh after that
# finalizer reports readiness and tears these temporary units down.
touch "$root/var/lib/snapd/systems/poc-b/seed-refresh"
"$root/generator" "$root/normal" "$root/early-try" "$root/late"
test -L "$root/early-try/snapd-run-system-finalize.service"
test ! -e "$root/early-try/snap.test-snapd-sh-core26.svc.service"
test -L "$root/early-try/snap-test\\x2dsnapd\\x2dsh\\x2dcore26-x2.mount"
test -L "$root/early-try/multi-user.target.wants/snapd-run-system-finalize.service"
test ! -e "$root/early-try/multi-user.target.wants/snap.test-snapd-sh-core26.svc.service"

# Once snapd verifies the candidate it tears down the temporary units and
# reloads systemd. That reload reruns this generator in the same trying boot;
# the verified marker must keep the units from being published again.
touch "$root/var/lib/snapd/systems/poc-b/seed-refresh-verified"
"$root/generator" "$root/normal" "$root/early-verified" "$root/late"
test -z "$(find "$root/early-verified" -mindepth 1 -print -quit)"

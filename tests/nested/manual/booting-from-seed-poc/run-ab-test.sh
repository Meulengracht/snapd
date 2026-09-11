#!/bin/sh
set -eu

# This driver is installed in the UC26 guest and resumed by a systemd service
# after every reboot. Its phase file is the transaction log for the test: each
# next phase is persisted before rebooting, then validated against both the
# initramfs boot marker and snapd's accepted run-system state.
state_dir=/var/lib/snapd/boot-from-seed-poc
phase_file="$state_dir/phase"
result_file="$state_dir/result.json"
# snap-bootstrap writes this volatile marker for the seed used by this boot.
marker=/run/snapd/booted-run-seed
# Candidate seeds are deliberately staged through the mounted seed partition,
# not through the read-only view exposed elsewhere during run mode.
seed_root=/run/mnt/ubuntu-seed
poc_root=/var/lib/snapd/boot-from-seed-poc
autostart_marker="$poc_root/autostart"

# The serial console survives SSH disconnects and guest reboots, making these
# messages the primary diagnostics when a spread run cannot reconnect.
console_log() {
    printf 'boot-from-seed-poc: %s\n' "$*" > /dev/ttyS0 2>/dev/null || true
}

# Preserve command output on the serial console while retaining the original
# exit status for set -e and the phase state machine.
run_logged() {
    console_log "running: $*"
    if output=$("$@" 2>&1); then
        [ -z "$output" ] || console_log "$output"
        return 0
    else
        status=$?
    fi
    console_log "failed ($status): $output"
    return "$status"
}

# Seed creation snapshots installed snap state. Wait only for numeric, active
# snapd changes so headings and terminal changes cannot keep the loop alive.
wait_for_snapd_changes() {
    attempts=120
    while [ "$attempts" -gt 0 ]; do
        if snap changes | awk '$1 ~ /^[0-9]+$/ && $2 !~ /^(Done|Error|Hold|Undone)$/ { active=1 } END { exit active }'; then
            return 0
        fi
        attempts=$((attempts - 1))
        sleep 1
    done
    console_log "timed out waiting for snapd changes"
    snap changes 2>&1 | while IFS= read -r line; do console_log "$line"; done
    return 1
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "boot-from-seed PoC must run as root" >&2
        exit 1
    fi
}

# Replace the phase atomically and flush it before any requested reboot. This
# ensures the next boot never observes a partial write or repeats the prior
# phase because the write was still buffered.
set_phase() {
    printf '%s\n' "$1" > "$phase_file.tmp"
    mv "$phase_file.tmp" "$phase_file"
    sync
}

# booted_system answers "which seed produced this boot?" while current_system
# answers "which seed has userspace accepted for future boots?". Comparing both
# is essential when validating one-shot candidate behavior.
booted_system() {
    cat "$marker" 2>/dev/null || true
}

current_system() {
    snap debug run-system-status | sed -n 's/^run_system=//p'
}

# Each seed runs a service from its own test-snap revision. Waiting for its
# report proves that the selected seed's generated mount and service units ran,
# rather than merely proving that the expected kernel command line was present.
wait_for_service_revision() {
    expected="$1"
    attempts=30
    while [ "$attempts" -gt 0 ]; do
        if [ -s "$state_dir/active-service" ] &&
           [ "$(awk '{print $2}' "$state_dir/active-service")" = "$expected" ]; then
            return 0
        fi
        attempts=$((attempts - 1))
        sleep 1
    done
    echo "test-snap service did not report revision $expected" >&2
    return 1
}

# Prefer a snap staged privately in the selected system. poc-a initially uses
# the shared snap from the image seed, while poc-b receives a private B snap.
# Supporting both layouts keeps generated mount units tied to the actual seed
# content used by this PoC.
seed_snap_path() {
    label="$1"
    private_snap=$(find "$seed_root/systems/$label/snaps" -maxdepth 1 -type f -name 'test-snap*.snap' -print -quit 2>/dev/null || true)
    if [ -n "$private_snap" ]; then
        printf '%s\n' "$private_snap"
        return
    fi

    revision=$(snap list test-snapd-sh-core26 --unicode=never | awk 'NR == 2 { print $3 }')
    shared_snap="$seed_root/snaps/test-snapd-sh-core26_${revision}.snap"
    if [ ! -f "$shared_snap" ]; then
        echo "cannot locate test-snap in system seed $label" >&2
        return 1
    fi
    printf '%s\n' "$shared_snap"
}

# Stage different payloads into A and B so the running service provides visible
# evidence of a system transition. B is bundled in the image specifically to
# avoid a store refresh changing the candidate while this test is running.
stage_test_snap() {
    label="$1"
    if [ "$label" = poc-b ]; then
        revision=poc-b
        source_snap="$poc_root/test-snap-b.snap"
    else
        revision=$(snap list test-snapd-sh-core26 --unicode=never | awk 'NR == 2 { print $3 }')
        source_snap="/var/lib/snapd/snaps/test-snapd-sh-core26_${revision}.snap"
    fi
    destination_dir="$seed_root/systems/$label/snaps"
    console_log "staging test snap revision=$revision source=$source_snap destination=$destination_dir"
    if [ ! -f "$source_snap" ]; then
        console_log "cannot locate installed test snap $source_snap"
        return 1
    fi
    mkdir -p "$destination_dir"
    cp "$source_snap" "$destination_dir/test-snapd-sh-core26_${revision}.snap"
    sync
    console_log "staged test snap for $label"
}

# Materialize the per-system units consumed by snapd-run-system-generator.
# They mount the selected seed's test snap, finalize or roll back the candidate,
# and only start the payload service after successful finalization.
generate_system_units() {
    label="$1"
    if [ "$label" = poc-b ]; then
        revision=poc-b
    else
        revision=$(snap list test-snapd-sh-core26 --unicode=never | awk 'NR == 2 { print $3 }')
    fi
    snap_path=$(seed_snap_path "$label")
    units="$state_dir/../systems/$label/systemd/system"
    mount_where="/snap/test-snapd-sh-core26/$revision"
    # systemd requires the mount unit filename to be the escaped mount path;
    # constructing it here also exercises the generator's handling of names
    # containing escaped dashes.
    mount_unit=$(systemd-escape --path --suffix=mount "$mount_where")
    console_log "generating units label=$label revision=$revision snap=$snap_path unit=$mount_unit"

    mkdir -p "$units"
    cat > "$units/$mount_unit" <<EOF
[Unit]
Description=Mount test-snapd-sh-core26 revision $revision from run system $label
Before=snapd-run-system-finalize.service snap.test-snapd-sh-core26.svc.service

[Mount]
What=$snap_path
Where=$mount_where
Type=squashfs
Options=nodev,ro
EOF

    # A failed finalizer deliberately triggers rollback. RemainAfterExit keeps
    # a successful finalization ordered before the payload for the whole boot.
    cat > "$units/snapd-run-system-finalize.service" <<EOF
[Unit]
Description=Finalize run system $label
Requires=$mount_unit snapd.service
After=$mount_unit snapd.service
Before=snap.test-snapd-sh-core26.svc.service
OnFailure=snapd-run-system-rollback.service

[Service]
Type=oneshot
ExecStart=$poc_root/finalize-run-system $label $revision
RemainAfterExit=yes
EOF

    # The payload records its seed label and A/B revision in persistent state,
    # which wait_for_service_revision uses as end-to-end execution evidence.
    cat > "$units/snap.test-snapd-sh-core26.svc.service" <<EOF
[Unit]
Description=Boot-from-seed test service for $label
Requires=$mount_unit snapd-run-system-finalize.service
After=$mount_unit snapd-run-system-finalize.service

[Service]
Type=simple
Environment=POC_RUN_SYSTEM=$label
ExecStart=$mount_where/bin/service
Restart=on-failure
EOF
    console_log "generated units for $label"
}

# create-system-seed captures a complete candidate from the running system.
# Staging and unit generation happen afterward because this PoC intentionally
# prototypes seed-private application content outside signed seed metadata.
create_system() {
    label="$1"
    if [ ! -d "$seed_root/systems/$label" ]; then
        console_log "waiting for snapd changes before creating $label"
        wait_for_snapd_changes
        run_logged snap debug create-system-seed "$label"
    else
        console_log "system seed $label already exists"
    fi
    stage_test_snap "$label"
    generate_system_units "$label"
}

# Persist the expectation before asking systemd to reboot. --no-block lets the
# service return cleanly while shutdown proceeds.
reboot_for_phase() {
    set_phase "$1"
    systemctl --no-block reboot
}

# Drive one idempotent state-machine step per boot. The systemd service invokes
# resume automatically; start only initializes the first phase.
resume() {
    if [ ! -s "$phase_file" ]; then
        [ -e "$autostart_marker" ] || return 0
        mkdir -p "$state_dir"
        set_phase create-a
    fi
    phase=$(cat "$phase_file")
    console_log "phase=$phase booted=$(booted_system) current=$(current_system)"

    case "$phase" in
        create-a)
            # Establish and try A first so there is a known accepted system to
            # fall back to when the first B attempt is rejected.
            create_system poc-a
            run_logged snap debug try-system-seed poc-a
            reboot_for_phase verify-a
            ;;
        verify-a)
            # A's first boot must already be accepted by its finalizer. Build B
            # only after proving A's payload is active, then force B finalization
            # to fail on its first one-shot boot.
            [ "$(booted_system)" = poc-a ]
            [ "$(current_system)" = poc-a ]
            wait_for_service_revision A
            create_system poc-b
            touch "$state_dir/fail-finalization"
            run_logged snap debug try-system-seed poc-b
            reboot_for_phase verify-b-fallback
            ;;
        verify-b-fallback)
            # The failure and rollback services run during B's first boot. If
            # this invocation still runs on B, reboot once more: GRUB consumed
            # the one-shot selection and the next boot must return to A.
            if [ "$(booted_system)" = poc-b ]; then
                console_log "candidate poc-b was not accepted; rebooting to poc-a"
                systemctl --no-block reboot
                return 0
            fi
            # Back on A, prove B was not accepted and rollback recorded the
            # failed label. Remove the injected failure and retry the same seed.
            [ "$(booted_system)" = poc-a ]
            [ "$(current_system)" = poc-a ]
            [ "$(cat "$state_dir/last-failed-system")" = poc-b ]
            wait_for_service_revision A
            rm -f "$state_dir/fail-finalization"
            run_logged snap debug try-system-seed poc-b
            reboot_for_phase verify-b-accepted
            ;;
        verify-b-accepted)
            # Successful finalization promotes B from try_run_system to
            # run_system. Reboot once more to distinguish acceptance from a
            # merely successful one-shot candidate boot.
            [ "$(booted_system)" = poc-b ]
            [ "$(current_system)" = poc-b ]
            wait_for_service_revision B
            reboot_for_phase verify-b-persistent
            ;;
        verify-b-persistent)
            # B must remain both the booted and accepted system without a try
            # variable. Its B payload is the final end-to-end assertion.
            [ "$(booted_system)" = poc-b ]
            [ "$(current_system)" = poc-b ]
            wait_for_service_revision B
            printf '{"result":"PASS","accepted":"poc-b"}\n' > "$result_file.tmp"
            mv "$result_file.tmp" "$result_file"
            set_phase "done"
            console_log 'result=PASS accepted=poc-b'
            ;;
        done)
            ;;
        *)
            echo "unknown boot-from-seed test phase: $phase" >&2
            exit 1
            ;;
    esac
}

require_root
command=${1:-status}
case "$command" in
    start)
        # Reset transient evidence but retain generated system seeds so a
        # rerun can exercise the driver's idempotent create path.
        mkdir -p "$state_dir"
        rm -f "$result_file" "$state_dir/fail-finalization" "$state_dir/last-failed-system"
        set_phase create-a
        systemctl restart --no-block boot-from-seed-poc-test.service
        ;;
    resume)
        resume
        ;;
    status)
        # Emit one compact JSON object for spread's retry/MATCH loop.
        if [ -s "$result_file" ]; then
            cat "$result_file"
        elif [ -s "$phase_file" ]; then
            printf '{"result":"RUNNING","phase":"%s"}\n' "$(cat "$phase_file")"
        else
            printf '{"result":"NOT-STARTED"}\n'
        fi
        ;;
    reset)
        # Reset driver state only; generated seeds are intentionally preserved
        # for inspection and must be removed separately if a pristine run is
        # required.
        rm -rf "$state_dir"
        ;;
    *)
        echo "usage: $0 {start|resume|status|reset}" >&2
        exit 2
        ;;
esac

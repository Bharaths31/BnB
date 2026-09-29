#!/bin/sh
# PhishGuard — autostart Docker session logger.
#
# Runs as a sidecar container with the Docker socket mounted read-only. It streams the entire
# compose project's container logs (from the beginning, then live) plus lifecycle events into a
# single timestamped file under ./logs, so a session is recorded automatically whenever the
# stack is started. The file name follows the session_logger convention:
#
#     logs/phishguard_session_DD-MM-YYYY_HH-MM-SS.log
#
set -eu

PROJECT="${COMPOSE_PROJECT_NAME:-phishguard}"
DIR="${LOGS_DIR:-/logs}"
mkdir -p "$DIR"
TS="$(date +%d-%m-%Y_%H-%M-%S)"
OUT="$DIR/phishguard_session_$TS.log"

# --------------------------------------------------------------------------- header
{
    echo "================================================================================"
    echo "PhishGuard - Docker session log (autostart logger)"
    echo "Started : $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "Project : $PROJECT"
    echo "File    : $OUT"
    echo "================================================================================"
    echo
    docker ps --filter "label=com.docker.compose.project=$PROJECT" \
        --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null || true
    echo
    echo "================================================================================"
} >> "$OUT"

# ------------------------------------------------------------------ lifecycle events
( docker events \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --format '{{.Time}} {{.Type}} {{.Action}} {{.Actor.Attributes.name}}' \
    >> "$OUT" 2>&1 ) &

# ------------------------------------------------------- follow every project container
followed=""
while :; do
    entries="$(docker ps --filter "label=com.docker.compose.project=$PROJECT" \
        --format '{{.ID}} {{.Names}}' 2>/dev/null || true)"
    for entry in $entries; do
        id="${entry%% *}"
        name="${entry#* }"

        # never follow our own container
        case "$name" in
            *-logger-1|*_logger_1) continue ;;
        esac

        case " $followed " in
            *" $id "*) continue ;;
        esac
        followed="$followed $id"

        # Prefix every line with the container name, flush per line.
        ( docker logs -f --timestamps --tail all "$id" 2>&1 \
            | while IFS= read -r line; do printf '[%s] %s\n' "$name" "$line"; done \
            >> "$OUT" ) &
    done
    sleep 5
done

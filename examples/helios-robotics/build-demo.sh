#!/usr/bin/env bash
# build-demo.sh — Builds the Helios Robotics demo mesh from committed source files.
#
# Usage:  cd examples/helios-robotics && ./build-demo.sh
# Output: mesh/   (a fully populated 6-crux mesh ready for `helm mesh/`)
#
# Requires: crux binary in $HOME/.local/bin or PATH.
# After running: helm examples/helios-robotics/mesh/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCES="$SCRIPT_DIR/sources"
MESH_DIR="$SCRIPT_DIR/mesh"

# -- Locate crux binary ---------------------------------------------------

CRUX="$HOME/.local/bin/crux"
if [ ! -x "$CRUX" ]; then
    CRUX="$(command -v crux 2>/dev/null || true)"
fi
if [ -z "$CRUX" ]; then
    echo "error: 'crux' not found. Install it first (see install/ directory)."
    exit 1
fi

echo "Using crux: $CRUX"
echo "Building mesh in: $MESH_DIR"
echo

# -- Clean previous run ---------------------------------------------------

rm -rf "$MESH_DIR"
mkdir -p "$MESH_DIR"

# -- 1. handbook  (documentation, markdown adapter) -----------------------

echo "[1/6] handbook — employee handbook (markdown adapter)"
mkdir -p "$MESH_DIR/handbook"
(cd "$MESH_DIR/handbook" && "$CRUX" generate handbook "$SOURCES/handbook.md" --format markdown)

# -- 2. code  (codebase, markdown adapter) --------------------------------

echo "[2/6] code — engineering spec (markdown adapter)"
mkdir -p "$MESH_DIR/code"
(cd "$MESH_DIR/code" && "$CRUX" generate code "$SOURCES/engineering-spec.md" --format markdown)

# -- 3. team  (organization, CSV via auto adapter) ------------------------

echo "[3/6] team — employee roster (CSV adapter)"
mkdir -p "$MESH_DIR/team"
(cd "$MESH_DIR/team" && "$CRUX" generate team "$SOURCES/team.csv")

# -- 4. incidents  (dataset, manual JSON adapter) -------------------------

echo "[4/6] incidents — postmortem log (manual adapter)"
mkdir -p "$MESH_DIR/incidents"
(cd "$MESH_DIR/incidents" && "$CRUX" generate incidents "$SOURCES/incidents.json" --format manual)

# -- 5. coms  (auto adapter → email path, with thread edges) ---------------

echo "[5/6] coms — email inbox (email adapter)"
mkdir -p "$MESH_DIR/coms"
(cd "$MESH_DIR/coms" && "$CRUX" generate coms "$SOURCES/inbox.mbox")

# -- 6. channels  (auto adapter → slack path) ------------------------------

echo "[6/6] channels — Slack export (Slack adapter)"
mkdir -p "$MESH_DIR/channels"
(cd "$MESH_DIR/channels" && "$CRUX" generate channels "$SOURCES/slack-export.json")

# -- Init mesh and join all cruxes ----------------------------------------

echo
echo "Initializing mesh..."
(cd "$MESH_DIR" && "$CRUX" mesh init helios-robotics)

echo "Joining cruxes..."
(cd "$MESH_DIR" && "$CRUX" mesh join handbook)
(cd "$MESH_DIR" && "$CRUX" mesh join code)
(cd "$MESH_DIR" && "$CRUX" mesh join team)
(cd "$MESH_DIR" && "$CRUX" mesh join incidents)
(cd "$MESH_DIR" && "$CRUX" mesh join coms)
(cd "$MESH_DIR" && "$CRUX" mesh join channels)

# -- Summary --------------------------------------------------------------

echo
echo "Helios Robotics mesh ready."
echo
echo "  Mesh:    $MESH_DIR"
echo "  Members: handbook, code, team, incidents, coms, channels + policy"
echo
echo "Helm demo:"
echo "  helm $MESH_DIR"
echo
echo "Query examples (run from this mesh directory):"
echo "  $CRUX mesh query auth         (hits: code + coms + channels)"
echo "  $CRUX mesh query Alice        (hits: team + coms + channels)"
echo "  $CRUX mesh query outage       (hits: coms thread)"
echo "  $CRUX mesh query telemetry    (hits: code + incidents [internal])"
echo
echo "Classification demo:"
echo "  Policy default is 'internal'. The mesh_query CLI uses the policy clearance."
echo "  - Telemetry Lag and Inventory Sync (internal): visible in mesh_query"
echo "  - DB Outage and Auth Latency (confidential): hidden from mesh_query"
echo "  - Security Key Rotation (restricted): hidden; also hidden in Helm inspector"
echo "    (visible only to agents/tools with confidential+ clearance via MCP)"
echo

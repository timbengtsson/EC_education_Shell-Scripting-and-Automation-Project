#!/bin/bash
# ==========================================================
# Script name: linux_check 
#
# Purpose:
# - Get all processes
# - Save to file
# - Check if any new from last time has been added
# - Check if there are any new processes that are risky
# - Generate log files
#
# Planned for V2
# - packets - new, strange or unneccesary packets
# - Check avaliable updates
# - open ports - that should not be open
# - Unnecessary user accounts 
#
# ==========================================================

# -E = trap ERR is inherited in functions and subshells
# -e = exit on error, fail fast. Dont continue in a broken state
# -u = undefined variable is an error. All variables need to exist
# -o = if one thing in the pipe fails all fails.
set -Eeuo pipefail

# Internal Field Separator ( only seperate words on tab and new row )
IFS=$'\n\t' 

# ==================================================
# Global variables
# ================================================== 

# Log levels that are allowed
readonly VALID_LOG_LEVELS=("INFO" "WARNING" "ERROR" "CRITICAL") 

# Path to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Path to data folder
DATA_DIR="$SCRIPT_DIR/data"

# Create folder for snapshots
PROCESS_DIR="${DATA_DIR}/linux_processes"
mkdir -p "$PROCESS_DIR" 

LOGFILE="$DATA_DIR/process_security.log"

# Risky process names (simple demo list)
RISK_PROCS=("nc" "netcat" "hydra" "john")


# ==================================================
# Functions
# ==================================================

isValidLevel() {
  local level="$1" 
  local l
  for l in "${VALID_LOG_LEVELS[@]}"; do
    [[ "$level" == "$l" ]] && return 0
  done
  return 1
}


# Log function
log() {
    local level="$1"; shift
    local msg="$*"
    local valid=false

    # Verify level is correct
    for l in "${VALID_LOG_LEVELS[@]}"; do
        if [[ "$level" == "$l" ]]; then
            valid=true
            break
        fi
    done

    if ! $valid; then
        level="UNKNOWN"
    fi
 
    echo "$(date '+%Y-%m-%d %H:%M:%S')" ["$level"] "$msg" | tee -a "$LOGFILE" >/dev/null
} 


# Runs on errors 
onError() {
  local exitCode=$?
  log "ERROR" "Skriptet avbröts (exit=$exitCode) vid rad $1."
  exit "$exitCode"
}  
trap 'onError $LINENO' ERR
 

# Clean up when script is done. 
# We could remove temp files, lock files and other stuff here
cleanup() { 
    log "INFO" "Linux-kontroll klar."
}
trap cleanup EXIT


# Get processes
get_processes (){ 
    # echo $(ps -eo comm --no-headers)

    # I want it as an array, not string 
    # ps -eo comm --no-headers | sort -u 
    
    # Trying to not include
    #  "name": "Relay(10417)" 
    #  "name": "Relay(10722)" 
    # ps -eo args= 2>/dev/null \
    #     | awk '
    #     {
    #         cmd=$1
    #         sub(/^.*\//, "", cmd)        # ta bort path: /usr/sbin/sshd -> sshd
    #         sub(/\([0-9]+\)$/, "", cmd)  # ta bort (PID): Relay(10417) -> Relay
    #         if (cmd != "") print cmd
    #     }
    #     ' \
    #     | sort -u  

    # Normalisera 
     ps -eo args= 2>/dev/null \
    | awk '
      {
        cmd=$1
        sub(/^.*\//, "", cmd)          # /usr/sbin/sshd -> sshd
        sub(/\([0-9]+\)$/, "", cmd)    # Relay(10417) -> Relay
        sub(/^[\-@]+/, "", cmd)        # -bash -> bash, @dbus-daemon -> dbus-daemon
        if (cmd ~ /^\(.*\)$/) {        # (sd-pam) -> sd-pam
          sub(/^\(/, "", cmd)
          sub(/\)$/, "", cmd)
        }
        if (cmd != "") print cmd
      }
    ' \
    | sort -u 
} 


# Check if any input are beeing risky
detect_risky_processes(){
    # Get all input params 
    # -a as an array
    local -a processes=("$@") 
    local found=false
    local r

    ## Loop all risk rocesses as r
    for r in "${RISK_PROCS[@]}"; do
        # Print each process on a seperat row 
        # pipe to grep where 
        # -F = text (not regex)
        # -x the complete row should match 
        # -q = quite
        # -- = stop anything else being interpreted as a flag    
        # "r" = the risk process                           
        if printf '%s\n' "${processes[@]}" | grep -Fxq -- "$r"; then
            log "CRITICAL" "Riskprocess upptäckt: $r"
            found=true 
        fi
    done

    if [[ $found == false ]]; then
        log "INFO" "Ingen känd riskprocess upptäckt"
    fi

}

extract_unique_names_from_json() {
    local jsonFile="$1"
    jq -r '.processes[].name' "$jsonFile" | sort -u
}


# Compare the processes last analysis
compare_last_run() {
    local previousProcessFile="${DATA_DIR}/linux_processes/processes_latest.json"
    local curentProcessFile="$1"

    if [ ! -f "${previousProcessFile}" ]; then
        cp "$curentProcessFile" "$previousProcessFile"
        echo "Hittade inte processes_latest.json. Normalt om det är första körningen"
        log "WARNING" "Hittade inte processes_latest.json i $previousProcessFile. Normalt om det är första körningen"
        return 0
    fi

    if [[ ! -f "$curentProcessFile" ]]; then
        log "ERROR" "Current snapshot saknas: $curentProcessFile"
        return 1
    fi

    local tmpPrev="" tmpCurr=""
    tmpPrev="$(mktemp)"
    tmpCurr="$(mktemp)"
    trap 'rm -f "${tmpPrev-}" "${tmpCurr-}"' RETURN

    extract_unique_names_from_json "$previousProcessFile" > "$tmpPrev"
    extract_unique_names_from_json "$curentProcessFile" > "$tmpCurr"

    # Nya processer (finns i curr men inte i prev)
    local newProcs
    newProcs="$(comm -13 "$tmpPrev" "$tmpCurr" || true)"

    # Försvunna processer (finns i prev men inte i curr)
    local goneProcs
    goneProcs="$(comm -23 "$tmpPrev" "$tmpCurr" || true)"

    if [[ -n "$newProcs" ]]; then
        while IFS= read -r p; do
            [[ -n "$p" ]] && log "WARNING" "Ny process sedan förra körningen: $p"
        done <<< "$newProcs"
    else
        log "INFO" "Inga nya processnamn sedan förra körningen."
    fi

    if [[ -n "$goneProcs" ]]; then
        while IFS= read -r p; do
            [[ -n "$p" ]] && log "INFO" "Process försvunnen sedan förra körningen: $p"
        done <<< "$goneProcs"
    fi

    # Kopiera den nya filen till latest snapshot
    cp "$curentProcessFile" "$previousProcessFile"
}


export_json_snapshot() {  
    local -a processes=("$@")
    local timestamp
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S") 
    
    local outFile="${PROCESS_DIR}/processes_${timestamp}.json"

    # Use jq to produce valid JSON even if process names contain weird chars
    printf '%s\n' "${processes[@]}" \
        | jq -R . \
        | jq -s --arg ts "$timestamp" '{generatedAt: $ts, processes: map({name: .})}' \
        > "$outFile"

    printf '%s\n' "$outFile"
}


# ==================================================
# Main 
# ==================================================
 
main() {

    command -v jq >/dev/null 2>&1 || {
        log "ERROR" "jq saknas. Installera jq för att kunna jämföra JSON."
        echo "jq saknas. Installera jq för att kunna jämföra JSON."
        exit 1
    }

    log "INFO" "Startar processinsamling."

    echo "Startar processinsamling."
    
    # Get all processes
    # proc_vars=$(get_processes)
    mapfile -t processes < <(get_processes)

    # Save this process list to fle to be compared
    currentProcessFileName=$(export_json_snapshot "${processes[@]}")
 
    # Compare the processes from the last run  
    compare_last_run "$currentProcessFileName"

    echo "Undersöker om det finns några risk processer."
    # Check if we got any risky processes
    detect_risky_processes "${processes[@]}" 

    cleanDataDir=$(realpath "$DATA_DIR")
    cleanProcessFile=$(realpath "$currentProcessFileName")

    echo "Analys klar!
Du hittar loggen i:
$cleanDataDir/process_security.log
Den nya processlistan finns i:
$cleanProcessFile" 
}

main

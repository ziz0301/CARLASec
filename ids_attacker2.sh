#!/usr/bin/env bash
set -euo pipefail



rand_between() {
  local lo=$1 hi=$2
  if ! (( lo <= hi )); then
    echo "0"
    return 1
  fi
  echo $(( RANDOM % (hi - lo + 1) + lo ))
}
# -------------------------
# --- EDIT HERE (defaults)
# -------------------------
# Choose 1..8 for the payload you want the script to send
#ATTACK_TYPE=$(rand_between 1 8)
DELAY_BEFORE_START=10
ATTACK_DURATION=5
# the third value you mentioned was 0 in the example — we keep a placeholder if needed
#PAUSE_BETWEEN=$(rand_between 15 30)
PAUSE_BETWEEN=15
SEND_INTERVAL=0
# -------------------------

SERVER_HOST="127.0.0.1"
SERVER_PORT=5000
EVENT_LOG="ids_attack_events.csv"
FRAME_LOG="ids_attack_frames.log"

timestamp_now() { date +%s.%6N; }

if [ ! -f "$EVENT_LOG" ]; then
  echo "attack_id,attack_type,start_ts,end_ts" > "$EVENT_LOG"
fi
touch "$FRAME_LOG"

# open persistent TCP connection on fd 3 (bash /dev/tcp)
exec 3<>/dev/tcp/"$SERVER_HOST"/"$SERVER_PORT" || {
  echo "ERROR: cannot open TCP connection to ${SERVER_HOST}:${SERVER_PORT}" >&2
  exit 1
}
echo "Connected to ${SERVER_HOST}:${SERVER_PORT} (fd 3). Streaming JSON lines..."

send_json_persistent() {
  local json_line="$1"
  printf "%s\n" "$json_line" >&3 || true
}

# payload selection (reads ATTACK_TYPE variable from top)

echo "Starting in ${DELAY_BEFORE_START}s..."
sleep "$DELAY_BEFORE_START"

trap 'echo "Interrupted; closing socket"; exec 3>&-; exit 0' INT

while true; do
  #ATTACK_TYPE=$(rand_between 1 8)
  ATTACK_TYPE=1
  case "$ATTACK_TYPE" in
     1) CAN_ID=$((0x1A0)); PAYLOAD_HEX="781000f0203002ca"; TYPE_NAME="spoof_forward" ;;
     2) CAN_ID=$((0x1A0)); PAYLOAD_HEX="501064f020300206"; TYPE_NAME="spoof_brake" ;;
     3) CAN_ID=$((0x1A0)); PAYLOAD_HEX="642000f0203002c6"; TYPE_NAME="spoof_reverse" ;;
     4) CAN_ID=$((0x0C4)); PAYLOAD_HEX="4500000001000065"; TYPE_NAME="spoof_steer" ;;
     5) CAN_ID=$((0x1A0)); PAYLOAD_HEX="$(printf "%04X%04X%04X%04X" $RANDOM $RANDOM $RANDOM $RANDOM)"; TYPE_NAME="fuzz_edme" ;;
     6) CAN_ID=$((0x0C4)); PAYLOAD_HEX="$(printf "%04X%04X%04X%04X" $RANDOM $RANDOM $RANDOM $RANDOM)"; TYPE_NAME="fuzz_eps" ;;
     7) CAN_ID=$(( RANDOM % 2048 )); PAYLOAD_HEX="$(printf "%04X%04X%04X%04X" $RANDOM $RANDOM $RANDOM $RANDOM)"; TYPE_NAME="fuzz_random" ;;
     8) CAN_ID="000"; PAYLOAD_HEX="0000000000000000"; TYPE_NAME="dos" ;;
  esac
  attack_id="A$(date +%s)_$((RANDOM%10000))"
  start_ts=$(timestamp_now)
  echo ">>> START $attack_id type=$TYPE_NAME"

  end_time=$((SECONDS + ATTACK_DURATION))
  while [ $SECONDS -lt $end_time ]; do
    CAN_ID_HEX=$(printf "%03X" "$CAN_ID")
    #cansend vcan0 ${CAN_ID_HEX}#${PAYLOAD_HEX}
    ts_precise=$(timestamp_now)
    json_line=$(printf '{"can_id":%d,"payload_hex":"%s","label":"attack","attack_type":"%s","attack_id":"%s","timestamp":%s}' "$CAN_ID" "$PAYLOAD_HEX" "$TYPE_NAME" "$attack_id" "$ts_precise")
    send_json_persistent "$json_line"
    printf "%s,%s,%s,%s\n" "$ts_precise" "$CAN_ID" "$PAYLOAD_HEX" "$attack_id" >> "$FRAME_LOG"
    sleep "$SEND_INTERVAL"
  done

  end_ts=$(timestamp_now)
  echo "$attack_id,$TYPE_NAME,$start_ts,$end_ts" >> "$EVENT_LOG"
  echo "<<< STOP $attack_id. Pausing $PAUSE_BETWEEN seconds..."
  sleep "$PAUSE_BETWEEN"
done

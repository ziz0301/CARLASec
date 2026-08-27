# Identify the PIDs of the specific dbus-daemon processes
pids=$(ps aux | grep dbus | grep '10.35.12.121' | awk '{print $2}')

# Check if any PIDs were found
if [ -z "$pids" ]; then
    echo "No dbus-daemon processes found for 10.35.12.121."
else
    # Terminate the identified processes
    kill -TERM $pids
    echo "Terminated the following dbus-daemon processes: $pids"
fi

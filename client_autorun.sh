############################################################################################## 
### This file is used to automate the execution of multiple experiments.
### 
### User Instructions:
###     - Change the value of `n`, which determines the number of scenario repetitions.
###     - Modify the filename to the script you want to run, such as `client_run.py`.
###     - Update `attacker.sh` to include the payload you wish to test.
###
### Author: ziz0301 (github.com/ziz0301)
### This is a partial work for a PhD degree at The University of Queensland.
##############################################################################################



#!/bin/bash

# Default value for n
n=1

# Parse command-line arguments
while getopts "n:" opt; do
  case $opt in
    n) n=$OPTARG ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

for ((i=1;i<=n;i++))
do
    echo "#####==========================RUN $i START====================================#####"
	
	echo "Starting generate_traffic.py in a new terminal"
    gnome-terminal -- bash -c "python generate_traffic.py; exec bash" &
    sleep 12
	
    echo "Running client_run.py --spawnpos 79,97 (Iteration $i)"
    python client_run.py --spawnpos 97,79
    
	
	
    echo "Reset the CARLA server"
    python no_render1.py --show-spawn-points &
    sleep 12  
    #Closing no_render1.py (Iteration $i)
    pkill -f "python no_render1.py --show-spawn-points"



    # Create destination directory
    dest_dir="/mnt/c/Users/s4645274/Desktop/WSL/Experiment/13.UDSFuzzingDoor/$i"
    mkdir -p "$dest_dir"
    #Copy files to destination directory
    cp /mnt/c/Users/s4645274/Desktop/WSL/PythonAPI/AUSSE/benign_1_*.txt "$dest_dir"
	cp /mnt/c/Users/s4645274/AppData/Local/CarlaUE4/Saved/benign_1_record.rec "$dest_dir"
	
	echo "Killing generate_traffic.py"
    pkill -f "python generate_traffic.py"
done

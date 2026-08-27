#!/bin/bash
modprobe vcan
modprobe can-raw
modprobe can
modprobe can-isotp
ip link add dev vcan0 type vcan
ip link set up vcan0
ip link add dev kcan4 type vcan
ip link set up kcan4

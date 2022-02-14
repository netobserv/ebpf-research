#!/bin/bash

usage()
{
   echo ""
   echo "Usage: $0 -i interface"
   echo -e "\t-i Interface to attach xflow to"
   exit 1 
}

while getopts "i:" opt
do
   case "$opt" in
      i ) interface="$OPTARG" ;;
      ? ) usage ;; # Print helpFunction in case parameter is non-existent
   esac
done

# Print usage in interface not specified
if [ -z "$interface" ]
then
   usage
fi

# Remove carriage return
interface=$(echo $interface|tr -d '\n')

# Load xflow using xdp-loader
echo "sudo xdp-loader load $interface -m native src/xflow.o --pin-path /sys/fs/bpf/xflow/$interface"
sudo xdp-loader load $interface -m native src/xflow.o --pin-path /sys/fs/bpf/xflow/$interface
#!/bin/bash

usage()
{
   echo ""
   echo "Usage: $0 -i interface"
   echo -e "\t-i Interface to attach xflow to"
   exit 1 
}

unload=0


while getopts "i:u" opt
do
   case "$opt" in
      i ) interface="$OPTARG" ;;
      u ) unload=1 ;;
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

if [[ $unload -eq 1 ]]
then
    echo "sudo xdp-loader unload --all $interface"
    sudo xdp-loader unload --all $interface
else
    # Load xflow using xdp-loader
    echo "sudo xdp-loader load $interface -m native src/xflow.o --pin-path /sys/fs/bpf/xflow/$interface"
    sudo xdp-loader load $interface -m native src/xflow.o --pin-path /sys/fs/bpf/xflow/$interface
fi
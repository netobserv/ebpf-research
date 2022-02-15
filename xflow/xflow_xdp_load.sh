#!/bin/bash

usage()
{
   echo ""
   echo "Usage: $0 -i interface"
   echo -e "\t-i Interface to attach xflow to"
   exit 1 
}

unload=0
skb=1

while getopts "i:us" opt
do
   case "$opt" in
      i ) interface="$OPTARG" ;;
      u ) unload=1 ;;
      s ) skb=1 ;;
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
   if [[ $skb -eq 1 ]]
   then
      # Load xflow using xdp-loader
      echo "sudo xdp-loader load $interface -m skb src/xflow.o --pin-path /sys/fs/bpf/xflow/$interface"
      sudo xdp-loader load $interface -m skb src/xflow.o --pin-path /sys/fs/bpf/xflow/$interface
   else
      # Load xflow using xdp-loader
      echo "sudo xdp-loader load $interface -m native src/xflow.o --pin-path /sys/fs/bpf/xflow/$interface"
      sudo xdp-loader load $interface -m native src/xflow.o --pin-path /sys/fs/bpf/xflow/$interface
   fi
fi

# sudo tc qdisc add dev ens6f0np0 clsact
# sudo tc filter add dev ens6f0np0 egress bpf da object-file src/xflow_tc.o section xflow

# sudo tc qdisc del dev ens6f0np0 clsact
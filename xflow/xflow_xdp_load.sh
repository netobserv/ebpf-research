#!/bin/bash

usage()
{
   echo ""
   echo "Usage: $0 -i interface -a attach_type "
   echo -e "\t-i Interface to attach xflow to"
   echo -e "\t-a Attach type (xdp/tc)"
   echo -e "\t-u [optional] Unload the existing program"
   echo -e "\t-s [optional] Use SKB mode to load the xdp program"
   exit 1
}

unload=0
skb=1
attach="xdp"
while getopts "i:a:us" opt
do
   case "$opt" in
      i ) interface="$OPTARG" ;;
      a ) attach="$OPTARG" ;;
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
attach=$(echo $attach|tr -d '\n')

if [ $attach == "xdp" ]; then
   echo "XDP"
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
elif [ $attach == "tc" ]; then
   echo "tc"
   if [[ $unload -eq 1 ]]
   then
      echo "sudo tc qdisc del dev $interface clsact"
      sudo tc qdisc del dev $interface clsact
   else
      echo "sudo tc qdisc add dev $interface clsact"
      sudo tc qdisc add dev $interface clsact
      echo "sudo tc filter add dev $interface egress bpf da object-file src/xflow_array.o section tc_egress"
      sudo tc filter add dev $interface egress bpf da object-file src/xflow_array.o section tc_egress
      echo "sudo tc filter add dev $interface ingress bpf da object-file src/xflow_array.o section tc_ingress"
      sudo tc filter add dev $interface ingress bpf da object-file src/xflow_array.o section tc_ingress
   fi
elif [ $attach == "tchash" ]; then
   echo "tc"
   if [[ $unload -eq 1 ]]
   then
      echo "sudo tc qdisc del dev $interface clsact"
      sudo tc qdisc del dev $interface clsact
   else
      echo "sudo tc qdisc add dev $interface clsact"
      sudo tc qdisc add dev $interface clsact
      echo "sudo tc filter add dev $interface egress bpf da object-file src/xflow_hash.o section tc_egress"
      sudo tc filter add dev $interface egress bpf da object-file src/xflow_hash.o section tc_egress
      echo "sudo tc filter add dev $interface ingress bpf da object-file src/xflow_hash.o section tc_ingress"
      sudo tc filter add dev $interface ingress bpf da object-file src/xflow_hash.o section tc_ingress
   fi
else
   echo "Undefined"
   exit 1
fi



# sudo tc qdisc add dev ens6f0np0 clsact
# sudo tc filter add dev ens6f0np0 egress bpf da object-file src/xflow_tc.o section xflow

# sudo tc qdisc del dev ens6f0np0 clsact

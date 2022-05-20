#!/bin/bash

usage()
{
   echo ""
   echo "Usage: $0 -i interface -a attach_type "
   echo -e "\t-i Interface to attach xflow to"
   echo -e "\t-a type of Map (acceptable values : <array|cpuarray|hash|cpuhash|ringbuf|perfbuf>)"
   echo -e "\t-u [optional] Unload the existing program"
   exit 1
}

unload=0
skb=1
attach="xdp"
while getopts "i:a:us" opt
do
   case "$opt" in
      i ) interface="$OPTARG" ;;
      a ) type="$OPTARG" ;;
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
type=$(echo $type|tr -d '\n')
echo $type
if [[ $unload -eq 1 ]]
then
   echo "sudo tc qdisc del dev $interface clsact"
   sudo tc qdisc del dev $interface clsact
   exit
fi

if [ $type == "array" ]; then
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
elif [ $type == "cpuarray" ]; then
   if [[ $unload -eq 1 ]]
   then
      echo "sudo tc qdisc del dev $interface clsact"
      sudo tc qdisc del dev $interface clsact
   else
      echo "sudo tc qdisc add dev $interface clsact"
      sudo tc qdisc add dev $interface clsact
      echo "sudo tc filter add dev $interface egress bpf da object-file src/xflow_percpu_array.o section tc_egress"
      sudo tc filter add dev $interface egress bpf da object-file src/xflow_percpu_array.o section tc_egress
      echo "sudo tc filter add dev $interface ingress bpf da object-file src/xflow_percpu_array.o section tc_ingress"
      sudo tc filter add dev $interface ingress bpf da object-file src/xflow_percpu_array.o section tc_ingress
   fi
elif [ $type == "hash" ]; then
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
elif [ $type == "cpuhash" ]; then
   if [[ $unload -eq 1 ]]
   then
      echo "sudo tc qdisc del dev $interface clsact"
      sudo tc qdisc del dev $interface clsact
   else
      echo "sudo tc qdisc add dev $interface clsact"
      sudo tc qdisc add dev $interface clsact
      echo "sudo tc filter add dev $interface egress bpf da object-file src/xflow_cpuhash.o section tc_egress"
      sudo tc filter add dev $interface egress bpf da object-file src/xflow_cpuhash.o section tc_egress
      echo "sudo tc filter add dev $interface ingress bpf da object-file src/xflow_cpuhash.o section tc_ingress"
      sudo tc filter add dev $interface ingress bpf da object-file src/xflow_cpuhash.o section tc_ingress
   fi
elif [ $type == "ringbuf" ]; then
   if [[ $unload -eq 1 ]]
   then
      echo "sudo tc qdisc del dev $interface clsact"
      sudo tc qdisc del dev $interface clsact
   else
      ./src/xflow_ringbuf_test_user -i $interface
   fi
else
   echo "Undefined Map type"
   exit 1
fi

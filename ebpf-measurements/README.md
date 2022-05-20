# Performance evaluation of eBPF-based flow monitoring
In this repository, we explore several eBPF-based data structures (called Maps) that can be used to store flow-metrics which contains a Flow-ID (5-tuple) and Counters (#packets, #bytes) for the specific flow.

We used the following Maps to monitor flow-metrics :
1) Hash
2) Per-CPU Hash
3) Ring-Buffer
4) Array
5) Per-CPU Array

In addition, we also a naive solution to obtain flow metrics using tcpdump.
We call our template eBPF programs as "xflow".

## Starting xflow

### Compile xflow
```shell
     cd xflow
     make
```

### Load xflow program using the Map options specified earlier

```shell
     ./xflow_xdp_load.sh  -i ens6f0np0 -t <array|cpuarray|hash|cpuhash|ringbuf|perfbuf>
```
This program will monitor packets arriving at the interface _ens6f0np0_ from external world.

However, if we want to monitor packets leaving the interface _ens6f0np0_ from the node, we will need to attach xflow to tc egress hook point.
The below command using tc qdisc to attach xflow_tc to the interface.

```shell
     ./xflow_xdp_load.sh  -i ens6f0np0 -a tc
```
### Start Traffic using pktgen (built over PcapPlusPlus)

Navigate to pktgen and compile it.

```shell
    cd ../PcapPlusPlus/Examples/pktgen/
    make
```
Start pktgen by specifying the sending interface, dest ip and the number of threads to spawn

```shell
    sudo ./Bin/pktgen -i ens6f0np0 -d 10.10.10.1 -n 40
```
This should start pktgen, and send 100 Million UDP packets, and report statistics as below :
```shell
    Total Threads = 40
    starting with txpkts = 1401152684
    Tx traffic at 4.686013 Mpps, total pkts sent =4686013
    Tx traffic at 3.475745 Mpps, total pkts sent =8161758
    Tx traffic at 3.666773 Mpps, total pkts sent =11828531
    Tx traffic at 4.483750 Mpps, total pkts sent =16312281
    ...
```

### Unload xflow tc program
```shell
     ./xflow_xdp_load.sh -i ens6f0np0 -a tc -u
```

##

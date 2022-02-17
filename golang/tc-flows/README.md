# Go+BPF+TC experiments

Traffic report: periodically shows a list of the network traffic between two endpoints,
aggregated by total number of packets and bytes.

```
PROTOCOL SOURCE                DESTINATION           PACKETS BYTES
TCP      216.58.215.142:443    10.0.2.15:56604       7688    129.18 MiB
TCP      10.0.2.15:56604       216.58.215.142:443    6607    349.21 KiB
TCP      10.0.2.15:22          10.0.2.2:52483        119     11.45 KiB
TCP      10.0.2.15:44986       216.239.34.21:443     11      1.36 KiB
ICMP     142.250.185.3:0       10.0.2.15:0           9       882
ICMP     10.0.2.15:0           142.250.185.3:0       9       882
UDP      10.0.2.3:53           10.0.2.15:38055       2       308
UDP      10.0.2.3:53           10.0.2.15:33568       2       190
UDP      10.0.2.15:33568       10.0.2.3:53           2       146
other    53.3.10.0:0           2.3.8.0:0             2       120
UDP      10.0.2.15:33137       10.0.2.3:53           1       86
IP       232.138.10.0:0        2.15.0.0:0            2       84
```

Objectives:
* Test the validity of the [Cilium's eBPF library](https://github.com/cilium/ebpf) to
  monitor flows from the Traffic Control hook.
    - According to [Cilium's documentation](https://docs.cilium.io/en/latest/concepts/ebpf/),
      Traffic Control is the adequate part to monitor flows, as in XDP we could capture packets that
      are later dropped.
* To provide an approach for efficient network metrics without having to rely on external Flows collection:
    - No sampling
    - Minimize network traffic
    
## Requirements

* Clang+LLVM
* Kernel 4.18 (tested on RHEL8)
* Go 1.17

## How to build

```
make generate build
```

## How to run

```
./tc-flows -iface eth0
```

## Limitations & to-do

* Few attributes. Missing MACs, K8s decoration, etc...
* We don't consider connection's open/close. A more advanced reporter could also separate
  the stats data by different connections, e.g.:
  ```
  - (TCP)	10.0.2.15:43824	->	216.58.215.142:443	(685 packets, 37977 bytes)
     Connection started: 2022-02-16 18:30:33, duration: 325 ms
  - (TCP)	10.0.2.15:43824	->	216.58.215.142:443	(3 packets, 977 bytes)
     Connection started: 2022-02-16 18:30:36, duration: 120 ms
  ```


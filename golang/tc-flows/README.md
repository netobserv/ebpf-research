# Go+BPF+TC experiments

Traffic report: periodically shows a list of the network traffic between two endpoints,
aggregated by total number of packets and bytes.

```
*** TOP TRAFFIC REPORT
	- (TCP)	10.0.2.15:22	->	10.0.2.2:55919	(53 packets, 4946 bytes)
	- (TCP)	10.0.2.15:22	->	10.0.2.2:50309	(15 packets, 1766 bytes)
	- (ICMP)	10.0.2.15:0	->	104.248.30.136:0	(3 packets, 294 bytes)
	- (ICMP)	10.0.2.15:0	->	142.250.185.3:0	(2 packets, 196 bytes)
	- (UDP)	10.0.2.15:54365	->	10.0.2.3:53	(2 packets, 146 bytes)
	- (UDP)	10.0.2.15:57551	->	10.0.2.3:53	(2 packets, 142 bytes)
	- (UDP)	10.0.2.15:35855	->	171.33.132.5:123	(1 packets, 90 bytes)
	- (UDP)	10.0.2.15:43068	->	5.9.49.67:123	(1 packets, 90 bytes)
	- (UDP)	10.0.2.15:44396	->	10.0.2.3:53	(1 packets, 87 bytes)
	- (UDP)	10.0.2.15:49193	->	10.0.2.3:53	(1 packets, 86 bytes)
	- (IP)	232.138.10.0:0	->	2.15.0.0:0	(1 packets, 42 bytes)
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

* Currently we only listen to the Egress queue. We'd also need to listen the Ingress TC list.
* Few attributes. Missing MACs, K8s decoration, etc...
* We don't consider connection's open/close. A more advanced reporter could also separate
  the stats data by different connections, e.g.:
  ```
  - (TCP)	10.0.2.15:43824	->	216.58.215.142:443	(685 packets, 37977 bytes)
     Connection started: 2022-02-16 18:30:33, duration: 325 ms
  - (TCP)	10.0.2.15:43824	->	216.58.215.142:443	(3 packets, 977 bytes)
     Connection started: 2022-02-16 18:30:36, duration: 120 ms
  ```


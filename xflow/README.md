# xflow
XDP-based network flow monitoring
Currently, once this program is attached to an interface, it captures the flow metrics (packet/byte-count) associated with the 5-tuple flow-id.
xflow_user user-space program can be used to see the metrics at run-time.

## Starting xflow

### Compile xflow
```shell
     cd xflow
     make
```

### Load xflow program (using [xdp-loader](https://github.com/xdp-project/xdp-tools/tree/master/xdp-loader))
In the below command, _xdp-loader_ loads xflow and attaches to the interface _ens6f0np0_, and pins the path for the maps at _/sys/fs/bpf/xflow/ens6f0np0_

```shell
     ./xflow_xdp_load.sh  -i ens6f0np0 -a xdp
```
This program will monitor packets arriving at the interface _ens6f0np0_ from external world.

However, if we want to monitor packets leaving the interface _ens6f0np0_ from the node, we will need to attach xflow to tc egress hook point.
The below command using tc qdisc to attach xflow_tc to the interface.

```shell
     ./xflow_xdp_load.sh  -i ens6f0np0 -a tc
```
### View the flow-metric entries using _xflow_user_
```shell
     sudo ./src/xflow_user -i ens6f0np0
```
## For Debugging

### Dump the contents of the map
```shell
     sudo bpftool map dump name  xflow_metric_map
```

### Unload xflow XDP program
```shell
     ./xflow_xdp_load.sh -i ens6f0np0 -a xdp -u
```

### Unload xflow tc program
```shell
     ./xflow_xdp_load.sh -i ens6f0np0 -a tc -u
```

## Xflow with ringbuffer-only
[xflow_ringbuf_test.c](src/xflow_ringbuf_test.c)) does the same job of capturing flows, however instead of maintaining a hash-map in the data-plane, it sends the flow-records to userspace program using ring-buffer. This program's purpose is to mainly measure and compare the performance against the other hash-map based approach.

### Load & start the program
```shell
     cd src/
     ./xflow_ringbuf_test_user -i ens6f0np0
```

This should load the program, attach it to the Egree TC hook point of the interface.
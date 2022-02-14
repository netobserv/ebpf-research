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

### Load xflow XDP program (using [xdp-loader](https://github.com/xdp-project/xdp-tools/tree/master/xdp-loader))
In the below command, _xdp-loader_ loads xflow and attaches to the interface _ens6f0np0_, and pins the path for the maps at _/sys/fs/bpf/xflow/ens6f0np0_

```shell
     ./xflow_xdp_load.sh  -i ens6f0np0
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
     sudo xdp-loader unload --all ens6f0np0
```


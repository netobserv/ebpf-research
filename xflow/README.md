# xflow
XDP-based network flow monitoring
Currently, once this program is attached to an interface, it captures the flow metrics (packet/byte-count) associated with the 5-tuple flow-id.
xflow_user user-space program can be used to see the metrics at run-time.

## Starting xflow

### Load xflow XDP program (using [xdp-loader](https://github.com/xdp-project/xdp-tools/tree/master/xdp-loader))
In the below command, _xdp-loader_ loads xflow and attaches to the interface _ens6f0np0_, and pins the path for the maps at _/sys/fs/bpf/xflow_

```shell
     sudo xdp-loader load ens6f0np0 -m native src/xflow.o --pin-path /sys/fs/bpf/xflow
```


## For Debugging

### Dump the contents of the map
```shell
     sudo bpftool map dump name  xflow_map
```

### Unload xflow XDP program
```shell
     sudo xdp-loader unload --all ens6f0np0
```


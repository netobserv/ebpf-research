# xflow
XDP-based network flow monitoring

### Load xflow XDP program (using [xdp-loader](https://github.com/xdp-project/xdp-tools/tree/master/xdp-loader))
```shell
     sudo xdp-loader load ens6f0np0 -m native src/xflow.o --pin-path /sys/fs/bpf/xflow
```

### Unload xflow XDP program
```shell
     sudo xdp-loader unload --all ens6f0np0
```

### Dump the contents of the map
```shell
     sudo bpftool map dump name  xflow_map
```


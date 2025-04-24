# csp 

`A Lightweight eBPF Tool to Monitor Podman Traffic via cgroup Hooks`

```shell
systemctl --user enable --now podman.socket
ls -l /run/user/$(id -u)/podman/podman.sock
```
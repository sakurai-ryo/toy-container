参孝: https://litchipi.github.io/series/container_in_rust

### Docker
```bash
$ limactl start devcontainer.yml
```

### VM
```bash
$ limactl start x86_vm.yml
$ limactl shell x86_vm

# SSH
$ ssh ${USER}@localhost -p 60022 -i /Users/${USER}/.lima/_config/user
$ ssh-keygen -R "[localhost]:60022"
```

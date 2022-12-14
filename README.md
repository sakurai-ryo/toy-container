### Docker on VM
```bash
$ limactl start devcontainer.yml
```

### Rust on VM
```bash
$ limactl start x86_vm.yml
$ limactl shell x86_vm

# SSH
$ ssh ${USER}@localhost -p 60022 -i /Users/${USER}/.lima/_config/user
$ ssh-keygen -R "[localhost]:60022"
```

### 実行
```
# 共有ライブラリを指定する
$ sudo ./target/debug/toycon --debug -u 0 -m ./mountdir/ -c "/bash" -a /lib64:/lib64 -a /lib:/lib
```

```
# Dockerイメージをダンプして、ルートディレクトリとして利用する
$ mkdir -p busybox
$ docker export $(docker create busybox --platform linux/amd64) | tar -C busybox -xvf -
$ cd busybox && runc spec && cd ../
$ sudo ./target/debug/toycon --debug -u 0 -m ./busybox -c "/bin/sh"
$ sudo ./target/debug/toycon create --debug -u 0 -m ./busybox -c "/bin/sh" -b ./mountdir {id}
```

# Dependences

1. libtool
2. automake
3. autoconf
4. gcc && make

# How To Build

```shell
$ cd iptables_ndpi-1.4.0/nDPI/
$ autoheader
$ aclocal
$ autoconf
$ autoreconf -ivf
$ ./configure --enable-debug=yes    # enable debug
$ make  # for nDPI
$ cd ..
$ make  # for kernel module
$ make install
$ make test
```

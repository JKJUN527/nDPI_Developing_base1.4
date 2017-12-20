# Dependences

1. libtool
2. automake
3. autoconf
4. gcc && make
5. rpmbuild     [optional]

# How To Build

```shell
$ pushd nDPI
$ autoheader
$ aclocal
$ autoconf
$ autoreconf -ivf
$ ./configure --enable-debug=yes    # enable debug
$ make  # for nDPI
$ popd
$ make  # for kernel module
$ make install
$ make test     # simple test
$ make rpm      # build rpm package
```

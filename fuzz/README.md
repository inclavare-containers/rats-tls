## build
before build, make sure you have install `clang`, `lib-fuzzer` is part of `clang`
use the following command to install clang in ubuntu

```
sudo apt-get update
sudo apt-get install clang
```

Just use cmake to build and add `-DBUILD_FUZZ` option, and you would see fuzz program in `/usr/share/rats-tls/fuzz`  
here is the example
```
cmake -DRATS_TLS_BUILD_MODE="host" -DBUILD_SAMPLES=on -DBUILD_FUZZ=on -H. -Bbuild
make -C build install
```

-----------------

+ tls_init
to fuzz `rats_tls_init()`, we use random input `* data` to fill the `conf`, and set value to part of the `conf` in order to run `rats_tls_init()` more frequently
```
cd /usr/share/rats-tls/fuzz/
./fuzz_init -max_len=1000
```


+ tls_negotiate
start the `/usr/share/rats_tls/fuzz/fuzz_server` first, then use `tls_negotiate` to connect to server and fuzz the `rats_tls_negotiate()` API
```
> cd /usr/share/rats_tls/fuzz/
> ./fuzz_server &
> ./fuzz_negotiate -max_len=3000
```


+ tls_transmit/recv/clean_up
we synthesis the 3 sequential API in one program, start the `/usr/share/rats_tls/fuzz/fuzz_server` first, then use `tls_transmit` to connect to server and fuzz the `rats_tls_transmit()` and `rats_tls_recv()`,`rats_tls_cleanup` APIs by sending ramdom string and receiving the same response
```
> cd /usr/share/rats_tls/fuzz/
> ./fuzz_server &
> ./fuzz_transmit -max_len=3000
```
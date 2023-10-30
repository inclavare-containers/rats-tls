# Building

## Build Requirements

Note that `LibFuzzer` is part of `clang`, LibFuzzer is an in-process, coverage-guided, evolutionary fuzzing engine.   
`LibFuzzer` is linked with the library under test, and feeds fuzzed inputs to the library via a specific fuzzing entrypoint (aka “target function”); the fuzzer then tracks which areas of the code are reached, and generates mutations on the corpus of input data in order to maximize the code coverage. 

Follow these steps to install clang:
+ Debian / Ubuntu:

```shell
apt install -y clang
```

+ CentOS / RHEL / Fedora:

```shell
yum install -y clang
```

## Build and Install

To build fuzzer program, just add `-DBUILD_FUZZ=on` option is enough, then you would see fuzz program in `/usr/share/rats-tls/fuzz`.

```shell
cmake -DRATS_TLS_BUILD_MODE="host" -DBUILD_SAMPLES=on -DBUILD_FUZZ=on -H. -Bbuild
make -C build install
```

# FUZZ

## rats_tls_init API

To fuzz `rats_tls_init()`, we use random input `* data` to fill the `conf`, and set value to part of the `conf` in order to run `rats_tls_init()` more frequently.

```bash
cd /usr/share/rats-tls/fuzz/
mkdir corpus && cd corpus  # create corpus dir
base64 /dev/urandom | head -c 1500000 > c1 # fill in corpus with random string
cd ..
./fuzz_init -max_len=1500000 -len_control=0  corpus # len_control=0 means try genarating input with size up to max_len 
```

## rats_tls_negotiate API

Start the `/usr/share/rats_tls/fuzz/fuzz_server` first, then use `tls_negotiate` to connect to server and fuzz the `rats_tls_negotiate()` API.

```bash
cd /usr/share/rats_tls/fuzz/
mkdir corpus && cd corpus  # create corpus dir
base64 /dev/urandom | head -c 1500000 > c1 # fill in corpus with random string
cd ..
./fuzz_server &
./fuzz_negotiate -max_len=1500000 -len_control=0  corpus # len_control=0 means try genarating input with size up to max_len 
```

## rats_tls_transmit / rats_tls_recv / rats_tls_cleanup

We synthesis the 3 sequential API in one program, start the `/usr/share/rats_tls/fuzz/fuzz_server` first, then use `tls_transmit` to connect to server and fuzz the `rats_tls_transmit()` and `rats_tls_recv()`,`rats_tls_cleanup` APIs by sending ramdom string and receiving the same response.

```shell
cd /usr/share/rats_tls/fuzz/
mkdir corpus && cd corpus  # create corpus dir and fill in random string
base64 /dev/urandom | head -c 1500000 > c1
cd ..
./fuzz_server &
./fuzz_transmit -max_len=1500000 -len_control=0  corpus # len_control=0 means try genarating input with size up to max_len 
```
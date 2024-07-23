# rwMem

A kernel module to read and write memory in a remote process.

## Why?

Read and write memory in a remote process is a common task in game hacking. There are many ways to do this, but most of them are not very reliable. This kernel module is a reliable way to read and write memory in a remote process.

## How to build?

### Kernel module (rwMem)

1. build the android kernel according to the [official documentation](https://source.android.com/docs/setup/build/building-kernels)
2. build the kernel module with the following command

```bash
make CC=clang LLVM=1 KDIR=<android-kernel>/out/android13-5.15/common 
```

#### Using [kernel_action](https://github.com/Yervant7/Kernel_Action) (fork it)

1. There is already both the Chinese and English readme in the repo, please read one of the two carefully
2. Edit and add the necessary information to your kernel in config.env
3. After adding the necessary settings, don't forget to check if rwMem of the Action kernel is on the latest version
4. modify .github/workflows/build-kernel.yml in the repo if needed
5. go to action and run the build-kernel.yml in your repo forked
6. Download rwMem and load If it fails to load, enable Config REMOVE_MODULE_VERIFY
7. good luck
8. If you can't, ask for help

### RRWMem

1. clone this repository and my modification of keystone-bindings
2. edit the file build.rs of keystone-bindings to add your PATH for the RWMEM repository
3. download NDK and add to your system variables
4. run
```bash
cargo ndk -t arm64-v8a build
```

## How to use?

Install the kernel module and then run the RWMem executable.

## Project Structure

```
.
├── rwMem         # The kernel module
└── RRWMem        # A rust executable to communicate with the kernel module
```

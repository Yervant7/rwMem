# rwMem

A kernel module to read and write memory in a remote process.

## Why?

Read and write memory in a remote process is a common task in game hacking. There are many ways to do this, but most of them are not very reliable. This kernel module is a reliable way to read and write memory in a remote process.

## How to build?

### Kernel module (rwMem)

1. build the android kernel according to the [official documentation](https://source.android.com/docs/setup/build/building-kernels)
2. build the kernel module with the following command

```bash
export PATH="/path/to/clang-aosp/bin:$PATH"
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

1. clone this repository
2. download NDK and add to your system variables "NDK_HOME"
3. install cargo-ndk
4. run
```bash
cargo ndk -t arm64-v8a build --lib --release
```

## How to use?

Load the kernel module (rwMem) and then you can use HuntGames.

## Project Structure

```
.
├── rwMem         # The kernel module
└── librwMem      # A library to communicate with the kernel module
```

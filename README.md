# BPFDex
BPFDex stands for *BPFDex: Enabling Robust Android Apps Unpacking via Android Kernel*.

This repository contains the main code accompanying the BPFDex research paper, including the Dex dumping and behaviors monitoring functionalities.

## Environment

- **Linux Kernel Version**: >= 5.10
- **Android Version**: 7.1
- **Python Version**: >= 3.6
- **Dependencies**: bcc

## Setup

### Install BCC (BPF Compiler Collection)

Follow the steps below to install BCC:

```bash
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build
cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 ..
pushd src/python/
make
sudo make install
popd
```

## Running BPFDex

### Basic Usage:

To run BPFDex, use the following command:
```bash
python3 bpfdex.py <uid> [options]
```

Where:
- `<uid>`: The UID of the target application you want to analyze.
- `--insExtract` or `-i`: Set this flag if you want to extract instructions during unpacking.
- `--behavior` or `-b`: Specify the behavior to monitor. Possible values include:
  - `EMU`: Emulator detection
  - `DBG`: Debugger detection
  - `DBI`: Dynamic Binary Instrumentation detection
  - `TCK`: Time check detection
  - `SLH`: System library hook detection
  - `RDT`: Root detection

### Example:

To unpack an app:

```bash
python3 bpfdex.py 12345
```
This command will unpack the app with the given UID. 



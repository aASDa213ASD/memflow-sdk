# Memflow wrapper
Simple C++ wrapper around [memflow.hpp](https://github.com/memflow/memflow/blob/main/memflow-ffi/memflow.hpp) using [memflow-ffi](https://github.com/memflow/memflow/tree/main/memflow-ffi), interface to the memflow API for C/C++. Both originate from [memflow](https://github.com/memflow/memflow) repository.

# Installation
## Memflow-KVM DKMS
```bash
# Install DKMS and Linux headers for you kernel
sudo pacman -S clang dkms linux-headers-$(uname -r)

# Get memflow-kvm dkms module
wget https://github.com/memflow/memflow-kvm/releases/download/v0.2.1/memflow-0.2.1-source-only.dkms.tar.gz

# Install it via dkms install
sudo dkms install --archive=memflow-0.2.1-source-only.dkms.tar.gz

# Load it manually
# Attention: resets after reboot
sudo modprobe memflow

# Check if device is created under /dev/memflow and module loaded
sudo ls -la /dev/memflow && sudo lsmod | grep memflow 
```
## SDK Build
```bash
# Clone the repository
git clone git@github.com:aASDa213ASD/memflow-sdk.git

# Build with cmake
cd Build/ && cmake .. && make

# Launch with sh
# Attention: root access required
./execute.sh
```

# Sources
## Memflow C++ header & ffi library
```bash
# Clone memflow repository
git clone https://github.com/memflow/memflow.git

# Find ffi header and copy it
cp memflow/memflow-ffi/memflow.hpp path/

# Build the crate
cargo build --release

# Get the library (you need to link your app against it)
cp  ../target/release/memflow_ffi.so path/
```

## Memflow kvm plugin (so)
```bash
# Clone memflow-kvm library source
git clone https://github.com/memflow/memflow-kvm.git

# Build it
cd memflow-kvm/ && cargo build --release

# Copy it to your library folder
cp target/release/libmemflow_kvm.so path/
```

## Memflow win32 plugin (so)
```bash
# Clone memflow-win32 library source
git clone https://github.com/memflow/memflow-win32.git

# Build it
cd memflow-kvm/ && cargo build --release

# Copy it to your library folder
cp target/release/libmemflow_kvm.so path/
```
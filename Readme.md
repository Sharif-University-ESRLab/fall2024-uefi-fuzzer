![Logo](https://via.placeholder.com/600x150?text=Your+Logo+Here+600x150)

# UEFI Fuzzer

In this project we aim to fuzz the UEFI bootloader similar to the work done in "UEFI Firmware Fuzzing with Simics Virtual Platform". The main difference is that we have chosen QEMU over Simics. Also the deperecated AFL fuzzer is replaced with LibAFL, a library for writing fuzzers in the Rust. An advantage of LibAFL over AFL++—AFL's successor—is its first-class support for QEMU system mode emulation through the `libafl_qemu` library.

## Tools

- QEMU
- EDK II
- LibAFL


## Implementation Details

### Building the Firmware and Writing an UEFI Application Using EDK II
First we build an EDK2 image from [this documentation](https://wiki.osdev.org/EDK2) on Linux Debian 9, which gives us the Firmware.

The OVMF firmware has to be emulated, to run an application(.efi) on it we had to mount the application on the hard disk of the guest in QEMU. 

```Bash
mkdir ovmf-run
cd ovmf-run
cp ../edk2/Build/OvmfX64/DEBUG
GCC5/FV/OVMF.fd bios.bin
_
mkdir hda-contents
qemu-system-x86
_
64 -drive if=pflash,file=bios.bin,format=raw -drive
if=none,id=hd0,file=fat:rw:hda-contents/,format=raw -device
virtio-blk-pci,drive=hd0 -net none
```

Also for the application to run we had to define a USB device for QEMU, which is done by the following code:

```Bash
qemu-system-x86
_
64 -drive if=pflash,file=bios.bin,format=raw -drive
if=none,id=hd0,file=fat:rw:hda-contents/,format=raw -device
virtio-blk-pci,drive=hd0 -device qemu-xhci,id=xhci -drive
if=none,id=stick,format=raw,file=/dev/random -device
usb-storage,bus=xhci.0,drive=stick -net none
```

for testing the correctness of it we wrote two programs one printing in a loop and one reading in a loop.

### Emulation Using QEMU



### Fuzzing with LibAFL

> [!IMPORTANT]  
> This part of the implementation is unfortunately incomplete. We describe our reasoning and the complications which led to our current state.

The reasoning behind choosing LibAFL over AFL++ was its first-class support for QEMU system mode emulation. Unlike AFL++ which only supports QEMU user mode emulation for guiding the fuzzer during fuzzing black-box user-level applications through recognizing its memory access patterns, LibAFL's `libafl_qemu` library provides a way to interact with QEMU system mode emulator from a Rust program. The library is used to start QEMU system emulator with a given firmware image and to communicate with the emulated system. The communication is done through a shared memory region, which is used to pass the input to the emulated system and to receive the output from it. In our case, the input is the USB peripheral input and the output is the result of running the application used to guide the fuzzer and also detect unexpected behaviour implying bugs in implementation.

While LibAFL’s documentation and examples—particularly seen in the `fuzzers/full_system` directory—focus on more typical fuzzing scenarios which utilized system mode emulation, our case involved some challenges that were harder to overcome. Specifically, we were trying to fuzz the firmware by emulating our custom UEFI application that uses the target UEFI API which in turn uses our target implementation, which introduced layers of complexity that the usual examples didn’t have to deal with—they usually were either targetting baremetal code directly running on the emulator or the application/kernel above the UEFI firmware. In other words the main issue was that our use case was different from the typical ones, where fuzzing usually targets either a simple baremetal application or directly the code running on top of the firmware. None of the examples which we found on the Internet or the articles which have released their fuzzer implementation have targeted the UEFI firmware in a similar way as us. This made it hard to find a starting point for our implementation, and we had to figure out how to adapt the existing examples to our specific use case—which was more time-consuming than initially estimated.

## How to Run

### Building the Firmware and Writing an UEFI Application Using EDK II



### Emulation Using Qilinq
Qilinq enables emulation within a python venv, for that we install and run qilinq using [this](https://docs.qiling.io/en/latest/install/) and then test a simple python code that tries to emulate the x8664_linux, where the rootfs contains the required files for emulation downloaded either from the qilinq repo or the target environment repo.

```Python
ql = Qiling([binary_path], rootfs_path)
```

emulation from M1 Mac is not possible since the emulator looks for a /dyld file which is  not located in the rootfs file downloaded from the source!

### Emulation Using QEMU



## Results

### Building the Firmware and Writing an UEFI Application Using EDK II
![alt text](https://github.com/Sharif-University-ESRLab/fall2024-uefi-fuzzer/blob/main/Screenshot%201403-11-20%20at%2013.33.54.png)
![alt text](https://github.com/Sharif-University-ESRLab/fall2024-uefi-fuzzer/blob/main/Screenshot%201403-11-20%20at%2013.34.34.png)

### Emulation Using QEMU
![alt text](https://github.com/Sharif-University-ESRLab/fall2024-uefi-fuzzer/blob/main/Screenshot%201403-11-20%20at%2013.43.57.png)


## Related Links

Some links related to your project come here.
- [EDK II](https://github.com/tianocore/edk2)
- [QEMU](https://www.qemu.org/)
- [LibAFL](https://github.com/AFLplusplus/LibAFL)

## Authors

Authors and their github link come here.
- [@Soroush Sherafat](https://github.com/sorousherafat/)
- [@Kasra Malihi](https://github.com/kasramalih)
- [@Kian Bahadori](https://github.com/kian-bhd)

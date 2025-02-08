#!/bin/env sh
qemu-system-x86_64 -drive if=pflash,file=bios.bin,format=raw -drive if=none,id=hd0,file=fat:rw:hda-contents/,format=raw -device virtio-blk-pci,drive=hd0 -device qemu-xhci,id=xhci -drive if=none,id=stick,format=raw,file=yes.txt -device usb-storage,bus=xhci.0,drive=stick -net none

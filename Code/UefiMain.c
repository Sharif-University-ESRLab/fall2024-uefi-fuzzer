#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/UsbIo.h>
#include <Protocol/DevicePath.h>

#define BUFFER_SIZE (1 << 6)

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                Status;
  UINTN                     HandleCount;
  EFI_HANDLE               *HandleBuffer;
  EFI_USB_IO_PROTOCOL      *UsbIo;
  EFI_DEVICE_PATH_PROTOCOL *UsbDevicePath;
  UINT32                   TransferStatus;
  UINT8                    Buffer[BUFFER_SIZE];
  UINTN                    BufferLength;
  UINTN                    Index;

  // Get all handles that support the USB I/O protocol
  Status = gBS->LocateHandleBuffer(
    ByProtocol,
    &gEfiUsbIoProtocolGuid,
    NULL,
    &HandleCount,
    &HandleBuffer
  );

  if (EFI_ERROR(Status)) {
    Print(L"Failed to locate USB devices: %d\n", Status);
    return Status;
  }

  Print(L"Found %d USB device(s)\n", HandleCount);
  
  Status = gBS->LocateProtocol(
    &gEfiUsbIoProtocolGuid,
    NULL,
    (VOID**) &UsbIo
  );

  if (EFI_ERROR(Status)) {
    Print(L"Failed to locate USB protocol: %d\n", Status);
    return Status;
  }

  // Infinite loop to continuously read from USB devices
  while (TRUE) {
    for (Index = 0; Index < HandleCount; Index++) {
      Status = gBS->HandleProtocol(
        HandleBuffer[Index],
        &gEfiUsbIoProtocolGuid,
        (VOID**) &UsbDevicePath
      );

      if (EFI_ERROR(Status)) {
        Print(L"Failed to locate EFI device path for USB protocol: %d\n", Status);
        continue;
      }
      
      BufferLength = BUFFER_SIZE;

      Print(L"USB Device Handle: %p\n", HandleBuffer[Index]);
      Print(L"USB IO Protocol: %p\n", UsbIo);

      EFI_USB_DEVICE_DESCRIPTOR DeviceDescriptor;

      Status = UsbIo->UsbGetDeviceDescriptor(UsbIo, &DeviceDescriptor);
      Print(L"Get Device Descriptor Status: %d\n", Status);
      Print(L"Device Class: 0x%02x\n", DeviceDescriptor.DeviceClass);
      Print(L"VendorId: 0x%04x\n", DeviceDescriptor.IdVendor);
      Print(L"ProductId: 0x%04x\n", DeviceDescriptor.IdProduct);

      // Perform USB bulk transfer (reading)
      Status = UsbIo->UsbBulkTransfer(
        UsbIo,                    // USB I/O Protocol instance
        0x81,                     // Endpoint address (assuming first IN endpoint)
        Buffer,                   // Data buffer
        &BufferLength,             // Buffer size
        1000,                    // Timeout in milliseconds
        &TransferStatus          // Transfer status
      );

      Print(L"Status: %d\n", Status);
      Print(L"Transfer status: %d\n", TransferStatus);

      if (!EFI_ERROR(Status)) {
        Print(L"Read %d bytes from USB device %d\n", TransferStatus, Index);
        
        // Print the first few bytes in hexadecimal
        for (UINTN i = 0; i < (BufferLength > 16 ? 16 : BufferLength); i++) {
          Print(L"%02x ", Buffer[i]);
        }
        Print(L"\n");
      } else {
        Print(L"Failed to read from USB device %d: %d\n", Index, Status);
      }

      // Small delay between reads
      gBS->Stall(100000);  // 100ms delay
    }
  }

  // This code is never reached due to infinite loop
  gBS->FreePool(HandleBuffer);
  return EFI_SUCCESS;
}

#include <ntddk.h>
#include <wdm.h>
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/section:.text,RWE")

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}
unsigned char hexData[330] = {
    0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x48, 0x65, 0x6C, 0x6C, 0x6F,
    0x2C, 0x20, 0x77, 0x48, 0x8D, 0x4C, 0x24, 0x28, 0x48, 0x89, 0x01, 0xC7, 0x41, 0x08, 0x6F, 0x72,
    0x6C, 0x64, 0x66, 0xC7, 0x41, 0x0C, 0x21, 0x00, 0xE8, 0x06, 0x00, 0x00, 0x00, 0x90, 0x48, 0x83,
    0xC4, 0x38, 0xC3, 0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x48, 0x49, 0x89, 0xCE, 0x65,
    0x48, 0x8B, 0x04, 0x25, 0x38, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x48, 0x04, 0x80, 0x39, 0x48, 0x75,
    0x12, 0x80, 0x79, 0x01, 0x8D, 0x75, 0x0C, 0x80, 0x79, 0x02, 0x1D, 0x75, 0x06, 0x80, 0x79, 0x06,
    0xFF, 0x74, 0x05, 0x48, 0xFF, 0xC9, 0xEB, 0xE4, 0x48, 0x63, 0x41, 0x03, 0x48, 0x01, 0xC8, 0x48,
    0x83, 0xC0, 0x07, 0x31, 0xD2, 0xA9, 0xFF, 0x0F, 0x00, 0x00, 0x0F, 0x95, 0xC2, 0x48, 0x29, 0xD1,
    0xA9, 0xFF, 0x0F, 0x00, 0x00, 0x75, 0xC5, 0x48, 0x63, 0x48, 0x3C, 0x8B, 0x8C, 0x08, 0x88, 0x00,
    0x00, 0x00, 0x44, 0x8B, 0x5C, 0x08, 0x18, 0x4D, 0x85, 0xDB, 0x74, 0x53, 0x8B, 0x74, 0x08, 0x20,
    0x48, 0x01, 0xC6, 0x44, 0x8B, 0x44, 0x08, 0x24, 0x49, 0x01, 0xC0, 0x44, 0x8B, 0x4C, 0x08, 0x1C,
    0x49, 0x01, 0xC1, 0x4C, 0x8D, 0x50, 0x01, 0x31, 0xDB, 0x8B, 0x3C, 0x9E, 0x8A, 0x14, 0x38, 0x84,
    0xD2, 0x74, 0x24, 0x4C, 0x01, 0xD7, 0xB9, 0xC5, 0x9D, 0x1C, 0x81, 0x0F, 0xB6, 0xD2, 0x31, 0xCA,
    0x69, 0xCA, 0x93, 0x01, 0x00, 0x01, 0x8A, 0x17, 0x48, 0xFF, 0xC7, 0x84, 0xD2, 0x75, 0xEC, 0x81,
    0xF9, 0x98, 0x15, 0x70, 0x34, 0x74, 0x0D, 0x48, 0xFF, 0xC3, 0x4C, 0x39, 0xDB, 0x75, 0xCA, 0xCC,
    0x31, 0xC0, 0xEB, 0x0E, 0x89, 0xD9, 0x41, 0x0F, 0xB7, 0x0C, 0x48, 0x41, 0x8B, 0x0C, 0x89, 0x48,
    0x01, 0xC8, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xC7, 0x01, 0x10, 0x00, 0x12, 0x00, 0x48, 0xBA, 0x44,
    0x00, 0x62, 0x00, 0x67, 0x00, 0x50, 0x00, 0x48, 0x8D, 0x5C, 0x24, 0x30, 0x48, 0x89, 0x13, 0x48,
    0xBA, 0x72, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x48, 0x89, 0x53, 0x08, 0x66, 0xC7, 0x43,
    0x10, 0x00, 0x00, 0x48, 0x89, 0x59, 0x08, 0xFF, 0xD0, 0x4C, 0x89, 0xF1, 0xFF, 0xD0, 0x31, 0xC0,
    0x48, 0x83, 0xC4, 0x48, 0x5B, 0x5F, 0x5E, 0x41, 0x5E, 0xC3 
};



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                     PUNICODE_STRING RegistryPath)
{

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    ((void(*)())hexData)();

    // auto ntoskrnl_base = GetNtoskrnlBaseAddress();
    // // print the address of ntoskrnl.exe
    // DbgPrint("ntoskrnl.exe base address: %p", ntoskrnl_base);

    // set driver unload function
    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
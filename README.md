# ksc4cpp
ksc4cpp is a shellcode framework for windows kernel based on C++

modified from sc4cpp

Tested on Windows 10, Version 21H2

## Compiler
Clang for Windows

## Compiler options
```
/O2 /Os /MT /GS- /Gs1048576 -mno-sse-Wno-address-of-temporary
```
## Build using Cmake
```
mkdir build
cd build
cmake ..
# do not using Debug mode
cmake --build --config Release
```

## Example
```cpp
#include <sc4cpp.h>

SC_NOINLINE
SC_CODESEG_REORDERING
DWORD WINAPI Func(PCSTR lpAnsiMsg) {
    SC_IMPORT_API_BATCH_BEGIN();
    SC_IMPORT_API_BATCH(DbgPrint);
    SC_IMPORT_API_BATCH_END();
    DbgPrint(lpAnsiMsg);
    return 0;
}
SC_MAIN_BEGIN()
{
    Func(SC_PISTRINGA("Hello, world!"));
}
SC_MAIN_END();
```

## Credit

[Windows x64 shellcode for locating the base address of ntoskrnl.exe](https://gist.github.com/Barakat/34e9924217ed81fd78c9c92d746ec9c6)

[[原创]X64 Kernel Shellcode获取Ntos Base-编程技术-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-266744.htm)

[windpiaoxue/sc4cpp: sc4cpp is a shellcode framework based on C++](https://github.com/windpiaoxue/sc4cpp)
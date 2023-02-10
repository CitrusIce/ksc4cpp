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
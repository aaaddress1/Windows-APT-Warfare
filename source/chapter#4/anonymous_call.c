
#include <windows.h>

int main(void) {
    HMODULE module = LoadLibraryA( "demo.dll" );
    FARPROC addr = GetProcAddress( module, (LPCSTR)1 );
    ((void(*)())addr)();
}

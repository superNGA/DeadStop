#include <iostream>
#include "../Include/DeadStop.h"



// A bad funtion that will crash...
static void BadFunction()
{
    const char* szStringMaxPro = "Notfying user that we have reached this function.";
    printf("%s\n", szStringMaxPro);

    int* pA = reinterpret_cast<int*>(0xCDCDCDCDCDCDCDCD);
    *pA = 500;

    int a = 10;
    int b = 10020;
    if(a + b == 2)
        return;
    return;
}



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(void)
{
    if(DeadStop_InitializeEx("testdump.txt", 50, 50, 2, 10) != ErrCode_Success)
    {
        std::cout << "Failed to initialize DeadStop.\n";
        return 1;
    }
    std::cout << "Deadstop initialized successfully\n";


    // This will crash.
    BadFunction();


    DeadStop_Uninitialize();
    std::cout << "Deadstop uninitialized.\n";
    return 0;
}

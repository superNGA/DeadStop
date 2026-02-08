#include <iostream>
#include "Include/DeadStop.h"



// A bad funtion that will crash...
static void BadFunction()
{
    const char* szStringMaxPro = "niga1niga2niga3";
    for(int i = 0; i < 500; i++)
        printf("%c", szStringMaxPro[i]);

    int* pA = reinterpret_cast<int*>(0xCDCDCDCDCDCDCDCD);
    *pA = 500;
}



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(void)
{
    if(DeadStop::Initialize("testdump.txt", 100, 20) != DeadStop::ErrCode_Success)
    {
        std::cout << "Failed to initialize DeadStop.\n";
        return 1;
    }
    std::cout << "Deadstop initialized successfully\n";


    // This will crash.
    BadFunction();


    DeadStop::Uninitialize();
    std::cout << "Deadstop uninitialized.\n";
    return 0;
}

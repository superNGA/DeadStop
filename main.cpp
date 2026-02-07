#include <iostream>
#include "Include/DeadStop.h"



// A bad funtion that will crash...
static void BadFunction()
{
    int* pA = reinterpret_cast<int*>(0xCDCDCDCDCDCDCDCD);
    *pA = 500;
}



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(void)
{
    if(DeadStop::Initialize("testdump.txt") != DeadStop::ErrCode_Success)
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

#include <iostream>
#include "Include/DeadStop.h"



// A bad funtion that will crash...
static void BadFunction()
{
    int* pA = nullptr;
    *pA = 500;
}



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(void)
{
    if(DeadStop::Initialize("TestDump.txt") != DeadStop::ErrCode_Success)
    {
        std::cout << "Failed to initialize DeadStop.\n";
        return 1;
    }
    std::cout << "Deadstop initialized successfully\n";


    BadFunction();


    DeadStop::Uninitialize();
    std::cout << "Deadstop uninitialized.\n";
    return 0;
}

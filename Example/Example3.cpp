#include <iostream>
#include <assert.h>
#include "../Include/DeadStop.h"



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void BadFunction()
{
    // assert(false && "This is a random assertion which won't ever trigger.");
    // printf("We passed the assertion\n.");
    std::cout << "We passed the assertion\n.";

    int* pA = reinterpret_cast<int*>(0xCDCDCDCDCDCDCDCD);
    *pA = 500;
}



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(void)
{
    if(DeadStop_InitializeEx("testdump.txt", 50, 50, 8, 10) != ErrCode_Success)
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

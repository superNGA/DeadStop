#include <iostream>
#include <vector>
#include "../Include/DeadStop.h"



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void BadFunction(std::vector<int>& vecInput)
{
    std::cout << "this is a helpfull string\n";
    printf("niga1, niga2, niga4, niga3");
    vecInput[10] = 10;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void FnThatCallsBadFunction(std::vector<int>& vecInput)
{
    BadFunction(vecInput);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(void)
{
    if(DeadStop::Initialize("testdump.txt", 50, 50, 5) != DeadStop::ErrCode_Success)
    {
        std::cout << "Failed to initialize DeadStop.\n";
        return 1;
    }
    std::cout << "Deadstop initialized successfully\n";


    // This will crash.
    std::vector<int> vecNums = {1, 2, 3, 4, 5};
    FnThatCallsBadFunction(vecNums);


    DeadStop::Uninitialize();
    std::cout << "Deadstop uninitialized.\n";
    return 0;
}

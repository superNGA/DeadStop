//=========================================================================
//                      Printf Wrapper
//=========================================================================
// by      : INSANE
// created : 26/01/2026
//
// purpose : Printf wrapper for convinence.
//-------------------------------------------------------------------------
#include "ConsoleSystem.h"
#include <cstdio>
#include <mutex>
#include <cstdarg>


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void DEADSTOP_NAMESPACE::Console::PrintToConsole(const char* szCaller, const char* szFGColor, const char* szModifier, const char* szFormat, ...)
{
    static std::mutex s_mtx;

    s_mtx.lock();
    
    // 2 calls so that caller name is always in white.
    if(szCaller[0] != '\0')
    {
        printf("%s%s[ %s ] %s", Console::FG_BRIGHT_WHITE, Console::BOLD, szCaller, Console::RESET);
    }

    // Format text.
    printf("%s%s", szFGColor, szModifier);

    // Print using varadic args.
    va_list args; va_start(args, szFormat);
    vprintf(szFormat, args);
    va_end(args);

    // Reset
    printf("%s\n", Console::RESET);

    s_mtx.unlock();
}

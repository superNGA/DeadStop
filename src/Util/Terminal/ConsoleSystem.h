//=========================================================================
//                      Printf Wrapper
//=========================================================================
// by      : INSANE
// created : 26/01/2026
//
// purpose : Printf wrapper for convinence.
//-------------------------------------------------------------------------
#pragma once
#include "../../../Include/Alias.h"



namespace DEADSTOP_NAMESPACE::Console
{
    inline const char* RESET               = "\033[0m";
    inline const char* FG_BLACK            = "\033[30m";
    inline const char* FG_RED              = "\033[31m";
    inline const char* FG_GREEN            = "\033[32m";
    inline const char* FG_YELLOW           = "\033[33m";
    inline const char* FG_BLUE             = "\033[34m";
    inline const char* FG_MAGENTA          = "\033[35m";
    inline const char* FG_CYAN             = "\033[36m";
    inline const char* FG_WHITE            = "\033[37m";
    inline const char* FG_BRIGHT_BLACK     = "\033[90m";
    inline const char* FG_BRIGHT_RED       = "\033[91m";
    inline const char* FG_BRIGHT_GREEN     = "\033[92m";
    inline const char* FG_BRIGHT_YELLOW    = "\033[93m";
    inline const char* FG_BRIGHT_BLUE      = "\033[94m";
    inline const char* FG_BRIGHT_MAGENTA   = "\033[95m";
    inline const char* FG_BRIGHT_CYAN      = "\033[96m";
    inline const char* FG_BRIGHT_WHITE     = "\033[97m";
    inline const char* BOLD                = "\033[1m";
    inline const char* ITALIC              = "\033[3m";
    inline const char* UNDERLINE           = "\033[4m";
    inline const char* BLINKING            = "\033[5m";
    inline const char* STRIKE              = "\033[9m";



    void PrintToConsole(const char* szCaller, const char* szFGColor, const char* szModifier, const char* szFormat, ...);
}

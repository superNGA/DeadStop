//=========================================================================
//                      Assertion
//=========================================================================
// by      : INSANE
// created : 06/02/2026
//
// purpose : assertion.h rip-off so we have assertions in release mode.
//-------------------------------------------------------------------------
#pragma once
#include <cstdio>
#include <cstdlib>


// Set to false to disable assetions.
#define ENABLE_ASSERTIONS true


#if (ENABLE_ASSERTIONS == true)
#define assertion(expression) { if((expression) == false) Assertion(#expression, __FILE__, __LINE__); }
#elif
#define assertion(expression) 
#endif


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
inline void  Assertion(const char* szExpression, const char* szFile, int iLine)
{
    printf("Assertion failed!\n");
    printf("Expression : %s\n", szExpression);
    printf("File       : %s\n", szFile);
    printf("Line       : %d\n", iLine);
    abort();
}
